use crate::config::FlowSpecAction;
use crate::flowspec::{FlowSpecEngine, PacketMatcher};
use crate::stats::{FlowKey, StatsCollector};
use anyhow::{Context, Result};
use pnet::datalink::{self, Channel, Config, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Simple packet deduplication using a hash of recent packets
struct PacketDedup {
    recent: Mutex<HashSet<u64>>,
    max_size: usize,
}

impl PacketDedup {
    fn new(max_size: usize) -> Self {
        Self {
            recent: Mutex::new(HashSet::with_capacity(max_size)),
            max_size,
        }
    }

    /// Returns true if this packet was already seen recently
    fn check_and_add(&self, data: &[u8]) -> bool {
        let hash = Self::hash_packet(data);
        let mut recent = self.recent.lock().unwrap();

        if recent.contains(&hash) {
            return true; // Already seen
        }

        // Add to recent set, clear if too large
        if recent.len() >= self.max_size {
            recent.clear();
        }
        recent.insert(hash);
        false
    }

    fn hash_packet(data: &[u8]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        hasher.finish()
    }
}

pub struct ForwardingEngine {
    wan_interface: String,
    lan_interface: String,
    flowspec_engine: Arc<FlowSpecEngine>,
    stats: StatsCollector,
    running: Arc<AtomicBool>,
}

impl ForwardingEngine {
    pub fn new(
        wan_interface: String,
        lan_interface: String,
        flowspec_engine: Arc<FlowSpecEngine>,
        stats: StatsCollector,
    ) -> Self {
        Self {
            wan_interface,
            lan_interface,
            flowspec_engine,
            stats,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&self) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        let wan_iface = find_interface(&self.wan_interface)?;
        let lan_iface = find_interface(&self.lan_interface)?;

        tracing::info!(
            "Starting forwarding: {} <-> {}",
            self.wan_interface,
            self.lan_interface
        );

        // Shared deduplication cache to prevent forwarding loops
        let dedup = Arc::new(PacketDedup::new(1024));

        let _wan_to_lan_handle = self.spawn_forwarder(
            wan_iface.clone(),
            lan_iface.clone(),
            "wan->lan",
            dedup.clone(),
        )?;

        let _lan_to_wan_handle = self.spawn_forwarder(
            lan_iface,
            wan_iface,
            "lan->wan",
            dedup,
        )?;

        Ok(())
    }

    fn spawn_forwarder(
        &self,
        rx_iface: NetworkInterface,
        tx_iface: NetworkInterface,
        direction: &'static str,
        dedup: Arc<PacketDedup>,
    ) -> Result<thread::JoinHandle<()>> {
        let flowspec = self.flowspec_engine.clone();
        let stats = self.stats.clone();
        let running = self.running.clone();
        let rx_name = rx_iface.name.clone();
        let tx_name = tx_iface.name.clone();

        let rx_config = Config {
            read_timeout: Some(Duration::from_millis(100)),
            ..Default::default()
        };

        // Create RX channel
        let mut rx = match datalink::channel(&rx_iface, rx_config)? {
            Channel::Ethernet(_, rx) => rx,
            _ => anyhow::bail!("Unsupported channel type for RX"),
        };

        // Create TX channel
        let mut tx = match datalink::channel(&tx_iface, Config::default())? {
            Channel::Ethernet(tx, _) => tx,
            _ => anyhow::bail!("Unsupported channel type for TX"),
        };

        let rx_stats = stats.get_or_create_interface_stats(&rx_name);
        let tx_stats = stats.get_or_create_interface_stats(&tx_name);

        let handle = thread::spawn(move || {
            tracing::info!("[{}] Forwarder started: {} -> {}", direction, rx_name, tx_name);

            let mut pkt_count: u64 = 0;
            let mut fwd_count: u64 = 0;
            let mut dup_count: u64 = 0;

            while running.load(Ordering::Relaxed) {
                match rx.next() {
                    Ok(packet_data) => {
                        pkt_count += 1;

                        // Check for duplicate (packet we forwarded that looped back)
                        if dedup.check_and_add(packet_data) {
                            dup_count += 1;
                            continue;
                        }

                        if let Some(eth_packet) = EthernetPacket::new(packet_data) {
                            rx_stats.record_rx(packet_data.len() as u64);

                            let mut should_forward = true;
                            let mut src_ip = String::new();
                            let mut dst_ip = String::new();
                            let mut proto: u8 = 0;

                            // Apply FlowSpec rules for IPv4 packets
                            if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                                if let Some(ipv4) = Ipv4Packet::new(eth_packet.payload()) {
                                    let src_addr = ipv4.get_source();
                                    let dst_addr = ipv4.get_destination();
                                    src_ip = src_addr.to_string();
                                    dst_ip = dst_addr.to_string();
                                    proto = ipv4.get_next_level_protocol().0;

                                    // Extract ports and TCP flags for flow tracking
                                    let (src_port, dst_port, tcp_flags) = match ipv4.get_next_level_protocol() {
                                        IpNextHeaderProtocols::Tcp => {
                                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                                (tcp.get_source(), tcp.get_destination(), tcp.get_flags())
                                            } else {
                                                (0, 0, 0)
                                            }
                                        }
                                        IpNextHeaderProtocols::Udp => {
                                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                                (udp.get_source(), udp.get_destination(), 0)
                                            } else {
                                                (0, 0, 0)
                                            }
                                        }
                                        _ => (0, 0, 0),
                                    };

                                    // Record flow for IPFIX export (subject to sampling)
                                    let flow_key = FlowKey::new(src_addr, dst_addr, src_port, dst_port, proto);
                                    stats.record_flow(flow_key, packet_data.len() as u64, tcp_flags as u8);

                                    if let Some(packet_info) = PacketMatcher::extract_packet_info(&ipv4) {
                                        let action = flowspec.process_packet(&packet_info);

                                        match action {
                                            FlowSpecAction::Drop => {
                                                stats.global().dropped_packets.fetch_add(1, Ordering::Relaxed);
                                                should_forward = false;
                                                tracing::debug!("[{}] DROP: {} -> {} (proto={})",
                                                    direction, src_ip, dst_ip, proto);
                                            }
                                            FlowSpecAction::Accept | FlowSpecAction::RateLimit => {}
                                        }
                                    }
                                }
                            }

                            // Forward packet if not dropped
                            if should_forward {
                                if let Some(res) = tx.send_to(packet_data, None) {
                                    match res {
                                        Ok(_) => {
                                            fwd_count += 1;
                                            tx_stats.record_tx(packet_data.len() as u64);
                                            stats.global().forwarded_packets.fetch_add(1, Ordering::Relaxed);
                                            if fwd_count <= 3 || fwd_count % 100 == 0 {
                                                tracing::debug!("[{}] FWD #{}: {} -> {} proto={} ({} bytes)",
                                                    direction, fwd_count, src_ip, dst_ip, proto, packet_data.len());
                                            }
                                        }
                                        Err(e) => {
                                            tx_stats.record_tx_error();
                                            tracing::warn!("[{}] TX error: {}", direction, e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::TimedOut {
                            rx_stats.record_rx_error();
                            tracing::debug!("[{}] RX error: {}", direction, e);
                        }
                    }
                }
            }

            tracing::info!("[{}] Forwarder stopped (rx={}, fwd={}, dup={})",
                direction, pkt_count, fwd_count, dup_count);
        });

        Ok(handle)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

fn find_interface(name: &str) -> Result<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .with_context(|| format!("Interface not found: {}", name))
}
