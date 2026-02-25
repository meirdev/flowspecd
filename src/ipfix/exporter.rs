use crate::config::IpfixConfig;
use crate::ipfix::template::{Template, FLOWSPEC_STATS_TEMPLATE_ID, FLOW_RECORD_TEMPLATE_ID};
use crate::stats::{FlowRecord, StatsCollector};
use anyhow::Result;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

const IPFIX_VERSION: u16 = 10;
const MAX_PACKET_SIZE: usize = 1400;

pub struct IpfixExporter {
    config: IpfixConfig,
    stats: StatsCollector,
    sequence_number: AtomicU32,
    flowspec_template: Template,
    flow_record_template: Template,
}

impl IpfixExporter {
    pub fn new(config: IpfixConfig, stats: StatsCollector) -> Self {
        Self {
            config,
            stats,
            sequence_number: AtomicU32::new(0),
            flowspec_template: Template::flowspec_stats(),
            flow_record_template: Template::flow_record(),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.config.collector).await?;

        tracing::info!("IPFIX exporter sending to {}", self.config.collector);

        let mut interval = tokio::time::interval(Duration::from_secs(self.config.export_interval_secs));
        let mut template_interval = tokio::time::interval(Duration::from_secs(300)); // Send template every 5 min

        // Send initial template
        let template_packet = self.build_template_packet();
        socket.send(&template_packet).await?;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Export FlowSpec rule statistics
                    if let Ok(packet) = self.build_flowspec_data_packet() {
                        if packet.len() > 16 {
                            if let Err(e) = socket.send(&packet).await {
                                tracing::warn!("Failed to send IPFIX flowspec data: {}", e);
                            } else {
                                tracing::debug!("Sent IPFIX flowspec data packet ({} bytes)", packet.len());
                            }
                        }
                    }

                    // Export flow records
                    let flow_packets = self.build_flow_record_packets();
                    for packet in flow_packets {
                        if let Err(e) = socket.send(&packet).await {
                            tracing::warn!("Failed to send IPFIX flow record: {}", e);
                        } else {
                            tracing::debug!("Sent IPFIX flow record packet ({} bytes)", packet.len());
                        }
                    }
                }
                _ = template_interval.tick() => {
                    let template_packet = self.build_template_packet();
                    if let Err(e) = socket.send(&template_packet).await {
                        tracing::warn!("Failed to send IPFIX template: {}", e);
                    }
                }
            }
        }
    }

    fn build_header(&self, length: u16) -> Vec<u8> {
        let mut header = Vec::with_capacity(16);

        let export_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let seq = self.sequence_number.fetch_add(1, Ordering::Relaxed);

        header.extend_from_slice(&IPFIX_VERSION.to_be_bytes());
        header.extend_from_slice(&length.to_be_bytes());
        header.extend_from_slice(&export_time.to_be_bytes());
        header.extend_from_slice(&seq.to_be_bytes());
        header.extend_from_slice(&self.config.observation_domain_id.to_be_bytes());

        header
    }

    fn build_template_packet(&self) -> Vec<u8> {
        let flowspec_template_data = self.flowspec_template.encode();
        let flow_record_template_data = self.flow_record_template.encode();
        let total_len = 16 + flowspec_template_data.len() + flow_record_template_data.len();

        let mut packet = self.build_header(total_len as u16);
        packet.extend_from_slice(&flowspec_template_data);
        packet.extend_from_slice(&flow_record_template_data);

        packet
    }

    fn build_flowspec_data_packet(&self) -> Result<Vec<u8>> {
        let rule_stats = self.stats.all_rule_stats();
        if rule_stats.is_empty() {
            return Ok(Vec::new());
        }

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut records = Vec::new();

        for (rule_id, stats) in rule_stats.iter() {
            let mut record = Vec::new();

            // observationDomainId
            record.extend_from_slice(&self.config.observation_domain_id.to_be_bytes());

            // flowId (hash of rule_id)
            let mut hasher = DefaultHasher::new();
            rule_id.hash(&mut hasher);
            record.extend_from_slice(&hasher.finish().to_be_bytes());

            // packetDeltaCount
            record.extend_from_slice(&stats.packets.to_be_bytes());

            // octetDeltaCount
            record.extend_from_slice(&stats.bytes.to_be_bytes());

            // droppedPacketDeltaCount
            record.extend_from_slice(&stats.dropped_packets.to_be_bytes());

            // droppedOctetDeltaCount
            record.extend_from_slice(&stats.dropped_bytes.to_be_bytes());

            // flowStartMilliseconds (uptime start)
            let start_ms = now_ms - (self.stats.uptime_secs() * 1000);
            record.extend_from_slice(&start_ms.to_be_bytes());

            // flowEndMilliseconds
            record.extend_from_slice(&now_ms.to_be_bytes());

            records.push(record);
        }

        // Build Data Set
        let mut data_set = Vec::new();
        data_set.extend_from_slice(&FLOWSPEC_STATS_TEMPLATE_ID.to_be_bytes()); // Set ID
        let set_len_pos = data_set.len();
        data_set.extend_from_slice(&0u16.to_be_bytes()); // Length placeholder

        for record in records {
            if data_set.len() + record.len() + 16 > MAX_PACKET_SIZE {
                break; // Don't exceed MTU
            }
            data_set.extend_from_slice(&record);
        }

        // Padding to 4-byte boundary
        while data_set.len() % 4 != 0 {
            data_set.push(0);
        }

        // Update set length
        let set_len = data_set.len() as u16;
        data_set[set_len_pos..set_len_pos + 2].copy_from_slice(&set_len.to_be_bytes());

        // Build final packet
        let total_len = 16 + data_set.len();
        let mut packet = self.build_header(total_len as u16);
        packet.extend_from_slice(&data_set);

        Ok(packet)
    }

    /// Build IPFIX packets containing flow records with 5-tuple + tcp_flags
    fn build_flow_record_packets(&self) -> Vec<Vec<u8>> {
        let flows = self.stats.export_flows();
        if flows.is_empty() {
            return Vec::new();
        }

        let sampling_rate = self.stats.sampling_rate();
        let record_size = self.flow_record_template.record_length();
        // Account for header (16) + set header (4) + padding
        let max_records_per_packet = (MAX_PACKET_SIZE - 20) / record_size;

        let mut packets = Vec::new();
        let mut current_records: Vec<Vec<u8>> = Vec::new();

        for flow in &flows {
            let record = self.encode_flow_record(flow, sampling_rate);

            if current_records.len() >= max_records_per_packet {
                // Flush current batch
                if let Some(packet) = self.build_flow_data_packet(&current_records) {
                    packets.push(packet);
                }
                current_records.clear();
            }

            current_records.push(record);
        }

        // Flush remaining records
        if !current_records.is_empty() {
            if let Some(packet) = self.build_flow_data_packet(&current_records) {
                packets.push(packet);
            }
        }

        tracing::debug!("Exported {} flows in {} IPFIX packets", flows.len(), packets.len());
        packets
    }

    fn encode_flow_record(&self, flow: &FlowRecord, sampling_rate: u32) -> Vec<u8> {
        let mut record = Vec::with_capacity(42); // Fixed record size

        // sourceIPv4Address (4 bytes)
        record.extend_from_slice(&flow.key.src_addr.octets());

        // destinationIPv4Address (4 bytes)
        record.extend_from_slice(&flow.key.dst_addr.octets());

        // sourceTransportPort (2 bytes)
        record.extend_from_slice(&flow.key.src_port.to_be_bytes());

        // destinationTransportPort (2 bytes)
        record.extend_from_slice(&flow.key.dst_port.to_be_bytes());

        // protocolIdentifier (1 byte)
        record.push(flow.key.protocol);

        // tcpControlBits (1 byte)
        record.push(flow.tcp_flags);

        // packetDeltaCount (8 bytes) - multiply by sampling rate for estimated actual count
        let estimated_packets = flow.packets * (sampling_rate as u64);
        record.extend_from_slice(&estimated_packets.to_be_bytes());

        // octetDeltaCount (8 bytes) - multiply by sampling rate for estimated actual bytes
        let estimated_bytes = flow.bytes * (sampling_rate as u64);
        record.extend_from_slice(&estimated_bytes.to_be_bytes());

        // flowStartMilliseconds (8 bytes)
        record.extend_from_slice(&flow.first_seen_ms.to_be_bytes());

        // flowEndMilliseconds (8 bytes)
        record.extend_from_slice(&flow.last_seen_ms.to_be_bytes());

        // samplingInterval (4 bytes)
        record.extend_from_slice(&sampling_rate.to_be_bytes());

        record
    }

    fn build_flow_data_packet(&self, records: &[Vec<u8>]) -> Option<Vec<u8>> {
        if records.is_empty() {
            return None;
        }

        // Build Data Set
        let mut data_set = Vec::new();
        data_set.extend_from_slice(&FLOW_RECORD_TEMPLATE_ID.to_be_bytes()); // Set ID
        let set_len_pos = data_set.len();
        data_set.extend_from_slice(&0u16.to_be_bytes()); // Length placeholder

        for record in records {
            data_set.extend_from_slice(record);
        }

        // Padding to 4-byte boundary
        while data_set.len() % 4 != 0 {
            data_set.push(0);
        }

        // Update set length
        let set_len = data_set.len() as u16;
        data_set[set_len_pos..set_len_pos + 2].copy_from_slice(&set_len.to_be_bytes());

        // Build final packet
        let total_len = 16 + data_set.len();
        let mut packet = self.build_header(total_len as u16);
        packet.extend_from_slice(&data_set);

        Some(packet)
    }
}
