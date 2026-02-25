use crate::bgp::flowspec::{parse_traffic_action, FlowSpecNlri};
use crate::config::{BgpConfig, BgpPeerConfig, FlowSpecAction};
use crate::flowspec::FlowSpecEngine;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const BGP_MARKER: [u8; 16] = [0xff; 16];
const BGP_HEADER_LEN: usize = 19;

// BGP Message Types
const BGP_OPEN: u8 = 1;
const BGP_UPDATE: u8 = 2;
const BGP_NOTIFICATION: u8 = 3;
const BGP_KEEPALIVE: u8 = 4;

// AFI/SAFI for FlowSpec
const AFI_IPV4: u16 = 1;
const SAFI_FLOWSPEC: u8 = 133;

pub struct BgpSpeaker {
    config: BgpConfig,
    flowspec_engine: Arc<FlowSpecEngine>,
    rule_counter: AtomicU64,
}

impl BgpSpeaker {
    pub fn new(config: BgpConfig, flowspec_engine: Arc<FlowSpecEngine>) -> Self {
        Self {
            config,
            flowspec_engine,
            rule_counter: AtomicU64::new(0),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let listen_addr = SocketAddr::from(([0, 0, 0, 0], self.config.listen_port));
        let listener = TcpListener::bind(listen_addr).await
            .with_context(|| format!("Failed to bind BGP listener on port {}", self.config.listen_port))?;

        tracing::info!("BGP speaker listening on {}", listen_addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    tracing::info!("BGP connection from {}", peer_addr);

                    if let Some(peer_config) = self.find_peer_config(peer_addr) {
                        let flowspec_engine = self.flowspec_engine.clone();
                        let local_as = self.config.local_as;
                        let peer_config = peer_config.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_peer_session(
                                stream,
                                peer_addr,
                                local_as,
                                peer_config,
                                flowspec_engine,
                            ).await {
                                tracing::warn!("BGP session error with {}: {}", peer_addr, e);
                            }
                        });
                    } else {
                        tracing::warn!("Rejecting BGP connection from unconfigured peer: {}", peer_addr);
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to accept BGP connection: {}", e);
                }
            }
        }
    }

    fn find_peer_config(&self, peer_addr: SocketAddr) -> Option<&BgpPeerConfig> {
        let peer_ip = match peer_addr {
            SocketAddr::V4(addr) => *addr.ip(),
            _ => return None,
        };

        self.config.peers.iter().find(|p| p.address == peer_ip)
    }

    pub fn next_rule_id(&self) -> String {
        let id = self.rule_counter.fetch_add(1, Ordering::Relaxed);
        format!("bgp-rule-{}", id)
    }
}

async fn handle_peer_session(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    local_as: u32,
    peer_config: BgpPeerConfig,
    flowspec_engine: Arc<FlowSpecEngine>,
) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    let mut rule_counter: u64 = 0;

    // Wait for OPEN message from peer
    let n = stream.read(&mut buf).await?;
    if n < BGP_HEADER_LEN {
        anyhow::bail!("Incomplete BGP header");
    }

    let msg_type = buf[18];
    if msg_type != BGP_OPEN {
        anyhow::bail!("Expected OPEN message, got type {}", msg_type);
    }

    tracing::debug!("Received BGP OPEN from {}", peer_addr);

    // Send OPEN message
    let open_msg = build_open_message(local_as, Ipv4Addr::new(10, 0, 0, 1));
    stream.write_all(&open_msg).await?;

    // Send KEEPALIVE
    let keepalive = build_keepalive_message();
    stream.write_all(&keepalive).await?;

    tracing::info!("BGP session established with {} (AS{})", peer_addr, peer_config.remote_as);

    // Main message loop
    loop {
        tokio::select! {
            result = stream.read(&mut buf) => {
                let n = result?;
                if n == 0 {
                    tracing::info!("BGP session closed by {}", peer_addr);
                    break;
                }

                if n < BGP_HEADER_LEN {
                    continue;
                }

                let msg_len = u16::from_be_bytes([buf[16], buf[17]]) as usize;
                let msg_type = buf[18];

                match msg_type {
                    BGP_KEEPALIVE => {
                        // Respond with KEEPALIVE
                        stream.write_all(&keepalive).await?;
                    }
                    BGP_UPDATE => {
                        if peer_config.flowspec {
                            if let Some((nlri, action, rate_limit)) = parse_flowspec_update(&buf[BGP_HEADER_LEN..n]) {
                                rule_counter += 1;
                                let rule_id = format!("bgp-{}-{}", peer_addr.ip(), rule_counter);
                                let rule = nlri.to_rule(&rule_id, action, rate_limit);
                                flowspec_engine.add_rule(rule);
                                tracing::info!("Added FlowSpec rule {} from {}", rule_id, peer_addr);
                            }
                        }
                    }
                    BGP_NOTIFICATION => {
                        let error_code = if n > BGP_HEADER_LEN { buf[BGP_HEADER_LEN] } else { 0 };
                        let error_subcode = if n > BGP_HEADER_LEN + 1 { buf[BGP_HEADER_LEN + 1] } else { 0 };
                        tracing::warn!(
                            "BGP NOTIFICATION from {}: error={}, subcode={}",
                            peer_addr, error_code, error_subcode
                        );
                        break;
                    }
                    _ => {
                        tracing::debug!("Unknown BGP message type: {}", msg_type);
                    }
                }
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                // Send periodic KEEPALIVE
                stream.write_all(&keepalive).await?;
            }
        }
    }

    Ok(())
}

fn build_open_message(local_as: u32, router_id: Ipv4Addr) -> Vec<u8> {
    let mut msg = Vec::with_capacity(128);

    // Build capabilities
    let mut capabilities = Vec::new();

    // MP-BGP capability for IPv4 Unicast (required for most peers)
    capabilities.extend_from_slice(&[
        1, 4,           // Capability code (MP-BGP) + length
        0, 1,           // AFI: IPv4
        0,              // Reserved
        1,              // SAFI: Unicast
    ]);

    // MP-BGP capability for IPv4 FlowSpec
    capabilities.extend_from_slice(&[
        1, 4,           // Capability code (MP-BGP) + length
        0, 1,           // AFI: IPv4
        0,              // Reserved
        133,            // SAFI: FlowSpec
    ]);

    // 4-byte AS capability
    capabilities.extend_from_slice(&[
        65, 4,          // Capability code (4-byte AS) + length
    ]);
    capabilities.extend_from_slice(&local_as.to_be_bytes());

    // Optional parameters (capabilities parameter type = 2)
    let mut opt_params = vec![2, capabilities.len() as u8];
    opt_params.extend_from_slice(&capabilities);

    // BGP OPEN message
    let version = 4u8;
    let my_as = if local_as > 65535 { 23456u16 } else { local_as as u16 }; // AS_TRANS if 4-byte
    let hold_time = 180u16;

    let open_len = 10 + opt_params.len();

    // Marker
    msg.extend_from_slice(&BGP_MARKER);
    // Length
    msg.extend_from_slice(&((BGP_HEADER_LEN + open_len) as u16).to_be_bytes());
    // Type
    msg.push(BGP_OPEN);
    // Version
    msg.push(version);
    // My AS
    msg.extend_from_slice(&my_as.to_be_bytes());
    // Hold Time
    msg.extend_from_slice(&hold_time.to_be_bytes());
    // BGP Identifier
    msg.extend_from_slice(&router_id.octets());
    // Optional Parameters Length
    msg.push(opt_params.len() as u8);
    // Optional Parameters
    msg.extend_from_slice(&opt_params);

    msg
}

fn build_keepalive_message() -> Vec<u8> {
    let mut msg = Vec::with_capacity(BGP_HEADER_LEN);
    msg.extend_from_slice(&BGP_MARKER);
    msg.extend_from_slice(&(BGP_HEADER_LEN as u16).to_be_bytes());
    msg.push(BGP_KEEPALIVE);
    msg
}

fn parse_flowspec_update(data: &[u8]) -> Option<(FlowSpecNlri, FlowSpecAction, Option<u64>)> {
    if data.len() < 4 {
        return None;
    }

    let withdrawn_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut offset = 2 + withdrawn_len;

    if offset + 2 > data.len() {
        return None;
    }

    let path_attr_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    let path_attr_end = offset + path_attr_len;
    if path_attr_end > data.len() {
        return None;
    }

    let mut action = FlowSpecAction::Accept;
    let mut rate_limit_bps = None;

    // Parse path attributes for extended communities
    while offset < path_attr_end {
        if offset + 3 > data.len() {
            break;
        }

        let attr_flags = data[offset];
        let attr_type = data[offset + 1];
        let extended = (attr_flags & 0x10) != 0;

        let attr_len = if extended {
            if offset + 4 > data.len() {
                break;
            }
            let len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            len
        } else {
            let len = data[offset + 2] as usize;
            offset += 3;
            len
        };

        if offset + attr_len > data.len() {
            break;
        }

        // Extended Communities (type 16)
        if attr_type == 16 {
            let mut ec_offset = 0;
            while ec_offset + 8 <= attr_len {
                if let Some((act, rate)) = parse_traffic_action(&data[offset + ec_offset..offset + ec_offset + 8]) {
                    action = act;
                    rate_limit_bps = rate;
                }
                ec_offset += 8;
            }
        }

        // MP_REACH_NLRI (type 14) - contains FlowSpec NLRI
        if attr_type == 14 && attr_len >= 5 {
            let afi = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let safi = data[offset + 2];

            if afi == AFI_IPV4 && safi == SAFI_FLOWSPEC {
                let nh_len = data[offset + 3] as usize;
                let nlri_start = offset + 4 + nh_len + 1; // +1 for reserved byte

                if nlri_start < offset + attr_len {
                    // Parse NLRI length
                    let nlri_len = data[nlri_start] as usize;
                    if nlri_start + 1 + nlri_len <= offset + attr_len {
                        if let Some(nlri) = FlowSpecNlri::parse(&data[nlri_start + 1..nlri_start + 1 + nlri_len]) {
                            return Some((nlri, action, rate_limit_bps));
                        }
                    }
                }
            }
        }

        offset += attr_len;
    }

    None
}
