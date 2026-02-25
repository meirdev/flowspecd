mod backend;
mod bgp;
mod metrics;

use backend::nftables::Nftables;
use backend::{Action, Backend, Rule};
use bgp::attributes::PathAttribute;
use bgp::flowspec::TrafficAction;
use bgp::session::{extract_flowspec, extract_flowspec_withdrawals, Message, Session};
use clap::Parser;
use deku::DekuContainerRead;

#[derive(Parser, Debug)]
#[command(name = "rust-router")]
#[command(about = "BGP FlowSpec router with nftables backend")]
struct Args {
    /// Local AS number
    #[arg(long, default_value_t = 65001)]
    my_as: u16,

    /// BGP router ID (IPv4 address as dotted decimal or hex)
    #[arg(long, default_value = "10.0.0.1", value_parser = parse_bgp_id)]
    bgp_id: u32,

    /// Hold time in seconds
    #[arg(long, default_value_t = 180)]
    hold_time: u16,

    /// Listen address (ip:port) - mutually exclusive with --connect
    #[arg(long, default_value = "127.0.0.1:1179")]
    listen: String,

    /// Connect to peer (ip:port) instead of listening
    #[arg(long)]
    connect: Option<String>,

    /// Dry run mode - print nft commands without executing
    #[arg(long)]
    dry_run: bool,

    /// Prometheus metrics port (if not set, metrics are disabled)
    #[arg(long)]
    metrics_port: Option<u16>,
}

/// Parse BGP ID from dotted decimal (10.0.0.1) or hex (0x0A000001)
fn parse_bgp_id(s: &str) -> Result<u32, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u32::from_str_radix(&s[2..], 16).map_err(|e| e.to_string())
    } else if s.contains('.') {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return Err("Invalid IPv4 format".to_string());
        }
        let octets: Result<Vec<u8>, _> = parts.iter().map(|p| p.parse::<u8>()).collect();
        let octets = octets.map_err(|e| e.to_string())?;
        Ok(((octets[0] as u32) << 24)
            | ((octets[1] as u32) << 16)
            | ((octets[2] as u32) << 8)
            | (octets[3] as u32))
    } else {
        s.parse::<u32>().map_err(|e| e.to_string())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut session = if let Some(peer_addr) = &args.connect {
        println!("Connecting to {}...", peer_addr);
        Session::connect(peer_addr, args.my_as, args.bgp_id, args.hold_time).await?
    } else {
        println!("Listening on {}...", args.listen);
        Session::listen(&args.listen, args.my_as, args.bgp_id, args.hold_time).await?
    };

    // Initialize nftables backend
    let mut nft = Nftables::new();
    if !args.dry_run {
        if let Err(e) = nft.init() {
            eprintln!("Warning: Failed to initialize nftables: {}", e);
            eprintln!("Running in dry-run mode");
        }
    }

    // Start metrics server if port is configured
    if let Some(port) = args.metrics_port {
        metrics::start_server(port);
    }

    println!("Performing BGP handshake...");
    let peer_open = if args.connect.is_some() {
        session.handshake().await?
    } else {
        session.accept_handshake().await?
    };

    println!("Session established!");
    println!("  Peer AS: {}", peer_open.my_as);
    println!("  Peer BGP ID: {:08X}", peer_open.bgp_id);
    println!("  Hold time: {}", peer_open.hold_time);

    println!("\nWaiting for messages...");
    loop {
        match session.read_message().await {
            Ok(Message::Update(update)) => {
                println!("Received UPDATE");
                match update.parse_attributes() {
                    Ok(attrs) => {
                        // Handle announcements
                        let flowspecs = extract_flowspec(&attrs);
                        let action = extract_action(&attrs);

                        for fs in &flowspecs {
                            println!("  FlowSpec ADD: {:?}", fs.components);
                            println!("  Action: {:?}", action);

                            let rule = Rule::new(fs, action.clone());

                            if args.dry_run {
                                println!("  [dry-run] {}", nft.command_for_rule(&rule));
                            } else {
                                match nft.apply(&rule) {
                                    Ok(()) => println!("  Applied to nftables"),
                                    Err(e) => eprintln!("  Failed to apply: {}", e),
                                }
                            }
                        }

                        // Handle withdrawals
                        let withdrawals = extract_flowspec_withdrawals(&attrs);

                        for fs in &withdrawals {
                            println!("  FlowSpec WITHDRAW: {:?}", fs.components);

                            let rule = Rule::new(fs, Action::Drop);

                            if args.dry_run {
                                println!("  [dry-run] {}", nft.command_for_remove(&rule));
                            } else {
                                match nft.remove(&rule) {
                                    Ok(()) => println!("  Removed from nftables"),
                                    Err(e) => eprintln!("  Failed to remove: {}", e),
                                }
                            }
                        }
                    }
                    Err(e) => println!("  parse error: {:?}", e),
                }
            }
            Ok(Message::Keepalive) => {
                println!("Received KEEPALIVE");
                session.send_keepalive().await?;
            }
            Ok(Message::Notification(n)) => {
                println!("Received NOTIFICATION: {:?}", n.error_code);
                break;
            }
            Ok(msg) => println!("Received: {:?}", msg),
            Err(e) => {
                eprintln!("Error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Extract action from extended communities in path attributes
fn extract_action(attrs: &[PathAttribute]) -> Action {
    for attr in attrs {
        if let PathAttribute::ExtendedCommunities(data) = attr {
            // Parse extended communities (8 bytes each)
            for chunk in data.chunks(8) {
                if chunk.len() == 8 {
                    if let Ok((_, action)) = TrafficAction::from_bytes((chunk, 0)) {
                        match action {
                            TrafficAction::RateBytes { rate, .. } => {
                                if rate == 0.0 {
                                    return Action::Drop;
                                }
                                return Action::RateLimit {
                                    bytes_per_sec: rate,
                                };
                            }
                            TrafficAction::RatePackets { rate, .. } => {
                                if rate == 0.0 {
                                    return Action::Drop;
                                }
                                // Convert packets/sec to approximate bytes/sec
                                return Action::RateLimit {
                                    bytes_per_sec: rate * 1500.0,
                                };
                            }
                            TrafficAction::Action { terminal, .. } => {
                                if terminal {
                                    return Action::Accept;
                                }
                            }
                            TrafficAction::TrafficMarking { dscp, .. } => {
                                return Action::Mark { dscp };
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    // Default action: drop (common for FlowSpec DDoS mitigation)
    Action::Drop
}
