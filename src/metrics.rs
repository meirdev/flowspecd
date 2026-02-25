use prometheus::{Encoder, GaugeVec, Opts, Registry, TextEncoder};
use serde::Deserialize;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use sysinfo::Networks;
use tiny_http::{Response, Server};

const TABLE_NAME: &str = "flowspec";

#[derive(Debug, Deserialize)]
struct NftOutput {
    nftables: Vec<NftObject>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
enum NftObject {
    Rule { rule: NftRule },
    Other(serde_json::Value),
}

#[derive(Debug, Deserialize)]
struct NftRule {
    table: String,
    comment: Option<String>,
    expr: Vec<NftExpr>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
enum NftExpr {
    Counter { counter: Counter },
    Other(serde_json::Value),
}

#[derive(Debug, Deserialize)]
struct Counter {
    packets: u64,
    bytes: u64,
}

/// Collected metrics for a single rule
/// For rate-limit rules: first counter = matched, second counter = dropped
/// For drop/accept rules: only one counter (matched = dropped for drop action)
struct RuleMetrics {
    comment: String,
    matched_packets: u64,
    matched_bytes: u64,
    dropped_packets: u64,
    dropped_bytes: u64,
}

/// Query nftables and collect metrics for all rules
fn collect_nft_metrics() -> Vec<RuleMetrics> {
    let output = Command::new("nft")
        .args(["-j", "list", "table", "inet", TABLE_NAME])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let json_str = String::from_utf8_lossy(&output.stdout);
    let nft_output: NftOutput = match serde_json::from_str(&json_str) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let mut metrics = Vec::new();

    for obj in nft_output.nftables {
        if let NftObject::Rule { rule } = obj {
            // Only include rules from flowspec table
            if rule.table != TABLE_NAME {
                continue;
            }

            let comment = rule.comment.unwrap_or_else(|| "unknown".to_string());

            // Collect all counters in this rule
            let counters: Vec<&Counter> = rule
                .expr
                .iter()
                .filter_map(|e| match e {
                    NftExpr::Counter { counter } => Some(counter),
                    _ => None,
                })
                .collect();

            if counters.is_empty() {
                continue;
            }

            // First counter = matched packets
            // Second counter (if exists) = dropped packets (for rate-limit)
            let matched = counters[0];
            let dropped = counters.get(1).unwrap_or(&matched);

            metrics.push(RuleMetrics {
                comment,
                matched_packets: matched.packets,
                matched_bytes: matched.bytes,
                dropped_packets: dropped.packets,
                dropped_bytes: dropped.bytes,
            });
        }
    }

    metrics
}

/// Start the metrics HTTP server on the given port
pub fn start_server(port: u16) {
    let addr = format!("0.0.0.0:{}", port);

    // Create prometheus registry and gauges
    let registry = Arc::new(Registry::new());

    let matched_packets_gauge = GaugeVec::new(
        Opts::new(
            "flowspec_rule_matched_packets_total",
            "Total packets matched by FlowSpec rule",
        ),
        &["rule"],
    )
    .unwrap();

    let matched_bytes_gauge = GaugeVec::new(
        Opts::new(
            "flowspec_rule_matched_bytes_total",
            "Total bytes matched by FlowSpec rule",
        ),
        &["rule"],
    )
    .unwrap();

    let dropped_packets_gauge = GaugeVec::new(
        Opts::new(
            "flowspec_rule_dropped_packets_total",
            "Total packets dropped by FlowSpec rule (rate-limited or blocked)",
        ),
        &["rule"],
    )
    .unwrap();

    let dropped_bytes_gauge = GaugeVec::new(
        Opts::new(
            "flowspec_rule_dropped_bytes_total",
            "Total bytes dropped by FlowSpec rule (rate-limited or blocked)",
        ),
        &["rule"],
    )
    .unwrap();

    // Network interface metrics
    let net_rx_bytes_gauge = GaugeVec::new(
        Opts::new(
            "network_receive_bytes_total",
            "Total bytes received on network interface",
        ),
        &["interface"],
    )
    .unwrap();

    let net_tx_bytes_gauge = GaugeVec::new(
        Opts::new(
            "network_transmit_bytes_total",
            "Total bytes transmitted on network interface",
        ),
        &["interface"],
    )
    .unwrap();

    let net_rx_packets_gauge = GaugeVec::new(
        Opts::new(
            "network_receive_packets_total",
            "Total packets received on network interface",
        ),
        &["interface"],
    )
    .unwrap();

    let net_tx_packets_gauge = GaugeVec::new(
        Opts::new(
            "network_transmit_packets_total",
            "Total packets transmitted on network interface",
        ),
        &["interface"],
    )
    .unwrap();

    let net_rx_errors_gauge = GaugeVec::new(
        Opts::new(
            "network_receive_errors_total",
            "Total receive errors on network interface",
        ),
        &["interface"],
    )
    .unwrap();

    let net_tx_errors_gauge = GaugeVec::new(
        Opts::new(
            "network_transmit_errors_total",
            "Total transmit errors on network interface",
        ),
        &["interface"],
    )
    .unwrap();

    registry
        .register(Box::new(matched_packets_gauge.clone()))
        .unwrap();
    registry
        .register(Box::new(matched_bytes_gauge.clone()))
        .unwrap();
    registry
        .register(Box::new(dropped_packets_gauge.clone()))
        .unwrap();
    registry
        .register(Box::new(dropped_bytes_gauge.clone()))
        .unwrap();
    registry
        .register(Box::new(net_rx_bytes_gauge.clone()))
        .unwrap();
    registry
        .register(Box::new(net_tx_bytes_gauge.clone()))
        .unwrap();
    registry
        .register(Box::new(net_rx_packets_gauge.clone()))
        .unwrap();
    registry
        .register(Box::new(net_tx_packets_gauge.clone()))
        .unwrap();
    registry
        .register(Box::new(net_rx_errors_gauge.clone()))
        .unwrap();
    registry
        .register(Box::new(net_tx_errors_gauge.clone()))
        .unwrap();

    thread::spawn(move || {
        let server = match Server::http(&addr) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to start metrics server: {}", e);
                return;
            }
        };

        println!("Metrics server listening on http://{}/metrics", addr);

        for request in server.incoming_requests() {
            let path = request.url();

            let response = if path == "/metrics" {
                // Reset gauges and collect fresh data
                matched_packets_gauge.reset();
                matched_bytes_gauge.reset();
                dropped_packets_gauge.reset();
                dropped_bytes_gauge.reset();
                net_rx_bytes_gauge.reset();
                net_tx_bytes_gauge.reset();
                net_rx_packets_gauge.reset();
                net_tx_packets_gauge.reset();
                net_rx_errors_gauge.reset();
                net_tx_errors_gauge.reset();

                // Collect nftables metrics
                for m in collect_nft_metrics() {
                    matched_packets_gauge
                        .with_label_values(&[&m.comment])
                        .set(m.matched_packets as f64);
                    matched_bytes_gauge
                        .with_label_values(&[&m.comment])
                        .set(m.matched_bytes as f64);
                    dropped_packets_gauge
                        .with_label_values(&[&m.comment])
                        .set(m.dropped_packets as f64);
                    dropped_bytes_gauge
                        .with_label_values(&[&m.comment])
                        .set(m.dropped_bytes as f64);
                }

                // Collect network interface metrics
                let networks = Networks::new_with_refreshed_list();
                for (name, data) in &networks {
                    net_rx_bytes_gauge
                        .with_label_values(&[name])
                        .set(data.total_received() as f64);
                    net_tx_bytes_gauge
                        .with_label_values(&[name])
                        .set(data.total_transmitted() as f64);
                    net_rx_packets_gauge
                        .with_label_values(&[name])
                        .set(data.total_packets_received() as f64);
                    net_tx_packets_gauge
                        .with_label_values(&[name])
                        .set(data.total_packets_transmitted() as f64);
                    net_rx_errors_gauge
                        .with_label_values(&[name])
                        .set(data.total_errors_on_received() as f64);
                    net_tx_errors_gauge
                        .with_label_values(&[name])
                        .set(data.total_errors_on_transmitted() as f64);
                }

                // Encode metrics
                let encoder = TextEncoder::new();
                let metric_families = registry.gather();
                let mut buffer = Vec::new();
                encoder.encode(&metric_families, &mut buffer).unwrap();

                Response::from_data(buffer).with_header(
                    tiny_http::Header::from_bytes(
                        &b"Content-Type"[..],
                        encoder.format_type().as_bytes(),
                    )
                    .unwrap(),
                )
            } else {
                Response::from_string("Not Found").with_status_code(404)
            };

            let _ = request.respond(response);
        }
    });
}
