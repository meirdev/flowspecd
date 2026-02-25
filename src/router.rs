use crate::api::{run_api, ApiState};
use crate::bgp::BgpSpeaker;
use crate::config::Config;
use crate::flowspec::FlowSpecEngine;
use crate::forwarding::ForwardingEngine;
use crate::ipfix::IpfixExporter;
use crate::stats::StatsCollector;
use anyhow::Result;
use std::sync::Arc;

pub struct Router {
    config: Config,
    stats: StatsCollector,
    flowspec_engine: Arc<FlowSpecEngine>,
}

impl Router {
    pub fn new(config: Config) -> Self {
        // Create stats collector with sampling rate from IPFIX config (if present)
        let sampling_rate = config.ipfix.as_ref().map(|c| c.sampling_rate).unwrap_or(1);
        let stats = StatsCollector::with_sampling_rate(sampling_rate);

        let flowspec_engine = Arc::new(FlowSpecEngine::new(
            config.flowspec.default_action,
            stats.clone(),
        ));

        // Load static FlowSpec rules from config
        for rule_cfg in &config.flowspec.rules {
            let mut rule = crate::flowspec::FlowSpecRule::new(
                rule_cfg.name.clone(),
                rule_cfg.name.clone(),
            );

            if let Some(prefix) = rule_cfg.src_prefix {
                rule = rule.with_src_prefix(prefix);
            }
            if let Some(prefix) = rule_cfg.dst_prefix {
                rule = rule.with_dst_prefix(prefix);
            }
            if let Some(proto) = rule_cfg.protocol {
                rule = rule.with_protocol(proto);
            }
            if let Some(ref port) = rule_cfg.src_port {
                rule = rule.with_src_port(port.start, port.end);
            }
            if let Some(ref port) = rule_cfg.dst_port {
                rule = rule.with_dst_port(port.start, port.end);
            }

            rule = rule.with_action(rule_cfg.action);

            if let Some(rate) = rule_cfg.rate_limit_bps {
                rule = rule.with_rate_limit(rate);
            }

            flowspec_engine.add_rule(rule);
        }

        Self {
            config,
            stats,
            flowspec_engine,
        }
    }

    pub async fn run(&self) -> Result<()> {
        tracing::info!(
            "Starting rust-router (router_id: {})",
            self.config.router.router_id
        );

        // Start forwarding engine
        let forwarding = ForwardingEngine::new(
            self.config.wan_interface().name.clone(),
            self.config.lan_interface().name.clone(),
            self.flowspec_engine.clone(),
            self.stats.clone(),
        );
        forwarding.start()?;

        // Start BGP speaker if configured
        if let Some(ref bgp_config) = self.config.bgp {
            let bgp = BgpSpeaker::new(bgp_config.clone(), self.flowspec_engine.clone());
            tokio::spawn(async move {
                if let Err(e) = bgp.run().await {
                    tracing::error!("BGP speaker error: {}", e);
                }
            });
        }

        // Start IPFIX exporter if configured
        if let Some(ref ipfix_config) = self.config.ipfix {
            let exporter = IpfixExporter::new(ipfix_config.clone(), self.stats.clone());
            tokio::spawn(async move {
                if let Err(e) = exporter.run().await {
                    tracing::error!("IPFIX exporter error: {}", e);
                }
            });
        }

        // Start REST API if configured
        if let Some(ref api_config) = self.config.api {
            let state = ApiState {
                flowspec_engine: self.flowspec_engine.clone(),
                stats: self.stats.clone(),
            };
            let api_config = api_config.clone();
            tokio::spawn(async move {
                if let Err(e) = run_api(api_config, state).await {
                    tracing::error!("REST API error: {}", e);
                }
            });
        }

        tracing::info!(
            "Router started with {} FlowSpec rules",
            self.flowspec_engine.rule_count()
        );

        // Keep running
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            self.log_stats();
        }
    }

    fn log_stats(&self) {
        let global = self.stats.global().snapshot();
        tracing::info!(
            "Stats: total_pkts={}, forwarded={}, dropped={}, rules={}, flows={}",
            global.total_packets,
            global.forwarded_packets,
            global.dropped_packets,
            self.flowspec_engine.rule_count(),
            self.stats.flow_count()
        );
    }
}
