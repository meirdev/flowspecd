mod rules;
mod matcher;
mod actions;

pub use rules::{FlowSpecRule, RuleId};
pub use matcher::PacketMatcher;
pub use actions::{Action, RateLimiter};

use crate::config::FlowSpecAction;
use crate::stats::{RuleStats, StatsCollector};
use dashmap::DashMap;
use std::sync::Arc;

pub struct FlowSpecEngine {
    rules: DashMap<RuleId, FlowSpecRule>,
    rule_stats: DashMap<RuleId, Arc<RuleStats>>,
    default_action: FlowSpecAction,
    stats_collector: StatsCollector,
}

impl FlowSpecEngine {
    pub fn new(default_action: FlowSpecAction, stats_collector: StatsCollector) -> Self {
        Self {
            rules: DashMap::new(),
            rule_stats: DashMap::new(),
            default_action,
            stats_collector,
        }
    }

    pub fn add_rule(&self, rule: FlowSpecRule) {
        let rule_id = rule.id.clone();
        let stats = self.stats_collector.get_or_create_rule_stats(&rule_id);
        self.rule_stats.insert(rule_id.clone(), stats);
        self.rules.insert(rule_id, rule);
        tracing::info!("Added FlowSpec rule: {}", self.rules.len());
    }

    pub fn remove_rule(&self, rule_id: &RuleId) {
        self.rules.remove(rule_id);
        self.rule_stats.remove(rule_id);
        tracing::info!("Removed FlowSpec rule, remaining: {}", self.rules.len());
    }

    pub fn process_packet(&self, packet: &PacketInfo) -> FlowSpecAction {
        for entry in self.rules.iter() {
            let rule = entry.value();
            if rule.matches(packet) {
                if let Some(stats) = self.rule_stats.get(&rule.id) {
                    match rule.action {
                        FlowSpecAction::Accept => stats.record_accept(packet.length as u64),
                        FlowSpecAction::Drop => stats.record_drop(packet.length as u64),
                        FlowSpecAction::RateLimit => {
                            if rule.should_rate_limit(packet.length) {
                                stats.record_rate_limit(packet.length as u64);
                                return FlowSpecAction::Drop;
                            }
                            stats.record_accept(packet.length as u64);
                        }
                    }
                }
                return rule.action;
            }
        }
        self.default_action
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn list_rules(&self) -> Vec<FlowSpecRule> {
        self.rules.iter().map(|e| e.value().clone()).collect()
    }
}

/// Fragment flags for FlowSpec matching (RFC 8955 Type 12)
#[derive(Debug, Clone, Copy, Default)]
pub struct FragmentFlags {
    /// Don't Fragment (DF) bit set
    pub dont_fragment: bool,
    /// Is a Fragment (more fragments or fragment offset > 0)
    pub is_fragment: bool,
    /// First Fragment (fragment offset == 0 but MF set)
    pub first_fragment: bool,
    /// Last Fragment (fragment offset > 0 but MF not set)
    pub last_fragment: bool,
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    // Type 1: Destination Prefix
    pub dst_addr: std::net::Ipv4Addr,
    // Type 2: Source Prefix
    pub src_addr: std::net::Ipv4Addr,
    // Type 3: IP Protocol
    pub protocol: u8,
    // Type 5: Destination Port
    pub dst_port: Option<u16>,
    // Type 6: Source Port
    pub src_port: Option<u16>,
    // Type 7: ICMP Type
    pub icmp_type: Option<u8>,
    // Type 8: ICMP Code
    pub icmp_code: Option<u8>,
    // Type 9: TCP Flags
    pub tcp_flags: Option<u8>,
    // Type 10: Packet Length
    pub length: usize,
    // Type 11: DSCP
    pub dscp: u8,
    // Type 12: Fragment
    pub fragment: FragmentFlags,
}
