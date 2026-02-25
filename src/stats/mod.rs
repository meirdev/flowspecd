use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Default)]
pub struct RuleStats {
    pub packets: AtomicU64,
    pub bytes: AtomicU64,
    pub dropped_packets: AtomicU64,
    pub dropped_bytes: AtomicU64,
    pub rate_limited_packets: AtomicU64,
    pub rate_limited_bytes: AtomicU64,
}

impl RuleStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_accept(&self, bytes: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_drop(&self, bytes: u64) {
        self.dropped_packets.fetch_add(1, Ordering::Relaxed);
        self.dropped_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_rate_limit(&self, bytes: u64) {
        self.rate_limited_packets.fetch_add(1, Ordering::Relaxed);
        self.rate_limited_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> RuleStatsSnapshot {
        RuleStatsSnapshot {
            packets: self.packets.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
            dropped_bytes: self.dropped_bytes.load(Ordering::Relaxed),
            rate_limited_packets: self.rate_limited_packets.load(Ordering::Relaxed),
            rate_limited_bytes: self.rate_limited_bytes.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleStatsSnapshot {
    pub packets: u64,
    pub bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
    pub rate_limited_packets: u64,
    pub rate_limited_bytes: u64,
}

#[derive(Debug, Default)]
pub struct InterfaceStats {
    pub rx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_errors: AtomicU64,
    pub tx_errors: AtomicU64,
}

impl InterfaceStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_rx(&self, bytes: u64) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_tx(&self, bytes: u64) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_rx_error(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tx_error(&self) {
        self.tx_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> InterfaceStatsSnapshot {
        InterfaceStatsSnapshot {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_errors: self.rx_errors.load(Ordering::Relaxed),
            tx_errors: self.tx_errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct InterfaceStatsSnapshot {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

#[derive(Clone)]
pub struct StatsCollector {
    start_time: Instant,
    interface_stats: Arc<RwLock<HashMap<String, Arc<InterfaceStats>>>>,
    rule_stats: Arc<RwLock<HashMap<String, Arc<RuleStats>>>>,
    global: Arc<GlobalStats>,
    flow_table: Arc<FlowTable>,
}

#[derive(Debug, Default)]
pub struct GlobalStats {
    pub total_packets: AtomicU64,
    pub total_bytes: AtomicU64,
    pub forwarded_packets: AtomicU64,
    pub dropped_packets: AtomicU64,
}

impl GlobalStats {
    pub fn snapshot(&self) -> GlobalStatsSnapshot {
        GlobalStatsSnapshot {
            total_packets: self.total_packets.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            forwarded_packets: self.forwarded_packets.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
        }
    }
}

/// 5-tuple flow key for flow tracking
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn new(src_addr: Ipv4Addr, dst_addr: Ipv4Addr, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        Self {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            protocol,
        }
    }
}

/// Flow record with statistics and TCP flags
#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub key: FlowKey,
    pub packets: u64,
    pub bytes: u64,
    pub tcp_flags: u8,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

impl FlowRecord {
    pub fn new(key: FlowKey, bytes: u64, tcp_flags: u8, timestamp_ms: u64) -> Self {
        Self {
            key,
            packets: 1,
            bytes,
            tcp_flags,
            first_seen_ms: timestamp_ms,
            last_seen_ms: timestamp_ms,
        }
    }

    pub fn update(&mut self, bytes: u64, tcp_flags: u8, timestamp_ms: u64) {
        self.packets += 1;
        self.bytes += bytes;
        self.tcp_flags |= tcp_flags; // Accumulate TCP flags
        self.last_seen_ms = timestamp_ms;
    }
}

/// Flow table for tracking active flows
pub struct FlowTable {
    flows: RwLock<HashMap<FlowKey, FlowRecord>>,
    max_flows: usize,
    sampling_counter: AtomicU64,
    sampling_rate: u32,
}

impl FlowTable {
    pub fn new(max_flows: usize, sampling_rate: u32) -> Self {
        Self {
            flows: RwLock::new(HashMap::with_capacity(max_flows / 2)),
            max_flows,
            sampling_counter: AtomicU64::new(0),
            sampling_rate: sampling_rate.max(1),
        }
    }

    fn current_time_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Record a packet, respecting the sampling rate
    /// Returns true if the packet was sampled
    pub fn record_packet(&self, key: FlowKey, bytes: u64, tcp_flags: u8) -> bool {
        // Sampling: only record 1 in N packets
        let count = self.sampling_counter.fetch_add(1, Ordering::Relaxed);
        if count % (self.sampling_rate as u64) != 0 {
            return false;
        }

        let timestamp_ms = Self::current_time_ms();
        let mut flows = self.flows.write();

        // Check if flow exists
        if let Some(flow) = flows.get_mut(&key) {
            flow.update(bytes, tcp_flags, timestamp_ms);
        } else {
            // Check if we need to evict old flows
            if flows.len() >= self.max_flows {
                // Simple eviction: remove oldest flow
                if let Some(oldest_key) = flows.iter()
                    .min_by_key(|(_, f)| f.last_seen_ms)
                    .map(|(k, _)| *k)
                {
                    flows.remove(&oldest_key);
                }
            }
            flows.insert(key, FlowRecord::new(key, bytes, tcp_flags, timestamp_ms));
        }

        true
    }

    /// Export and clear all flows
    pub fn export_flows(&self) -> Vec<FlowRecord> {
        let mut flows = self.flows.write();
        let result: Vec<FlowRecord> = flows.values().cloned().collect();
        flows.clear();
        result
    }

    /// Get current flow count
    pub fn flow_count(&self) -> usize {
        self.flows.read().len()
    }

    /// Get sampling rate
    pub fn sampling_rate(&self) -> u32 {
        self.sampling_rate
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GlobalStatsSnapshot {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub forwarded_packets: u64,
    pub dropped_packets: u64,
}

impl StatsCollector {
    pub fn new() -> Self {
        Self::with_sampling_rate(1)
    }

    pub fn with_sampling_rate(sampling_rate: u32) -> Self {
        Self {
            start_time: Instant::now(),
            interface_stats: Arc::new(RwLock::new(HashMap::new())),
            rule_stats: Arc::new(RwLock::new(HashMap::new())),
            global: Arc::new(GlobalStats::default()),
            flow_table: Arc::new(FlowTable::new(10000, sampling_rate)), // 10K max flows
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn get_or_create_interface_stats(&self, name: &str) -> Arc<InterfaceStats> {
        {
            let stats = self.interface_stats.read();
            if let Some(s) = stats.get(name) {
                return s.clone();
            }
        }
        let mut stats = self.interface_stats.write();
        stats.entry(name.to_string())
            .or_insert_with(|| Arc::new(InterfaceStats::new()))
            .clone()
    }

    pub fn get_or_create_rule_stats(&self, rule_id: &str) -> Arc<RuleStats> {
        {
            let stats = self.rule_stats.read();
            if let Some(s) = stats.get(rule_id) {
                return s.clone();
            }
        }
        let mut stats = self.rule_stats.write();
        stats.entry(rule_id.to_string())
            .or_insert_with(|| Arc::new(RuleStats::new()))
            .clone()
    }

    pub fn global(&self) -> &GlobalStats {
        &self.global
    }

    pub fn all_interface_stats(&self) -> HashMap<String, InterfaceStatsSnapshot> {
        self.interface_stats.read()
            .iter()
            .map(|(k, v)| (k.clone(), v.snapshot()))
            .collect()
    }

    pub fn all_rule_stats(&self) -> HashMap<String, RuleStatsSnapshot> {
        self.rule_stats.read()
            .iter()
            .map(|(k, v)| (k.clone(), v.snapshot()))
            .collect()
    }

    /// Record a flow packet (subject to sampling)
    pub fn record_flow(&self, key: FlowKey, bytes: u64, tcp_flags: u8) -> bool {
        self.flow_table.record_packet(key, bytes, tcp_flags)
    }

    /// Export and clear all flow records
    pub fn export_flows(&self) -> Vec<FlowRecord> {
        self.flow_table.export_flows()
    }

    /// Get current flow count
    pub fn flow_count(&self) -> usize {
        self.flow_table.flow_count()
    }

    /// Get flow table sampling rate
    pub fn sampling_rate(&self) -> u32 {
        self.flow_table.sampling_rate()
    }
}

impl Default for StatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FlowRecordSnapshot {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub tcp_flags: u8,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

impl From<&FlowRecord> for FlowRecordSnapshot {
    fn from(record: &FlowRecord) -> Self {
        Self {
            src_addr: record.key.src_addr,
            dst_addr: record.key.dst_addr,
            src_port: record.key.src_port,
            dst_port: record.key.dst_port,
            protocol: record.key.protocol,
            tcp_flags: record.tcp_flags,
            packets: record.packets,
            bytes: record.bytes,
            first_seen_ms: record.first_seen_ms,
            last_seen_ms: record.last_seen_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_stats_accept() {
        let stats = RuleStats::new();
        stats.record_accept(100);
        stats.record_accept(200);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets, 2);
        assert_eq!(snapshot.bytes, 300);
        assert_eq!(snapshot.dropped_packets, 0);
    }

    #[test]
    fn test_rule_stats_drop() {
        let stats = RuleStats::new();
        stats.record_drop(50);
        stats.record_drop(150);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.dropped_packets, 2);
        assert_eq!(snapshot.dropped_bytes, 200);
        assert_eq!(snapshot.packets, 0);
    }

    #[test]
    fn test_rule_stats_rate_limit() {
        let stats = RuleStats::new();
        stats.record_rate_limit(75);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.rate_limited_packets, 1);
        assert_eq!(snapshot.rate_limited_bytes, 75);
    }

    #[test]
    fn test_interface_stats() {
        let stats = InterfaceStats::new();
        stats.record_rx(1500);
        stats.record_rx(1000);
        stats.record_tx(500);
        stats.record_rx_error();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.rx_packets, 2);
        assert_eq!(snapshot.rx_bytes, 2500);
        assert_eq!(snapshot.tx_packets, 1);
        assert_eq!(snapshot.tx_bytes, 500);
        assert_eq!(snapshot.rx_errors, 1);
        assert_eq!(snapshot.tx_errors, 0);
    }

    #[test]
    fn test_stats_collector() {
        let collector = StatsCollector::new();

        // Test interface stats creation
        let eth0 = collector.get_or_create_interface_stats("eth0");
        eth0.record_rx(100);

        // Get same interface stats again
        let eth0_again = collector.get_or_create_interface_stats("eth0");
        eth0_again.record_rx(200);

        let all_iface = collector.all_interface_stats();
        assert_eq!(all_iface.len(), 1);
        assert_eq!(all_iface["eth0"].rx_packets, 2);
        assert_eq!(all_iface["eth0"].rx_bytes, 300);
    }

    #[test]
    fn test_stats_collector_rules() {
        let collector = StatsCollector::new();

        let rule1 = collector.get_or_create_rule_stats("rule-1");
        rule1.record_accept(100);

        let rule2 = collector.get_or_create_rule_stats("rule-2");
        rule2.record_drop(50);

        let all_rules = collector.all_rule_stats();
        assert_eq!(all_rules.len(), 2);
        assert_eq!(all_rules["rule-1"].packets, 1);
        assert_eq!(all_rules["rule-2"].dropped_packets, 1);
    }

    #[test]
    fn test_global_stats() {
        let collector = StatsCollector::new();
        collector.global().total_packets.fetch_add(10, Ordering::Relaxed);
        collector.global().forwarded_packets.fetch_add(8, Ordering::Relaxed);
        collector.global().dropped_packets.fetch_add(2, Ordering::Relaxed);

        let snapshot = collector.global().snapshot();
        assert_eq!(snapshot.total_packets, 10);
        assert_eq!(snapshot.forwarded_packets, 8);
        assert_eq!(snapshot.dropped_packets, 2);
    }
}
