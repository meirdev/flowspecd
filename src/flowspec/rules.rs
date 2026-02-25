use crate::config::{FlowSpecAction, PortRange};
use crate::flowspec::actions::RateLimiter;
use crate::flowspec::{FragmentFlags, PacketInfo};
use ipnet::Ipv4Net;

pub type RuleId = String;

/// TCP flags bitmask for matching (RFC 8955 Type 9)
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct TcpFlagsMatch {
    /// Flags that must be set
    pub match_flags: u8,
    /// Flags that must not be set
    pub not_flags: u8,
}

/// Packet length range for matching (RFC 8955 Type 10)
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct LengthRange {
    pub min: u16,
    pub max: u16,
}

impl LengthRange {
    pub fn new(min: u16, max: u16) -> Self {
        Self { min, max }
    }

    pub fn contains(&self, len: usize) -> bool {
        let len = len as u16;
        len >= self.min && len <= self.max
    }
}

/// Fragment match criteria (RFC 8955 Type 12)
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct FragmentMatch {
    /// Match Don't Fragment packets
    pub dont_fragment: Option<bool>,
    /// Match fragmented packets
    pub is_fragment: Option<bool>,
    /// Match first fragment
    pub first_fragment: Option<bool>,
    /// Match last fragment
    pub last_fragment: Option<bool>,
}

/// FlowSpec rule with all RFC 8955 components
#[derive(Debug, Clone)]
pub struct FlowSpecRule {
    pub id: RuleId,
    pub name: String,
    pub priority: u32,

    // Type 1: Destination Prefix
    pub dst_prefix: Option<Ipv4Net>,
    // Type 2: Source Prefix
    pub src_prefix: Option<Ipv4Net>,
    // Type 3: IP Protocol
    pub protocol: Option<u8>,
    // Type 4: Port (matches either src OR dst)
    pub port: Option<PortRange>,
    // Type 5: Destination Port
    pub dst_port: Option<PortRange>,
    // Type 6: Source Port
    pub src_port: Option<PortRange>,
    // Type 7: ICMP Type
    pub icmp_type: Option<u8>,
    // Type 8: ICMP Code
    pub icmp_code: Option<u8>,
    // Type 9: TCP Flags
    pub tcp_flags: Option<TcpFlagsMatch>,
    // Type 10: Packet Length
    pub packet_length: Option<LengthRange>,
    // Type 11: DSCP
    pub dscp: Option<u8>,
    // Type 12: Fragment
    pub fragment: Option<FragmentMatch>,

    // Action
    pub action: FlowSpecAction,
    pub rate_limiter: Option<RateLimiter>,
}

impl FlowSpecRule {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            priority: 100,
            dst_prefix: None,
            src_prefix: None,
            protocol: None,
            port: None,
            dst_port: None,
            src_port: None,
            icmp_type: None,
            icmp_code: None,
            tcp_flags: None,
            packet_length: None,
            dscp: None,
            fragment: None,
            action: FlowSpecAction::Accept,
            rate_limiter: None,
        }
    }

    // Type 1: Destination Prefix
    pub fn with_dst_prefix(mut self, prefix: Ipv4Net) -> Self {
        self.dst_prefix = Some(prefix);
        self
    }

    // Type 2: Source Prefix
    pub fn with_src_prefix(mut self, prefix: Ipv4Net) -> Self {
        self.src_prefix = Some(prefix);
        self
    }

    // Type 3: IP Protocol
    pub fn with_protocol(mut self, protocol: u8) -> Self {
        self.protocol = Some(protocol);
        self
    }

    // Type 4: Port (matches src OR dst)
    pub fn with_port(mut self, start: u16, end: u16) -> Self {
        self.port = Some(PortRange { start, end });
        self
    }

    // Type 5: Destination Port
    pub fn with_dst_port(mut self, start: u16, end: u16) -> Self {
        self.dst_port = Some(PortRange { start, end });
        self
    }

    // Type 6: Source Port
    pub fn with_src_port(mut self, start: u16, end: u16) -> Self {
        self.src_port = Some(PortRange { start, end });
        self
    }

    // Type 7: ICMP Type
    pub fn with_icmp_type(mut self, icmp_type: u8) -> Self {
        self.icmp_type = Some(icmp_type);
        self
    }

    // Type 8: ICMP Code
    pub fn with_icmp_code(mut self, icmp_code: u8) -> Self {
        self.icmp_code = Some(icmp_code);
        self
    }

    // Type 9: TCP Flags
    pub fn with_tcp_flags(mut self, match_flags: u8, not_flags: u8) -> Self {
        self.tcp_flags = Some(TcpFlagsMatch { match_flags, not_flags });
        self
    }

    // Type 10: Packet Length
    pub fn with_packet_length(mut self, min: u16, max: u16) -> Self {
        self.packet_length = Some(LengthRange::new(min, max));
        self
    }

    // Type 11: DSCP
    pub fn with_dscp(mut self, dscp: u8) -> Self {
        self.dscp = Some(dscp);
        self
    }

    // Type 12: Fragment
    pub fn with_fragment(mut self, fragment: FragmentMatch) -> Self {
        self.fragment = Some(fragment);
        self
    }

    pub fn with_action(mut self, action: FlowSpecAction) -> Self {
        self.action = action;
        self
    }

    pub fn with_rate_limit(mut self, bytes_per_second: u64) -> Self {
        self.action = FlowSpecAction::RateLimit;
        self.rate_limiter = Some(RateLimiter::new(bytes_per_second));
        self
    }

    pub fn matches(&self, packet: &PacketInfo) -> bool {
        // Type 1: Destination Prefix
        if let Some(ref prefix) = self.dst_prefix {
            if !prefix.contains(&packet.dst_addr) {
                return false;
            }
        }

        // Type 2: Source Prefix
        if let Some(ref prefix) = self.src_prefix {
            if !prefix.contains(&packet.src_addr) {
                return false;
            }
        }

        // Type 3: IP Protocol
        if let Some(proto) = self.protocol {
            if packet.protocol != proto {
                return false;
            }
        }

        // Type 4: Port (matches src OR dst)
        if let Some(ref port_range) = self.port {
            let src_matches = packet.src_port.map(|p| port_range.contains(p)).unwrap_or(false);
            let dst_matches = packet.dst_port.map(|p| port_range.contains(p)).unwrap_or(false);
            if !src_matches && !dst_matches {
                return false;
            }
        }

        // Type 5: Destination Port
        if let Some(ref port_range) = self.dst_port {
            if let Some(port) = packet.dst_port {
                if !port_range.contains(port) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Type 6: Source Port
        if let Some(ref port_range) = self.src_port {
            if let Some(port) = packet.src_port {
                if !port_range.contains(port) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Type 7: ICMP Type
        if let Some(icmp_type) = self.icmp_type {
            if packet.icmp_type != Some(icmp_type) {
                return false;
            }
        }

        // Type 8: ICMP Code
        if let Some(icmp_code) = self.icmp_code {
            if packet.icmp_code != Some(icmp_code) {
                return false;
            }
        }

        // Type 9: TCP Flags
        if let Some(ref flags) = self.tcp_flags {
            if let Some(pkt_flags) = packet.tcp_flags {
                // Check that required flags are set
                if (pkt_flags & flags.match_flags) != flags.match_flags {
                    return false;
                }
                // Check that forbidden flags are not set
                if (pkt_flags & flags.not_flags) != 0 {
                    return false;
                }
            } else {
                return false; // No TCP flags means not TCP
            }
        }

        // Type 10: Packet Length
        if let Some(ref len_range) = self.packet_length {
            if !len_range.contains(packet.length) {
                return false;
            }
        }

        // Type 11: DSCP
        if let Some(dscp) = self.dscp {
            if packet.dscp != dscp {
                return false;
            }
        }

        // Type 12: Fragment
        if let Some(ref frag) = self.fragment {
            if let Some(df) = frag.dont_fragment {
                if packet.fragment.dont_fragment != df {
                    return false;
                }
            }
            if let Some(is_frag) = frag.is_fragment {
                if packet.fragment.is_fragment != is_frag {
                    return false;
                }
            }
            if let Some(first) = frag.first_fragment {
                if packet.fragment.first_fragment != first {
                    return false;
                }
            }
            if let Some(last) = frag.last_fragment {
                if packet.fragment.last_fragment != last {
                    return false;
                }
            }
        }

        true
    }

    pub fn should_rate_limit(&self, packet_len: usize) -> bool {
        if let Some(ref limiter) = self.rate_limiter {
            return !limiter.allow(packet_len as u64);
        }
        false
    }
}

impl serde::Serialize for FlowSpecRule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("FlowSpecRule", 17)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("priority", &self.priority)?;
        // Type 1: Destination Prefix
        state.serialize_field("dst_prefix", &self.dst_prefix.map(|p| p.to_string()))?;
        // Type 2: Source Prefix
        state.serialize_field("src_prefix", &self.src_prefix.map(|p| p.to_string()))?;
        // Type 3: IP Protocol
        state.serialize_field("protocol", &self.protocol)?;
        // Type 4: Port (src OR dst)
        state.serialize_field("port", &self.port)?;
        // Type 5: Destination Port
        state.serialize_field("dst_port", &self.dst_port)?;
        // Type 6: Source Port
        state.serialize_field("src_port", &self.src_port)?;
        // Type 7: ICMP Type
        state.serialize_field("icmp_type", &self.icmp_type)?;
        // Type 8: ICMP Code
        state.serialize_field("icmp_code", &self.icmp_code)?;
        // Type 9: TCP Flags
        state.serialize_field("tcp_flags", &self.tcp_flags)?;
        // Type 10: Packet Length
        state.serialize_field("packet_length", &self.packet_length)?;
        // Type 11: DSCP
        state.serialize_field("dscp", &self.dscp)?;
        // Type 12: Fragment
        state.serialize_field("fragment", &self.fragment)?;
        // Action
        state.serialize_field("action", &self.action)?;
        state.serialize_field("rate_limit_bps", &self.rate_limiter.as_ref().map(|r| r.bytes_per_second()))?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet(
        src: &str,
        dst: &str,
        protocol: u8,
        src_port: Option<u16>,
        dst_port: Option<u16>,
    ) -> PacketInfo {
        PacketInfo {
            src_addr: src.parse().unwrap(),
            dst_addr: dst.parse().unwrap(),
            protocol,
            src_port,
            dst_port,
            icmp_type: None,
            icmp_code: None,
            tcp_flags: None,
            dscp: 0,
            length: 100,
            fragment: FragmentFlags::default(),
        }
    }

    #[test]
    fn test_rule_matches_any() {
        let rule = FlowSpecRule::new("test", "Test Rule");
        let packet = make_packet("192.168.1.1", "10.0.0.1", 6, Some(12345), Some(80));
        assert!(rule.matches(&packet));
    }

    #[test]
    fn test_rule_matches_src_prefix() {
        let rule = FlowSpecRule::new("test", "Test Rule")
            .with_src_prefix("192.168.1.0/24".parse().unwrap());

        let matching = make_packet("192.168.1.100", "10.0.0.1", 6, Some(12345), Some(80));
        let non_matching = make_packet("10.0.0.1", "10.0.0.1", 6, Some(12345), Some(80));

        assert!(rule.matches(&matching));
        assert!(!rule.matches(&non_matching));
    }

    #[test]
    fn test_rule_matches_dst_prefix() {
        let rule = FlowSpecRule::new("test", "Test Rule")
            .with_dst_prefix("10.0.0.0/8".parse().unwrap());

        let matching = make_packet("192.168.1.1", "10.1.2.3", 6, Some(12345), Some(80));
        let non_matching = make_packet("192.168.1.1", "192.168.1.1", 6, Some(12345), Some(80));

        assert!(rule.matches(&matching));
        assert!(!rule.matches(&non_matching));
    }

    #[test]
    fn test_rule_matches_protocol() {
        let rule = FlowSpecRule::new("test", "Test Rule")
            .with_protocol(6); // TCP

        let tcp_packet = make_packet("192.168.1.1", "10.0.0.1", 6, Some(12345), Some(80));
        let udp_packet = make_packet("192.168.1.1", "10.0.0.1", 17, Some(12345), Some(53));

        assert!(rule.matches(&tcp_packet));
        assert!(!rule.matches(&udp_packet));
    }

    #[test]
    fn test_rule_matches_dst_port() {
        let rule = FlowSpecRule::new("test", "Test Rule")
            .with_dst_port(80, 80);

        let http = make_packet("192.168.1.1", "10.0.0.1", 6, Some(12345), Some(80));
        let https = make_packet("192.168.1.1", "10.0.0.1", 6, Some(12345), Some(443));
        let no_port = make_packet("192.168.1.1", "10.0.0.1", 1, None, None); // ICMP

        assert!(rule.matches(&http));
        assert!(!rule.matches(&https));
        assert!(!rule.matches(&no_port));
    }

    #[test]
    fn test_rule_matches_port_range() {
        let rule = FlowSpecRule::new("test", "Test Rule")
            .with_dst_port(80, 443);

        let port_80 = make_packet("192.168.1.1", "10.0.0.1", 6, Some(12345), Some(80));
        let port_443 = make_packet("192.168.1.1", "10.0.0.1", 6, Some(12345), Some(443));
        let port_8080 = make_packet("192.168.1.1", "10.0.0.1", 6, Some(12345), Some(8080));

        assert!(rule.matches(&port_80));
        assert!(rule.matches(&port_443));
        assert!(!rule.matches(&port_8080));
    }

    #[test]
    fn test_rule_matches_combined() {
        let rule = FlowSpecRule::new("test", "Block SSH from specific subnet")
            .with_src_prefix("192.168.1.0/24".parse().unwrap())
            .with_protocol(6)
            .with_dst_port(22, 22);

        let matching = make_packet("192.168.1.50", "10.0.0.1", 6, Some(12345), Some(22));
        let wrong_subnet = make_packet("10.0.0.1", "10.0.0.1", 6, Some(12345), Some(22));
        let wrong_port = make_packet("192.168.1.50", "10.0.0.1", 6, Some(12345), Some(80));
        let wrong_proto = make_packet("192.168.1.50", "10.0.0.1", 17, Some(12345), Some(22));

        assert!(rule.matches(&matching));
        assert!(!rule.matches(&wrong_subnet));
        assert!(!rule.matches(&wrong_port));
        assert!(!rule.matches(&wrong_proto));
    }

    #[test]
    fn test_rule_with_action() {
        let drop_rule = FlowSpecRule::new("test", "Drop Rule")
            .with_action(FlowSpecAction::Drop);
        assert_eq!(drop_rule.action, FlowSpecAction::Drop);

        let accept_rule = FlowSpecRule::new("test", "Accept Rule")
            .with_action(FlowSpecAction::Accept);
        assert_eq!(accept_rule.action, FlowSpecAction::Accept);
    }
}
