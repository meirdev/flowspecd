use std::process::Command;
use thiserror::Error;

use crate::bgp::flowspec::Component;
use crate::bgp::Prefix;

use super::{numeric_match_to_string, tcp_flags_to_string, Action, Backend, Rule};

const TABLE_NAME: &str = "flowspec";
const CHAIN_NAME: &str = "filter";

#[derive(Debug, Error)]
pub enum NftError {
    #[error("nft command failed: {0}")]
    Command(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Nftables {
    initialized: bool,
}

impl Nftables {
    pub fn new() -> Self {
        Self { initialized: false }
    }

    /// Initialize the nftables table and chain
    pub fn init(&mut self) -> Result<(), NftError> {
        if self.initialized {
            return Ok(());
        }

        // Create table
        self.run_nft(&format!("add table inet {}", TABLE_NAME))?;

        // Create chain with priority before standard filter
        self.run_nft(&format!(
            "add chain inet {} {} {{ type filter hook forward priority -10; policy accept; }}",
            TABLE_NAME, CHAIN_NAME
        ))?;

        self.initialized = true;
        Ok(())
    }

    fn run_nft(&self, cmd: &str) -> Result<(), NftError> {
        let output = Command::new("nft").arg(cmd).output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NftError::Command(format!("{}: {}", cmd, stderr)));
        }

        Ok(())
    }

    /// Convert a Rule to an nft rule string
    fn rule_to_nft(&self, rule: &Rule) -> String {
        let mut conditions = Vec::new();

        for component in &rule.components {
            match component {
                Component::DestinationPrefix(prefix) => {
                    conditions.push(format!("ip daddr {}", prefix_to_cidr(prefix)));
                }
                Component::SourcePrefix(prefix) => {
                    conditions.push(format!("ip saddr {}", prefix_to_cidr(prefix)));
                }
                Component::IpProtocol(matches) => {
                    let protos: Vec<String> = matches
                        .iter()
                        .filter(|m| m.op.eq)
                        .map(|m| protocol_name(m.value as u8))
                        .collect();
                    if !protos.is_empty() {
                        conditions.push(format!("meta l4proto {{ {} }}", protos.join(", ")));
                    }
                }
                Component::Port(matches) => {
                    let expr = numeric_match_to_string(matches);
                    conditions.push(format!("th dport {{ {} }}", expr));
                    conditions.push(format!("th sport {{ {} }}", expr));
                }
                Component::DestinationPort(matches) => {
                    let expr = numeric_match_to_string(matches);
                    conditions.push(format!("th dport {{ {} }}", expr));
                }
                Component::SourcePort(matches) => {
                    let expr = numeric_match_to_string(matches);
                    conditions.push(format!("th sport {{ {} }}", expr));
                }
                Component::IcmpType(matches) => {
                    let types: Vec<String> = matches
                        .iter()
                        .filter(|m| m.op.eq)
                        .map(|m| m.value.to_string())
                        .collect();
                    if !types.is_empty() {
                        conditions.push(format!("icmp type {{ {} }}", types.join(", ")));
                    }
                }
                Component::IcmpCode(matches) => {
                    let codes: Vec<String> = matches
                        .iter()
                        .filter(|m| m.op.eq)
                        .map(|m| m.value.to_string())
                        .collect();
                    if !codes.is_empty() {
                        conditions.push(format!("icmp code {{ {} }}", codes.join(", ")));
                    }
                }
                Component::TcpFlags(matches) => {
                    let flags = tcp_flags_to_string(matches);
                    if !flags.is_empty() {
                        conditions.push(format!("tcp flags & ({}) != 0", flags));
                    }
                }
                Component::PacketLength(matches) => {
                    let expr = numeric_match_to_string(matches);
                    conditions.push(format!("meta length {{ {} }}", expr));
                }
                Component::Dscp(matches) => {
                    let values: Vec<String> = matches
                        .iter()
                        .filter(|m| m.op.eq)
                        .map(|m| m.value.to_string())
                        .collect();
                    if !values.is_empty() {
                        conditions.push(format!("ip dscp {{ {} }}", values.join(", ")));
                    }
                }
                Component::Fragment(matches) => {
                    // Fragment matching: check if packet is fragmented
                    for m in matches {
                        if m.value & 0x01 != 0 {
                            // Don't fragment
                            if m.op.not {
                                conditions.push("ip frag-off & 0x4000 == 0".to_string());
                            } else {
                                conditions.push("ip frag-off & 0x4000 != 0".to_string());
                            }
                        }
                        if m.value & 0x02 != 0 {
                            // Is fragment
                            if m.op.not {
                                conditions.push("ip frag-off & 0x1fff == 0".to_string());
                            } else {
                                conditions.push("ip frag-off & 0x1fff != 0".to_string());
                            }
                        }
                    }
                }
            }
        }

        // For rate limiting, we use two counters:
        // - First counter: counts all matching packets
        // - Second counter (after limit): counts dropped packets
        let action = match &rule.action {
            Action::Drop => "counter drop".to_string(),
            Action::Accept => "counter accept".to_string(),
            Action::RateLimit { bytes_per_sec } => {
                if *bytes_per_sec == 0.0 {
                    "counter drop".to_string()
                } else {
                    // First counter counts all matched packets
                    // "limit rate over X" matches packets EXCEEDING the rate
                    // Second counter counts dropped packets only
                    format!(
                        "counter limit rate over {} bytes/second counter drop",
                        *bytes_per_sec as u64
                    )
                }
            }
            Action::Mark { dscp } => {
                format!("counter ip dscp set {}", dscp)
            }
        };

        if conditions.is_empty() {
            action
        } else {
            format!("{} {}", conditions.join(" "), action)
        }
    }

    /// Generate a rule handle comment for identification
    fn rule_comment(&self, rule: &Rule) -> String {
        // Create a deterministic identifier from rule components
        let mut id = String::new();
        for c in &rule.components {
            match c {
                Component::DestinationPrefix(p) => {
                    id.push_str(&format!("d{}/{}", prefix_to_ip(p), p.length))
                }
                Component::SourcePrefix(p) => {
                    id.push_str(&format!("s{}/{}", prefix_to_ip(p), p.length))
                }
                Component::DestinationPort(m) => {
                    id.push_str(&format!("dp{}", m.first().map(|m| m.value).unwrap_or(0)))
                }
                Component::SourcePort(m) => {
                    id.push_str(&format!("sp{}", m.first().map(|m| m.value).unwrap_or(0)))
                }
                Component::IpProtocol(m) => {
                    id.push_str(&format!("p{}", m.first().map(|m| m.value).unwrap_or(0)))
                }
                _ => {}
            }
        }
        if id.is_empty() {
            id = "default".to_string();
        }
        id
    }
}

impl Default for Nftables {
    fn default() -> Self {
        Self::new()
    }
}

impl Nftables {
    /// Generate the nft command that would be run for a rule (for dry-run mode)
    pub fn command_for_rule(&self, rule: &Rule) -> String {
        let nft_rule = self.rule_to_nft(rule);
        let comment = self.rule_comment(rule);
        format!(
            "nft add rule inet {} {} {} comment \"{}\"",
            TABLE_NAME, CHAIN_NAME, nft_rule, comment
        )
    }

    /// Generate the nft command for removing a rule (for dry-run mode)
    pub fn command_for_remove(&self, rule: &Rule) -> String {
        let comment = self.rule_comment(rule);
        format!(
            "nft delete rule inet {} {} comment \"{}\"",
            TABLE_NAME, CHAIN_NAME, comment
        )
    }
}

impl Backend for Nftables {
    type Error = NftError;

    fn apply(&mut self, rule: &Rule) -> Result<(), Self::Error> {
        self.init()?;

        let nft_rule = self.rule_to_nft(rule);
        let comment = self.rule_comment(rule);

        // Add rule with comment for later identification
        self.run_nft(&format!(
            "add rule inet {} {} {} comment \"{}\"",
            TABLE_NAME, CHAIN_NAME, nft_rule, comment
        ))?;

        Ok(())
    }

    fn remove(&mut self, rule: &Rule) -> Result<(), Self::Error> {
        let comment = self.rule_comment(rule);

        // Find and delete rule by comment
        // This requires listing rules and finding the handle
        let output = Command::new("nft")
            .args(["-a", "list", "chain", "inet", TABLE_NAME, CHAIN_NAME])
            .output()?;

        if !output.status.success() {
            return Ok(()); // Chain doesn't exist, nothing to remove
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains(&format!("comment \"{}\"", comment)) {
                // Extract handle number
                if let Some(handle_pos) = line.find("# handle ") {
                    let handle_str = &line[handle_pos + 9..];
                    if let Some(handle) = handle_str.split_whitespace().next() {
                        self.run_nft(&format!(
                            "delete rule inet {} {} handle {}",
                            TABLE_NAME, CHAIN_NAME, handle
                        ))?;
                    }
                }
            }
        }

        Ok(())
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        // Delete the entire table (removes all rules)
        let _ = self.run_nft(&format!("delete table inet {}", TABLE_NAME));
        self.initialized = false;
        Ok(())
    }
}

fn prefix_to_ip(prefix: &Prefix) -> String {
    let mut octets = [0u8; 4];
    for (i, &byte) in prefix.prefix.iter().enumerate() {
        if i < 4 {
            octets[i] = byte;
        }
    }
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

fn prefix_to_cidr(prefix: &Prefix) -> String {
    format!("{}/{}", prefix_to_ip(prefix), prefix.length)
}

fn protocol_name(proto: u8) -> String {
    match proto {
        1 => "icmp".to_string(),
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        47 => "gre".to_string(),
        50 => "esp".to_string(),
        51 => "ah".to_string(),
        58 => "icmpv6".to_string(),
        _ => proto.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::flowspec::{NumericMatch, NumericOp};

    fn make_eq_match(value: u64) -> NumericMatch {
        NumericMatch {
            op: NumericOp {
                end: true,
                and: false,
                len: 0,
                reserved: false,
                lt: false,
                gt: false,
                eq: true,
            },
            value,
        }
    }

    #[test]
    fn test_rule_to_nft_drop_port() {
        let nft = Nftables::new();
        let rule = Rule {
            components: vec![Component::DestinationPort(vec![make_eq_match(80)])],
            action: Action::Drop,
        };

        let nft_rule = nft.rule_to_nft(&rule);
        assert!(nft_rule.contains("th dport"));
        assert!(nft_rule.contains("80"));
        assert!(nft_rule.contains("counter drop"));
    }

    #[test]
    fn test_rule_to_nft_prefix() {
        let nft = Nftables::new();
        let rule = Rule {
            components: vec![Component::DestinationPrefix(Prefix {
                length: 24,
                prefix: vec![192, 168, 1],
            })],
            action: Action::Drop,
        };

        let nft_rule = nft.rule_to_nft(&rule);
        assert!(nft_rule.contains("ip daddr 192.168.1.0/24"));
        assert!(nft_rule.contains("counter drop"));
    }

    #[test]
    fn test_rule_to_nft_rate_limit() {
        let nft = Nftables::new();
        let rule = Rule {
            components: vec![Component::DestinationPrefix(Prefix {
                length: 32,
                prefix: vec![10, 0, 0, 1],
            })],
            action: Action::RateLimit {
                bytes_per_sec: 1000.0,
            },
        };

        let nft_rule = nft.rule_to_nft(&rule);
        assert!(nft_rule.contains("ip daddr 10.0.0.1/32"));
        // First counter counts all matched packets
        // Second counter (after limit) counts dropped packets
        assert!(nft_rule.contains("counter limit rate over 1000 bytes/second counter drop"));
    }

    #[test]
    fn test_protocol_name() {
        assert_eq!(protocol_name(6), "tcp");
        assert_eq!(protocol_name(17), "udp");
        assert_eq!(protocol_name(1), "icmp");
        assert_eq!(protocol_name(99), "99");
    }
}
