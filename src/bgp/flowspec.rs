use crate::config::{FlowSpecAction, PortRange};
use crate::flowspec::FlowSpecRule;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

/// FlowSpec NLRI components (RFC 5575)
#[derive(Debug, Clone)]
pub struct FlowSpecNlri {
    pub dst_prefix: Option<Ipv4Net>,
    pub src_prefix: Option<Ipv4Net>,
    pub protocol: Vec<u8>,
    pub dst_port: Vec<PortOperator>,
    pub src_port: Vec<PortOperator>,
    pub icmp_type: Vec<u8>,
    pub icmp_code: Vec<u8>,
    pub tcp_flags: Option<u8>,
    pub packet_length: Vec<LengthOperator>,
    pub dscp: Vec<u8>,
    pub fragment: Option<u8>,
}

#[derive(Debug, Clone)]
pub enum PortOperator {
    Eq(u16),
    Gt(u16),
    Lt(u16),
    Ge(u16),
    Le(u16),
    Range(u16, u16),
}

#[derive(Debug, Clone)]
pub enum LengthOperator {
    Eq(u16),
    Gt(u16),
    Lt(u16),
    Range(u16, u16),
}

impl Default for FlowSpecNlri {
    fn default() -> Self {
        Self {
            dst_prefix: None,
            src_prefix: None,
            protocol: Vec::new(),
            dst_port: Vec::new(),
            src_port: Vec::new(),
            icmp_type: Vec::new(),
            icmp_code: Vec::new(),
            tcp_flags: None,
            packet_length: Vec::new(),
            dscp: Vec::new(),
            fragment: None,
        }
    }
}

impl FlowSpecNlri {
    /// Parse FlowSpec NLRI from BGP UPDATE message bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let mut nlri = FlowSpecNlri::default();
        let mut offset = 0;

        while offset < data.len() {
            if offset >= data.len() {
                break;
            }

            let component_type = data[offset];
            offset += 1;

            match component_type {
                1 => {
                    // Destination Prefix
                    if offset + 1 > data.len() {
                        break;
                    }
                    let prefix_len = data[offset] as usize;
                    offset += 1;
                    let byte_len = (prefix_len + 7) / 8;
                    if offset + byte_len > data.len() {
                        break;
                    }
                    let mut addr_bytes = [0u8; 4];
                    for i in 0..byte_len.min(4) {
                        addr_bytes[i] = data[offset + i];
                    }
                    offset += byte_len;
                    let addr = Ipv4Addr::from(addr_bytes);
                    nlri.dst_prefix = Ipv4Net::new(addr, prefix_len as u8).ok();
                }
                2 => {
                    // Source Prefix
                    if offset + 1 > data.len() {
                        break;
                    }
                    let prefix_len = data[offset] as usize;
                    offset += 1;
                    let byte_len = (prefix_len + 7) / 8;
                    if offset + byte_len > data.len() {
                        break;
                    }
                    let mut addr_bytes = [0u8; 4];
                    for i in 0..byte_len.min(4) {
                        addr_bytes[i] = data[offset + i];
                    }
                    offset += byte_len;
                    let addr = Ipv4Addr::from(addr_bytes);
                    nlri.src_prefix = Ipv4Net::new(addr, prefix_len as u8).ok();
                }
                3 => {
                    // IP Protocol
                    let (protos, consumed) = parse_numeric_operator(&data[offset..]);
                    for p in protos {
                        nlri.protocol.push(p as u8);
                    }
                    offset += consumed;
                }
                4 => {
                    // Destination Port
                    let (ops, consumed) = parse_port_operator(&data[offset..]);
                    nlri.dst_port.extend(ops);
                    offset += consumed;
                }
                5 => {
                    // Source Port
                    let (ops, consumed) = parse_port_operator(&data[offset..]);
                    nlri.src_port.extend(ops);
                    offset += consumed;
                }
                6 => {
                    // ICMP Type
                    let (types, consumed) = parse_numeric_operator(&data[offset..]);
                    for t in types {
                        nlri.icmp_type.push(t as u8);
                    }
                    offset += consumed;
                }
                7 => {
                    // ICMP Code
                    let (codes, consumed) = parse_numeric_operator(&data[offset..]);
                    for c in codes {
                        nlri.icmp_code.push(c as u8);
                    }
                    offset += consumed;
                }
                9 => {
                    // TCP Flags
                    if offset + 2 <= data.len() {
                        nlri.tcp_flags = Some(data[offset + 1]);
                        offset += 2;
                    }
                }
                10 => {
                    // Packet Length
                    let (ops, consumed) = parse_length_operator(&data[offset..]);
                    nlri.packet_length.extend(ops);
                    offset += consumed;
                }
                11 => {
                    // DSCP
                    let (dscps, consumed) = parse_numeric_operator(&data[offset..]);
                    for d in dscps {
                        nlri.dscp.push(d as u8);
                    }
                    offset += consumed;
                }
                12 => {
                    // Fragment
                    if offset + 2 <= data.len() {
                        nlri.fragment = Some(data[offset + 1]);
                        offset += 2;
                    }
                }
                _ => {
                    // Unknown component, skip
                    break;
                }
            }
        }

        Some(nlri)
    }

    pub fn to_rule(&self, rule_id: &str, action: FlowSpecAction, rate_limit_bps: Option<u64>) -> FlowSpecRule {
        let mut rule = FlowSpecRule::new(rule_id, format!("bgp-{}", rule_id));

        if let Some(prefix) = self.dst_prefix {
            rule = rule.with_dst_prefix(prefix);
        }

        if let Some(prefix) = self.src_prefix {
            rule = rule.with_src_prefix(prefix);
        }

        if let Some(&proto) = self.protocol.first() {
            rule = rule.with_protocol(proto);
        }

        if let Some(op) = self.dst_port.first() {
            match op {
                PortOperator::Eq(p) => rule = rule.with_dst_port(*p, *p),
                PortOperator::Range(start, end) => rule = rule.with_dst_port(*start, *end),
                PortOperator::Ge(p) => rule = rule.with_dst_port(*p, 65535),
                PortOperator::Le(p) => rule = rule.with_dst_port(0, *p),
                PortOperator::Gt(p) => rule = rule.with_dst_port(p + 1, 65535),
                PortOperator::Lt(p) => rule = rule.with_dst_port(0, p.saturating_sub(1)),
            }
        }

        if let Some(op) = self.src_port.first() {
            match op {
                PortOperator::Eq(p) => rule = rule.with_src_port(*p, *p),
                PortOperator::Range(start, end) => rule = rule.with_src_port(*start, *end),
                PortOperator::Ge(p) => rule = rule.with_src_port(*p, 65535),
                PortOperator::Le(p) => rule = rule.with_src_port(0, *p),
                PortOperator::Gt(p) => rule = rule.with_src_port(p + 1, 65535),
                PortOperator::Lt(p) => rule = rule.with_src_port(0, p.saturating_sub(1)),
            }
        }

        rule = rule.with_action(action);

        if let Some(rate) = rate_limit_bps {
            rule = rule.with_rate_limit(rate);
        }

        rule
    }
}

fn parse_numeric_operator(data: &[u8]) -> (Vec<u16>, usize) {
    let mut values = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let op_byte = data[offset];
        let end_bit = (op_byte & 0x80) != 0;
        let value_len = if (op_byte & 0x10) != 0 { 2 } else { 1 };

        offset += 1;

        if offset + value_len > data.len() {
            break;
        }

        let value = if value_len == 2 {
            u16::from_be_bytes([data[offset], data[offset + 1]])
        } else {
            data[offset] as u16
        };
        values.push(value);
        offset += value_len;

        if end_bit {
            break;
        }
    }

    (values, offset)
}

fn parse_port_operator(data: &[u8]) -> (Vec<PortOperator>, usize) {
    let mut ops = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let op_byte = data[offset];
        let end_bit = (op_byte & 0x80) != 0;
        let lt_bit = (op_byte & 0x04) != 0;
        let gt_bit = (op_byte & 0x02) != 0;
        let eq_bit = (op_byte & 0x01) != 0;
        let value_len = if (op_byte & 0x10) != 0 { 2 } else { 1 };

        offset += 1;

        if offset + value_len > data.len() {
            break;
        }

        let value = if value_len == 2 {
            u16::from_be_bytes([data[offset], data[offset + 1]])
        } else {
            data[offset] as u16
        };
        offset += value_len;

        let op = match (lt_bit, gt_bit, eq_bit) {
            (false, false, true) => PortOperator::Eq(value),
            (true, false, false) => PortOperator::Lt(value),
            (false, true, false) => PortOperator::Gt(value),
            (true, false, true) => PortOperator::Le(value),
            (false, true, true) => PortOperator::Ge(value),
            _ => PortOperator::Eq(value),
        };
        ops.push(op);

        if end_bit {
            break;
        }
    }

    (ops, offset)
}

fn parse_length_operator(data: &[u8]) -> (Vec<LengthOperator>, usize) {
    let mut ops = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let op_byte = data[offset];
        let end_bit = (op_byte & 0x80) != 0;
        let lt_bit = (op_byte & 0x04) != 0;
        let gt_bit = (op_byte & 0x02) != 0;
        let eq_bit = (op_byte & 0x01) != 0;
        let value_len = if (op_byte & 0x10) != 0 { 2 } else { 1 };

        offset += 1;

        if offset + value_len > data.len() {
            break;
        }

        let value = if value_len == 2 {
            u16::from_be_bytes([data[offset], data[offset + 1]])
        } else {
            data[offset] as u16
        };
        offset += value_len;

        let op = match (lt_bit, gt_bit, eq_bit) {
            (false, false, true) => LengthOperator::Eq(value),
            (true, false, false) => LengthOperator::Lt(value),
            (false, true, false) => LengthOperator::Gt(value),
            _ => LengthOperator::Eq(value),
        };
        ops.push(op);

        if end_bit {
            break;
        }
    }

    (ops, offset)
}

/// Parse FlowSpec extended community for traffic action
pub fn parse_traffic_action(community: &[u8]) -> Option<(FlowSpecAction, Option<u64>)> {
    if community.len() < 8 {
        return None;
    }

    let type_high = community[0];
    let type_low = community[1];

    match (type_high, type_low) {
        (0x80, 0x06) => {
            // Traffic-rate (rate-limit)
            let rate = f32::from_be_bytes([
                community[4],
                community[5],
                community[6],
                community[7],
            ]);
            if rate == 0.0 {
                Some((FlowSpecAction::Drop, None))
            } else {
                Some((FlowSpecAction::RateLimit, Some((rate * 8.0) as u64)))
            }
        }
        (0x80, 0x07) => {
            // Traffic-action
            let action_byte = community[7];
            if action_byte & 0x02 != 0 {
                // Terminal action - drop
                Some((FlowSpecAction::Drop, None))
            } else {
                Some((FlowSpecAction::Accept, None))
            }
        }
        _ => None,
    }
}
