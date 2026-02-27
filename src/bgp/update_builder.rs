//! BGP UPDATE message builder for FlowSpec
//!
//! Builds binary UPDATE messages with MP_REACH_NLRI/MP_UNREACH_NLRI
//! containing FlowSpec NLRIs and Extended Communities for traffic actions.

use deku::DekuContainerWrite;

use super::flowspec::{
    BitmaskMatch, Component, ComponentType, FlowSpecNlri, NumericMatch, TrafficAction,
};
use super::Prefix;

/// Path attribute type codes
const ATTR_ORIGIN: u8 = 1;
const ATTR_AS_PATH: u8 = 2;
const ATTR_LOCAL_PREF: u8 = 5;
const ATTR_MP_REACH_NLRI: u8 = 14;
const ATTR_MP_UNREACH_NLRI: u8 = 15;
const ATTR_EXTENDED_COMMUNITIES: u8 = 16;

/// AFI/SAFI for IPv4 FlowSpec
const AFI_IPV4: u16 = 1;
const SAFI_FLOWSPEC: u8 = 133;

/// UPDATE message builder
pub struct UpdateBuilder {
    announces: Vec<(FlowSpecNlri, TrafficAction)>,
    withdraws: Vec<FlowSpecNlri>,
}

impl UpdateBuilder {
    pub fn new() -> Self {
        Self {
            announces: Vec::new(),
            withdraws: Vec::new(),
        }
    }

    /// Add a FlowSpec announcement with traffic action
    pub fn announce(&mut self, nlri: FlowSpecNlri, action: TrafficAction) {
        self.announces.push((nlri, action));
    }

    /// Add a FlowSpec withdrawal
    pub fn withdraw(&mut self, nlri: FlowSpecNlri) {
        self.withdraws.push(nlri);
    }

    /// Build the complete UPDATE message body (without header)
    pub fn build(&self) -> Vec<u8> {
        let mut update = Vec::new();

        // Withdrawn routes length (2 bytes) - always 0 for FlowSpec
        update.extend_from_slice(&[0x00, 0x00]);

        // Build path attributes
        let mut path_attrs = Vec::new();

        // For announcements, we need: ORIGIN, AS_PATH, LOCAL_PREF, MP_REACH_NLRI, EXTENDED_COMMUNITIES
        if !self.announces.is_empty() {
            path_attrs.extend(build_origin_attr());
            path_attrs.extend(build_as_path_attr());
            path_attrs.extend(build_local_pref_attr());

            let nlris: Vec<&FlowSpecNlri> = self.announces.iter().map(|(n, _)| n).collect();
            path_attrs.extend(build_mp_reach_nlri(&nlris));

            let actions: Vec<&TrafficAction> = self.announces.iter().map(|(_, a)| a).collect();
            path_attrs.extend(build_extended_communities(&actions));
        }

        // For withdrawals, we need: MP_UNREACH_NLRI
        if !self.withdraws.is_empty() {
            let nlris: Vec<&FlowSpecNlri> = self.withdraws.iter().collect();
            path_attrs.extend(build_mp_unreach_nlri(&nlris));
        }

        // Path attributes length (2 bytes)
        let attr_len = path_attrs.len() as u16;
        update.extend_from_slice(&attr_len.to_be_bytes());

        // Path attributes
        update.extend(path_attrs);

        // NLRI (empty for FlowSpec - uses MP_REACH_NLRI instead)
        update
    }
}

impl Default for UpdateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Build ORIGIN attribute (IGP = 0)
fn build_origin_attr() -> Vec<u8> {
    vec![
        0x40, // Flags: Transitive, Well-known
        ATTR_ORIGIN,
        0x01, // Length: 1 byte
        0x00, // Value: IGP
    ]
}

/// Build AS_PATH attribute (empty)
fn build_as_path_attr() -> Vec<u8> {
    vec![
        0x40,         // Flags: Transitive, Well-known
        ATTR_AS_PATH,
        0x00,         // Length: 0 bytes (empty AS_PATH)
    ]
}

/// Build LOCAL_PREF attribute (default 100)
fn build_local_pref_attr() -> Vec<u8> {
    vec![
        0x40,            // Flags: Transitive, Well-known
        ATTR_LOCAL_PREF,
        0x04,            // Length: 4 bytes
        0x00, 0x00, 0x00, 0x64, // Value: 100
    ]
}

/// Build MP_REACH_NLRI attribute with FlowSpec NLRIs
fn build_mp_reach_nlri(nlris: &[&FlowSpecNlri]) -> Vec<u8> {
    let mut value = Vec::new();

    // AFI (2 bytes): IPv4 = 1
    value.extend_from_slice(&AFI_IPV4.to_be_bytes());

    // SAFI (1 byte): FlowSpec = 133
    value.push(SAFI_FLOWSPEC);

    // Next hop length (1 byte): 0 for FlowSpec
    value.push(0x00);

    // Reserved (1 byte)
    value.push(0x00);

    // NLRI(s)
    for nlri in nlris {
        value.extend(encode_flowspec_nlri(nlri));
    }

    // Build attribute header
    let mut attr = Vec::new();

    // Flags: Optional (0x80), Extended length if > 255 bytes
    if value.len() > 255 {
        attr.push(0x90); // Optional, Extended length
        attr.push(ATTR_MP_REACH_NLRI);
        let len = value.len() as u16;
        attr.extend_from_slice(&len.to_be_bytes());
    } else {
        attr.push(0x80); // Optional
        attr.push(ATTR_MP_REACH_NLRI);
        attr.push(value.len() as u8);
    }

    attr.extend(value);
    attr
}

/// Build MP_UNREACH_NLRI attribute for withdrawals
fn build_mp_unreach_nlri(nlris: &[&FlowSpecNlri]) -> Vec<u8> {
    let mut value = Vec::new();

    // AFI (2 bytes): IPv4 = 1
    value.extend_from_slice(&AFI_IPV4.to_be_bytes());

    // SAFI (1 byte): FlowSpec = 133
    value.push(SAFI_FLOWSPEC);

    // NLRI(s) - no next hop for withdrawals
    for nlri in nlris {
        value.extend(encode_flowspec_nlri(nlri));
    }

    // Build attribute header
    let mut attr = Vec::new();

    if value.len() > 255 {
        attr.push(0x90); // Optional, Extended length
        attr.push(ATTR_MP_UNREACH_NLRI);
        let len = value.len() as u16;
        attr.extend_from_slice(&len.to_be_bytes());
    } else {
        attr.push(0x80); // Optional
        attr.push(ATTR_MP_UNREACH_NLRI);
        attr.push(value.len() as u8);
    }

    attr.extend(value);
    attr
}

/// Build EXTENDED_COMMUNITIES attribute with traffic actions
fn build_extended_communities(actions: &[&TrafficAction]) -> Vec<u8> {
    let mut value = Vec::new();

    for action in actions {
        value.extend(encode_traffic_action(action));
    }

    if value.is_empty() {
        return Vec::new();
    }

    // Build attribute header
    let mut attr = Vec::new();

    // Flags: Optional (0x80), Transitive (0x40)
    if value.len() > 255 {
        attr.push(0xD0); // Optional, Transitive, Extended length
        attr.push(ATTR_EXTENDED_COMMUNITIES);
        let len = value.len() as u16;
        attr.extend_from_slice(&len.to_be_bytes());
    } else {
        attr.push(0xC0); // Optional, Transitive
        attr.push(ATTR_EXTENDED_COMMUNITIES);
        attr.push(value.len() as u8);
    }

    attr.extend(value);
    attr
}

/// Get the component type number for sorting
fn component_type_number(component: &Component) -> u8 {
    match component {
        Component::DestinationPrefix(_) => 1,
        Component::SourcePrefix(_) => 2,
        Component::IpProtocol(_) => 3,
        Component::Port(_) => 4,
        Component::DestinationPort(_) => 5,
        Component::SourcePort(_) => 6,
        Component::IcmpType(_) => 7,
        Component::IcmpCode(_) => 8,
        Component::TcpFlags(_) => 9,
        Component::PacketLength(_) => 10,
        Component::Dscp(_) => 11,
        Component::Fragment(_) => 12,
    }
}

/// Encode a FlowSpec NLRI to bytes (length + components)
fn encode_flowspec_nlri(nlri: &FlowSpecNlri) -> Vec<u8> {
    let mut components_bytes = Vec::new();

    // Sort components by type number (RFC 5575 requirement)
    let mut sorted_components: Vec<&Component> = nlri.components.iter().collect();
    sorted_components.sort_by_key(|c| component_type_number(c));

    for component in sorted_components {
        components_bytes.extend(encode_component(component));
    }

    // Encode length (1 or 2 bytes)
    let len = components_bytes.len();
    let mut result = Vec::new();

    if len >= 240 {
        // Extended length: 2 bytes
        result.push(0xF0 | ((len >> 8) as u8 & 0x0F));
        result.push(len as u8);
    } else {
        result.push(len as u8);
    }

    result.extend(components_bytes);
    result
}

/// Encode a single FlowSpec component
fn encode_component(component: &Component) -> Vec<u8> {
    match component {
        Component::DestinationPrefix(prefix) => encode_prefix_component(ComponentType::DestinationPrefix, prefix),
        Component::SourcePrefix(prefix) => encode_prefix_component(ComponentType::SourcePrefix, prefix),
        Component::IpProtocol(matches) => encode_numeric_component(ComponentType::IpProtocol, matches),
        Component::Port(matches) => encode_numeric_component(ComponentType::Port, matches),
        Component::DestinationPort(matches) => encode_numeric_component(ComponentType::DestinationPort, matches),
        Component::SourcePort(matches) => encode_numeric_component(ComponentType::SourcePort, matches),
        Component::IcmpType(matches) => encode_numeric_component(ComponentType::IcmpType, matches),
        Component::IcmpCode(matches) => encode_numeric_component(ComponentType::IcmpCode, matches),
        Component::TcpFlags(matches) => encode_bitmask_component(ComponentType::TcpFlags, matches),
        Component::PacketLength(matches) => encode_numeric_component(ComponentType::PacketLength, matches),
        Component::Dscp(matches) => encode_numeric_component(ComponentType::Dscp, matches),
        Component::Fragment(matches) => encode_bitmask_component(ComponentType::Fragment, matches),
    }
}

/// Encode a prefix component (destination or source)
fn encode_prefix_component(ctype: ComponentType, prefix: &Prefix) -> Vec<u8> {
    let mut bytes = vec![ctype as u8];
    bytes.push(prefix.length);
    bytes.extend(&prefix.prefix);
    bytes
}

/// Encode a numeric component (port, protocol, etc.)
/// The end bit is set ONLY on the last match regardless of what the struct says
fn encode_numeric_component(ctype: ComponentType, matches: &[NumericMatch]) -> Vec<u8> {
    let mut bytes = vec![ctype as u8];

    for (i, m) in matches.iter().enumerate() {
        let is_last = i == matches.len() - 1;
        // Override the end bit - only set on last match
        let mut op = m.op;
        op.end = is_last;
        bytes.push(encode_numeric_op(&op, is_last));
        bytes.extend(encode_numeric_value(m.value, m.op.len));
    }

    bytes
}

/// Encode a bitmask component (tcp-flags, fragment)
/// The end bit is set ONLY on the last match regardless of what the struct says
fn encode_bitmask_component(ctype: ComponentType, matches: &[BitmaskMatch]) -> Vec<u8> {
    let mut bytes = vec![ctype as u8];

    for (i, m) in matches.iter().enumerate() {
        let is_last = i == matches.len() - 1;
        // Override the end bit - only set on last match
        let mut op = m.op;
        op.end = is_last;
        bytes.push(encode_bitmask_op(&op, is_last));
        bytes.extend(encode_numeric_value(m.value, m.op.len));
    }

    bytes
}

/// Encode a NumericOp to a single byte
fn encode_numeric_op(op: &super::flowspec::NumericOp, is_last: bool) -> u8 {
    let mut byte: u8 = 0;
    if is_last {
        byte |= 0x80; // end bit
    }
    if op.and {
        byte |= 0x40;
    }
    byte |= (op.len & 0x03) << 4;
    if op.lt {
        byte |= 0x04;
    }
    if op.gt {
        byte |= 0x02;
    }
    if op.eq {
        byte |= 0x01;
    }
    byte
}

/// Encode a BitmaskOp to a single byte
fn encode_bitmask_op(op: &super::flowspec::BitmaskOp, is_last: bool) -> u8 {
    let mut byte: u8 = 0;
    if is_last {
        byte |= 0x80; // end bit
    }
    if op.and {
        byte |= 0x40;
    }
    byte |= (op.len & 0x03) << 4;
    if op.not {
        byte |= 0x02;
    }
    if op.match_ {
        byte |= 0x01;
    }
    byte
}

/// Encode a numeric value based on length field
fn encode_numeric_value(value: u64, len: u8) -> Vec<u8> {
    match len {
        0 => vec![value as u8],                          // 1 byte
        1 => (value as u16).to_be_bytes().to_vec(),      // 2 bytes
        2 => (value as u32).to_be_bytes().to_vec(),      // 4 bytes
        _ => value.to_be_bytes().to_vec(),               // 8 bytes
    }
}

/// Encode a TrafficAction to 8-byte extended community
fn encode_traffic_action(action: &TrafficAction) -> Vec<u8> {
    // Use deku's to_bytes for serialization
    action.to_bytes().unwrap_or_else(|_| vec![0; 8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::flowspec::{NumericOp, BitmaskOp};

    #[test]
    fn test_encode_destination_prefix() {
        let prefix = Prefix {
            length: 24,
            prefix: vec![192, 168, 1],
        };
        let bytes = encode_prefix_component(ComponentType::DestinationPrefix, &prefix);
        assert_eq!(bytes, vec![0x01, 0x18, 0xC0, 0xA8, 0x01]);
    }

    #[test]
    fn test_encode_destination_port() {
        let matches = vec![NumericMatch {
            op: NumericOp {
                end: true,
                and: false,
                len: 0,
                reserved: false,
                lt: false,
                gt: false,
                eq: true,
            },
            value: 80,
        }];
        let bytes = encode_numeric_component(ComponentType::DestinationPort, &matches);
        // Type=5, Op=0x81 (end, eq), Value=80
        assert_eq!(bytes, vec![0x05, 0x81, 0x50]);
    }

    #[test]
    fn test_encode_tcp_flags() {
        let matches = vec![BitmaskMatch {
            op: BitmaskOp {
                end: true,
                and: false,
                len: 0,
                reserved: 0,
                not: false,
                match_: true,
            },
            value: 0x02, // SYN
        }];
        let bytes = encode_bitmask_component(ComponentType::TcpFlags, &matches);
        // Type=9, Op=0x81 (end, match), Value=0x02
        assert_eq!(bytes, vec![0x09, 0x81, 0x02]);
    }

    #[test]
    fn test_encode_flowspec_nlri() {
        let nlri = FlowSpecNlri {
            components: vec![Component::DestinationPort(vec![NumericMatch {
                op: NumericOp {
                    end: true,
                    and: false,
                    len: 0,
                    reserved: false,
                    lt: false,
                    gt: false,
                    eq: true,
                },
                value: 80,
            }])],
        };
        let bytes = encode_flowspec_nlri(&nlri);
        // Length=3, Type=5, Op=0x81, Value=80
        assert_eq!(bytes, vec![0x03, 0x05, 0x81, 0x50]);
    }

    #[test]
    fn test_build_update_announce() {
        let nlri = FlowSpecNlri {
            components: vec![Component::DestinationPort(vec![NumericMatch {
                op: NumericOp {
                    end: true,
                    and: false,
                    len: 0,
                    reserved: false,
                    lt: false,
                    gt: false,
                    eq: true,
                },
                value: 80,
            }])],
        };
        let action = TrafficAction::RateBytes {
            as_number: 0,
            rate: 0.0,
        };

        let mut builder = UpdateBuilder::new();
        builder.announce(nlri, action);
        let bytes = builder.build();

        // Should have: withdrawn_len(2) + attr_len(2) + attrs(variable)
        assert!(bytes.len() > 4);
        // Withdrawn length should be 0
        assert_eq!(&bytes[0..2], &[0x00, 0x00]);
    }

    #[test]
    fn test_build_update_withdraw() {
        let nlri = FlowSpecNlri {
            components: vec![Component::SourcePrefix(Prefix {
                length: 24,
                prefix: vec![10, 0, 0],
            })],
        };

        let mut builder = UpdateBuilder::new();
        builder.withdraw(nlri);
        let bytes = builder.build();

        // Should have MP_UNREACH_NLRI
        assert!(bytes.len() > 4);
    }

    #[test]
    fn test_encode_traffic_action_discard() {
        let action = TrafficAction::RateBytes {
            as_number: 0,
            rate: 0.0,
        };
        let bytes = encode_traffic_action(&action);
        // Type=0x8006, AS=0, Rate=0.0
        assert_eq!(bytes, vec![0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_debug_full_update() {
        use crate::bgp::command::parse_command;

        let cmd = parse_command("announce flowspec destination-port =80 protocol =tcp then discard").unwrap();

        let mut builder = UpdateBuilder::new();
        builder.announce(cmd.flowspec, cmd.action.unwrap());
        let bytes = builder.build();

        eprintln!("Full UPDATE bytes ({} bytes): {:02X?}", bytes.len(), bytes);

        // The test itself just verifies we can build without panicking
        assert!(!bytes.is_empty());
    }
}
