//! FlowSpec command DSL parser (ExaBGP-compatible syntax)
//!
//! Example commands:
//! ```text
//! announce flowspec source 10.0.0.0/24 destination-port =80 protocol =tcp then discard
//! withdraw flowspec source 10.0.0.0/24 destination-port =80 protocol =tcp
//! ```

use std::fmt;

use super::flowspec::{
    BitmaskMatch, BitmaskOp, Component, FlowSpecNlri, NumericMatch, NumericOp, TrafficAction,
};
use super::Prefix;

/// Command operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Announce,
    Withdraw,
}

/// Parsed FlowSpec command
#[derive(Debug, Clone)]
pub struct Command {
    pub operation: Operation,
    pub flowspec: FlowSpecNlri,
    pub action: Option<TrafficAction>,
}

/// Parse error
#[derive(Debug, Clone)]
pub enum ParseError {
    EmptyInput,
    UnknownCommand(String),
    MissingFlowspecKeyword,
    InvalidPrefix(String),
    InvalidPort(String),
    InvalidProtocol(String),
    InvalidOperator(String),
    InvalidTcpFlags(String),
    InvalidFragment(String),
    InvalidAction(String),
    MissingValue(String),
    InvalidNumber(String),
    UnknownField(String),
    MissingBracket,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::EmptyInput => write!(f, "empty input"),
            ParseError::UnknownCommand(s) => write!(f, "unknown command: {}", s),
            ParseError::MissingFlowspecKeyword => write!(f, "missing 'flowspec' keyword"),
            ParseError::InvalidPrefix(s) => write!(f, "invalid prefix: {}", s),
            ParseError::InvalidPort(s) => write!(f, "invalid port: {}", s),
            ParseError::InvalidProtocol(s) => write!(f, "invalid protocol: {}", s),
            ParseError::InvalidOperator(s) => write!(f, "invalid operator: {}", s),
            ParseError::InvalidTcpFlags(s) => write!(f, "invalid tcp flags: {}", s),
            ParseError::InvalidFragment(s) => write!(f, "invalid fragment type: {}", s),
            ParseError::InvalidAction(s) => write!(f, "invalid action: {}", s),
            ParseError::MissingValue(s) => write!(f, "missing value for: {}", s),
            ParseError::InvalidNumber(s) => write!(f, "invalid number: {}", s),
            ParseError::UnknownField(s) => write!(f, "unknown field: {}", s),
            ParseError::MissingBracket => write!(f, "missing bracket"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a command line into a Command struct
pub fn parse_command(line: &str) -> Result<Command, ParseError> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Err(ParseError::EmptyInput);
    }

    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() {
        return Err(ParseError::EmptyInput);
    }

    // Parse operation
    let operation = match tokens[0].to_lowercase().as_str() {
        "announce" => Operation::Announce,
        "withdraw" => Operation::Withdraw,
        other => return Err(ParseError::UnknownCommand(other.to_string())),
    };

    // Expect "flowspec" keyword
    if tokens.len() < 2 || tokens[1].to_lowercase() != "flowspec" {
        return Err(ParseError::MissingFlowspecKeyword);
    }

    // Parse match fields and action
    let mut components = Vec::new();
    let mut action = None;
    let mut i = 2;

    while i < tokens.len() {
        let token = tokens[i].to_lowercase();

        if token == "then" {
            // Parse action
            i += 1;
            if i >= tokens.len() {
                return Err(ParseError::MissingValue("then".to_string()));
            }
            action = Some(parse_action(&tokens[i..])?);
            break;
        }

        match token.as_str() {
            "source" => {
                i += 1;
                if i >= tokens.len() {
                    return Err(ParseError::MissingValue("source".to_string()));
                }
                let prefix = parse_prefix(tokens[i])?;
                components.push(Component::SourcePrefix(prefix));
            }
            "destination" => {
                i += 1;
                if i >= tokens.len() {
                    return Err(ParseError::MissingValue("destination".to_string()));
                }
                let prefix = parse_prefix(tokens[i])?;
                components.push(Component::DestinationPrefix(prefix));
            }
            "protocol" => {
                i += 1;
                if i >= tokens.len() {
                    return Err(ParseError::MissingValue("protocol".to_string()));
                }
                let m = parse_protocol(tokens[i])?;
                components.push(Component::IpProtocol(vec![m]));
            }
            "destination-port" => {
                i += 1;
                if i >= tokens.len() {
                    return Err(ParseError::MissingValue("destination-port".to_string()));
                }
                let m = parse_numeric_value(tokens[i])?;
                // Check if we already have a destination-port component to add to
                if let Some(Component::DestinationPort(ref mut matches)) = components
                    .iter_mut()
                    .find(|c| matches!(c, Component::DestinationPort(_)))
                {
                    matches.push(m);
                } else {
                    components.push(Component::DestinationPort(vec![m]));
                }
            }
            "source-port" => {
                i += 1;
                if i >= tokens.len() {
                    return Err(ParseError::MissingValue("source-port".to_string()));
                }
                let m = parse_numeric_value(tokens[i])?;
                if let Some(Component::SourcePort(ref mut matches)) = components
                    .iter_mut()
                    .find(|c| matches!(c, Component::SourcePort(_)))
                {
                    matches.push(m);
                } else {
                    components.push(Component::SourcePort(vec![m]));
                }
            }
            "port" => {
                i += 1;
                if i >= tokens.len() {
                    return Err(ParseError::MissingValue("port".to_string()));
                }
                let m = parse_numeric_value(tokens[i])?;
                if let Some(Component::Port(ref mut matches)) = components
                    .iter_mut()
                    .find(|c| matches!(c, Component::Port(_)))
                {
                    matches.push(m);
                } else {
                    components.push(Component::Port(vec![m]));
                }
            }
            "tcp-flags" => {
                i += 1;
                let (flags, consumed) = parse_bracketed_flags(&tokens[i..])?;
                components.push(Component::TcpFlags(flags));
                i += consumed - 1; // -1 because we increment at end of loop
            }
            "packet-length" => {
                i += 1;
                if i >= tokens.len() {
                    return Err(ParseError::MissingValue("packet-length".to_string()));
                }
                let m = parse_numeric_value(tokens[i])?;
                if let Some(Component::PacketLength(ref mut matches)) = components
                    .iter_mut()
                    .find(|c| matches!(c, Component::PacketLength(_)))
                {
                    matches.push(m);
                } else {
                    components.push(Component::PacketLength(vec![m]));
                }
            }
            "icmp-type" => {
                i += 1;
                if i >= tokens.len() {
                    return Err(ParseError::MissingValue("icmp-type".to_string()));
                }
                let m = parse_numeric_value(tokens[i])?;
                components.push(Component::IcmpType(vec![m]));
            }
            "icmp-code" => {
                i += 1;
                if i >= tokens.len() {
                    return Err(ParseError::MissingValue("icmp-code".to_string()));
                }
                let m = parse_numeric_value(tokens[i])?;
                components.push(Component::IcmpCode(vec![m]));
            }
            "dscp" => {
                i += 1;
                if i >= tokens.len() {
                    return Err(ParseError::MissingValue("dscp".to_string()));
                }
                let m = parse_numeric_value(tokens[i])?;
                components.push(Component::Dscp(vec![m]));
            }
            "fragment" => {
                i += 1;
                let (frags, consumed) = parse_bracketed_fragment(&tokens[i..])?;
                components.push(Component::Fragment(frags));
                i += consumed - 1;
            }
            other => {
                return Err(ParseError::UnknownField(other.to_string()));
            }
        }

        i += 1;
    }

    Ok(Command {
        operation,
        flowspec: FlowSpecNlri { components },
        action,
    })
}

/// Parse an IPv4 prefix (e.g., "10.0.0.0/24")
fn parse_prefix(s: &str) -> Result<Prefix, ParseError> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err(ParseError::InvalidPrefix(s.to_string()));
    }

    let length: u8 = parts[1]
        .parse()
        .map_err(|_| ParseError::InvalidPrefix(s.to_string()))?;

    let octets: Vec<&str> = parts[0].split('.').collect();
    if octets.len() != 4 {
        return Err(ParseError::InvalidPrefix(s.to_string()));
    }

    let mut prefix_bytes = Vec::new();
    let bytes_needed = (length as usize + 7) / 8;

    for (i, octet) in octets.iter().enumerate() {
        if i >= bytes_needed {
            break;
        }
        let byte: u8 = octet
            .parse()
            .map_err(|_| ParseError::InvalidPrefix(s.to_string()))?;
        prefix_bytes.push(byte);
    }

    Ok(Prefix {
        length,
        prefix: prefix_bytes,
    })
}

/// Parse a protocol value (e.g., "=tcp", "=udp", "=6")
fn parse_protocol(s: &str) -> Result<NumericMatch, ParseError> {
    let s = s.trim_start_matches('=');

    let value = match s.to_lowercase().as_str() {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        "gre" => 47,
        "esp" => 50,
        "ah" => 51,
        "sctp" => 132,
        _ => s
            .parse::<u64>()
            .map_err(|_| ParseError::InvalidProtocol(s.to_string()))?,
    };

    Ok(NumericMatch {
        op: NumericOp {
            end: true,
            and: false,
            len: 0, // 1 byte
            reserved: false,
            lt: false,
            gt: false,
            eq: true,
        },
        value,
    })
}

/// Parse a numeric value with operator (e.g., "=80", ">=1024", ">1500")
fn parse_numeric_value(s: &str) -> Result<NumericMatch, ParseError> {
    let (op, value_str) = parse_operator(s)?;

    let value: u64 = value_str
        .parse()
        .map_err(|_| ParseError::InvalidNumber(value_str.to_string()))?;

    // Determine length based on value
    let len = if value <= 0xFF {
        0 // 1 byte
    } else if value <= 0xFFFF {
        1 // 2 bytes
    } else if value <= 0xFFFFFFFF {
        2 // 4 bytes
    } else {
        3 // 8 bytes
    };

    Ok(NumericMatch {
        op: NumericOp {
            end: true,
            and: false,
            len,
            reserved: false,
            lt: op.0,
            gt: op.1,
            eq: op.2,
        },
        value,
    })
}

/// Parse operator prefix, returns (lt, gt, eq) and remaining string
fn parse_operator(s: &str) -> Result<((bool, bool, bool), &str), ParseError> {
    if let Some(rest) = s.strip_prefix(">=") {
        Ok(((false, true, true), rest))
    } else if let Some(rest) = s.strip_prefix("<=") {
        Ok(((true, false, true), rest))
    } else if let Some(rest) = s.strip_prefix('>') {
        Ok(((false, true, false), rest))
    } else if let Some(rest) = s.strip_prefix('<') {
        Ok(((true, false, false), rest))
    } else if let Some(rest) = s.strip_prefix('=') {
        Ok(((false, false, true), rest))
    } else {
        // Default to equals
        Ok(((false, false, true), s))
    }
}

/// Parse bracketed TCP flags (e.g., "[ syn ]" or "[ syn ack ]")
fn parse_bracketed_flags(tokens: &[&str]) -> Result<(Vec<BitmaskMatch>, usize), ParseError> {
    if tokens.is_empty() {
        return Err(ParseError::MissingValue("tcp-flags".to_string()));
    }

    let mut i = 0;
    let mut in_bracket = false;
    let mut flags: u8 = 0;

    // Check for opening bracket
    if tokens[i] == "[" {
        in_bracket = true;
        i += 1;
    } else if tokens[i].starts_with('[') {
        in_bracket = true;
        // Handle "[syn" case
        let flag_str = tokens[i].trim_start_matches('[').trim_end_matches(']');
        if !flag_str.is_empty() {
            flags |= parse_tcp_flag(flag_str)?;
        }
        if tokens[i].ends_with(']') {
            return Ok((
                vec![BitmaskMatch {
                    op: BitmaskOp {
                        end: true,
                        and: false,
                        len: 0,
                        reserved: 0,
                        not: false,
                        match_: true,
                    },
                    value: flags as u64,
                }],
                1,
            ));
        }
        i += 1;
    }

    // Parse flags until closing bracket
    while i < tokens.len() {
        let token = tokens[i];
        if token == "]" {
            i += 1; // Consume the closing bracket
            break;
        }
        if token.ends_with(']') {
            let flag_str = token.trim_end_matches(']');
            if !flag_str.is_empty() {
                flags |= parse_tcp_flag(flag_str)?;
            }
            i += 1;
            break;
        }
        flags |= parse_tcp_flag(token)?;
        i += 1;
    }

    if !in_bracket && i == 0 {
        // Single flag without brackets
        flags = parse_tcp_flag(tokens[0])?;
        i = 1;
    }

    Ok((
        vec![BitmaskMatch {
            op: BitmaskOp {
                end: true,
                and: false,
                len: 0, // 1 byte
                reserved: 0,
                not: false,
                match_: true,
            },
            value: flags as u64,
        }],
        i,
    ))
}

/// Parse a single TCP flag name
fn parse_tcp_flag(s: &str) -> Result<u8, ParseError> {
    match s.to_lowercase().as_str() {
        "fin" => Ok(0x01),
        "syn" => Ok(0x02),
        "rst" => Ok(0x04),
        "psh" => Ok(0x08),
        "ack" => Ok(0x10),
        "urg" => Ok(0x20),
        _ => Err(ParseError::InvalidTcpFlags(s.to_string())),
    }
}

/// Parse bracketed fragment type (e.g., "[ is-fragment ]")
fn parse_bracketed_fragment(tokens: &[&str]) -> Result<(Vec<BitmaskMatch>, usize), ParseError> {
    if tokens.is_empty() {
        return Err(ParseError::MissingValue("fragment".to_string()));
    }

    let mut i = 0;
    let mut fragment_bits: u8 = 0;

    // Check for opening bracket
    if tokens[i] == "[" {
        i += 1;
    } else if tokens[i].starts_with('[') {
        let frag_str = tokens[i].trim_start_matches('[').trim_end_matches(']');
        if !frag_str.is_empty() {
            fragment_bits |= parse_fragment_type(frag_str)?;
        }
        if tokens[i].ends_with(']') {
            return Ok((
                vec![BitmaskMatch {
                    op: BitmaskOp {
                        end: true,
                        and: false,
                        len: 0,
                        reserved: 0,
                        not: false,
                        match_: true,
                    },
                    value: fragment_bits as u64,
                }],
                1,
            ));
        }
        i += 1;
    }

    // Parse fragment types until closing bracket
    while i < tokens.len() {
        let token = tokens[i];
        if token == "]" {
            i += 1; // Consume the closing bracket
            break;
        }
        if token.ends_with(']') {
            let frag_str = token.trim_end_matches(']');
            if !frag_str.is_empty() {
                fragment_bits |= parse_fragment_type(frag_str)?;
            }
            i += 1;
            break;
        }
        fragment_bits |= parse_fragment_type(token)?;
        i += 1;
    }

    Ok((
        vec![BitmaskMatch {
            op: BitmaskOp {
                end: true,
                and: false,
                len: 0,
                reserved: 0,
                not: false,
                match_: true,
            },
            value: fragment_bits as u64,
        }],
        i,
    ))
}

/// Parse fragment type name
fn parse_fragment_type(s: &str) -> Result<u8, ParseError> {
    match s.to_lowercase().as_str() {
        "not-a-fragment" | "dont-fragment" => Ok(0x01),
        "is-fragment" => Ok(0x02),
        "first-fragment" => Ok(0x04),
        "last-fragment" => Ok(0x08),
        _ => Err(ParseError::InvalidFragment(s.to_string())),
    }
}

/// Parse action (e.g., "discard", "rate-limit 1000000", "mark 46")
fn parse_action(tokens: &[&str]) -> Result<TrafficAction, ParseError> {
    if tokens.is_empty() {
        return Err(ParseError::MissingValue("action".to_string()));
    }

    match tokens[0].to_lowercase().as_str() {
        "discard" | "drop" => Ok(TrafficAction::RateBytes {
            as_number: 0,
            rate: 0.0,
        }),
        "accept" => Ok(TrafficAction::Action {
            _reserved: 0,
            sample: false,
            terminal: true,
        }),
        "rate-limit" => {
            if tokens.len() < 2 {
                return Err(ParseError::MissingValue("rate-limit".to_string()));
            }
            let rate: f32 = tokens[1]
                .parse()
                .map_err(|_| ParseError::InvalidNumber(tokens[1].to_string()))?;
            Ok(TrafficAction::RateBytes { as_number: 0, rate })
        }
        "mark" => {
            if tokens.len() < 2 {
                return Err(ParseError::MissingValue("mark".to_string()));
            }
            let dscp: u8 = tokens[1]
                .parse()
                .map_err(|_| ParseError::InvalidNumber(tokens[1].to_string()))?;
            if dscp > 63 {
                return Err(ParseError::InvalidAction(format!(
                    "DSCP must be 0-63, got {}",
                    dscp
                )));
            }
            Ok(TrafficAction::TrafficMarking {
                _reserved: 0,
                dscp,
            })
        }
        "redirect" => {
            if tokens.len() < 2 {
                return Err(ParseError::MissingValue("redirect".to_string()));
            }
            // Parse "asn:value" format
            let parts: Vec<&str> = tokens[1].split(':').collect();
            if parts.len() != 2 {
                return Err(ParseError::InvalidAction(format!(
                    "redirect format should be 'asn:value', got {}",
                    tokens[1]
                )));
            }
            let as_number: u16 = parts[0]
                .parse()
                .map_err(|_| ParseError::InvalidNumber(parts[0].to_string()))?;
            let value: u32 = parts[1]
                .parse()
                .map_err(|_| ParseError::InvalidNumber(parts[1].to_string()))?;
            Ok(TrafficAction::RedirectAs2 { as_number, value })
        }
        other => Err(ParseError::InvalidAction(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_announce_discard() {
        let cmd =
            parse_command("announce flowspec source 10.0.0.0/24 destination-port =80 then discard")
                .unwrap();
        assert_eq!(cmd.operation, Operation::Announce);
        assert_eq!(cmd.flowspec.components.len(), 2);

        // Check source prefix
        if let Component::SourcePrefix(prefix) = &cmd.flowspec.components[0] {
            assert_eq!(prefix.length, 24);
        } else {
            panic!("expected SourcePrefix");
        }

        // Check destination port
        if let Component::DestinationPort(matches) = &cmd.flowspec.components[1] {
            assert_eq!(matches[0].value, 80);
            assert!(matches[0].op.eq);
        } else {
            panic!("expected DestinationPort");
        }

        // Check action
        if let Some(TrafficAction::RateBytes { rate, .. }) = cmd.action {
            assert_eq!(rate, 0.0);
        } else {
            panic!("expected RateBytes (discard)");
        }
    }

    #[test]
    fn test_parse_withdraw() {
        let cmd =
            parse_command("withdraw flowspec source 192.168.1.0/24 protocol =tcp").unwrap();
        assert_eq!(cmd.operation, Operation::Withdraw);
        assert_eq!(cmd.flowspec.components.len(), 2);
        assert!(cmd.action.is_none());
    }

    #[test]
    fn test_parse_rate_limit() {
        let cmd =
            parse_command("announce flowspec destination-port =443 then rate-limit 1000000")
                .unwrap();

        if let Some(TrafficAction::RateBytes { rate, .. }) = cmd.action {
            assert_eq!(rate, 1000000.0);
        } else {
            panic!("expected RateBytes");
        }
    }

    #[test]
    fn test_parse_tcp_flags() {
        let cmd =
            parse_command("announce flowspec tcp-flags [ syn ack ] then discard").unwrap();

        if let Component::TcpFlags(matches) = &cmd.flowspec.components[0] {
            // syn=0x02, ack=0x10 -> 0x12
            assert_eq!(matches[0].value, 0x12);
        } else {
            panic!("expected TcpFlags");
        }
    }

    #[test]
    fn test_parse_packet_length() {
        let cmd =
            parse_command("announce flowspec packet-length >1500 then discard").unwrap();

        if let Component::PacketLength(matches) = &cmd.flowspec.components[0] {
            assert_eq!(matches[0].value, 1500);
            assert!(matches[0].op.gt);
            assert!(!matches[0].op.eq);
        } else {
            panic!("expected PacketLength");
        }
    }

    #[test]
    fn test_parse_mark() {
        let cmd = parse_command("announce flowspec source 10.0.0.0/8 then mark 46").unwrap();

        if let Some(TrafficAction::TrafficMarking { dscp, .. }) = cmd.action {
            assert_eq!(dscp, 46);
        } else {
            panic!("expected TrafficMarking");
        }
    }

    #[test]
    fn test_parse_fragment() {
        let cmd =
            parse_command("announce flowspec fragment [ is-fragment ] then discard").unwrap();

        if let Component::Fragment(matches) = &cmd.flowspec.components[0] {
            assert_eq!(matches[0].value, 0x02); // is-fragment
        } else {
            panic!("expected Fragment");
        }
    }

    #[test]
    fn test_parse_multiple_ports() {
        let cmd = parse_command(
            "announce flowspec destination-port >=1024 destination-port <=65535 then accept",
        )
        .unwrap();

        if let Component::DestinationPort(matches) = &cmd.flowspec.components[0] {
            assert_eq!(matches.len(), 2);
            assert_eq!(matches[0].value, 1024);
            assert!(matches[0].op.gt);
            assert!(matches[0].op.eq);
            assert_eq!(matches[1].value, 65535);
            assert!(matches[1].op.lt);
            assert!(matches[1].op.eq);
        } else {
            panic!("expected DestinationPort");
        }
    }

    #[test]
    fn test_parse_redirect() {
        let cmd =
            parse_command("announce flowspec source 10.0.0.0/24 then redirect 65001:100").unwrap();

        if let Some(TrafficAction::RedirectAs2 { as_number, value }) = cmd.action {
            assert_eq!(as_number, 65001);
            assert_eq!(value, 100);
        } else {
            panic!("expected RedirectAs2");
        }
    }

    #[test]
    fn test_empty_and_comment() {
        assert!(parse_command("").is_err());
        assert!(parse_command("   ").is_err());
        assert!(parse_command("# this is a comment").is_err());
    }

    #[test]
    fn test_invalid_command() {
        assert!(parse_command("invalid flowspec source 10.0.0.0/24").is_err());
        assert!(parse_command("announce notflowspec source 10.0.0.0/24").is_err());
    }
}
