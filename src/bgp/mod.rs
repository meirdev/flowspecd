pub mod attributes;
pub mod flowspec;
pub mod fsm;
pub mod session;

use deku::prelude::*;
use num_derive::ToPrimitive;
use num_traits::ToPrimitive;

const BGP_VERSION: u8 = 4;
const BGP_MARKER: [u8; 16] = [0xFF; 16];
pub const BGP_HEADER_LEN: usize = 19;

/// Address Family Identifier (RFC 4760)
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToPrimitive, DekuRead, DekuWrite)]
#[deku(id_type = "u16", endian = "big")]
#[repr(u16)]
pub enum Afi {
    Ipv4 = 1,
    Ipv6 = 2,
}

/// Subsequent Address Family Identifier (RFC 4760)
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToPrimitive, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum Safi {
    Unicast = 1,
    Multicast = 2,
    FlowSpec = 133,
    FlowSpecVpn = 134,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum MessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
}

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite)]
pub struct Header {
    #[deku(assert_eq = "BGP_MARKER")]
    pub marker: [u8; 16],
    #[deku(endian = "big")]
    pub length: u16,
    pub message_type: MessageType,
}

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite)]
pub struct Open {
    #[deku(assert_eq = "BGP_VERSION")]
    pub version: u8,
    #[deku(endian = "big")]
    pub my_as: u16,
    #[deku(endian = "big")]
    pub hold_time: u16,
    #[deku(endian = "big")]
    pub bgp_id: u32,
    #[deku(update = "self.opt_params.len()")]
    pub opt_params_len: u8,
    #[deku(count = "opt_params_len")]
    pub opt_params: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum ErrorCode {
    MessageHeader = 1,
    OpenMessage = 2,
    UpdateMessage = 3,
    HoldTimerExpired = 4,
    FiniteStateMachine = 5,
    Cease = 6,
}

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite)]
pub struct Notification {
    pub error_code: ErrorCode,
    pub error_subcode: u8,
    #[deku(read_all)]
    pub data: Vec<u8>,
}

impl Notification {
    /// Create a new NOTIFICATION message
    pub fn new(error_code: ErrorCode, error_subcode: u8) -> Self {
        Self {
            error_code,
            error_subcode,
            data: vec![],
        }
    }

    /// Create a new NOTIFICATION message with data
    pub fn with_data(error_code: ErrorCode, error_subcode: u8, data: Vec<u8>) -> Self {
        Self {
            error_code,
            error_subcode,
            data,
        }
    }
}

impl std::fmt::Display for Notification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let subcode_desc = match self.error_code {
            ErrorCode::MessageHeader => match self.error_subcode {
                1 => "Connection Not Synchronized",
                2 => "Bad Message Length",
                3 => "Bad Message Type",
                _ => "Unknown",
            },
            ErrorCode::OpenMessage => match self.error_subcode {
                1 => "Unsupported Version Number",
                2 => "Bad Peer AS",
                3 => "Bad BGP Identifier",
                4 => "Unsupported Optional Parameter",
                5 => "Authentication Failure (Deprecated)",
                6 => "Unacceptable Hold Time",
                7 => "Unsupported Capability",
                _ => "Unknown",
            },
            ErrorCode::UpdateMessage => match self.error_subcode {
                1 => "Malformed Attribute List",
                2 => "Unrecognized Well-known Attribute",
                3 => "Missing Well-known Attribute",
                4 => "Attribute Flags Error",
                5 => "Attribute Length Error",
                6 => "Invalid ORIGIN Attribute",
                7 => "AS Routing Loop (Deprecated)",
                8 => "Invalid NEXT_HOP Attribute",
                9 => "Optional Attribute Error",
                10 => "Invalid Network Field",
                11 => "Malformed AS_PATH",
                _ => "Unknown",
            },
            ErrorCode::HoldTimerExpired => "Hold Timer Expired",
            ErrorCode::FiniteStateMachine => match self.error_subcode {
                0 => "Unspecified Error",
                1 => "Receive Unexpected Message in OpenSent State",
                2 => "Receive Unexpected Message in OpenConfirm State",
                3 => "Receive Unexpected Message in Established State",
                _ => "Unknown",
            },
            ErrorCode::Cease => match self.error_subcode {
                1 => "Maximum Number of Prefixes Reached",
                2 => "Administrative Shutdown",
                3 => "Peer De-configured",
                4 => "Administrative Reset",
                5 => "Connection Rejected",
                6 => "Other Configuration Change",
                7 => "Connection Collision Resolution",
                8 => "Out of Resources",
                _ => "Unknown",
            },
        };
        write!(
            f,
            "{:?} (subcode {}: {})",
            self.error_code, self.error_subcode, subcode_desc
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite)]
pub struct Prefix {
    pub length: u8,
    #[deku(count = "(length + 7) / 8")]
    pub prefix: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite)]
pub struct Update {
    #[deku(
        endian = "big",
        update = "self.withdrawn_routes.iter().map(|p| 1 + p.prefix.len()).sum::<usize>()"
    )]
    pub withdrawn_len: u16,
    #[deku(bytes_read = "withdrawn_len")]
    pub withdrawn_routes: Vec<Prefix>,
    #[deku(endian = "big", update = "self.path_attributes.len()")]
    pub path_attr_len: u16,
    #[deku(count = "path_attr_len")]
    pub path_attributes: Vec<u8>,
    #[deku(read_all)]
    pub nlri: Vec<Prefix>,
}

/// BGP Capability (RFC 5492)
/// Format: code (1 byte) + length (1 byte) + value
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Capability {
    MultiProtocol { afi: Afi, safi: Safi },
    RouteRefresh,
    FourOctetAs { asn: u32 },
}

impl Capability {
    pub fn multi_protocol(afi: Afi, safi: Safi) -> Self {
        Self::MultiProtocol { afi, safi }
    }

    pub fn ipv4_unicast() -> Self {
        Self::multi_protocol(Afi::Ipv4, Safi::Unicast)
    }

    pub fn ipv4_flowspec() -> Self {
        Self::multi_protocol(Afi::Ipv4, Safi::FlowSpec)
    }

    /// Encode capability as bytes (code + length + value)
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Capability::MultiProtocol { afi, safi } => {
                let afi_val = afi.to_u16().unwrap();
                let safi_val = safi.to_u8().unwrap();
                vec![
                    0x01,                 // Code: Multiprotocol
                    0x04,                 // Length: 4 bytes
                    (afi_val >> 8) as u8, // AFI high
                    afi_val as u8,        // AFI low
                    0x00,                 // Reserved
                    safi_val,             // SAFI
                ]
            }
            Capability::RouteRefresh => {
                vec![0x02, 0x00] // Code: Route Refresh, Length: 0
            }
            Capability::FourOctetAs { asn } => {
                vec![
                    0x41, // Code: 4-octet AS (65)
                    0x04, // Length: 4 bytes
                    (asn >> 24) as u8,
                    (asn >> 16) as u8,
                    (asn >> 8) as u8,
                    *asn as u8,
                ]
            }
        }
    }

    /// Encode as optional parameter (Type=2)
    fn to_opt_param(&self) -> Vec<u8> {
        let cap_bytes = self.to_bytes();
        let mut out = vec![0x02, cap_bytes.len() as u8];
        out.extend(cap_bytes);
        out
    }
}

impl Header {
    pub fn new(message_type: MessageType, body_len: u16) -> Self {
        Self {
            marker: BGP_MARKER,
            length: BGP_HEADER_LEN as u16 + body_len,
            message_type,
        }
    }
}

impl Open {
    pub fn new(my_as: u16, hold_time: u16, bgp_id: u32) -> Self {
        Self {
            version: BGP_VERSION,
            my_as,
            hold_time,
            bgp_id,
            opt_params_len: 0,
            opt_params: vec![],
        }
    }

    /// Create OPEN with MP-BGP capabilities for FlowSpec
    pub fn with_flowspec(my_as: u16, hold_time: u16, bgp_id: u32) -> Self {
        let mut opt_params = vec![];
        opt_params.extend(Capability::ipv4_unicast().to_opt_param());
        opt_params.extend(Capability::ipv4_flowspec().to_opt_param());

        Self {
            version: BGP_VERSION,
            my_as,
            hold_time,
            bgp_id,
            opt_params_len: opt_params.len() as u8,
            opt_params,
        }
    }
}

impl Update {
    /// Parse path attributes from raw bytes
    pub fn parse_attributes(&self) -> Result<Vec<attributes::PathAttribute>, DekuError> {
        attributes::parse_path_attributes(&self.path_attributes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = Header::new(MessageType::Keepalive, 0);
        let bytes = header.to_bytes().unwrap();
        assert_eq!(bytes.len(), BGP_HEADER_LEN);

        let (_, parsed) = Header::from_bytes((&bytes, 0)).unwrap();
        assert_eq!(parsed, header);
    }

    #[test]
    fn test_open_roundtrip() {
        let open = Open::new(65, 180, 0x0A000001);
        let bytes = open.to_bytes().unwrap();

        let (_, parsed) = Open::from_bytes((&bytes, 0)).unwrap();
        assert_eq!(parsed.my_as, 65);
        assert_eq!(parsed.hold_time, 180);
        assert_eq!(parsed.bgp_id, 0x0A000001);
    }

    #[test]
    fn test_prefix_parse() {
        let data = [0x18, 0xC0, 0xA8, 0x01]; // 192.168.1.0/24
        let (_, prefix) = Prefix::from_bytes((&data, 0)).unwrap();
        assert_eq!(prefix.length, 24);
        assert_eq!(prefix.prefix, vec![0xC0, 0xA8, 0x01]);
    }
}
