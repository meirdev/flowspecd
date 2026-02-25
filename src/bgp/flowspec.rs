use deku::prelude::*;

use super::Prefix;

/// FlowSpec component types (RFC 8955 Section 4)
#[derive(Debug, Clone, Copy, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum ComponentType {
    DestinationPrefix = 1,
    SourcePrefix = 2,
    IpProtocol = 3,
    Port = 4,
    DestinationPort = 5,
    SourcePort = 6,
    IcmpType = 7,
    IcmpCode = 8,
    TcpFlags = 9,
    PacketLength = 10,
    Dscp = 11,
    Fragment = 12,
}

/// Numeric operator for value comparisons
/// Numeric operator for value comparisons (1 byte)
#[derive(Debug, Clone, Copy, PartialEq, Eq, DekuRead, DekuWrite)]
pub struct NumericOp {
    #[deku(bits = "1")]
    pub end: bool,
    #[deku(bits = "1")]
    pub and: bool,
    #[deku(bits = "2")]
    pub len: u8, // 0=1byte, 1=2bytes, 2=4bytes, 3=8bytes
    #[deku(bits = "1")]
    pub reserved: bool,
    #[deku(bits = "1")]
    pub lt: bool,
    #[deku(bits = "1")]
    pub gt: bool,
    #[deku(bits = "1")]
    pub eq: bool,
}

/// Bitmask operator for flag matching (1 byte)
#[derive(Debug, Clone, Copy, PartialEq, Eq, DekuRead, DekuWrite)]
pub struct BitmaskOp {
    #[deku(bits = "1")]
    pub end: bool,
    #[deku(bits = "1")]
    pub and: bool,
    #[deku(bits = "2")]
    pub len: u8,
    #[deku(bits = "2")]
    pub reserved: u8,
    #[deku(bits = "1")]
    pub not: bool,
    #[deku(bits = "1")]
    pub match_: bool,
}

/// Trait for operators with variable-length values
trait Operator: Sized + for<'a> DekuReader<'a, ()> {
    fn end(&self) -> bool;
    fn value_len(&self) -> usize;
}

impl Operator for NumericOp {
    fn end(&self) -> bool {
        self.end
    }
    fn value_len(&self) -> usize {
        1 << self.len
    }
}

impl Operator for BitmaskOp {
    fn end(&self) -> bool {
        self.end
    }
    fn value_len(&self) -> usize {
        1 << self.len
    }
}

/// A match entry (operator + value)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match<Op> {
    pub op: Op,
    pub value: u64,
}

pub type NumericMatch = Match<NumericOp>;
pub type BitmaskMatch = Match<BitmaskOp>;

/// FlowSpec component
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Component {
    DestinationPrefix(Prefix),
    SourcePrefix(Prefix),
    IpProtocol(Vec<NumericMatch>),
    Port(Vec<NumericMatch>),
    DestinationPort(Vec<NumericMatch>),
    SourcePort(Vec<NumericMatch>),
    IcmpType(Vec<NumericMatch>),
    IcmpCode(Vec<NumericMatch>),
    TcpFlags(Vec<BitmaskMatch>),
    PacketLength(Vec<NumericMatch>),
    Dscp(Vec<NumericMatch>),
    Fragment(Vec<BitmaskMatch>),
}

/// Parse operator+value matches until end bit is set
fn parse_matches<R, Op>(reader: &mut deku::reader::Reader<R>) -> Result<Vec<Match<Op>>, DekuError>
where
    R: std::io::Read + std::io::Seek,
    Op: Operator,
{
    let mut matches = Vec::new();
    loop {
        let op = Op::from_reader_with_ctx(reader, ())?;
        let value = match op.value_len() {
            1 => u8::from_reader_with_ctx(reader, ())? as u64,
            2 => u16::from_reader_with_ctx(reader, deku::ctx::Endian::Big)? as u64,
            4 => u32::from_reader_with_ctx(reader, deku::ctx::Endian::Big)? as u64,
            8 => u64::from_reader_with_ctx(reader, deku::ctx::Endian::Big)?,
            _ => return Err(DekuError::Parse("invalid length".into())),
        };
        let end = op.end();
        matches.push(Match { op, value });
        if end {
            break;
        }
    }
    Ok(matches)
}

/// Parse a single FlowSpec component
fn parse_component<R: std::io::Read + std::io::Seek>(
    reader: &mut deku::reader::Reader<R>,
) -> Result<Component, DekuError> {
    let component_type = ComponentType::from_reader_with_ctx(reader, ())?;

    match component_type {
        ComponentType::DestinationPrefix => Ok(Component::DestinationPrefix(
            Prefix::from_reader_with_ctx(reader, ())?,
        )),
        ComponentType::SourcePrefix => Ok(Component::SourcePrefix(Prefix::from_reader_with_ctx(
            reader,
            (),
        )?)),
        ComponentType::IpProtocol => Ok(Component::IpProtocol(parse_matches(reader)?)),
        ComponentType::Port => Ok(Component::Port(parse_matches(reader)?)),
        ComponentType::DestinationPort => Ok(Component::DestinationPort(parse_matches(reader)?)),
        ComponentType::SourcePort => Ok(Component::SourcePort(parse_matches(reader)?)),
        ComponentType::IcmpType => Ok(Component::IcmpType(parse_matches(reader)?)),
        ComponentType::IcmpCode => Ok(Component::IcmpCode(parse_matches(reader)?)),
        ComponentType::TcpFlags => Ok(Component::TcpFlags(parse_matches(reader)?)),
        ComponentType::PacketLength => Ok(Component::PacketLength(parse_matches(reader)?)),
        ComponentType::Dscp => Ok(Component::Dscp(parse_matches(reader)?)),
        ComponentType::Fragment => Ok(Component::Fragment(parse_matches(reader)?)),
    }
}

/// FlowSpec NLRI
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSpecNlri {
    pub components: Vec<Component>,
}

impl FlowSpecNlri {
    pub fn from_bytes(data: &[u8]) -> Result<Self, DekuError> {
        // Read length (1 or 2 bytes)
        let (nlri_len, offset) = if data[0] >= 0xf0 {
            let len = (((data[0] & 0x0f) as usize) << 8) | (data[1] as usize);
            (len, 2)
        } else {
            (data[0] as usize, 1)
        };

        let nlri_data = &data[offset..offset + nlri_len];
        Self::parse_components(nlri_data)
    }

    fn parse_components(data: &[u8]) -> Result<Self, DekuError> {
        let mut cursor = std::io::Cursor::new(data);
        let mut reader = deku::reader::Reader::new(&mut cursor);
        let mut components = Vec::new();
        let len = data.len();

        loop {
            let pos = reader.bits_read / 8;
            if pos >= len {
                break;
            }
            components.push(parse_component(&mut reader)?);
        }

        Ok(Self { components })
    }
}

/// Traffic action extended community (RFC 8955 Section 7)
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u16", endian = "big")]
pub enum TrafficAction {
    #[deku(id = 0x8006)]
    RateBytes {
        #[deku(endian = "big")]
        as_number: u16,
        #[deku(endian = "big")]
        rate: f32,
    },
    #[deku(id = 0x800c)]
    RatePackets {
        #[deku(endian = "big")]
        as_number: u16,
        #[deku(endian = "big")]
        rate: f32,
    },
    #[deku(id = 0x8007)]
    Action {
        #[deku(pad_bytes_before = "5", bits = "6")]
        _reserved: u8,
        #[deku(bits = "1")]
        sample: bool,
        #[deku(bits = "1")]
        terminal: bool,
    },
    #[deku(id = 0x8008)]
    RedirectAs2 {
        #[deku(endian = "big")]
        as_number: u16,
        #[deku(endian = "big")]
        value: u32,
    },
    #[deku(id = 0x8108)]
    RedirectIpv4 {
        #[deku(endian = "big")]
        ipv4: u32,
        #[deku(endian = "big")]
        value: u16,
    },
    #[deku(id = 0x8208)]
    RedirectAs4 {
        #[deku(endian = "big")]
        as_number: u32,
        #[deku(endian = "big")]
        value: u16,
    },
    #[deku(id = 0x8009)]
    TrafficMarking {
        #[deku(pad_bytes_before = "5", bits = "2")]
        _reserved: u8,
        #[deku(bits = "6")]
        dscp: u8,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_numeric_op_parse() {
        // End bit set, eq=true, 1-byte value
        let data = [0x81, 0x06]; // TCP protocol
        let mut cursor = std::io::Cursor::new(&data);
        let mut reader = deku::reader::Reader::new(&mut cursor);

        let op = NumericOp::from_reader_with_ctx(&mut reader, ()).unwrap();
        assert!(op.end);
        assert!(!op.and);
        assert_eq!(op.len, 0); // 1 byte
        assert!(op.eq);
        assert!(!op.lt);
        assert!(!op.gt);
    }

    #[test]
    fn test_flowspec_dest_prefix() {
        // Length=5, Type=1 (dest), prefixlen=24, prefix=192.168.1
        let data = [0x05, 0x01, 0x18, 0xC0, 0xA8, 0x01];
        let nlri = FlowSpecNlri::from_bytes(&data).unwrap();
        assert_eq!(nlri.components.len(), 1);

        if let Component::DestinationPrefix(prefix) = &nlri.components[0] {
            assert_eq!(prefix.length, 24);
            assert_eq!(prefix.prefix, vec![0xC0, 0xA8, 0x01]);
        } else {
            panic!("expected DestinationPrefix");
        }
    }

    #[test]
    fn test_flowspec_dest_port() {
        // Length=3, Type=5 (dest port), op=0x81 (end, eq), value=80
        let data = [0x03, 0x05, 0x81, 0x50];
        let nlri = FlowSpecNlri::from_bytes(&data).unwrap();

        if let Component::DestinationPort(matches) = &nlri.components[0] {
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0].value, 80);
            assert!(matches[0].op.eq);
        } else {
            panic!("expected DestinationPort");
        }
    }

    #[test]
    fn test_traffic_action_rate() {
        // Type 0x8006 (rate-bytes), AS=0, rate=0.0 (drop)
        let data = [0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (_, action) = TrafficAction::from_bytes((&data, 0)).unwrap();

        if let TrafficAction::RateBytes { as_number, rate } = action {
            assert_eq!(as_number, 0);
            assert_eq!(rate, 0.0);
        } else {
            panic!("expected RateBytes");
        }
    }

    #[test]
    fn test_traffic_action_marking() {
        // Type 0x8009 (traffic-marking), DSCP=46 (EF)
        let data = [0x80, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E];
        let (_, action) = TrafficAction::from_bytes((&data, 0)).unwrap();

        if let TrafficAction::TrafficMarking { dscp, .. } = action {
            assert_eq!(dscp, 46);
        } else {
            panic!("expected TrafficMarking");
        }
    }
}
