use deku::prelude::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use super::flowspec::FlowSpecNlri;
use super::{Afi, Safi};

/// Path attribute type codes (RFC 4271, RFC 4760)
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum AttrTypeCode {
    Origin = 1,
    AsPath = 2,
    NextHop = 3,
    Med = 4,
    LocalPref = 5,
    AtomicAggregate = 6,
    Aggregator = 7,
    Communities = 8,
    MpReachNlri = 14,
    MpUnreachNlri = 15,
    ExtendedCommunities = 16,
    LargeCommunities = 32,
}

/// Path attribute flags (1 byte)
#[derive(Debug, Clone, Copy, PartialEq, Eq, DekuRead, DekuWrite)]
pub struct AttrFlags {
    #[deku(bits = "1")]
    pub optional: bool,
    #[deku(bits = "1")]
    pub transitive: bool,
    #[deku(bits = "1")]
    pub partial: bool,
    #[deku(bits = "1")]
    pub extended_length: bool,
    #[deku(bits = "4")]
    pub _reserved: u8,
}

/// MP_REACH_NLRI attribute (RFC 4760)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpReachNlri {
    pub afi: Afi,
    pub safi: Safi,
    pub next_hop: Vec<u8>,
    pub nlri: Vec<u8>,
}

/// MP_UNREACH_NLRI attribute (RFC 4760)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpUnreachNlri {
    pub afi: Afi,
    pub safi: Safi,
    pub withdrawn: Vec<u8>,
}

/// Parsed path attribute
#[derive(Debug, Clone, PartialEq)]
pub enum PathAttribute {
    Origin(u8),
    AsPath(Vec<u8>),
    NextHop(u32),
    Med(u32),
    LocalPref(u32),
    AtomicAggregate,
    Communities(Vec<u32>),
    ExtendedCommunities(Vec<u8>),
    MpReachNlri(MpReachNlri),
    MpUnreachNlri(MpUnreachNlri),
    Unknown { type_code: u8, data: Vec<u8> },
}

impl MpReachNlri {
    pub fn from_bytes(data: &[u8]) -> Result<Self, DekuError> {
        let mut cursor = std::io::Cursor::new(data);
        let mut reader = deku::reader::Reader::new(&mut cursor);

        let afi = Afi::from_reader_with_ctx(&mut reader, ())?;
        let safi = Safi::from_reader_with_ctx(&mut reader, ())?;
        let nh_len = u8::from_reader_with_ctx(&mut reader, ())?;

        let mut next_hop = vec![0u8; nh_len as usize];
        for byte in &mut next_hop {
            *byte = u8::from_reader_with_ctx(&mut reader, ())?;
        }

        // Reserved byte
        let _ = u8::from_reader_with_ctx(&mut reader, ())?;

        // Rest is NLRI
        let pos = reader.bits_read / 8;
        let nlri = data[pos..].to_vec();

        Ok(Self {
            afi,
            safi,
            next_hop,
            nlri,
        })
    }

    /// Parse FlowSpec NLRI if this is a FlowSpec attribute
    pub fn parse_flowspec(&self) -> Result<Vec<FlowSpecNlri>, DekuError> {
        if self.safi != Safi::FlowSpec && self.safi != Safi::FlowSpecVpn {
            return Err(DekuError::Parse("not a FlowSpec NLRI".into()));
        }

        let mut nlris = Vec::new();
        let mut offset = 0;

        while offset < self.nlri.len() {
            let nlri = FlowSpecNlri::from_bytes(&self.nlri[offset..])?;
            // Calculate consumed bytes
            let len = if self.nlri[offset] >= 0xf0 {
                let l =
                    (((self.nlri[offset] & 0x0f) as usize) << 8) | (self.nlri[offset + 1] as usize);
                l + 2
            } else {
                self.nlri[offset] as usize + 1
            };
            offset += len;
            nlris.push(nlri);
        }

        Ok(nlris)
    }
}

impl MpUnreachNlri {
    pub fn from_bytes(data: &[u8]) -> Result<Self, DekuError> {
        let mut cursor = std::io::Cursor::new(data);
        let mut reader = deku::reader::Reader::new(&mut cursor);

        let afi = Afi::from_reader_with_ctx(&mut reader, ())?;
        let safi = Safi::from_reader_with_ctx(&mut reader, ())?;

        let pos = reader.bits_read / 8;
        let withdrawn = data[pos..].to_vec();

        Ok(Self {
            afi,
            safi,
            withdrawn,
        })
    }

    /// Parse FlowSpec withdrawn NLRI
    pub fn parse_flowspec(&self) -> Result<Vec<FlowSpecNlri>, DekuError> {
        if self.safi != Safi::FlowSpec && self.safi != Safi::FlowSpecVpn {
            return Err(DekuError::Parse("not a FlowSpec NLRI".into()));
        }

        let mut nlris = Vec::new();
        let mut offset = 0;

        while offset < self.withdrawn.len() {
            let nlri = FlowSpecNlri::from_bytes(&self.withdrawn[offset..])?;
            let len = if self.withdrawn[offset] >= 0xf0 {
                let l = (((self.withdrawn[offset] & 0x0f) as usize) << 8)
                    | (self.withdrawn[offset + 1] as usize);
                l + 2
            } else {
                self.withdrawn[offset] as usize + 1
            };
            offset += len;
            nlris.push(nlri);
        }

        Ok(nlris)
    }
}

/// Parse path attributes from raw bytes
pub fn parse_path_attributes(data: &[u8]) -> Result<Vec<PathAttribute>, DekuError> {
    let mut attrs = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let mut cursor = std::io::Cursor::new(&data[offset..]);
        let mut reader = deku::reader::Reader::new(&mut cursor);

        let flags = AttrFlags::from_reader_with_ctx(&mut reader, ())?;
        let type_code = u8::from_reader_with_ctx(&mut reader, ())?;

        let length = if flags.extended_length {
            u16::from_reader_with_ctx(&mut reader, deku::ctx::Endian::Big)? as usize
        } else {
            u8::from_reader_with_ctx(&mut reader, ())? as usize
        };

        let header_len = if flags.extended_length { 4 } else { 3 };
        let value_start = offset + header_len;
        let value = &data[value_start..value_start + length];

        let attr = match AttrTypeCode::from_u8(type_code) {
            Some(AttrTypeCode::Origin) => PathAttribute::Origin(value[0]),
            Some(AttrTypeCode::AsPath) => PathAttribute::AsPath(value.to_vec()),
            Some(AttrTypeCode::NextHop) => {
                let ip = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                PathAttribute::NextHop(ip)
            }
            Some(AttrTypeCode::Med) => {
                let med = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                PathAttribute::Med(med)
            }
            Some(AttrTypeCode::LocalPref) => {
                let lp = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                PathAttribute::LocalPref(lp)
            }
            Some(AttrTypeCode::AtomicAggregate) => PathAttribute::AtomicAggregate,
            Some(AttrTypeCode::Communities) => {
                let mut comms = Vec::new();
                for chunk in value.chunks(4) {
                    if chunk.len() == 4 {
                        comms.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                    }
                }
                PathAttribute::Communities(comms)
            }
            Some(AttrTypeCode::MpReachNlri) => {
                PathAttribute::MpReachNlri(MpReachNlri::from_bytes(value)?)
            }
            Some(AttrTypeCode::MpUnreachNlri) => {
                PathAttribute::MpUnreachNlri(MpUnreachNlri::from_bytes(value)?)
            }
            Some(AttrTypeCode::ExtendedCommunities) => {
                PathAttribute::ExtendedCommunities(value.to_vec())
            }
            Some(AttrTypeCode::Aggregator) | Some(AttrTypeCode::LargeCommunities) | None => {
                PathAttribute::Unknown {
                    type_code,
                    data: value.to_vec(),
                }
            }
        };

        attrs.push(attr);
        offset = value_start + length;
    }

    Ok(attrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attr_flags_parse() {
        // Optional=1, Transitive=1, Partial=0, Extended=0
        let data = [0xC0];
        let (_, flags) = AttrFlags::from_bytes((&data, 0)).unwrap();
        assert!(flags.optional);
        assert!(flags.transitive);
        assert!(!flags.partial);
        assert!(!flags.extended_length);
    }

    #[test]
    fn test_mp_reach_flowspec() {
        // AFI=1 (IPv4), SAFI=133 (FlowSpec), NH_LEN=0, Reserved, NLRI
        // NLRI: length=3, type=5 (dest port), op=0x81, value=80
        let data = [
            0x00, 0x01, // AFI IPv4
            0x85, // SAFI FlowSpec (133)
            0x00, // Next hop length
            0x00, // Reserved
            0x03, 0x05, 0x81, 0x50, // FlowSpec NLRI
        ];

        let mp = MpReachNlri::from_bytes(&data).unwrap();
        assert_eq!(mp.afi, Afi::Ipv4);
        assert_eq!(mp.safi, Safi::FlowSpec);
        assert_eq!(mp.next_hop.len(), 0);

        let flowspecs = mp.parse_flowspec().unwrap();
        assert_eq!(flowspecs.len(), 1);
    }

    #[test]
    fn test_mp_unreach_flowspec() {
        // AFI=1, SAFI=133, Withdrawn NLRI
        let data = [
            0x00, 0x01, // AFI IPv4
            0x85, // SAFI FlowSpec
            0x03, 0x05, 0x81, 0x50, // FlowSpec NLRI to withdraw
        ];

        let mp = MpUnreachNlri::from_bytes(&data).unwrap();
        assert_eq!(mp.afi, Afi::Ipv4);
        assert_eq!(mp.safi, Safi::FlowSpec);

        let flowspecs = mp.parse_flowspec().unwrap();
        assert_eq!(flowspecs.len(), 1);
    }

    #[test]
    fn test_parse_origin_attr() {
        // Flags=0x40 (transitive), Type=1 (origin), Len=1, Value=0 (IGP)
        let data = [0x40, 0x01, 0x01, 0x00];
        let attrs = parse_path_attributes(&data).unwrap();

        assert_eq!(attrs.len(), 1);
        if let PathAttribute::Origin(origin) = &attrs[0] {
            assert_eq!(*origin, 0);
        } else {
            panic!("expected Origin");
        }
    }

    #[test]
    fn test_parse_mp_reach_attr() {
        // Flags=0x90 (optional, extended), Type=14, Len=9
        // Content: AFI(2) + SAFI(1) + NH_LEN(1) + Reserved(1) + NLRI(4) = 9
        let data = [
            0x90, 0x0E, 0x00, 0x09, // Header with extended length=9
            0x00, 0x01, // AFI IPv4
            0x85, // SAFI FlowSpec
            0x00, // NH len
            0x00, // Reserved
            0x03, 0x05, 0x81, 0x50, // NLRI
        ];

        let attrs = parse_path_attributes(&data).unwrap();
        assert_eq!(attrs.len(), 1);

        if let PathAttribute::MpReachNlri(mp) = &attrs[0] {
            assert_eq!(mp.afi, Afi::Ipv4);
            assert_eq!(mp.safi, Safi::FlowSpec);
        } else {
            panic!("expected MpReachNlri");
        }
    }
}
