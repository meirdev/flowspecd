/// IPFIX Template definitions (RFC 7011)

pub const FLOWSPEC_STATS_TEMPLATE_ID: u16 = 256;
pub const FLOW_RECORD_TEMPLATE_ID: u16 = 257;

#[derive(Debug, Clone)]
pub struct Template {
    pub id: u16,
    pub fields: Vec<TemplateField>,
}

#[derive(Debug, Clone)]
pub struct TemplateField {
    pub id: u16,
    pub length: u16,
    pub enterprise_id: Option<u32>,
}

impl Template {
    pub fn flowspec_stats() -> Self {
        Self {
            id: FLOWSPEC_STATS_TEMPLATE_ID,
            fields: vec![
                // observationDomainId
                TemplateField { id: 149, length: 4, enterprise_id: None },
                // flowId (rule ID hash)
                TemplateField { id: 148, length: 8, enterprise_id: None },
                // packetDeltaCount
                TemplateField { id: 2, length: 8, enterprise_id: None },
                // octetDeltaCount
                TemplateField { id: 1, length: 8, enterprise_id: None },
                // droppedPacketDeltaCount
                TemplateField { id: 132, length: 8, enterprise_id: None },
                // droppedOctetDeltaCount
                TemplateField { id: 133, length: 8, enterprise_id: None },
                // flowStartMilliseconds
                TemplateField { id: 152, length: 8, enterprise_id: None },
                // flowEndMilliseconds
                TemplateField { id: 153, length: 8, enterprise_id: None },
            ],
        }
    }

    /// Flow record template with 5-tuple, TCP flags, and packet/byte counts
    pub fn flow_record() -> Self {
        Self {
            id: FLOW_RECORD_TEMPLATE_ID,
            fields: vec![
                // sourceIPv4Address (IANA IE 8)
                TemplateField { id: 8, length: 4, enterprise_id: None },
                // destinationIPv4Address (IANA IE 12)
                TemplateField { id: 12, length: 4, enterprise_id: None },
                // sourceTransportPort (IANA IE 7)
                TemplateField { id: 7, length: 2, enterprise_id: None },
                // destinationTransportPort (IANA IE 11)
                TemplateField { id: 11, length: 2, enterprise_id: None },
                // protocolIdentifier (IANA IE 4)
                TemplateField { id: 4, length: 1, enterprise_id: None },
                // tcpControlBits (IANA IE 6)
                TemplateField { id: 6, length: 1, enterprise_id: None },
                // packetDeltaCount (IANA IE 2)
                TemplateField { id: 2, length: 8, enterprise_id: None },
                // octetDeltaCount (IANA IE 1)
                TemplateField { id: 1, length: 8, enterprise_id: None },
                // flowStartMilliseconds (IANA IE 152)
                TemplateField { id: 152, length: 8, enterprise_id: None },
                // flowEndMilliseconds (IANA IE 153)
                TemplateField { id: 153, length: 8, enterprise_id: None },
                // samplingInterval (IANA IE 34) - indicates sampling rate
                TemplateField { id: 34, length: 4, enterprise_id: None },
            ],
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Template Set Header
        buf.extend_from_slice(&2u16.to_be_bytes()); // Set ID = 2 (Template Set)
        let set_len_pos = buf.len();
        buf.extend_from_slice(&0u16.to_be_bytes()); // Length placeholder

        // Template Record Header
        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&(self.fields.len() as u16).to_be_bytes());

        // Template Fields
        for field in &self.fields {
            if field.enterprise_id.is_some() {
                buf.extend_from_slice(&(field.id | 0x8000).to_be_bytes());
            } else {
                buf.extend_from_slice(&field.id.to_be_bytes());
            }
            buf.extend_from_slice(&field.length.to_be_bytes());
            if let Some(eid) = field.enterprise_id {
                buf.extend_from_slice(&eid.to_be_bytes());
            }
        }

        // Padding to 4-byte boundary
        while buf.len() % 4 != 0 {
            buf.push(0);
        }

        // Update set length
        let set_len = (buf.len()) as u16;
        buf[set_len_pos..set_len_pos + 2].copy_from_slice(&set_len.to_be_bytes());

        buf
    }

    pub fn record_length(&self) -> usize {
        self.fields.iter().map(|f| f.length as usize).sum()
    }
}
