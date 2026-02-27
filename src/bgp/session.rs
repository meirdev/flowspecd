use deku::prelude::*;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::attributes::PathAttribute;
use super::{ErrorCode, Header, MessageType, Notification, Open, Safi, Update, BGP_HEADER_LEN};

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(#[from] DekuError),
}

pub type Result<T> = std::result::Result<T, SessionError>;

/// Received BGP message
#[derive(Debug)]
pub enum Message {
    Open(Open),
    Update(Update),
    Notification(Notification),
    Keepalive,
}

#[derive(Debug)]
pub struct Session {
    stream: TcpStream,
    pub my_as: u16,
    pub bgp_id: u32,
    pub hold_time: u16,
}

impl Session {
    pub fn new(stream: TcpStream, my_as: u16, bgp_id: u32, hold_time: u16) -> Self {
        Self {
            stream,
            my_as,
            bgp_id,
            hold_time,
        }
    }

    pub async fn send_open(&mut self) -> Result<()> {
        let open = Open::with_flowspec(self.my_as, self.hold_time, self.bgp_id);
        let body = open.to_bytes()?;
        let header = Header::new(MessageType::Open, body.len() as u16);

        eprintln!(
            "DEBUG: Sending OPEN - AS:{} BGP-ID:{:08X} Hold:{}",
            self.my_as, self.bgp_id, self.hold_time
        );
        let header_bytes = header.to_bytes()?;
        eprintln!(
            "DEBUG: Header ({} bytes): {:02X?}",
            header_bytes.len(),
            header_bytes
        );
        eprintln!("DEBUG: OPEN body ({} bytes): {:02X?}", body.len(), body);

        self.stream.write_all(&header_bytes).await?;
        self.stream.write_all(&body).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn send_keepalive(&mut self) -> Result<()> {
        let header = Header::new(MessageType::Keepalive, 0);
        self.stream.write_all(&header.to_bytes()?).await?;
        Ok(())
    }

    /// Send NOTIFICATION message
    pub async fn send_notification(
        &mut self,
        error_code: ErrorCode,
        error_subcode: u8,
        data: Vec<u8>,
    ) -> Result<()> {
        let notification = Notification::with_data(error_code, error_subcode, data);
        let body = notification.to_bytes()?;
        let header = Header::new(MessageType::Notification, body.len() as u16);

        eprintln!(
            "DEBUG: Sending NOTIFICATION: {:?} subcode {}",
            error_code, error_subcode
        );
        self.stream.write_all(&header.to_bytes()?).await?;
        self.stream.write_all(&body).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Send UPDATE message with raw body bytes
    pub async fn send_update(&mut self, body: Vec<u8>) -> Result<()> {
        let header = Header::new(MessageType::Update, body.len() as u16);
        let header_bytes = header.to_bytes()?;

        eprintln!("DEBUG: Sending UPDATE ({} bytes body)", body.len());
        eprintln!(
            "DEBUG: Header ({} bytes): {:02X?}",
            header_bytes.len(),
            header_bytes
        );
        eprintln!("DEBUG: Body: {:02X?}", body);

        self.stream.write_all(&header_bytes).await?;
        self.stream.write_all(&body).await?;
        self.stream.flush().await?;
        eprintln!("DEBUG: UPDATE sent successfully");
        Ok(())
    }

    async fn read_header(&mut self) -> Result<Header> {
        let mut buf = [0u8; BGP_HEADER_LEN];
        self.stream.read_exact(&mut buf).await?;
        let (_, header) = Header::from_bytes((&buf, 0))?;
        eprintln!(
            "DEBUG: Read header - type:{:?} length:{}",
            header.message_type, header.length
        );
        Ok(header)
    }

    async fn read_open(&mut self, body_len: usize) -> Result<Open> {
        let mut buf = vec![0u8; body_len];
        self.stream.read_exact(&mut buf).await?;
        eprintln!(
            "DEBUG: Received OPEN body ({} bytes): {:02X?}",
            body_len, buf
        );
        let (_, open) = Open::from_bytes((&buf, 0))?;
        eprintln!(
            "DEBUG: Parsed OPEN - AS:{} BGP-ID:{:08X} Hold:{}",
            open.my_as, open.bgp_id, open.hold_time
        );
        Ok(open)
    }

    /// Read any BGP message
    pub async fn read_message(&mut self) -> Result<Message> {
        let header = self.read_header().await?;
        let body_len = header.length as usize - BGP_HEADER_LEN;

        match header.message_type {
            MessageType::Open => {
                let open = self.read_open(body_len).await?;
                Ok(Message::Open(open))
            }
            MessageType::Update => {
                let mut buf = vec![0u8; body_len];
                self.stream.read_exact(&mut buf).await?;
                let (_, update) = Update::from_bytes((&buf, 0))?;
                Ok(Message::Update(update))
            }
            MessageType::Notification => {
                let mut buf = vec![0u8; body_len];
                self.stream.read_exact(&mut buf).await?;
                let (_, notification) = Notification::from_bytes((&buf, 0))?;
                Ok(Message::Notification(notification))
            }
            MessageType::Keepalive => Ok(Message::Keepalive),
        }
    }
}

/// Extract FlowSpec NLRIs from UPDATE path attributes (announcements)
pub fn extract_flowspec(attrs: &[PathAttribute]) -> Vec<super::flowspec::FlowSpecNlri> {
    let mut nlris = Vec::new();

    for attr in attrs {
        if let PathAttribute::MpReachNlri(mp) = attr {
            if mp.safi == Safi::FlowSpec || mp.safi == Safi::FlowSpecVpn {
                if let Ok(parsed) = mp.parse_flowspec() {
                    nlris.extend(parsed);
                }
            }
        }
    }

    nlris
}

/// Extract withdrawn FlowSpec NLRIs from UPDATE path attributes
pub fn extract_flowspec_withdrawals(attrs: &[PathAttribute]) -> Vec<super::flowspec::FlowSpecNlri> {
    let mut nlris = Vec::new();

    for attr in attrs {
        if let PathAttribute::MpUnreachNlri(mp) = attr {
            if mp.safi == Safi::FlowSpec || mp.safi == Safi::FlowSpecVpn {
                if let Ok(parsed) = mp.parse_flowspec() {
                    nlris.extend(parsed);
                }
            }
        }
    }

    nlris
}
