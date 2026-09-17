use std::fmt;
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::ProtocolError;
use crate::protocol::versioning::ProtocolVersion;

/// Header size of `MessageEnvelope` in bytes:
/// version (1) + type (1) + flags (2) + message_id (8) + correlation_id (8) + timestamp (8) + payload_len (2) = 30 bytes.
pub const ENVELOPE_HEADER_SIZE: usize = 30;

/// Maximum payload size that can fit inside an envelope within a single 1420-byte Frame:
/// 1394 (MAX_PAYLOAD_SIZE) - 30 (ENVELOPE_HEADER_SIZE) = 1364 bytes.
pub const MAX_ENVELOPE_PAYLOAD_SIZE: usize = crate::protocol::frame::MAX_PAYLOAD_SIZE - ENVELOPE_HEADER_SIZE;

/// Protocol Message Type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    // --- Client to Server (0x01..0x3F) ---
    AuthRequest = 0x01,
    ConnectRequest = 0x02,
    DisconnectRequest = 0x03,
    SendMessage = 0x04,
    Ack = 0x05,
    Heartbeat = 0x06,
    KeyExchange = 0x07,
    RelayRequest = 0x08,
    RawEcho = 0x0F,

    // --- Server to Client: Responses (0x80..0x8F) ---
    AuthResponse = 0x81,
    ConnectionAccepted = 0x82,
    ConnectionRejected = 0x83,
    HeartbeatResponse = 0x84,
    ErrorResponse = 0x85,
    SendMessageResponse = 0x86,
    RawEchoResponse = 0x8F,

    // --- Server to Client: Events (0x90..0x9F) ---
    IncomingMessageEvent = 0x90,
    DeliveryStatusEvent = 0x91,
    PeerEvent = 0x92,
    RelayEvent = 0x93,
}

impl MessageType {
    pub fn from_u8(val: u8) -> Result<Self, ProtocolError> {
        match val {
            0x01 => Ok(MessageType::AuthRequest),
            0x02 => Ok(MessageType::ConnectRequest),
            0x03 => Ok(MessageType::DisconnectRequest),
            0x04 => Ok(MessageType::SendMessage),
            0x05 => Ok(MessageType::Ack),
            0x06 => Ok(MessageType::Heartbeat),
            0x07 => Ok(MessageType::KeyExchange),
            0x08 => Ok(MessageType::RelayRequest),
            0x0F => Ok(MessageType::RawEcho),

            0x81 => Ok(MessageType::AuthResponse),
            0x82 => Ok(MessageType::ConnectionAccepted),
            0x83 => Ok(MessageType::ConnectionRejected),
            0x84 => Ok(MessageType::HeartbeatResponse),
            0x85 => Ok(MessageType::ErrorResponse),
            0x86 => Ok(MessageType::SendMessageResponse),
            0x8F => Ok(MessageType::RawEchoResponse),

            0x90 => Ok(MessageType::IncomingMessageEvent),
            0x91 => Ok(MessageType::DeliveryStatusEvent),
            0x92 => Ok(MessageType::PeerEvent),
            0x93 => Ok(MessageType::RelayEvent),

            unknown => Err(ProtocolError::UnknownMessageType(unknown)),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn is_client_to_server(&self) -> bool {
        (self.to_u8() & 0x80) == 0
    }

    pub fn is_server_to_client(&self) -> bool {
        (self.to_u8() & 0x80) != 0
    }

    pub fn is_response(&self) -> bool {
        let v = self.to_u8();
        (0x80..=0x8F).contains(&v)
    }

    pub fn is_event(&self) -> bool {
        let v = self.to_u8();
        (0x90..=0x9F).contains(&v)
    }
}

/// A standard protocol envelope wrapping all application and control messages.
#[derive(Clone, PartialEq, Eq)]
pub struct MessageEnvelope {
    pub version: ProtocolVersion,
    pub message_type: MessageType,
    pub flags: u16,
    pub message_id: u64,
    pub correlation_id: u64,
    pub timestamp: u64,
    pub payload: Bytes,
}

impl fmt::Debug for MessageEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact payload content to prevent secret leakage in logs
        f.debug_struct("MessageEnvelope")
            .field("version", &self.version)
            .field("message_type", &self.message_type)
            .field("flags", &self.flags)
            .field("message_id", &self.message_id)
            .field("correlation_id", &self.correlation_id)
            .field("timestamp", &self.timestamp)
            .field("payload_len", &self.payload.len())
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

impl MessageEnvelope {
    /// Creates a new `MessageEnvelope` validating payload length limits.
    pub fn new(
        message_type: MessageType,
        message_id: u64,
        correlation_id: u64,
        timestamp: u64,
        payload: impl Into<Bytes>,
    ) -> Result<Self, ProtocolError> {
        let payload = payload.into();
        if payload.len() > MAX_ENVELOPE_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload.len(),
                max: MAX_ENVELOPE_PAYLOAD_SIZE,
            });
        }

        Ok(Self {
            version: ProtocolVersion::CURRENT,
            message_type,
            flags: 0,
            message_id,
            correlation_id,
            timestamp,
            payload,
        })
    }

    /// Sets envelope flags.
    pub fn with_flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    /// Encodes the envelope into a byte buffer.
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        if self.payload.len() > MAX_ENVELOPE_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                actual: self.payload.len(),
                max: MAX_ENVELOPE_PAYLOAD_SIZE,
            });
        }

        let total_size = ENVELOPE_HEADER_SIZE + self.payload.len();
        dst.reserve(total_size);

        dst.put_u8(self.version.to_u8());
        dst.put_u8(self.message_type.to_u8());
        dst.put_u16(self.flags);
        dst.put_u64(self.message_id);
        dst.put_u64(self.correlation_id);
        dst.put_u64(self.timestamp);
        dst.put_u16(self.payload.len() as u16);
        dst.put_slice(&self.payload);

        Ok(())
    }

    /// Encodes the envelope and returns a `Bytes` object.
    pub fn to_bytes(&self) -> Result<Bytes, ProtocolError> {
        let mut buf = BytesMut::with_capacity(ENVELOPE_HEADER_SIZE + self.payload.len());
        self.encode(&mut buf)?;
        Ok(buf.freeze())
    }

    /// Decodes a `MessageEnvelope` from a byte slice.
    pub fn decode(slice: &[u8]) -> Result<Self, ProtocolError> {
        if slice.len() < ENVELOPE_HEADER_SIZE {
            return Err(ProtocolError::FrameTooShort {
                expected: ENVELOPE_HEADER_SIZE,
                actual: slice.len(),
            });
        }

        let mut buf = slice;
        let version_raw = buf.get_u8();
        let version = ProtocolVersion::from_u8(version_raw)?;

        let type_raw = buf.get_u8();
        let message_type = MessageType::from_u8(type_raw)?;

        let flags = buf.get_u16();
        let message_id = buf.get_u64();
        let correlation_id = buf.get_u64();
        let timestamp = buf.get_u64();
        let payload_len = buf.get_u16() as usize;

        if payload_len > MAX_ENVELOPE_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload_len,
                max: MAX_ENVELOPE_PAYLOAD_SIZE,
            });
        }

        if buf.remaining() < payload_len {
            return Err(ProtocolError::FrameTooShort {
                expected: payload_len,
                actual: buf.remaining(),
            });
        }

        let payload = Bytes::copy_from_slice(&buf[..payload_len]);

        Ok(Self {
            version,
            message_type,
            flags,
            message_id,
            correlation_id,
            timestamp,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_roundtrip() {
        let payload = Bytes::from_static(b"Hello Structured Protocol!");
        let envelope = MessageEnvelope::new(
            MessageType::SendMessage,
            42,
            0,
            1710000000,
            payload.clone(),
        )
        .expect("valid envelope");

        let encoded = envelope.to_bytes().expect("encode ok");
        assert_eq!(encoded.len(), ENVELOPE_HEADER_SIZE + payload.len());

        let decoded = MessageEnvelope::decode(&encoded).expect("decode ok");
        assert_eq!(decoded.version, ProtocolVersion::V1);
        assert_eq!(decoded.message_type, MessageType::SendMessage);
        assert_eq!(decoded.message_id, 42);
        assert_eq!(decoded.correlation_id, 0);
        assert_eq!(decoded.timestamp, 1710000000);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_envelope_oversized_payload() {
        let oversized = Bytes::from(vec![0xAA; MAX_ENVELOPE_PAYLOAD_SIZE + 1]);
        let err = MessageEnvelope::new(MessageType::SendMessage, 1, 0, 0, oversized).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::PayloadTooLarge {
                actual: MAX_ENVELOPE_PAYLOAD_SIZE + 1,
                max: MAX_ENVELOPE_PAYLOAD_SIZE,
            }
        );
    }

    #[test]
    fn test_envelope_redaction() {
        let secret = Bytes::from_static(b"SUPER_SECRET_PAYLOAD");
        let envelope = MessageEnvelope::new(MessageType::AuthRequest, 1, 0, 0, secret).unwrap();
        let debug_str = format!("{:?}", envelope);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("SUPER_SECRET_PAYLOAD"));
    }
}
