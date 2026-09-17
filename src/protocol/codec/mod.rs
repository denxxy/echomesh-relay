use bytes::Bytes;

use crate::error::ProtocolError;
use crate::protocol::envelope::MessageEnvelope;
use crate::protocol::messages::{ClientToServerMessage, ServerToClientMessage};

/// Codec for encoding and decoding protocol envelopes and typed messages.
pub struct EnvelopeCodec;

impl EnvelopeCodec {
    /// Encapsulates a `ClientToServerMessage` into a `MessageEnvelope` and encodes to `Bytes`.
    pub fn encode_client_message(
        msg: &ClientToServerMessage,
        message_id: u64,
        correlation_id: u64,
        timestamp: u64,
    ) -> Result<Bytes, ProtocolError> {
        let payload = msg.encode();
        let envelope = MessageEnvelope::new(
            msg.message_type(),
            message_id,
            correlation_id,
            timestamp,
            payload,
        )?;
        envelope.to_bytes()
    }

    /// Decodes raw bytes into a `MessageEnvelope` and extracts the inner `ClientToServerMessage`.
    pub fn decode_client_message(
        bytes: &[u8],
    ) -> Result<(MessageEnvelope, ClientToServerMessage), ProtocolError> {
        let envelope = MessageEnvelope::decode(bytes)?;
        let msg = ClientToServerMessage::decode(envelope.message_type, &envelope.payload)?;
        Ok((envelope, msg))
    }

    /// Encapsulates a `ServerToClientMessage` into a `MessageEnvelope` and encodes to `Bytes`.
    pub fn encode_server_message(
        msg: &ServerToClientMessage,
        message_id: u64,
        correlation_id: u64,
        timestamp: u64,
    ) -> Result<Bytes, ProtocolError> {
        let payload = msg.encode();
        let envelope = MessageEnvelope::new(
            msg.message_type(),
            message_id,
            correlation_id,
            timestamp,
            payload,
        )?;
        envelope.to_bytes()
    }

    /// Decodes raw bytes into a `MessageEnvelope` and extracts the inner `ServerToClientMessage`.
    pub fn decode_server_message(
        bytes: &[u8],
    ) -> Result<(MessageEnvelope, ServerToClientMessage), ProtocolError> {
        let envelope = MessageEnvelope::decode(bytes)?;
        let msg = ServerToClientMessage::decode(envelope.message_type, &envelope.payload)?;
        Ok((envelope, msg))
    }

    /// Helper for wrapping a typed message into an envelope.
    pub fn wrap_client_message(
        msg: &ClientToServerMessage,
        message_id: u64,
        correlation_id: u64,
        timestamp: u64,
    ) -> Result<MessageEnvelope, ProtocolError> {
        let payload = msg.encode();
        MessageEnvelope::new(
            msg.message_type(),
            message_id,
            correlation_id,
            timestamp,
            payload,
        )
    }

    /// Helper for wrapping a server response or event into an envelope.
    pub fn wrap_server_message(
        msg: &ServerToClientMessage,
        message_id: u64,
        correlation_id: u64,
        timestamp: u64,
    ) -> Result<MessageEnvelope, ProtocolError> {
        let payload = msg.encode();
        MessageEnvelope::new(
            msg.message_type(),
            message_id,
            correlation_id,
            timestamp,
            payload,
        )
    }
}
