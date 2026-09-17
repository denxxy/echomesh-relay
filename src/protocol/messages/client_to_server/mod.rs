use std::fmt;
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::ProtocolError;
use crate::protocol::envelope::MessageType;

/// Messages sent from CLIENT to SERVER.
#[derive(Clone, PartialEq, Eq)]
pub enum ClientToServerMessage {
    AuthRequest {
        token: Vec<u8>,
        client_version: u32,
    },
    ConnectRequest {
        peer_id: [u8; 32],
    },
    DisconnectRequest {
        reason_code: u32,
    },
    SendMessage {
        recipient_id: [u8; 32],
        data: Bytes,
    },
    Ack {
        acknowledged_message_id: u64,
    },
    Heartbeat {
        sequence: u64,
    },
    KeyExchange {
        ephemeral_pubkey: [u8; 32],
    },
    RelayRequest {
        target_peer_id: [u8; 32],
    },
    RawEcho {
        payload: Bytes,
    },
}

impl fmt::Debug for ClientToServerMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientToServerMessage::AuthRequest { client_version, .. } => f
                .debug_struct("AuthRequest")
                .field("token", &"[REDACTED]")
                .field("client_version", client_version)
                .finish(),
            ClientToServerMessage::ConnectRequest { peer_id } => f
                .debug_struct("ConnectRequest")
                .field("peer_id", &crate::transport::obfuscation::hex_encode(peer_id))
                .finish(),
            ClientToServerMessage::DisconnectRequest { reason_code } => f
                .debug_struct("DisconnectRequest")
                .field("reason_code", reason_code)
                .finish(),
            ClientToServerMessage::SendMessage { recipient_id, data } => f
                .debug_struct("SendMessage")
                .field("recipient_id", &crate::transport::obfuscation::hex_encode(recipient_id))
                .field("data_len", &data.len())
                .field("data", &"[REDACTED]")
                .finish(),
            ClientToServerMessage::Ack { acknowledged_message_id } => f
                .debug_struct("Ack")
                .field("acknowledged_message_id", acknowledged_message_id)
                .finish(),
            ClientToServerMessage::Heartbeat { sequence } => f
                .debug_struct("Heartbeat")
                .field("sequence", sequence)
                .finish(),
            ClientToServerMessage::KeyExchange { .. } => f
                .debug_struct("KeyExchange")
                .field("ephemeral_pubkey", &"[REDACTED]")
                .finish(),
            ClientToServerMessage::RelayRequest { target_peer_id } => f
                .debug_struct("RelayRequest")
                .field("target_peer_id", &crate::transport::obfuscation::hex_encode(target_peer_id))
                .finish(),
            ClientToServerMessage::RawEcho { payload } => f
                .debug_struct("RawEcho")
                .field("payload_len", &payload.len())
                .finish(),
        }
    }
}

impl ClientToServerMessage {
    pub fn message_type(&self) -> MessageType {
        match self {
            ClientToServerMessage::AuthRequest { .. } => MessageType::AuthRequest,
            ClientToServerMessage::ConnectRequest { .. } => MessageType::ConnectRequest,
            ClientToServerMessage::DisconnectRequest { .. } => MessageType::DisconnectRequest,
            ClientToServerMessage::SendMessage { .. } => MessageType::SendMessage,
            ClientToServerMessage::Ack { .. } => MessageType::Ack,
            ClientToServerMessage::Heartbeat { .. } => MessageType::Heartbeat,
            ClientToServerMessage::KeyExchange { .. } => MessageType::KeyExchange,
            ClientToServerMessage::RelayRequest { .. } => MessageType::RelayRequest,
            ClientToServerMessage::RawEcho { .. } => MessageType::RawEcho,
        }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        match self {
            ClientToServerMessage::AuthRequest { token, client_version } => {
                buf.put_u16(token.len() as u16);
                buf.put_slice(token);
                buf.put_u32(*client_version);
            }
            ClientToServerMessage::ConnectRequest { peer_id } => {
                buf.put_slice(peer_id);
            }
            ClientToServerMessage::DisconnectRequest { reason_code } => {
                buf.put_u32(*reason_code);
            }
            ClientToServerMessage::SendMessage { recipient_id, data } => {
                buf.put_slice(recipient_id);
                buf.put_slice(data);
            }
            ClientToServerMessage::Ack { acknowledged_message_id } => {
                buf.put_u64(*acknowledged_message_id);
            }
            ClientToServerMessage::Heartbeat { sequence } => {
                buf.put_u64(*sequence);
            }
            ClientToServerMessage::KeyExchange { ephemeral_pubkey } => {
                buf.put_slice(ephemeral_pubkey);
            }
            ClientToServerMessage::RelayRequest { target_peer_id } => {
                buf.put_slice(target_peer_id);
            }
            ClientToServerMessage::RawEcho { payload } => {
                buf.put_slice(payload);
            }
        }
        buf.freeze()
    }

    pub fn decode(msg_type: MessageType, payload: &Bytes) -> Result<Self, ProtocolError> {
        let mut slice = &payload[..];
        match msg_type {
            MessageType::AuthRequest => {
                if slice.len() < 2 {
                    return Err(ProtocolError::FrameTooShort { expected: 2, actual: slice.len() });
                }
                let token_len = slice.get_u16() as usize;
                if slice.remaining() < token_len + 4 {
                    return Err(ProtocolError::FrameTooShort {
                        expected: token_len + 4,
                        actual: slice.remaining(),
                    });
                }
                let token = slice[..token_len].to_vec();
                slice.advance(token_len);
                let client_version = slice.get_u32();
                Ok(ClientToServerMessage::AuthRequest { token, client_version })
            }
            MessageType::ConnectRequest => {
                if slice.len() < 32 {
                    return Err(ProtocolError::FrameTooShort { expected: 32, actual: slice.len() });
                }
                let mut peer_id = [0u8; 32];
                peer_id.copy_from_slice(&slice[..32]);
                Ok(ClientToServerMessage::ConnectRequest { peer_id })
            }
            MessageType::DisconnectRequest => {
                if slice.len() < 4 {
                    return Err(ProtocolError::FrameTooShort { expected: 4, actual: slice.len() });
                }
                let reason_code = slice.get_u32();
                Ok(ClientToServerMessage::DisconnectRequest { reason_code })
            }
            MessageType::SendMessage => {
                if slice.len() < 32 {
                    return Err(ProtocolError::FrameTooShort { expected: 32, actual: slice.len() });
                }
                let mut recipient_id = [0u8; 32];
                recipient_id.copy_from_slice(&slice[..32]);
                let data = Bytes::copy_from_slice(&slice[32..]);
                Ok(ClientToServerMessage::SendMessage { recipient_id, data })
            }
            MessageType::Ack => {
                if slice.len() < 8 {
                    return Err(ProtocolError::FrameTooShort { expected: 8, actual: slice.len() });
                }
                let acknowledged_message_id = slice.get_u64();
                Ok(ClientToServerMessage::Ack { acknowledged_message_id })
            }
            MessageType::Heartbeat => {
                if slice.len() < 8 {
                    return Err(ProtocolError::FrameTooShort { expected: 8, actual: slice.len() });
                }
                let sequence = slice.get_u64();
                Ok(ClientToServerMessage::Heartbeat { sequence })
            }
            MessageType::KeyExchange => {
                if slice.len() < 32 {
                    return Err(ProtocolError::FrameTooShort { expected: 32, actual: slice.len() });
                }
                let mut ephemeral_pubkey = [0u8; 32];
                ephemeral_pubkey.copy_from_slice(&slice[..32]);
                Ok(ClientToServerMessage::KeyExchange { ephemeral_pubkey })
            }
            MessageType::RelayRequest => {
                if slice.len() < 32 {
                    return Err(ProtocolError::FrameTooShort { expected: 32, actual: slice.len() });
                }
                let mut target_peer_id = [0u8; 32];
                target_peer_id.copy_from_slice(&slice[..32]);
                Ok(ClientToServerMessage::RelayRequest { target_peer_id })
            }
            MessageType::RawEcho => {
                Ok(ClientToServerMessage::RawEcho { payload: payload.clone() })
            }
            _ => Err(ProtocolError::UnexpectedDirection),
        }
    }
}
