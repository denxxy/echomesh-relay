use std::fmt;
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::ProtocolError;
use crate::protocol::envelope::MessageType;

/// Delivery status codes for DeliveryStatusEvent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryStatus {
    Delivered = 1,
    Dropped = 2,
    Queued = 3,
    Failed = 4,
}

impl DeliveryStatus {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => DeliveryStatus::Delivered,
            2 => DeliveryStatus::Dropped,
            3 => DeliveryStatus::Queued,
            _ => DeliveryStatus::Failed,
        }
    }
}

/// Peer status codes for PeerEvent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerStatus {
    Online = 1,
    Offline = 2,
    RelayActive = 3,
}

impl PeerStatus {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => PeerStatus::Online,
            3 => PeerStatus::RelayActive,
            _ => PeerStatus::Offline,
        }
    }
}

/// Messages sent from SERVER to CLIENT.
///
/// Strictly separated into Responses (correlated to a client request)
/// and Events (unsolicited asynchronous push notifications).
#[derive(Clone, PartialEq, Eq)]
pub enum ServerToClientMessage {
    // --- Responses (Correlated) ---
    AuthResponse {
        success: bool,
        session_id: [u8; 16],
    },
    ConnectionAccepted {
        session_id: [u8; 16],
        assigned_peer_id: [u8; 32],
    },
    ConnectionRejected {
        reason_code: u32,
        message: String,
    },
    HeartbeatResponse {
        sequence: u64,
    },
    ErrorResponse {
        code: u32,
        message: String,
    },
    SendMessageResponse {
        message_id: u64,
        accepted: bool,
    },
    RawEchoResponse {
        payload: Bytes,
    },

    // --- Events (Unsolicited) ---
    IncomingMessageEvent {
        sender_id: [u8; 32],
        data: Bytes,
    },
    DeliveryStatusEvent {
        message_id: u64,
        status: DeliveryStatus,
    },
    PeerEvent {
        peer_id: [u8; 32],
        status: PeerStatus,
    },
    RelayEvent {
        session_id: [u8; 16],
        status: u8,
    },
}

impl fmt::Debug for ServerToClientMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerToClientMessage::AuthResponse { success, .. } => f
                .debug_struct("AuthResponse")
                .field("success", success)
                .field("session_id", &"[REDACTED]")
                .finish(),
            ServerToClientMessage::ConnectionAccepted { .. } => f
                .debug_struct("ConnectionAccepted")
                .field("session_id", &"[REDACTED]")
                .field("assigned_peer_id", &"[REDACTED]")
                .finish(),
            ServerToClientMessage::ConnectionRejected { reason_code, message } => f
                .debug_struct("ConnectionRejected")
                .field("reason_code", reason_code)
                .field("message", message)
                .finish(),
            ServerToClientMessage::HeartbeatResponse { sequence } => f
                .debug_struct("HeartbeatResponse")
                .field("sequence", sequence)
                .finish(),
            ServerToClientMessage::ErrorResponse { code, message } => f
                .debug_struct("ErrorResponse")
                .field("code", code)
                .field("message", message)
                .finish(),
            ServerToClientMessage::SendMessageResponse { message_id, accepted } => f
                .debug_struct("SendMessageResponse")
                .field("message_id", message_id)
                .field("accepted", accepted)
                .finish(),
            ServerToClientMessage::RawEchoResponse { payload } => f
                .debug_struct("RawEchoResponse")
                .field("payload_len", &payload.len())
                .finish(),
            ServerToClientMessage::IncomingMessageEvent { sender_id, data } => f
                .debug_struct("IncomingMessageEvent")
                .field("sender_id", &crate::transport::obfuscation::hex_encode(sender_id))
                .field("data_len", &data.len())
                .field("data", &"[REDACTED]")
                .finish(),
            ServerToClientMessage::DeliveryStatusEvent { message_id, status } => f
                .debug_struct("DeliveryStatusEvent")
                .field("message_id", message_id)
                .field("status", status)
                .finish(),
            ServerToClientMessage::PeerEvent { peer_id, status } => f
                .debug_struct("PeerEvent")
                .field("peer_id", &crate::transport::obfuscation::hex_encode(peer_id))
                .field("status", status)
                .finish(),
            ServerToClientMessage::RelayEvent { status, .. } => f
                .debug_struct("RelayEvent")
                .field("session_id", &"[REDACTED]")
                .field("status", status)
                .finish(),
        }
    }
}

impl ServerToClientMessage {
    pub fn message_type(&self) -> MessageType {
        match self {
            ServerToClientMessage::AuthResponse { .. } => MessageType::AuthResponse,
            ServerToClientMessage::ConnectionAccepted { .. } => MessageType::ConnectionAccepted,
            ServerToClientMessage::ConnectionRejected { .. } => MessageType::ConnectionRejected,
            ServerToClientMessage::HeartbeatResponse { .. } => MessageType::HeartbeatResponse,
            ServerToClientMessage::ErrorResponse { .. } => MessageType::ErrorResponse,
            ServerToClientMessage::SendMessageResponse { .. } => MessageType::SendMessageResponse,
            ServerToClientMessage::RawEchoResponse { .. } => MessageType::RawEchoResponse,
            ServerToClientMessage::IncomingMessageEvent { .. } => MessageType::IncomingMessageEvent,
            ServerToClientMessage::DeliveryStatusEvent { .. } => MessageType::DeliveryStatusEvent,
            ServerToClientMessage::PeerEvent { .. } => MessageType::PeerEvent,
            ServerToClientMessage::RelayEvent { .. } => MessageType::RelayEvent,
        }
    }

    pub fn is_response(&self) -> bool {
        self.message_type().is_response()
    }

    pub fn is_event(&self) -> bool {
        self.message_type().is_event()
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        match self {
            ServerToClientMessage::AuthResponse { success, session_id } => {
                buf.put_u8(if *success { 1 } else { 0 });
                buf.put_slice(session_id);
            }
            ServerToClientMessage::ConnectionAccepted { session_id, assigned_peer_id } => {
                buf.put_slice(session_id);
                buf.put_slice(assigned_peer_id);
            }
            ServerToClientMessage::ConnectionRejected { reason_code, message } => {
                buf.put_u32(*reason_code);
                let msg_bytes = message.as_bytes();
                buf.put_u16(msg_bytes.len() as u16);
                buf.put_slice(msg_bytes);
            }
            ServerToClientMessage::HeartbeatResponse { sequence } => {
                buf.put_u64(*sequence);
            }
            ServerToClientMessage::ErrorResponse { code, message } => {
                buf.put_u32(*code);
                let msg_bytes = message.as_bytes();
                buf.put_u16(msg_bytes.len() as u16);
                buf.put_slice(msg_bytes);
            }
            ServerToClientMessage::SendMessageResponse { message_id, accepted } => {
                buf.put_u64(*message_id);
                buf.put_u8(if *accepted { 1 } else { 0 });
            }
            ServerToClientMessage::RawEchoResponse { payload } => {
                buf.put_slice(payload);
            }
            ServerToClientMessage::IncomingMessageEvent { sender_id, data } => {
                buf.put_slice(sender_id);
                buf.put_slice(data);
            }
            ServerToClientMessage::DeliveryStatusEvent { message_id, status } => {
                buf.put_u64(*message_id);
                buf.put_u8(*status as u8);
            }
            ServerToClientMessage::PeerEvent { peer_id, status } => {
                buf.put_slice(peer_id);
                buf.put_u8(*status as u8);
            }
            ServerToClientMessage::RelayEvent { session_id, status } => {
                buf.put_slice(session_id);
                buf.put_u8(*status);
            }
        }
        buf.freeze()
    }

    pub fn decode(msg_type: MessageType, payload: &Bytes) -> Result<Self, ProtocolError> {
        let mut slice = &payload[..];
        match msg_type {
            MessageType::AuthResponse => {
                if slice.len() < 17 {
                    return Err(ProtocolError::FrameTooShort { expected: 17, actual: slice.len() });
                }
                let success = slice.get_u8() != 0;
                let mut session_id = [0u8; 16];
                session_id.copy_from_slice(&slice[..16]);
                Ok(ServerToClientMessage::AuthResponse { success, session_id })
            }
            MessageType::ConnectionAccepted => {
                if slice.len() < 48 {
                    return Err(ProtocolError::FrameTooShort { expected: 48, actual: slice.len() });
                }
                let mut session_id = [0u8; 16];
                session_id.copy_from_slice(&slice[..16]);
                let mut assigned_peer_id = [0u8; 32];
                assigned_peer_id.copy_from_slice(&slice[16..48]);
                Ok(ServerToClientMessage::ConnectionAccepted { session_id, assigned_peer_id })
            }
            MessageType::ConnectionRejected => {
                if slice.len() < 6 {
                    return Err(ProtocolError::FrameTooShort { expected: 6, actual: slice.len() });
                }
                let reason_code = slice.get_u32();
                let msg_len = slice.get_u16() as usize;
                if slice.remaining() < msg_len {
                    return Err(ProtocolError::FrameTooShort { expected: msg_len, actual: slice.remaining() });
                }
                let message = String::from_utf8_lossy(&slice[..msg_len]).to_string();
                Ok(ServerToClientMessage::ConnectionRejected { reason_code, message })
            }
            MessageType::HeartbeatResponse => {
                if slice.len() < 8 {
                    return Err(ProtocolError::FrameTooShort { expected: 8, actual: slice.len() });
                }
                let sequence = slice.get_u64();
                Ok(ServerToClientMessage::HeartbeatResponse { sequence })
            }
            MessageType::ErrorResponse => {
                if slice.len() < 6 {
                    return Err(ProtocolError::FrameTooShort { expected: 6, actual: slice.len() });
                }
                let code = slice.get_u32();
                let msg_len = slice.get_u16() as usize;
                if slice.remaining() < msg_len {
                    return Err(ProtocolError::FrameTooShort { expected: msg_len, actual: slice.remaining() });
                }
                let message = String::from_utf8_lossy(&slice[..msg_len]).to_string();
                Ok(ServerToClientMessage::ErrorResponse { code, message })
            }
            MessageType::SendMessageResponse => {
                if slice.len() < 9 {
                    return Err(ProtocolError::FrameTooShort { expected: 9, actual: slice.len() });
                }
                let message_id = slice.get_u64();
                let accepted = slice.get_u8() != 0;
                Ok(ServerToClientMessage::SendMessageResponse { message_id, accepted })
            }
            MessageType::RawEchoResponse => {
                Ok(ServerToClientMessage::RawEchoResponse { payload: payload.clone() })
            }
            MessageType::IncomingMessageEvent => {
                if slice.len() < 32 {
                    return Err(ProtocolError::FrameTooShort { expected: 32, actual: slice.len() });
                }
                let mut sender_id = [0u8; 32];
                sender_id.copy_from_slice(&slice[..32]);
                let data = Bytes::copy_from_slice(&slice[32..]);
                Ok(ServerToClientMessage::IncomingMessageEvent { sender_id, data })
            }
            MessageType::DeliveryStatusEvent => {
                if slice.len() < 9 {
                    return Err(ProtocolError::FrameTooShort { expected: 9, actual: slice.len() });
                }
                let message_id = slice.get_u64();
                let status = DeliveryStatus::from_u8(slice.get_u8());
                Ok(ServerToClientMessage::DeliveryStatusEvent { message_id, status })
            }
            MessageType::PeerEvent => {
                if slice.len() < 33 {
                    return Err(ProtocolError::FrameTooShort { expected: 33, actual: slice.len() });
                }
                let mut peer_id = [0u8; 32];
                peer_id.copy_from_slice(&slice[..32]);
                let status = PeerStatus::from_u8(slice[32]);
                Ok(ServerToClientMessage::PeerEvent { peer_id, status })
            }
            MessageType::RelayEvent => {
                if slice.len() < 17 {
                    return Err(ProtocolError::FrameTooShort { expected: 17, actual: slice.len() });
                }
                let mut session_id = [0u8; 16];
                session_id.copy_from_slice(&slice[..16]);
                let status = slice[16];
                Ok(ServerToClientMessage::RelayEvent { session_id, status })
            }
            _ => Err(ProtocolError::UnexpectedDirection),
        }
    }
}
