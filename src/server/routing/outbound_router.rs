use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::RoutingError;
use crate::protocol::codec::EnvelopeCodec;
use crate::protocol::frame::{Frame, Nonce, SessionId};
use crate::protocol::messages::ServerToClientMessage;
use crate::server::connections::{ConnectionId, ConnectionManager};

/// Outbound router responsible solely for routing SERVER → CLIENT messages and events.
#[derive(Clone)]
pub struct ServerOutboundRouter {
    connection_manager: ConnectionManager,
    msg_id_counter: std::sync::Arc<AtomicU64>,
}

impl ServerOutboundRouter {
    pub fn new(connection_manager: ConnectionManager) -> Self {
        Self {
            connection_manager,
            msg_id_counter: std::sync::Arc::new(AtomicU64::new(1)),
        }
    }

    /// Prepares a `Frame` containing the encoded `ServerToClientMessage` in an envelope.
    pub fn build_frame(
        &self,
        session_id: SessionId,
        correlation_id: u64,
        message: &ServerToClientMessage,
    ) -> Result<Frame, RoutingError> {
        let msg_id = self.msg_id_counter.fetch_add(1, Ordering::Relaxed);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let encoded_bytes = EnvelopeCodec::encode_server_message(
            message,
            msg_id,
            correlation_id,
            timestamp,
        )
        .map_err(|e| RoutingError::HandlerFailed(e.to_string()))?;

        let nonce: Nonce = [0u8; 8];
        Frame::new(session_id, nonce, encoded_bytes)
            .map_err(|e| RoutingError::HandlerFailed(e.to_string()))
    }

    /// Routes a server message to a specific connection.
    pub async fn send_to_connection(
        &self,
        conn_id: ConnectionId,
        session_id: SessionId,
        correlation_id: u64,
        message: &ServerToClientMessage,
    ) -> Result<(), RoutingError> {
        let frame = self.build_frame(session_id, correlation_id, message)?;
        self.connection_manager.send_to_connection(conn_id, frame).await
    }

    /// Routes a server message or event to a registered peer.
    pub async fn send_to_peer(
        &self,
        peer_id: &[u8; 32],
        session_id: SessionId,
        correlation_id: u64,
        message: &ServerToClientMessage,
    ) -> Result<(), RoutingError> {
        let frame = self.build_frame(session_id, correlation_id, message)?;
        self.connection_manager.send_to_peer(peer_id, frame).await
    }
}
