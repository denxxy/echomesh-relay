use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

use crate::error::RoutingError;
use crate::protocol::codec::EnvelopeCodec;
use crate::protocol::frame::{Frame, Nonce, SessionId};
use crate::protocol::messages::ClientToServerMessage;

/// Client Outbound Router.
///
/// Responsibilities:
/// 1. Assigns unique incrementing `message_id` to outbound client requests.
/// 2. Serializes and frames `ClientToServerMessage` into 1420-byte `Frame`s.
/// 3. Queues frames into the client's outbound write channel.
#[derive(Clone)]
pub struct ClientOutboundRouter {
    outbound_tx: Sender<Frame>,
    counter: Arc<AtomicU64>,
}

impl ClientOutboundRouter {
    pub fn new(outbound_tx: Sender<Frame>) -> Self {
        Self {
            outbound_tx,
            counter: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Next available unique message ID.
    pub fn next_message_id(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Prepares and queues an outbound message. Returns the assigned `message_id`.
    pub async fn send_message(
        &self,
        session_id: SessionId,
        message: &ClientToServerMessage,
    ) -> Result<u64, RoutingError> {
        let msg_id = self.next_message_id();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let encoded_bytes = EnvelopeCodec::encode_client_message(
            message,
            msg_id,
            0,
            timestamp,
        )
        .map_err(|e| RoutingError::HandlerFailed(e.to_string()))?;

        let nonce: Nonce = [0u8; 8];
        let frame = Frame::new(session_id, nonce, encoded_bytes)
            .map_err(|e| RoutingError::HandlerFailed(e.to_string()))?;

        self.outbound_tx
            .send(frame)
            .await
            .map_err(|_| RoutingError::ChannelClosed)?;

        Ok(msg_id)
    }

    /// Sends a raw frame directly (e.g. for echo compatibility).
    pub async fn send_frame(&self, frame: Frame) -> Result<(), RoutingError> {
        self.outbound_tx
            .send(frame)
            .await
            .map_err(|_| RoutingError::ChannelClosed)
    }
}
