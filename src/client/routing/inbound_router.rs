use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tracing::debug;

use crate::error::RoutingError;
use crate::protocol::envelope::MessageEnvelope;
use crate::protocol::messages::ServerToClientMessage;
use crate::client::handlers::ClientEventHandler;

/// Client Inbound Router.
///
/// Responsibilities:
/// 1. Correlates Server Responses to waiting Request Futures via `correlation_id`.
/// 2. Dispatches unsolicited Server Events to registered `ClientEventHandler`s.
pub struct ClientInboundRouter {
    pending_requests: Arc<Mutex<HashMap<u64, oneshot::Sender<ServerToClientMessage>>>>,
    event_handlers: Arc<Mutex<Vec<Arc<dyn ClientEventHandler>>>>,
}

impl Default for ClientInboundRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientInboundRouter {
    pub fn new() -> Self {
        Self {
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            event_handlers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Registers a pending request with a given `message_id` expecting a correlated response.
    pub async fn register_pending(&self, message_id: u64) -> oneshot::Receiver<ServerToClientMessage> {
        let (tx, rx) = oneshot::channel();
        let mut map = self.pending_requests.lock().await;
        map.insert(message_id, tx);
        rx
    }

    /// Adds an event handler for push notifications.
    pub async fn add_event_handler(&self, handler: Arc<dyn ClientEventHandler>) {
        let mut handlers = self.event_handlers.lock().await;
        handlers.push(handler);
    }

    /// Dispatches an incoming SERVER → CLIENT message.
    pub async fn dispatch(
        &self,
        envelope: &MessageEnvelope,
        message: ServerToClientMessage,
    ) -> Result<(), RoutingError> {
        if message.is_response() && envelope.correlation_id != 0 {
            // Wake waiting request
            let sender = {
                let mut map = self.pending_requests.lock().await;
                map.remove(&envelope.correlation_id)
            };

            if let Some(tx) = sender {
                let _ = tx.send(message);
                debug!(correlation_id = envelope.correlation_id, "correlated server response to pending request");
                return Ok(());
            } else {
                debug!(correlation_id = envelope.correlation_id, "response received for unknown or expired correlation ID");
            }
        }

        // Handle events
        match message {
            ServerToClientMessage::IncomingMessageEvent { sender_id, data } => {
                let handlers = self.event_handlers.lock().await;
                for h in handlers.iter() {
                    h.on_incoming_message(sender_id, data.clone());
                }
            }
            ServerToClientMessage::DeliveryStatusEvent { message_id, status } => {
                let handlers = self.event_handlers.lock().await;
                for h in handlers.iter() {
                    h.on_delivery_status(message_id, status);
                }
            }
            ServerToClientMessage::PeerEvent { peer_id, status } => {
                let handlers = self.event_handlers.lock().await;
                for h in handlers.iter() {
                    h.on_peer_event(peer_id, status);
                }
            }
            ServerToClientMessage::RelayEvent { session_id, status } => {
                let handlers = self.event_handlers.lock().await;
                for h in handlers.iter() {
                    h.on_relay_event(session_id, status);
                }
            }
            _ => {}
        }

        Ok(())
    }
}
