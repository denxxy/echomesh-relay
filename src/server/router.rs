use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{mpsc, RwLock};

use crate::protocol::frame::{Frame, SessionId};

pub type RouteId = SessionId;

/// Reserved outer-frame route used for relay control messages.
pub const ROUTER_CONTROL_ID: RouteId = [0xEC; 16];
/// Client -> relay route registration payload prefix.
pub const ROUTE_REGISTER_MAGIC: &[u8; 4] = b"EMR1";
/// Relay -> client route registration acknowledgement payload prefix.
pub const ROUTE_REGISTERED_MAGIC: &[u8; 4] = b"EMA1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteResult {
    Delivered,
    RecipientOffline,
    Backpressure,
}

#[derive(Clone)]
struct RouteEntry {
    connection_id: u64,
    tx: mpsc::Sender<Frame>,
}

/// Concurrent in-memory routing table for active client connections.
///
/// The relay stores only opaque 16-byte route identifiers. Full peer public
/// keys and end-to-end plaintext never need to be registered here.
#[derive(Clone, Default)]
pub struct RelayRouter {
    routes: Arc<RwLock<HashMap<RouteId, RouteEntry>>>,
    next_connection_id: Arc<AtomicU64>,
}

impl RelayRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers (or atomically replaces) an active route.
    /// Returns a connection generation used to avoid stale disconnects removing
    /// a newer connection that reused the same route id.
    pub async fn register(&self, route_id: RouteId, tx: mpsc::Sender<Frame>) -> u64 {
        let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed) + 1;
        self.routes.write().await.insert(
            route_id,
            RouteEntry {
                connection_id,
                tx,
            },
        );
        connection_id
    }

    pub async fn unregister(&self, route_id: RouteId, connection_id: u64) {
        let mut routes = self.routes.write().await;
        let should_remove = routes
            .get(&route_id)
            .map(|entry| entry.connection_id == connection_id)
            .unwrap_or(false);
        if should_remove {
            routes.remove(&route_id);
        }
    }

    /// Routes one already-authenticated frame to an active recipient.
    ///
    /// Before delivery the outer route field is rewritten to the sender route,
    /// so the recipient never has to trust client-supplied sender metadata.
    pub async fn route(&self, sender: RouteId, mut frame: Frame) -> RouteResult {
        let recipient = frame.session_id;
        let tx = {
            let routes = self.routes.read().await;
            routes.get(&recipient).map(|entry| entry.tx.clone())
        };

        let Some(tx) = tx else {
            return RouteResult::RecipientOffline;
        };

        frame.session_id = sender;
        match tx.try_send(frame) {
            Ok(()) => RouteResult::Delivered,
            Err(mpsc::error::TrySendError::Full(_)) => RouteResult::Backpressure,
            Err(mpsc::error::TrySendError::Closed(_)) => RouteResult::RecipientOffline,
        }
    }

    pub async fn active_routes(&self) -> usize {
        self.routes.read().await.len()
    }
}

pub fn registration_frame(route_id: RouteId) -> Frame {
    let mut payload = Vec::with_capacity(ROUTE_REGISTER_MAGIC.len() + route_id.len());
    payload.extend_from_slice(ROUTE_REGISTER_MAGIC);
    payload.extend_from_slice(&route_id);
    Frame::new(ROUTER_CONTROL_ID, [0u8; 8], Bytes::from(payload))
        .expect("registration control frame always fits")
}

pub fn registration_ack_frame(route_id: RouteId) -> Frame {
    let mut payload = Vec::with_capacity(ROUTE_REGISTERED_MAGIC.len() + route_id.len());
    payload.extend_from_slice(ROUTE_REGISTERED_MAGIC);
    payload.extend_from_slice(&route_id);
    Frame::new(ROUTER_CONTROL_ID, [0u8; 8], Bytes::from(payload))
        .expect("registration ack frame always fits")
}

pub fn parse_registration(frame: &Frame) -> Option<RouteId> {
    if frame.session_id != ROUTER_CONTROL_ID
        || frame.payload.len() != ROUTE_REGISTER_MAGIC.len() + 16
        || &frame.payload[..ROUTE_REGISTER_MAGIC.len()] != ROUTE_REGISTER_MAGIC
    {
        return None;
    }

    let mut route_id = [0u8; 16];
    route_id.copy_from_slice(&frame.payload[ROUTE_REGISTER_MAGIC.len()..]);
    Some(route_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_round_trip() {
        let route = [0x42; 16];
        let frame = registration_frame(route);
        assert_eq!(parse_registration(&frame), Some(route));
    }

    #[tokio::test]
    async fn route_rewrites_destination_to_sender() {
        let router = RelayRouter::new();
        let sender = [0x11; 16];
        let recipient = [0x22; 16];
        let (tx, mut rx) = mpsc::channel(1);
        router.register(recipient, tx).await;

        let frame = Frame::new(recipient, [7u8; 8], Bytes::from_static(b"ciphertext")).unwrap();
        assert_eq!(router.route(sender, frame).await, RouteResult::Delivered);

        let delivered = rx.recv().await.unwrap();
        assert_eq!(delivered.session_id, sender);
        assert_eq!(&delivered.payload[..], b"ciphertext");
    }

    #[tokio::test]
    async fn stale_unregister_does_not_remove_replacement() {
        let router = RelayRouter::new();
        let route = [0x44; 16];
        let (tx1, _rx1) = mpsc::channel(1);
        let (tx2, _rx2) = mpsc::channel(1);
        let id1 = router.register(route, tx1).await;
        let _id2 = router.register(route, tx2).await;
        router.unregister(route, id1).await;
        assert_eq!(router.active_routes().await, 1);
    }
}
