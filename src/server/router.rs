use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, RwLock};

use crate::protocol::frame::{Frame, SessionId};

pub type RouteId = SessionId;

pub const ROUTER_CONTROL_ID: RouteId = [0xEC; 16];
pub const ROUTE_REGISTER_MAGIC: &[u8; 4] = b"EMR2";
pub const ROUTE_REGISTERED_MAGIC: &[u8; 4] = b"EMA2";
pub const ROUTE_REGISTRATION_CONTEXT: &[u8] = b"EchoMesh route registration v2";
const ROUTE_REGISTRATION_LEN: usize = 4 + 16 + 32 + 64;

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

#[derive(Clone, Default)]
pub struct RelayRouter {
    routes: Arc<RwLock<HashMap<RouteId, RouteEntry>>>,
    next_connection_id: Arc<AtomicU64>,
}

impl RelayRouter {
    pub fn new() -> Self { Self::default() }

    pub async fn register(&self, route_id: RouteId, tx: mpsc::Sender<Frame>) -> u64 {
        let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed) + 1;
        self.routes.write().await.insert(route_id, RouteEntry { connection_id, tx });
        connection_id
    }

    pub async fn unregister(&self, route_id: RouteId, connection_id: u64) {
        let mut routes = self.routes.write().await;
        let should_remove = routes.get(&route_id)
            .map(|entry| entry.connection_id == connection_id)
            .unwrap_or(false);
        if should_remove { routes.remove(&route_id); }
    }

    pub async fn route(&self, sender: RouteId, mut frame: Frame) -> RouteResult {
        let recipient = frame.session_id;
        let tx = {
            let routes = self.routes.read().await;
            routes.get(&recipient).map(|entry| entry.tx.clone())
        };
        let Some(tx) = tx else { return RouteResult::RecipientOffline; };
        frame.session_id = sender;
        match tx.try_send(frame) {
            Ok(()) => RouteResult::Delivered,
            Err(mpsc::error::TrySendError::Full(_)) => RouteResult::Backpressure,
            Err(mpsc::error::TrySendError::Closed(_)) => RouteResult::RecipientOffline,
        }
    }

    pub async fn active_routes(&self) -> usize { self.routes.read().await.len() }
}

pub fn registration_ack_frame(route_id: RouteId) -> Frame {
    let mut payload = Vec::with_capacity(20);
    payload.extend_from_slice(ROUTE_REGISTERED_MAGIC);
    payload.extend_from_slice(&route_id);
    Frame::new(ROUTER_CONTROL_ID, [0u8; 8], Bytes::from(payload))
        .expect("registration ack frame always fits")
}

/// Validates proof-of-possession for the Ed25519 identity that owns a route.
/// A token-authenticated relay client cannot claim another peer's route without
/// that peer's signing key.
pub fn parse_registration(frame: &Frame) -> Option<RouteId> {
    if frame.session_id != ROUTER_CONTROL_ID
        || frame.payload.len() != ROUTE_REGISTRATION_LEN
        || &frame.payload[..4] != ROUTE_REGISTER_MAGIC
    {
        return None;
    }

    let mut route_id = [0u8; 16];
    route_id.copy_from_slice(&frame.payload[4..20]);
    let mut peer_id = [0u8; 32];
    peer_id.copy_from_slice(&frame.payload[20..52]);

    let digest = Sha256::digest(peer_id);
    if digest[..16] != route_id {
        return None;
    }

    let verifying_key = VerifyingKey::from_bytes(&peer_id).ok()?;
    let signature = Signature::from_slice(&frame.payload[52..116]).ok()?;
    let mut signed = Vec::with_capacity(ROUTE_REGISTRATION_CONTEXT.len() + 48);
    signed.extend_from_slice(ROUTE_REGISTRATION_CONTEXT);
    signed.extend_from_slice(&route_id);
    signed.extend_from_slice(&peer_id);
    verifying_key.verify(&signed, &signature).ok()?;
    Some(route_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_registration(seed: [u8; 32]) -> Frame {
        let signing = SigningKey::from_bytes(&seed);
        let peer_id = signing.verifying_key().to_bytes();
        let digest = Sha256::digest(peer_id);
        let mut route = [0u8; 16];
        route.copy_from_slice(&digest[..16]);
        let mut signed = Vec::new();
        signed.extend_from_slice(ROUTE_REGISTRATION_CONTEXT);
        signed.extend_from_slice(&route);
        signed.extend_from_slice(&peer_id);
        let signature = signing.sign(&signed);
        let mut payload = Vec::new();
        payload.extend_from_slice(ROUTE_REGISTER_MAGIC);
        payload.extend_from_slice(&route);
        payload.extend_from_slice(&peer_id);
        payload.extend_from_slice(&signature.to_bytes());
        Frame::new(ROUTER_CONTROL_ID, [0u8; 8], Bytes::from(payload)).unwrap()
    }

    #[test]
    fn signed_registration_round_trip() {
        let frame = signed_registration([0x42; 32]);
        assert!(parse_registration(&frame).is_some());
    }

    #[test]
    fn forged_route_registration_is_rejected() {
        let mut frame = signed_registration([0x42; 32]);
        let mut payload = frame.payload.to_vec();
        payload[4] ^= 1;
        frame.payload = Bytes::from(payload);
        assert_eq!(parse_registration(&frame), None);
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