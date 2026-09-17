use bytes::Bytes;
use crate::protocol::messages::{DeliveryStatus, PeerStatus};

/// Trait implemented by client applications to receive unsolicited server events.
pub trait ClientEventHandler: Send + Sync {
    fn on_incoming_message(&self, _sender_id: [u8; 32], _data: Bytes) {}
    fn on_delivery_status(&self, _message_id: u64, _status: DeliveryStatus) {}
    fn on_peer_event(&self, _peer_id: [u8; 32], _status: PeerStatus) {}
    fn on_relay_event(&self, _session_id: [u8; 16], _status: u8) {}
}

/// Default no-op event handler.
pub struct NoopClientEventHandler;
impl ClientEventHandler for NoopClientEventHandler {}
