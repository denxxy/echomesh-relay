use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::mpsc::Sender;

use crate::protocol::frame::Frame;

/// Unique identifier for a physical network connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(pub u64);

impl ConnectionId {
    pub fn next() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "conn#{}", self.0)
    }
}

/// Represents an active physical connection channel.
pub struct Connection {
    pub id: ConnectionId,
    pub peer_addr: SocketAddr,
    pub connected_at: Instant,
    pub outbound_tx: Sender<Frame>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("id", &self.id)
            .field("peer_addr", &self.peer_addr)
            .field("connected_at", &self.connected_at)
            .finish()
    }
}

impl Connection {
    pub fn new(id: ConnectionId, peer_addr: SocketAddr, outbound_tx: Sender<Frame>) -> Self {
        Self {
            id,
            peer_addr,
            connected_at: Instant::now(),
            outbound_tx,
        }
    }
}
