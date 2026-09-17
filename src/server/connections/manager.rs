use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc::Sender, RwLock};

use crate::error::RoutingError;
use crate::protocol::frame::{Frame, SessionId};
use crate::server::connections::connection::{Connection, ConnectionId};

/// Thread-safe manager for active physical connections and peer routing maps.
#[derive(Clone, Default)]
pub struct ConnectionManager {
    inner: Arc<RwLock<ConnectionManagerInner>>,
}

#[derive(Default)]
struct ConnectionManagerInner {
    connections: HashMap<ConnectionId, Connection>,
    session_to_conn: HashMap<SessionId, ConnectionId>,
    peer_to_conn: HashMap<[u8; 32], ConnectionId>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ConnectionManagerInner::default())),
        }
    }

    /// Registers a newly accepted connection and returns its assigned `ConnectionId`.
    pub async fn register(
        &self,
        peer_addr: SocketAddr,
        outbound_tx: Sender<Frame>,
    ) -> ConnectionId {
        let conn_id = ConnectionId::next();
        let conn = Connection::new(conn_id, peer_addr, outbound_tx);

        let mut inner = self.inner.write().await;
        inner.connections.insert(conn_id, conn);
        conn_id
    }

    /// Removes a connection and all associated session/peer mappings.
    pub async fn unregister(&self, conn_id: ConnectionId) {
        let mut inner = self.inner.write().await;
        inner.connections.remove(&conn_id);
        inner.session_to_conn.retain(|_, v| *v != conn_id);
        inner.peer_to_conn.retain(|_, v| *v != conn_id);
    }

    /// Binds a session and optional peer ID to an active connection.
    pub async fn bind_session(
        &self,
        conn_id: ConnectionId,
        session_id: SessionId,
        peer_id: Option<[u8; 32]>,
    ) {
        let mut inner = self.inner.write().await;
        inner.session_to_conn.insert(session_id, conn_id);
        if let Some(pid) = peer_id {
            inner.peer_to_conn.insert(pid, conn_id);
        }
    }

    /// Sends a `Frame` directly to a specific connection ID.
    pub async fn send_to_connection(
        &self,
        conn_id: ConnectionId,
        frame: Frame,
    ) -> Result<(), RoutingError> {
        let tx = {
            let inner = self.inner.read().await;
            inner
                .connections
                .get(&conn_id)
                .map(|c| c.outbound_tx.clone())
                .ok_or_else(|| RoutingError::DestinationNotFound(conn_id.to_string()))?
        };

        tx.send(frame)
            .await
            .map_err(|_| RoutingError::ChannelClosed)
    }

    /// Sends a `Frame` to a registered peer ID.
    pub async fn send_to_peer(
        &self,
        peer_id: &[u8; 32],
        frame: Frame,
    ) -> Result<(), RoutingError> {
        let conn_id = {
            let inner = self.inner.read().await;
            inner
                .peer_to_conn
                .get(peer_id)
                .copied()
                .ok_or_else(|| RoutingError::DestinationNotFound(crate::transport::obfuscation::hex_encode(peer_id)))?
        };

        self.send_to_connection(conn_id, frame).await
    }

    /// Returns the current number of active connections.
    pub async fn active_connections(&self) -> usize {
        let inner = self.inner.read().await;
        inner.connections.len()
    }
}
