use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::protocol::frame::SessionId;
use crate::server::sessions::session::Session;

/// Thread-safe manager for active authenticated sessions.
#[derive(Clone, Default)]
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<SessionId, Session>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Inserts or updates an authenticated session.
    pub async fn create_session(&self, session_id: SessionId, peer_id: Option<[u8; 32]>) -> Session {
        let session = Session::new(session_id, peer_id);
        let mut map = self.sessions.write().await;
        map.insert(session_id, session.clone());
        session
    }

    /// Looks up a session by ID and updates its last_seen timestamp.
    pub async fn touch_session(&self, session_id: &SessionId) -> Option<Session> {
        let mut map = self.sessions.write().await;
        if let Some(session) = map.get_mut(session_id) {
            session.touch();
            Some(session.clone())
        } else {
            None
        }
    }

    /// Removes a session when disconnected or terminated.
    pub async fn remove_session(&self, session_id: &SessionId) -> Option<Session> {
        let mut map = self.sessions.write().await;
        map.remove(session_id)
    }

    /// Returns the number of currently active sessions.
    pub async fn count(&self) -> usize {
        let map = self.sessions.read().await;
        map.len()
    }
}
