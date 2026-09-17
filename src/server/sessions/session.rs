use std::fmt;
use std::time::Instant;
use crate::protocol::frame::SessionId;

/// Represents an authenticated logical communication session.
#[derive(Clone)]
pub struct Session {
    pub session_id: SessionId,
    pub peer_id: Option<[u8; 32]>,
    pub authenticated_at: Instant,
    pub last_seen: Instant,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("session_id", &"[REDACTED]")
            .field("peer_id", &self.peer_id.map(|p| crate::transport::obfuscation::hex_encode(&p)))
            .field("authenticated_at", &self.authenticated_at)
            .field("last_seen", &self.last_seen)
            .finish()
    }
}

impl Session {
    pub fn new(session_id: SessionId, peer_id: Option<[u8; 32]>) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            peer_id,
            authenticated_at: now,
            last_seen: now,
        }
    }

    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }
}
