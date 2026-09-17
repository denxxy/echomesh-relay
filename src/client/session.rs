use std::fmt;
use std::net::SocketAddr;

use crate::protocol::frame::SessionId;

/// Represents the client-side session context.
#[derive(Clone)]
pub struct ClientSession {
    pub session_id: SessionId,
    pub server_addr: SocketAddr,
    pub is_authenticated: bool,
}

impl fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSession")
            .field("session_id", &"[REDACTED]")
            .field("server_addr", &self.server_addr)
            .field("is_authenticated", &self.is_authenticated)
            .finish()
    }
}

use crate::config::ECHO_SERVICE_PEER_ID;

impl ClientSession {
    pub fn new(server_addr: SocketAddr) -> Self {
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&ECHO_SERVICE_PEER_ID[..16]);
        Self {
            session_id,
            server_addr,
            is_authenticated: false,
        }
    }

    pub fn with_session_id(mut self, session_id: SessionId) -> Self {
        self.session_id = session_id;
        self
    }
}
