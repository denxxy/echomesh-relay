use std::collections::HashMap;
use std::sync::Arc;

use crate::error::RoutingError;
use crate::protocol::envelope::{MessageEnvelope, MessageType};
use crate::protocol::messages::{ClientToServerMessage, ServerToClientMessage};
use crate::server::handlers::{
    AuthHandler, EchoHandler, HeartbeatHandler, MessageHandler, ServerInboundHandler,
};
use crate::server::services::EchoService;
use crate::server::sessions::Session;

/// Inbound router responsible solely for dispatching incoming CLIENT → SERVER messages
/// to their registered handlers based on `MessageType`.
pub struct ServerInboundRouter {
    handlers: HashMap<MessageType, Arc<dyn ServerInboundHandler>>,
}

impl Default for ServerInboundRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerInboundRouter {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Creates a pre-configured router with standard relay handlers.
    pub fn standard_relay() -> Self {
        let mut router = Self::new();
        let echo_handler = Arc::new(EchoHandler::new(EchoService::new()));

        router.register(MessageType::RawEcho, echo_handler.clone());
        router.register(MessageType::SendMessage, Arc::new(MessageHandler));
        router.register(MessageType::Heartbeat, Arc::new(HeartbeatHandler));
        router.register(MessageType::AuthRequest, Arc::new(AuthHandler));
        router.register(MessageType::ConnectRequest, Arc::new(AuthHandler));

        router
    }

    /// Registers a handler for a specific `MessageType`.
    pub fn register(
        &mut self,
        message_type: MessageType,
        handler: Arc<dyn ServerInboundHandler>,
    ) {
        self.handlers.insert(message_type, handler);
    }

    /// Dispatches a message to its registered handler.
    pub async fn dispatch(
        &self,
        envelope: &MessageEnvelope,
        message: &ClientToServerMessage,
        session: &Session,
    ) -> Result<Option<ServerToClientMessage>, RoutingError> {
        let handler = self
            .handlers
            .get(&envelope.message_type)
            .ok_or_else(|| RoutingError::UnhandledMessageType(envelope.message_type.to_u8()))?;

        handler.handle(envelope, message, session).await
    }
}
