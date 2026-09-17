use crate::error::RoutingError;
use crate::protocol::envelope::MessageEnvelope;
use crate::protocol::messages::{ClientToServerMessage, ServerToClientMessage};
use crate::server::handlers::traits::{BoxFuture, ServerInboundHandler};
use crate::server::sessions::Session;

/// Handler for client heartbeat (keepalive ping) requests.
pub struct HeartbeatHandler;

impl ServerInboundHandler for HeartbeatHandler {
    fn handle<'a>(
        &'a self,
        _envelope: &'a MessageEnvelope,
        message: &'a ClientToServerMessage,
        _session: &'a Session,
    ) -> BoxFuture<'a, Result<Option<ServerToClientMessage>, RoutingError>> {
        Box::pin(async move {
            match message {
                ClientToServerMessage::Heartbeat { sequence } => {
                    Ok(Some(ServerToClientMessage::HeartbeatResponse { sequence: *sequence }))
                }
                _ => Err(RoutingError::UnhandledMessageType(message.message_type().to_u8())),
            }
        })
    }
}
