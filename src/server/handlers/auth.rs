use crate::error::RoutingError;
use crate::protocol::envelope::MessageEnvelope;
use crate::protocol::messages::{ClientToServerMessage, ServerToClientMessage};
use crate::server::handlers::traits::{BoxFuture, ServerInboundHandler};
use crate::server::sessions::Session;

/// Handler for client authentication and connection requests.
pub struct AuthHandler;

impl ServerInboundHandler for AuthHandler {
    fn handle<'a>(
        &'a self,
        _envelope: &'a MessageEnvelope,
        message: &'a ClientToServerMessage,
        session: &'a Session,
    ) -> BoxFuture<'a, Result<Option<ServerToClientMessage>, RoutingError>> {
        Box::pin(async move {
            match message {
                ClientToServerMessage::AuthRequest { .. } => {
                    Ok(Some(ServerToClientMessage::AuthResponse {
                        success: true,
                        session_id: session.session_id,
                    }))
                }
                ClientToServerMessage::ConnectRequest { peer_id } => {
                    Ok(Some(ServerToClientMessage::ConnectionAccepted {
                        session_id: session.session_id,
                        assigned_peer_id: *peer_id,
                    }))
                }
                _ => Err(RoutingError::UnhandledMessageType(message.message_type().to_u8())),
            }
        })
    }
}
