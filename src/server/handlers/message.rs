use crate::error::RoutingError;
use crate::protocol::envelope::MessageEnvelope;
use crate::protocol::messages::{ClientToServerMessage, ServerToClientMessage};
use crate::server::handlers::traits::{BoxFuture, ServerInboundHandler};
use crate::server::sessions::Session;

/// Handler for application message sending and relaying.
pub struct MessageHandler;

impl ServerInboundHandler for MessageHandler {
    fn handle<'a>(
        &'a self,
        envelope: &'a MessageEnvelope,
        message: &'a ClientToServerMessage,
        _session: &'a Session,
    ) -> BoxFuture<'a, Result<Option<ServerToClientMessage>, RoutingError>> {
        Box::pin(async move {
            match message {
                ClientToServerMessage::SendMessage { .. } => {
                    Ok(Some(ServerToClientMessage::SendMessageResponse {
                        message_id: envelope.message_id,
                        accepted: true,
                    }))
                }
                _ => Err(RoutingError::UnhandledMessageType(message.message_type().to_u8())),
            }
        })
    }
}
