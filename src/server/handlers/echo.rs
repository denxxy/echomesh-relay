use crate::error::RoutingError;
use crate::protocol::envelope::MessageEnvelope;
use crate::protocol::messages::{ClientToServerMessage, ServerToClientMessage};
use crate::server::handlers::traits::{BoxFuture, ServerInboundHandler};
use crate::server::services::EchoService;
use crate::server::sessions::Session;

/// Handler for echo service requests.
pub struct EchoHandler {
    service: EchoService,
}

impl EchoHandler {
    pub fn new(service: EchoService) -> Self {
        Self { service }
    }
}

impl ServerInboundHandler for EchoHandler {
    fn handle<'a>(
        &'a self,
        _envelope: &'a MessageEnvelope,
        message: &'a ClientToServerMessage,
        _session: &'a Session,
    ) -> BoxFuture<'a, Result<Option<ServerToClientMessage>, RoutingError>> {
        Box::pin(async move {
            match message {
                ClientToServerMessage::RawEcho { payload } => {
                    let echoed = self.service.process_echo(payload.clone());
                    Ok(Some(ServerToClientMessage::RawEchoResponse { payload: echoed }))
                }
                ClientToServerMessage::SendMessage { data, .. } => {
                    let echoed = self.service.process_echo(data.clone());
                    Ok(Some(ServerToClientMessage::RawEchoResponse { payload: echoed }))
                }
                _ => Err(RoutingError::UnhandledMessageType(message.message_type().to_u8())),
            }
        })
    }
}
