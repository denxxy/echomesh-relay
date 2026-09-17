use std::future::Future;
use std::pin::Pin;

use crate::error::RoutingError;
use crate::protocol::envelope::MessageEnvelope;
use crate::protocol::messages::{ClientToServerMessage, ServerToClientMessage};
use crate::server::sessions::Session;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Trait implemented by server inbound message handlers.
pub trait ServerInboundHandler: Send + Sync {
    fn handle<'a>(
        &'a self,
        envelope: &'a MessageEnvelope,
        message: &'a ClientToServerMessage,
        session: &'a Session,
    ) -> BoxFuture<'a, Result<Option<ServerToClientMessage>, RoutingError>>;
}
