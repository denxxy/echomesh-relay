use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tracing::{debug, warn};

use crate::config::ECHO_SERVICE_PEER_ID;
use crate::error::EchoMeshError;
use crate::protocol::codec::EnvelopeCodec;
use crate::protocol::envelope::MessageEnvelope;
use crate::protocol::frame::{constant_time_eq, Frame};
use crate::protocol::messages::client_to_server::ClientToServerMessage;
use crate::protocol::messages::server_to_client::ServerToClientMessage;
use crate::server::connections::{ConnectionId, ConnectionManager};
use crate::server::routing::{ServerInboundRouter, ServerOutboundRouter};
use crate::server::sessions::{Session, SessionManager};

/// Coordinates the complete SERVER Inbound & Outbound processing pipeline.
pub struct ServerPipeline {
    conn_id: ConnectionId,
    session: Session,
    outbound_tx: Sender<Frame>,
    inbound_router: Arc<ServerInboundRouter>,
    outbound_router: ServerOutboundRouter,
    _connection_manager: ConnectionManager,
    session_manager: SessionManager,
}

impl ServerPipeline {
    pub fn new(
        conn_id: ConnectionId,
        session: Session,
        outbound_tx: Sender<Frame>,
        inbound_router: Arc<ServerInboundRouter>,
        outbound_router: ServerOutboundRouter,
        connection_manager: ConnectionManager,
        session_manager: SessionManager,
    ) -> Self {
        Self {
            conn_id,
            session,
            outbound_tx,
            inbound_router,
            outbound_router,
            _connection_manager: connection_manager,
            session_manager,
        }
    }

    /// Processes a single incoming `Frame` from the network.
    pub async fn process_frame(&mut self, frame: Frame) -> Result<(), EchoMeshError> {
        let is_echo_service = constant_time_eq(&frame.session_id, &ECHO_SERVICE_PEER_ID[..16]);
        let is_current_session = constant_time_eq(&frame.session_id, &self.session.session_id);

        if !is_echo_service && !is_current_session {
            // Architecture Invariant 2: "Drop packets with unknown session IDs silently
            // without returning error payloads (prevents active scanning/probing)."
            debug!("dropping frame with unknown or mismatching session_id");
            return Ok(());
        }

        // Refresh session timestamp
        self.session_manager.touch_session(&self.session.session_id).await;

        // Try decoding as structured MessageEnvelope first
        if let Ok((envelope, client_msg)) = EnvelopeCodec::decode_client_message(&frame.payload) {
            debug!(
                msg_type = ?envelope.message_type,
                msg_id = envelope.message_id,
                "dispatching structured message through inbound router"
            );

            match self.inbound_router.dispatch(&envelope, &client_msg, &self.session).await {
                Ok(Some(response_msg)) => {
                    let response_frame = self.outbound_router.build_frame(
                        self.session.session_id,
                        envelope.message_id,
                        &response_msg,
                    )?;
                    let _ = self.outbound_tx.send(response_frame).await;
                }
                Ok(None) => {}
                Err(err) => {
                    warn!("handler returned error: {:?}", err);
                    let err_response = ServerToClientMessage::ErrorResponse {
                        code: 500,
                        message: "internal processing error".to_string(),
                    };
                    let err_frame = self.outbound_router.build_frame(
                        self.session.session_id,
                        envelope.message_id,
                        &err_response,
                    )?;
                    let _ = self.outbound_tx.send(err_frame).await;
                }
            }
        } else if is_echo_service {
            // Legacy / raw byte payload sent directly to Echo Service (e.g. in test suites)
            debug!(
                payload_len = frame.payload.len(),
                "dispatching raw echo frame to echo service"
            );

            let raw_msg = ClientToServerMessage::RawEcho {
                payload: frame.payload.clone(),
            };

            // Synthetic envelope for raw echo
            let synthetic_envelope = MessageEnvelope::new(
                raw_msg.message_type(),
                0,
                0,
                0,
                frame.payload.clone(),
            )?;

            if let Ok(Some(ServerToClientMessage::RawEchoResponse { payload })) =
                self.inbound_router
                    .dispatch(&synthetic_envelope, &raw_msg, &self.session)
                    .await
            {
                let reply_frame = Frame::new(frame.session_id, frame.nonce, payload)?;
                let _ = self.outbound_tx.send(reply_frame).await;
            }
        } else {
            debug!("dropping unparseable frame payload for non-echo session");
        }

        Ok(())
    }

    pub fn conn_id(&self) -> ConnectionId {
        self.conn_id
    }

    pub fn session(&self) -> &Session {
        &self.session
    }
}
