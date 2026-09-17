use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, warn};

use crate::config::ECHO_SERVICE_PEER_ID;
use crate::error::{EchoMeshError, RoutingError, TransportError};
use crate::protocol::codec::EnvelopeCodec;
use crate::protocol::frame::Frame;
use crate::protocol::messages::{ClientToServerMessage, ServerToClientMessage};
use crate::client::handlers::ClientEventHandler;
use crate::client::routing::{ClientInboundRouter, ClientOutboundRouter};
use crate::client::session::ClientSession;
use crate::client::state::ClientState;
use crate::transport::noise::{client_noise_handshake, NoiseFramedStream};
use crate::transport::obfuscation::PseudoTlsBuilder;

/// High-level client for communicating with an EchoMesh Relay server.
pub struct EchoMeshClient {
    session: ClientSession,
    outbound_router: ClientOutboundRouter,
    inbound_router: Arc<ClientInboundRouter>,
    shutdown_tx: watch::Sender<bool>,
    state: ClientState,
}

impl EchoMeshClient {
    /// Connects to an EchoMesh Relay server using Pseudo-TLS camouflage and Noise encryption.
    pub async fn connect(
        relay_addr: SocketAddr,
        secret_token: impl Into<Vec<u8>>,
        server_pubkey: &[u8],
    ) -> Result<Self, EchoMeshError> {
        let secret = secret_token.into();

        // 1. Establish TCP transport
        let mut stream = TcpStream::connect(relay_addr)
            .await
            .map_err(TransportError::Io)?;

        // 2. Send Pseudo-TLS 1.3 ClientHello camouflage
        let tls_builder = PseudoTlsBuilder::new(secret, "cloudflare.com");
        let client_hello = tls_builder.build();
        stream
            .write_all(&client_hello)
            .await
            .map_err(TransportError::Io)?;
        stream.flush().await.map_err(TransportError::Io)?;

        // 3. Perform Noise NK Handshake
        let noise_session = client_noise_handshake(&mut stream, server_pubkey)
            .await
            .map_err(|e| TransportError::MalformedHeader(e.to_string()))?;

        // 4. Initialize communication channels
        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Frame>(64);
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let inbound_router = Arc::new(ClientInboundRouter::new());
        let router_for_task = Arc::clone(&inbound_router);

        let mut framed = NoiseFramedStream::new(stream, noise_session);

        // 5. Spawn background client I/O actor
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    recv_res = framed.recv_frame() => {
                        match recv_res {
                            Ok(Some(frame)) => {
                                // Try decoding envelope
                                if let Ok((envelope, server_msg)) = EnvelopeCodec::decode_server_message(&frame.payload) {
                                    if let Err(e) = router_for_task.dispatch(&envelope, server_msg).await {
                                        warn!("client inbound dispatch error: {:?}", e);
                                    }
                                } else {
                                    // Raw echo response compatibility
                                    let synthetic_msg = ServerToClientMessage::RawEchoResponse { payload: frame.payload.clone() };
                                    let synthetic_env = crate::protocol::envelope::MessageEnvelope::new(
                                        synthetic_msg.message_type(),
                                        0,
                                        0,
                                        0,
                                        frame.payload.clone(),
                                    ).unwrap();
                                    let _ = router_for_task.dispatch(&synthetic_env, synthetic_msg).await;
                                }
                            }
                            Ok(None) => {
                                debug!("server closed stream cleanly");
                                break;
                            }
                            Err(e) => {
                                warn!("error reading frame from server: {:?}", e);
                                break;
                            }
                        }
                    }
                    Some(outbound_frame) = outbound_rx.recv() => {
                        if let Err(e) = framed.send_frame(&outbound_frame).await {
                            warn!("failed to send outbound frame to server: {:?}", e);
                            break;
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
            debug!("client network background task finished");
        });

        let mut session = ClientSession::new(relay_addr);
        session.is_authenticated = true;

        Ok(Self {
            session,
            outbound_router: ClientOutboundRouter::new(outbound_tx),
            inbound_router,
            shutdown_tx,
            state: ClientState::Connected,
        })
    }

    /// Sends an application message and waits for the correlated server response with a timeout.
    pub async fn send_message(
        &self,
        recipient_id: [u8; 32],
        data: Bytes,
        timeout: Duration,
    ) -> Result<ServerToClientMessage, EchoMeshError> {
        let msg = ClientToServerMessage::SendMessage {
            recipient_id,
            data,
        };

        let msg_id = self.outbound_router.send_message(self.session.session_id, &msg).await?;
        let response_rx = self.inbound_router.register_pending(msg_id).await;

        tokio::time::timeout(timeout, response_rx)
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| RoutingError::ChannelClosed.into())
    }

    /// Sends a ping keepalive request to the server and awaits heartbeat response.
    pub async fn ping(&self, timeout: Duration) -> Result<u64, EchoMeshError> {
        let sequence = 42u64;
        let msg = ClientToServerMessage::Heartbeat { sequence };

        let msg_id = self.outbound_router.send_message(self.session.session_id, &msg).await?;
        let response_rx = self.inbound_router.register_pending(msg_id).await;

        let resp = tokio::time::timeout(timeout, response_rx)
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| RoutingError::ChannelClosed)?;

        match resp {
            ServerToClientMessage::HeartbeatResponse { sequence: seq } => Ok(seq),
            other => Err(RoutingError::HandlerFailed(format!("unexpected response: {:?}", other)).into()),
        }
    }

    /// Sends an echo payload to the internal echo loopback service.
    pub async fn send_echo(&self, payload: Bytes) -> Result<(), EchoMeshError> {
        let mut echo_session_id = [0u8; 16];
        echo_session_id.copy_from_slice(&ECHO_SERVICE_PEER_ID[..16]);
        let msg = ClientToServerMessage::RawEcho { payload };
        self.outbound_router.send_message(echo_session_id, &msg).await?;
        Ok(())
    }

    /// Registers a handler for unsolicited server events.
    pub async fn add_event_handler(&self, handler: Arc<dyn ClientEventHandler>) {
        self.inbound_router.add_event_handler(handler).await;
    }

    /// Closes the client connection gracefully.
    pub fn disconnect(&mut self) -> Result<(), EchoMeshError> {
        self.state = ClientState::Closed;
        let _ = self.shutdown_tx.send(true);
        Ok(())
    }

    pub fn state(&self) -> ClientState {
        self.state
    }

    pub fn session(&self) -> &ClientSession {
        &self.session
    }
}
