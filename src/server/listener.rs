use std::io::Cursor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tracing::{debug, info, warn};

use crate::config::ECHO_SERVICE_PEER_ID;
use crate::server::connections::ConnectionManager;
use crate::server::networking::ServerPipeline;
use crate::server::routing::{ServerInboundRouter, ServerOutboundRouter};
use crate::server::sessions::SessionManager;
use crate::transport::noise::{server_noise_handshake, NoiseFramedStream};
use crate::transport::obfuscation::{
    hex_encode, parse_client_hello, ClientHelloStatus, TokenValidator,
    MAX_CLIENT_HELLO_SIZE,
};

pub use crate::config::ECHO_PEER_ID;
pub use crate::config::ECHO_SERVICE_PEER_ID as ECHO_SERVICE_PEER_ID_CONST;

pub use crate::server::config::{ListenerConfig, RelaySecrets};

/// An asynchronous stream adapter that yields a prefixed buffer of bytes
/// before delegating reads directly to the underlying stream.
pub struct PrefixedStream<S> {
    prefix: Cursor<Vec<u8>>,
    stream: S,
}

impl<S> PrefixedStream<S> {
    /// Creates a new `PrefixedStream`.
    pub fn new(prefix: Vec<u8>, stream: S) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            stream,
        }
    }

    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pos = self.prefix.position() as usize;
        let prefix_bytes = self.prefix.get_ref();
        if pos < prefix_bytes.len() {
            let to_read = (prefix_bytes.len() - pos).min(buf.remaining());
            buf.put_slice(&prefix_bytes[pos..pos + to_read]);
            self.prefix.set_position((pos + to_read) as u64);
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}



/// The core DPI-resistant TCP network listener for EchoMesh Relay.
pub struct RelayListener {
    listener: TcpListener,
    semaphore: Arc<Semaphore>,
    config: Arc<ListenerConfig>,
    validator: TokenValidator,
    connection_manager: ConnectionManager,
    session_manager: SessionManager,
    inbound_router: Arc<ServerInboundRouter>,
}

impl RelayListener {
    /// Binds to the configured socket address and initializes the concurrency limiter.
    pub async fn bind(config: ListenerConfig) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(config.bind_addr).await?;
        let semaphore = Arc::new(Semaphore::new(config.max_connections));
        let mut validator = TokenValidator::new(config.secret_token.clone());
        if config.insecure_no_token {
            validator = validator.with_insecure_no_token(true);
        }

        let connection_manager = ConnectionManager::new();
        let session_manager = SessionManager::new();
        let inbound_router = Arc::new(ServerInboundRouter::standard_relay());

        info!(
            max_connections = config.max_connections,
            insecure_no_token = config.insecure_no_token,
            "echomesh TCP listener bound successfully"
        );

        Ok(Self {
            listener,
            semaphore,
            config: Arc::new(config),
            validator,
            connection_manager,
            session_manager,
            inbound_router,
        })
    }

    /// Returns a reference to the active ConnectionManager.
    pub fn connection_manager(&self) -> &ConnectionManager {
        &self.connection_manager
    }

    /// Returns a reference to the active SessionManager.
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    /// Returns a reference to the registered ServerInboundRouter.
    pub fn inbound_router(&self) -> &Arc<ServerInboundRouter> {
        &self.inbound_router
    }

    /// Returns the local socket address this listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }

    /// Returns the current number of active concurrent connections.
    pub fn active_connections(&self) -> usize {
        self.config.max_connections - self.semaphore.available_permits()
    }

    /// Returns the active cryptographic secrets and client connection credentials.
    pub fn secrets(&self) -> &RelaySecrets {
        &self.config.secrets
    }

    /// Returns the pre-shared secret token for obfuscation authentication.
    pub fn secret_token(&self) -> &[u8] {
        &self.config.secrets.secret_token
    }

    /// Returns the hex-encoded public key for client configuration.
    pub fn public_key_hex(&self) -> &str {
        &self.config.secrets.public_key_hex
    }

    /// Returns the Base64-encoded public key for client configuration.
    pub fn public_key_base64(&self) -> &str {
        &self.config.secrets.public_key_base64
    }


    /// Returns the active listener configuration.
    pub fn config(&self) -> &ListenerConfig {
        &self.config
    }

    /// Runs the listener accept loop until an unrecoverable error occurs.
    pub async fn run(&self) -> Result<(), std::io::Error> {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        self.run_with_shutdown(shutdown_rx).await
    }

    /// Runs the listener accept loop with graceful shutdown support.
    pub async fn run_with_shutdown(
        &self,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<(), std::io::Error> {
        loop {
            // Accept connection from TCP socket
            let (stream, peer_addr) = tokio::select! {
                accept_res = self.listener.accept() => {
                    match accept_res {
                        Ok(conn) => conn,
                        Err(err) => {
                            warn!("failed to accept incoming socket connection: {:?}", err);
                            continue;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        debug!("listener shutting down gracefully");
                        break;
                    }
                    continue;
                }
            };

            // Acquire semaphore permit with backpressure
            let permit = match self.semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tokio::select! {
                        p_res = self.semaphore.clone().acquire_owned() => {
                            match p_res {
                                Ok(p) => p,
                                Err(_) => break, // Semaphore closed
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                            continue;
                        }
                    }
                }
            };

            let config = Arc::clone(&self.config);
            let validator = self.validator.clone();
            let connection_manager = self.connection_manager.clone();
            let session_manager = self.session_manager.clone();
            let inbound_router = Arc::clone(&self.inbound_router);

            // Spawn lightweight task for each connection
            tokio::spawn(async move {
                let _permit = permit; // Owned permit is held for lifecycle of connection
                handle_connection(
                    stream,
                    config,
                    validator,
                    peer_addr,
                    connection_manager,
                    session_manager,
                    inbound_router,
                )
                .await;
            });
        }

        Ok(())
    }
}

/// Handles a single incoming TCP connection.
///
/// Dispatches authenticated EchoMesh clients to internal Noise protocol,
/// and silently fall-through proxies unauthenticated clients, curl probes,
/// or active DPI scanners to the configured legitimate website.
async fn handle_connection(
    mut client_stream: TcpStream,
    config: Arc<ListenerConfig>,
    validator: TokenValidator,
    peer_addr: SocketAddr,
    connection_manager: ConnectionManager,
    session_manager: SessionManager,
    inbound_router: Arc<ServerInboundRouter>,
) {
    debug!(%peer_addr, "accepted new TCP connection");

    let mut initial_buf = Vec::new();
    let mut temp = [0u8; 1024];

    // Read initial data chunk with timeout
    let read_result =
        tokio::time::timeout(config.handshake_timeout, client_stream.read(&mut temp)).await;

    let _n = match read_result {
        Ok(Ok(n)) if n > 0 => {
            initial_buf.extend_from_slice(&temp[..n]);
            n
        }
        Ok(Ok(_)) => {
            debug!(%peer_addr, "incoming connection closed by peer before sending data");
            return;
        }
        Ok(Err(err)) => {
            warn!(%peer_addr, ?err, "I/O error reading initial data from incoming connection");
            return;
        }
        Err(_) => {
            warn!(%peer_addr, "Handshake timed out waiting for relay response");
            return;
        }
    };

    let hex_prefix = hex_encode(&initial_buf[..initial_buf.len().min(16)]);
    info!(
        %peer_addr,
        bytes_len = initial_buf.len(),
        hex_prefix = %hex_prefix,
        "Received initial frame: bytes.len()={}, hex_prefix={}",
        initial_buf.len(),
        hex_prefix
    );

    // Check if initial packet is TLS Handshake (Pseudo-TLS) or direct Noise handshake
    if initial_buf[0] == crate::transport::obfuscation::TLS_HANDSHAKE_CONTENT_TYPE {
        debug!("detected TLS record header (0x16), parsing ClientHello");
        let mut consumed_len = 0;
        let validate_client = |parsed: &crate::transport::obfuscation::ParsedClientHello| -> bool {
            let dev_mode = validator.is_insecure_no_token()
                || std::env::var("ECHOMESH_INSECURE_NO_AUTH")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
            let is_valid = if dev_mode {
                tracing::warn!("DEV MODE: Reality token check bypassed");
                true
            } else {
                validator.validate(parsed)
            };
            if !is_valid {
                tracing::warn!(
                    "Auth failed from {}. SNI: {:?}. Routing to fallback.",
                    peer_addr, parsed.sni
                );
            }
            is_valid
        };

        let is_authenticated = match parse_client_hello(&initial_buf) {
            ClientHelloStatus::Complete(parsed) => {
                if initial_buf.len() >= 5 {
                    let rec_len = u16::from_be_bytes([initial_buf[3], initial_buf[4]]) as usize;
                    consumed_len = 5 + rec_len;
                }
                let valid = validate_client(&parsed);
                debug!(
                    %peer_addr,
                    is_valid = valid,
                    sni = ?parsed.sni,
                    is_tls13 = parsed.is_tls13,
                    "ClientHello parsed"
                );
                valid
            }
            ClientHelloStatus::NeedMoreData {
                expected_record_len,
            } => {
                debug!(%peer_addr, expected_record_len, "ClientHello needs more data from stream");
                let needed = expected_record_len
                    .saturating_sub(initial_buf.len())
                    .min(MAX_CLIENT_HELLO_SIZE);
                if needed > 0 {
                    let mut rest = vec![0u8; needed];
                    if let Ok(Ok(_)) = tokio::time::timeout(
                        config.handshake_timeout,
                        client_stream.read_exact(&mut rest),
                    )
                    .await
                    {
                        initial_buf.extend_from_slice(&rest);
                        if let ClientHelloStatus::Complete(parsed) = parse_client_hello(&initial_buf) {
                            if initial_buf.len() >= 5 {
                                let rec_len =
                                    u16::from_be_bytes([initial_buf[3], initial_buf[4]]) as usize;
                                consumed_len = 5 + rec_len;
                            }
                            let valid = validate_client(&parsed);
                            debug!(%peer_addr, is_valid = valid, "ClientHello parsed after reading full record");
                            valid
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            ClientHelloStatus::Invalid(err) => {
                debug!(%peer_addr, ?err, "ClientHello parsing marked invalid");
                false
            }
        };

        if is_authenticated {
            debug!(%peer_addr, "client authenticated via pseudo-tls handshake; switching to noise protocol");
            let leftover = if initial_buf.len() > consumed_len {
                initial_buf[consumed_len..].to_vec()
            } else {
                Vec::new()
            };
            let mut stream = PrefixedStream::new(leftover, client_stream);
            if let Err(err) = handle_authenticated_noise_session(
                &mut stream,
                &config.secrets.private_key,
                peer_addr,
                connection_manager,
                session_manager,
                inbound_router,
            )
            .await
            {
                warn!("Handshake rejected from {}: {:?}", peer_addr, err);
            }
        } else {
            warn!("[DPI-Filter] Invalid auth header from {}, fallback triggered", peer_addr.ip());
            debug!(%peer_addr, "unauthenticated TLS client or active scanner detected; proxying to fallback target");
            fall_through_proxy(client_stream, &config.fallback_target, &initial_buf).await;
        }
    } else {
        // Not a TLS record (e.g. direct Noise handshake or HTTP probe)
        let msg_len = if initial_buf.len() >= 2 {
            u16::from_be_bytes([initial_buf[0], initial_buf[1]]) as usize
        } else {
            0
        };

        // Direct Noise handshake: 2-byte big-endian message length (NK message 1 is 48 bytes)
        if (32..=128).contains(&msg_len) {
            debug!(%peer_addr, msg_len, "detected direct Noise handshake message, initiating session");
            let mut stream = PrefixedStream::new(initial_buf, client_stream);
            if let Err(err) = handle_authenticated_noise_session(
                &mut stream,
                &config.secrets.private_key,
                peer_addr,
                connection_manager,
                session_manager,
                inbound_router,
            )
            .await
            {
                warn!("Handshake rejected from {}: {:?}", peer_addr, err);
            }
        } else {
            warn!("[DPI-Filter] Invalid auth header from {}, fallback triggered", peer_addr.ip());
            debug!(%peer_addr, "unrecognized packet format or HTTP probe; proxying to fallback target");
            fall_through_proxy(client_stream, &config.fallback_target, &initial_buf).await;
        }
    }
}

/// Fall-through proxy connecting to the disguise target and transparently bridging streams.
async fn fall_through_proxy(
    mut client_stream: TcpStream,
    fallback_target: &str,
    initial_buf: &[u8],
) {
    if fallback_target.trim().is_empty() {
        return;
    }

    // Connect with bounded timeout to prevent descriptor exhaustion on dead targets
    let upstream_res = tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(fallback_target),
    )
    .await;

    let mut upstream = match upstream_res {
        Ok(Ok(s)) => s,
        _ => {
            debug!("failed to connect to fallback target");
            return;
        }
    };

    // Forward the initial bytes already read from the client
    if !initial_buf.is_empty() {
        if upstream.write_all(initial_buf).await.is_err() {
            return;
        }
        let _ = upstream.flush().await;
    }

    // Bidirectionally copy traffic between client and upstream mask site with bounded idle duration
    let _ = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::io::copy_bidirectional(&mut client_stream, &mut upstream),
    )
    .await;
}

/// Handles authenticated EchoMesh client session over the Noise protocol,
/// dispatching all inbound frames through the `ServerPipeline`.
async fn handle_authenticated_noise_session<S>(
    stream: &mut S,
    server_private_key: &[u8],
    peer_addr: SocketAddr,
    connection_manager: ConnectionManager,
    session_manager: SessionManager,
    inbound_router: Arc<ServerInboundRouter>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let noise_session = match server_noise_handshake(stream, server_private_key, Some(peer_addr)).await {
        Ok(s) => s,
        Err(e) => {
            if let crate::transport::noise::NoiseError::Snow(ref snow_err) = e {
                let err_enum = crate::transport::noise::snow_error_enum(snow_err);
                warn!(%peer_addr, snow_error = %err_enum, "Handshake failed with snow::Error enum: {}", err_enum);
            }
            return Err(Box::new(e));
        }
    };

    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel(64);
    let conn_id = connection_manager.register(peer_addr, outbound_tx.clone()).await;

    // Default session ID mapped for this connection
    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&ECHO_SERVICE_PEER_ID[..16]);
    let session = session_manager.create_session(session_id, None).await;
    connection_manager.bind_session(conn_id, session_id, None).await;

    let outbound_router = ServerOutboundRouter::new(connection_manager.clone());
    let mut pipeline = ServerPipeline::new(
        conn_id,
        session,
        outbound_tx,
        inbound_router,
        outbound_router,
        connection_manager.clone(),
        session_manager.clone(),
    );

    let mut framed = NoiseFramedStream::new(stream, noise_session);
    debug!(%peer_addr, "Noise framed stream ready for frame exchange");

    loop {
        tokio::select! {
            frame_res = framed.recv_frame() => {
                match frame_res {
                    Ok(Some(frame)) => {
                        if let Err(err) = pipeline.process_frame(frame).await {
                            warn!(%peer_addr, ?err, "pipeline error processing frame");
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        debug!(%peer_addr, ?e, "connection read closed");
                        break;
                    }
                }
            }
            Some(outbound_frame) = outbound_rx.recv() => {
                if let Err(err) = framed.send_frame(&outbound_frame).await {
                    warn!(%peer_addr, ?err, "failed to send outbound frame");
                    break;
                }
            }
        }
    }

    connection_manager.unregister(conn_id).await;
    session_manager.remove_session(&session_id).await;
    debug!(%peer_addr, "Noise session ended normally");
    Ok(())
}

