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

use crate::protocol::frame::Frame;
use crate::transport::noise::{server_noise_handshake, NoiseFramedStream};
use crate::transport::obfuscation::{
    parse_client_hello, ClientHelloStatus, TokenValidator, MAX_CLIENT_HELLO_SIZE,
};

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

/// Configuration for `RelayListener`.
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    /// Bind address for the TCP socket.
    pub bind_addr: SocketAddr,

    /// Maximum concurrent connections permitted (file descriptor exhaustion guard).
    pub max_connections: usize,

    /// Fallback website target (e.g. "cloudflare.com:443" or "microsoft.com:443").
    pub fallback_target: String,

    /// Pre-shared secret token required in TLS ClientHello.random or SNI.
    pub secret_token: Vec<u8>,

    /// Timeout for reading initial ClientHello bytes.
    pub handshake_timeout: Duration,
}

impl ListenerConfig {
    /// Creates a new configuration with sensible security defaults.
    pub fn new(bind_addr: SocketAddr, secret_token: impl Into<Vec<u8>>) -> Self {
        Self {
            bind_addr,
            max_connections: 1024,
            fallback_target: "cloudflare.com:443".to_string(),
            secret_token: secret_token.into(),
            handshake_timeout: Duration::from_secs(5),
        }
    }

    /// Sets the fallback target for unauthenticated requests and active DPI probes.
    pub fn with_fallback_target(mut self, target: impl Into<String>) -> Self {
        self.fallback_target = target.into();
        self
    }

    /// Sets the maximum concurrent connections limit.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max.max(1);
        self
    }

    /// Sets the handshake read timeout.
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }
}

/// The core DPI-resistant TCP network listener for EchoMesh Relay.
pub struct RelayListener {
    listener: TcpListener,
    semaphore: Arc<Semaphore>,
    config: Arc<ListenerConfig>,
    validator: TokenValidator,
}

impl RelayListener {
    /// Binds to the configured socket address and initializes the concurrency limiter.
    pub async fn bind(config: ListenerConfig) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(config.bind_addr).await?;
        let semaphore = Arc::new(Semaphore::new(config.max_connections));
        let validator = TokenValidator::new(config.secret_token.clone());

        info!(
            max_connections = config.max_connections,
            "echomesh TCP listener bound successfully"
        );

        Ok(Self {
            listener,
            semaphore,
            config: Arc::new(config),
            validator,
        })
    }

    /// Returns the local socket address this listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }

    /// Returns the current number of active concurrent connections.
    pub fn active_connections(&self) -> usize {
        self.config.max_connections - self.semaphore.available_permits()
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
            let (stream, _peer_addr) = tokio::select! {
                accept_res = self.listener.accept() => {
                    match accept_res {
                        Ok(conn) => conn,
                        Err(_err) => {
                            warn!("failed to accept incoming socket connection");
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

            // Spawn lightweight task for each connection
            tokio::spawn(async move {
                let _permit = permit; // Owned permit is held for lifecycle of connection
                handle_connection(stream, config, validator).await;
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
) {
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
        _ => return, // Connection closed or timed out before receiving data
    };

    // Determine if initial packet contains authenticated TLS ClientHello
    let mut consumed_len = 0;
    let is_authenticated = match parse_client_hello(&initial_buf) {
        ClientHelloStatus::Complete(parsed) => {
            if initial_buf.len() >= 5 {
                let rec_len = u16::from_be_bytes([initial_buf[3], initial_buf[4]]) as usize;
                consumed_len = 5 + rec_len;
            }
            validator.validate(&parsed)
        }
        ClientHelloStatus::NeedMoreData {
            expected_record_len,
        } => {
            // Read remaining bytes of the record if within bounds
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
                        validator.validate(&parsed)
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
        ClientHelloStatus::Invalid(_) => false,
    };

    if is_authenticated {
        debug!("client authenticated via pseudo-tls handshake; switching to noise protocol");
        let leftover = if initial_buf.len() > consumed_len {
            initial_buf[consumed_len..].to_vec()
        } else {
            Vec::new()
        };
        let mut stream = PrefixedStream::new(leftover, client_stream);
        if let Err(_err) = handle_authenticated_noise_session(&mut stream).await {
            debug!("authenticated session terminated");
        }
    } else {
        // Fall-through proxying to legitimate website (e.g. Microsoft or Cloudflare)
        debug!("unauthenticated client or active scanner detected; proxying to fallback target");
        fall_through_proxy(client_stream, &config.fallback_target, &initial_buf).await;
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

/// Handles authenticated EchoMesh client session over the Noise protocol.
async fn handle_authenticated_noise_session<S>(
    stream: &mut S,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let session = server_noise_handshake(stream).await?;
    let mut framed = NoiseFramedStream::new(stream, session);

    // Relay processing loop: process or echo valid frames
    while let Some(frame) = framed.recv_frame().await? {
        // Echo frame back or forward through stateless relay
        let response = Frame::new(frame.session_id, frame.nonce, frame.payload)?;
        framed.send_frame(&response).await?;
    }

    Ok(())
}
