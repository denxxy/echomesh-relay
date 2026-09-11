use std::fmt;
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
use crate::transport::noise::{server_noise_handshake, NoiseFramedStream, NOISE_PATTERN};
use crate::transport::obfuscation::{
    hex_encode, parse_client_hello, ClientHelloStatus, TokenValidator, MAX_CLIENT_HELLO_SIZE,
};

/// Cryptographic secrets and connection identifiers for an EchoMesh Relay instance.
#[derive(Clone, PartialEq, Eq)]
pub struct RelaySecrets {
    /// Pre-shared secret token for Reality/TLS camouflage authentication (raw bytes).
    pub secret_token: Vec<u8>,
    /// Pre-shared secret token encoded as hex string.
    pub secret_token_hex: String,
    /// Relay X25519 static public key (raw 32 bytes).
    pub public_key: Vec<u8>,
    /// Relay X25519 static public key encoded as hex string (64 characters).
    pub public_key_hex: String,
    /// Relay X25519 static public key encoded as Base64 string.
    pub public_key_base64: String,
    /// Relay X25519 static private key (raw 32 bytes).
    pub private_key: Vec<u8>,
    /// Relay X25519 static private key encoded as hex string (64 characters).
    pub private_key_hex: String,
    /// Connection endpoint URL (e.g. "https://0.0.0.0:8443").
    pub url: String,
    /// Persistent key file path on disk, if loaded from or saved to a file.
    pub key_file: Option<std::path::PathBuf>,
}

impl fmt::Debug for RelaySecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact private key per security invariant
        f.debug_struct("RelaySecrets")
            .field("url", &self.url)
            .field("public_key_hex", &self.public_key_hex)
            .field("public_key_base64", &self.public_key_base64)
            .field("secret_token_hex", &self.secret_token_hex)
            .field("key_file", &self.key_file)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for RelaySecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EchoMesh Relay Secrets:\n  URL: {}\n  Public Key (Hex): {}\n  Public Key (Base64): {}\n  Secret Token (Hex): {}",
            self.url, self.public_key_hex, self.public_key_base64, self.secret_token_hex
        )
    }
}

impl RelaySecrets {
    /// Creates a new `RelaySecrets` bundle from explicit components.
    pub fn new(
        secret_token: Vec<u8>,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        url: impl Into<String>,
    ) -> Self {
        let secret_token_hex = hex_encode(&secret_token);
        let public_key_hex = hex_encode(&public_key);
        let public_key_base64 = crate::crypto::base64_encode(&public_key);
        let private_key_hex = hex_encode(&private_key);
        Self {
            secret_token,
            secret_token_hex,
            public_key,
            public_key_hex,
            public_key_base64,
            private_key,
            private_key_hex,
            url: url.into(),
            key_file: None,
        }
    }

    /// Generates a fresh `RelaySecrets` bundle using CSPRNG.
    /// If `secret_token` is `None` or empty, a 32-byte secure random token is generated.
    pub fn generate(
        bind_addr: SocketAddr,
        secret_token: Option<Vec<u8>>,
    ) -> Result<Self, snow::Error> {
        let builder = snow::Builder::new(NOISE_PATTERN.parse()?);
        let keypair = builder.generate_keypair()?;

        let secret = match secret_token {
            Some(s) if !s.is_empty() => s,
            _ => {
                let token_pair = builder.generate_keypair()?;
                token_pair.public
            }
        };

        let secret_token_hex = hex_encode(&secret);
        let public_key_hex = hex_encode(&keypair.public);
        let public_key_base64 = crate::crypto::base64_encode(&keypair.public);
        let private_key_hex = hex_encode(&keypair.private);
        let url = format!("https://{}", bind_addr);

        Ok(Self {
            secret_token: secret,
            secret_token_hex,
            public_key: keypair.public,
            public_key_hex,
            public_key_base64,
            private_key: keypair.private,
            private_key_hex,
            url,
            key_file: None,
        })
    }

    /// Creates a `RelaySecrets` bundle from a pre-loaded persistent `KeyPair`.
    pub fn from_keypair(
        bind_addr: SocketAddr,
        keypair: crate::crypto::KeyPair,
        secret_token: Option<Vec<u8>>,
    ) -> Result<Self, snow::Error> {
        let secret = match secret_token {
            Some(s) if !s.is_empty() => s,
            _ => {
                let builder = snow::Builder::new(NOISE_PATTERN.parse()?);
                let token_pair = builder.generate_keypair()?;
                token_pair.public
            }
        };

        let secret_token_hex = hex_encode(&secret);
        let public_key_hex = hex_encode(&keypair.public_key);
        let private_key_hex = hex_encode(&keypair.private_key);
        let url = format!("https://{}", bind_addr);

        Ok(Self {
            secret_token: secret,
            secret_token_hex,
            public_key: keypair.public_key,
            public_key_hex,
            public_key_base64: keypair.public_key_base64,
            private_key: keypair.private_key,
            private_key_hex,
            url,
            key_file: Some(keypair.key_path),
        })
    }

    /// Loads an existing key or generates a persistent key at `key_path` and creates `RelaySecrets`.
    pub fn load_or_generate(
        key_path: &std::path::Path,
        bind_addr: SocketAddr,
        secret_token: Option<Vec<u8>>,
    ) -> Result<Self, crate::crypto::KeyError> {
        let keypair = crate::crypto::load_or_generate_keypair(key_path)?;
        Ok(Self::from_keypair(bind_addr, keypair, secret_token)?)
    }
}

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

    /// Cryptographic secrets bundle for relay authentication and client connection.
    pub secrets: RelaySecrets,
}

impl ListenerConfig {
    /// Creates a new configuration with sensible security defaults.
    pub fn new(bind_addr: SocketAddr, secret_token: impl Into<Vec<u8>>) -> Self {
        let token_bytes = secret_token.into();
        let secrets = RelaySecrets::generate(bind_addr, Some(token_bytes.clone()))
            .unwrap_or_else(|_| {
                RelaySecrets::new(
                    token_bytes.clone(),
                    vec![0x42; 32],
                    vec![0x42; 32],
                    format!("https://{}", bind_addr),
                )
            });

        Self {
            bind_addr,
            max_connections: 1024,
            fallback_target: "cloudflare.com:443".to_string(),
            secret_token: token_bytes,
            handshake_timeout: Duration::from_secs(5),
            secrets,
        }
    }

    /// Creates a configuration with an explicit `RelaySecrets` bundle.
    pub fn new_with_secrets(bind_addr: SocketAddr, secrets: RelaySecrets) -> Self {
        Self {
            bind_addr,
            max_connections: 1024,
            fallback_target: "cloudflare.com:443".to_string(),
            secret_token: secrets.secret_token.clone(),
            handshake_timeout: Duration::from_secs(5),
            secrets,
        }
    }

    /// Sets the secrets bundle.
    pub fn with_secrets(mut self, secrets: RelaySecrets) -> Self {
        self.secret_token = secrets.secret_token.clone();
        self.secrets = secrets;
        self
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
