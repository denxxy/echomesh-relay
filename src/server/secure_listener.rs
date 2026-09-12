use std::fmt;
use std::io::Cursor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Mutex, Semaphore};
use tracing::{debug, info, warn};

use crate::config::DEFAULT_SECRET_TOKEN;
use crate::protocol::frame::{constant_time_eq, Frame};
use crate::server::router::{
    parse_registration, registration_ack_frame, RelayRouter, RouteId, RouteResult,
};
use crate::transport::noise::{server_noise_handshake, ENCRYPTED_FRAME_SIZE};
use crate::transport::obfuscation::{
    hex_decode, hex_encode, parse_client_hello, ClientHelloStatus, TokenValidator,
    MAX_CLIENT_HELLO_SIZE,
};

pub use crate::config::ECHO_PEER_ID;
pub use crate::config::ECHO_SERVICE_PEER_ID as ECHO_SERVICE_PEER_ID_CONST;

#[derive(Clone, PartialEq, Eq)]
pub struct RelaySecrets {
    pub secret_token: Vec<u8>,
    pub secret_token_hex: String,
    pub public_key: Vec<u8>,
    pub public_key_hex: String,
    pub public_key_base64: String,
    pub private_key: Vec<u8>,
    pub private_key_hex: String,
    pub url: String,
    pub key_file: Option<std::path::PathBuf>,
}

impl fmt::Debug for RelaySecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelaySecrets")
            .field("url", &self.url)
            .field("public_key_hex", &self.public_key_hex)
            .field("public_key_base64", &self.public_key_base64)
            .field("secret_token", &"[REDACTED]")
            .field("key_file", &self.key_file)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for RelaySecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EchoMesh Relay Credentials:\n  URL: {}\n  Public Key (Base64): {}\n  Secret Token: [REDACTED]",
            self.url, self.public_key_base64
        )
    }
}

impl RelaySecrets {
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

    pub fn generate(
        bind_addr: SocketAddr,
        secret_token: Option<Vec<u8>>,
    ) -> Result<Self, snow::Error> {
        let builder = snow::Builder::new(crate::transport::noise::NOISE_PATTERN.parse()?);
        let keypair = builder.generate_keypair()?;
        let secret = match secret_token {
            Some(s) if !s.is_empty() => s,
            _ => builder.generate_keypair()?.public,
        };
        Ok(Self::new(
            secret,
            keypair.public,
            keypair.private,
            format!("https://{}", bind_addr),
        ))
    }

    pub fn from_keypair(
        bind_addr: SocketAddr,
        keypair: crate::crypto::KeyPair,
        secret_token: Option<Vec<u8>>,
    ) -> Result<Self, snow::Error> {
        let secret = match secret_token {
            Some(s) if !s.is_empty() => s,
            _ => snow::Builder::new(crate::transport::noise::NOISE_PATTERN.parse()?)
                .generate_keypair()?
                .public,
        };
        let mut out = Self::new(
            secret,
            keypair.public_key,
            keypair.private_key,
            format!("https://{}", bind_addr),
        );
        out.key_file = Some(keypair.key_path);
        Ok(out)
    }

    pub fn load_or_generate(
        key_path: &std::path::Path,
        bind_addr: SocketAddr,
        secret_token: Option<Vec<u8>>,
    ) -> Result<Self, crate::crypto::KeyError> {
        let keypair = crate::crypto::load_or_generate_keypair(key_path)?;
        let token = if let Some(s) = secret_token.filter(|s| !s.is_empty()) {
            s
        } else if let Some(saved) = read_saved_token(key_path) {
            saved
        } else {
            DEFAULT_SECRET_TOKEN.to_vec()
        };

        let _ = save_token_files(key_path, &token, &keypair.public_key_base64);
        let mut out = Self::new(
            token,
            keypair.public_key,
            keypair.private_key,
            format!("https://{}", bind_addr),
        );
        out.key_file = Some(keypair.key_path);
        Ok(out)
    }
}

fn read_saved_token(key_path: &std::path::Path) -> Option<Vec<u8>> {
    let json_path = crate::crypto::derive_relay_json_path(key_path);
    if let Ok(content) = std::fs::read_to_string(json_path) {
        for key in &["\"secret_token_hex\":", "\"secret_token\":"] {
            if let Some(pos) = content.find(key) {
                let rest = &content[pos + key.len()..];
                let start = rest.find('"')? + 1;
                let tail = &rest[start..];
                let end = tail.find('"')?;
                let value = tail[..end].trim();
                if let Some(decoded) = hex_decode(value) {
                    return Some(decoded);
                }
                if !value.is_empty() {
                    return Some(value.as_bytes().to_vec());
                }
            }
        }
    }

    let token_path = crate::crypto::derive_token_path(key_path);
    let raw = std::fs::read(token_path).ok()?;
    if raw.len() == 32 {
        return Some(raw);
    }
    let text = String::from_utf8_lossy(&raw).trim().to_owned();
    hex_decode(&text).or_else(|| (!text.is_empty()).then(|| text.into_bytes()))
}

fn save_token_files(
    key_path: &std::path::Path,
    secret_token: &[u8],
    public_key_base64: &str,
) -> Result<(), std::io::Error> {
    let token_hex = hex_encode(secret_token);
    write_secure_file(
        &crate::crypto::derive_token_path(key_path),
        format!("{}\n", token_hex).as_bytes(),
    )?;
    let json = format!(
        "{{\n  \"public_key_base64\": \"{}\",\n  \"secret_token_hex\": \"{}\"\n}}\n",
        public_key_base64, token_hex
    );
    write_secure_file(&crate::crypto::derive_relay_json_path(key_path), json.as_bytes())
}

fn write_secure_file(path: &std::path::Path, data: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
        file.flush()?;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut file = std::fs::File::create(path)?;
        file.write_all(data)?;
        file.flush()?;
    }
    Ok(())
}

pub struct PrefixedStream<S> {
    prefix: Cursor<Vec<u8>>,
    stream: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, stream: S) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            stream,
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }

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
        let bytes = self.prefix.get_ref();
        if pos < bytes.len() {
            let n = (bytes.len() - pos).min(buf.remaining());
            buf.put_slice(&bytes[pos..pos + n]);
            self.prefix.set_position((pos + n) as u64);
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
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone)]
pub struct ListenerConfig {
    pub bind_addr: SocketAddr,
    pub max_connections: usize,
    pub fallback_target: String,
    pub secret_token: Vec<u8>,
    pub handshake_timeout: Duration,
    pub secrets: RelaySecrets,
    pub insecure_no_token: bool,
}

impl ListenerConfig {
    pub fn new(bind_addr: SocketAddr, secret_token: impl Into<Vec<u8>>) -> Self {
        let token = secret_token.into();
        let secrets = RelaySecrets::generate(bind_addr, Some(token.clone())).unwrap_or_else(|_| {
            RelaySecrets::new(
                token.clone(),
                vec![0x42; 32],
                vec![0x42; 32],
                format!("https://{}", bind_addr),
            )
        });
        Self::new_with_secrets(bind_addr, secrets)
    }

    pub fn new_with_secrets(bind_addr: SocketAddr, secrets: RelaySecrets) -> Self {
        Self {
            bind_addr,
            max_connections: 1024,
            fallback_target: "cloudflare.com:443".to_string(),
            secret_token: secrets.secret_token.clone(),
            handshake_timeout: Duration::from_secs(5),
            secrets,
            insecure_no_token: false,
        }
    }

    pub fn with_secrets(mut self, secrets: RelaySecrets) -> Self {
        self.secret_token = secrets.secret_token.clone();
        self.secrets = secrets;
        self
    }

    pub fn with_fallback_target(mut self, target: impl Into<String>) -> Self {
        self.fallback_target = target.into();
        self
    }

    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max.max(1);
        self
    }

    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    pub fn with_insecure_no_token(mut self, enabled: bool) -> Self {
        self.insecure_no_token = enabled;
        self
    }

    pub fn with_insecure_no_auth(self, enabled: bool) -> Self {
        self.with_insecure_no_token(enabled)
    }
}

pub struct RelayListener {
    listener: TcpListener,
    semaphore: Arc<Semaphore>,
    config: Arc<ListenerConfig>,
    validator: TokenValidator,
    router: RelayRouter,
}

impl RelayListener {
    pub async fn bind(config: ListenerConfig) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(config.bind_addr).await?;
        let semaphore = Arc::new(Semaphore::new(config.max_connections));
        let mut validator = TokenValidator::new(config.secret_token.clone());
        if config.insecure_no_token {
            validator = validator.with_insecure_no_token(true);
        }
        info!(
            max_connections = config.max_connections,
            insecure_no_token = config.insecure_no_token,
            "echomesh relay listener bound"
        );
        Ok(Self {
            listener,
            semaphore,
            config: Arc::new(config),
            validator,
            router: RelayRouter::new(),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }

    pub fn active_connections(&self) -> usize {
        self.config.max_connections - self.semaphore.available_permits()
    }

    pub fn secrets(&self) -> &RelaySecrets {
        &self.config.secrets
    }

    pub fn secret_token(&self) -> &[u8] {
        &self.config.secrets.secret_token
    }

    pub fn public_key_hex(&self) -> &str {
        &self.config.secrets.public_key_hex
    }

    pub fn public_key_base64(&self) -> &str {
        &self.config.secrets.public_key_base64
    }

    pub fn config(&self) -> &ListenerConfig {
        &self.config
    }

    pub fn router(&self) -> &RelayRouter {
        &self.router
    }

    pub async fn run(&self) -> Result<(), std::io::Error> {
        let (_tx, rx) = watch::channel(false);
        self.run_with_shutdown(rx).await
    }

    pub async fn run_with_shutdown(
        &self,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<(), std::io::Error> {
        loop {
            let (stream, _peer_addr) = tokio::select! {
                result = self.listener.accept() => match result {
                    Ok(v) => v,
                    Err(err) => {
                        warn!(error = ?err, "failed to accept incoming socket");
                        continue;
                    }
                },
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                    continue;
                }
            };

            let permit = match self.semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let config = self.config.clone();
            let validator = self.validator.clone();
            let router = self.router.clone();
            tokio::spawn(async move {
                let _permit = permit;
                handle_connection(stream, config, validator, router).await;
            });
        }
        Ok(())
    }
}

async fn handle_connection(
    mut client_stream: TcpStream,
    config: Arc<ListenerConfig>,
    validator: TokenValidator,
    router: RelayRouter,
) {
    let mut initial_buf = Vec::new();
    let mut temp = [0u8; 1024];
    let n = match tokio::time::timeout(config.handshake_timeout, client_stream.read(&mut temp)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return,
    };
    initial_buf.extend_from_slice(&temp[..n]);

    if initial_buf[0] == crate::transport::obfuscation::TLS_HANDSHAKE_CONTENT_TYPE {
        let mut consumed_len = 0usize;
        let authenticated = match parse_client_hello(&initial_buf) {
            ClientHelloStatus::Complete(parsed) => {
                if initial_buf.len() >= 5 {
                    consumed_len = 5 + u16::from_be_bytes([initial_buf[3], initial_buf[4]]) as usize;
                }
                validator.is_insecure_no_token() || validator.validate(&parsed)
            }
            ClientHelloStatus::NeedMoreData { expected_record_len } => {
                let needed = expected_record_len
                    .saturating_sub(initial_buf.len())
                    .min(MAX_CLIENT_HELLO_SIZE);
                if needed == 0 {
                    false
                } else {
                    let mut rest = vec![0u8; needed];
                    match tokio::time::timeout(
                        config.handshake_timeout,
                        client_stream.read_exact(&mut rest),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            initial_buf.extend_from_slice(&rest);
                            if let ClientHelloStatus::Complete(parsed) = parse_client_hello(&initial_buf) {
                                if initial_buf.len() >= 5 {
                                    consumed_len = 5
                                        + u16::from_be_bytes([initial_buf[3], initial_buf[4]]) as usize;
                                }
                                validator.is_insecure_no_token() || validator.validate(&parsed)
                            } else {
                                false
                            }
                        }
                        _ => false,
                    }
                }
            }
            ClientHelloStatus::Invalid(_) => false,
        };

        if authenticated {
            let leftover = initial_buf.get(consumed_len..).unwrap_or_default().to_vec();
            let mut stream = PrefixedStream::new(leftover, client_stream);
            let _ = handle_authenticated_noise_session(
                &mut stream,
                &config.secrets.private_key,
                router,
            )
            .await;
        } else {
            fall_through_proxy(client_stream, &config.fallback_target, &initial_buf).await;
        }
        return;
    }

    let msg_len = if initial_buf.len() >= 2 {
        u16::from_be_bytes([initial_buf[0], initial_buf[1]]) as usize
    } else {
        0
    };
    if (32..=128).contains(&msg_len) {
        let mut stream = PrefixedStream::new(initial_buf, client_stream);
        let _ = handle_authenticated_noise_session(&mut stream, &config.secrets.private_key, router).await;
    } else {
        fall_through_proxy(client_stream, &config.fallback_target, &initial_buf).await;
    }
}

async fn fall_through_proxy(
    mut client_stream: TcpStream,
    fallback_target: &str,
    initial_buf: &[u8],
) {
    if fallback_target.trim().is_empty() {
        return;
    }
    let mut upstream = match tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(fallback_target),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => return,
    };
    if upstream.write_all(initial_buf).await.is_err() {
        return;
    }
    let _ = upstream.flush().await;
    let _ = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::io::copy_bidirectional(&mut client_stream, &mut upstream),
    )
    .await;
}

async fn handle_authenticated_noise_session<S>(
    stream: &mut S,
    server_private_key: &[u8],
    router: RelayRouter,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let session = server_noise_handshake(stream, server_private_key, None).await?;
    let session = Arc::new(Mutex::new(session));
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Frame>(256);
    let registration = Arc::new(Mutex::new(None::<(RouteId, u64)>));

    let inbound_session = session.clone();
    let inbound_router = router.clone();
    let inbound_tx = outbound_tx.clone();
    let inbound_registration = registration.clone();

    let inbound = async move {
        loop {
            let len = match reader.read_u16().await {
                Ok(v) => v as usize,
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(_) => break,
            };
            if len == 0 || len > ENCRYPTED_FRAME_SIZE {
                break;
            }
            let mut ciphertext = vec![0u8; len];
            if reader.read_exact(&mut ciphertext).await.is_err() {
                break;
            }
            let frame = {
                let mut guard = inbound_session.lock().await;
                match guard.decrypt_frame(&ciphertext) {
                    Ok(frame) => frame,
                    Err(_) => break,
                }
            };

            if let Some(route_id) = parse_registration(&frame) {
                let connection_id = inbound_router.register(route_id, inbound_tx.clone()).await;
                *inbound_registration.lock().await = Some((route_id, connection_id));
                let _ = inbound_tx.send(registration_ack_frame(route_id)).await;
                continue;
            }

            if constant_time_eq(&frame.session_id, &crate::config::ECHO_SERVICE_PEER_ID[..16]) {
                let _ = inbound_tx.send(frame).await;
                continue;
            }

            let sender_route = inbound_registration.lock().await.map(|(route, _)| route);
            let Some(sender_route) = sender_route else {
                debug!("dropping unregistered relay data frame");
                continue;
            };

            match inbound_router.route(sender_route, frame).await {
                RouteResult::Delivered => {}
                RouteResult::RecipientOffline => debug!("recipient route is offline"),
                RouteResult::Backpressure => warn!("recipient route backpressure; frame dropped"),
            }
        }
    };

    let outbound_session = session.clone();
    let outbound = async move {
        while let Some(frame) = outbound_rx.recv().await {
            let packet = {
                let mut guard = outbound_session.lock().await;
                match guard.encrypt_frame(&frame) {
                    Ok(packet) => packet,
                    Err(_) => break,
                }
            };
            if writer.write_all(&packet).await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = inbound => {}
        _ = outbound => {}
    }

    if let Some((route_id, connection_id)) = *registration.lock().await {
        router.unregister(route_id, connection_id).await;
    }
    Ok(())
}
