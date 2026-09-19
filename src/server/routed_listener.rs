use std::collections::HashMap;
use std::io::Cursor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, RwLock, Semaphore};
use tracing::{debug, info, warn};

use crate::protocol::frame::Frame;
use crate::transport::noise::{server_noise_handshake, NoiseSession, ENCRYPTED_FRAME_SIZE};
use crate::transport::obfuscation::{
    parse_client_hello, ClientHelloStatus, TokenValidator, MAX_CLIENT_HELLO_SIZE,
    TLS_HANDSHAKE_CONTENT_TYPE,
};

pub use super::config::{ListenerConfig, RelaySecrets};

pub const ROUTE_REGISTRATION_ID: [u8; 16] = [0xF0; 16];
pub const ECHO_ROUTE_ID: [u8; 16] = [0xEE; 16];
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);
pub type RouteId = [u8; 16];
pub type PeerId = [u8; 32];

#[derive(Clone)]
pub struct RouteEntry {
    pub connection_id: u64,
    pub peer_id: PeerId,
    pub tx: mpsc::Sender<Frame>,
}

#[derive(Default)]
pub struct RouteRegistryInner {
    pub by_peer_id: HashMap<PeerId, RouteEntry>,
    pub by_prefix: HashMap<RouteId, RouteEntry>,
}

impl RouteRegistryInner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, peer_id: PeerId, connection_id: u64, tx: mpsc::Sender<Frame>) -> Option<RouteEntry> {
        let mut prefix = [0u8; 16];
        prefix.copy_from_slice(&peer_id[..16]);
        let entry = RouteEntry {
            connection_id,
            peer_id,
            tx,
        };
        self.by_prefix.insert(prefix, entry.clone());
        self.by_peer_id.insert(peer_id, entry)
    }

    pub fn remove_connection(&mut self, peer_id: &PeerId, connection_id: u64) -> bool {
        let is_current = self.by_peer_id.get(peer_id).map(|e| e.connection_id == connection_id).unwrap_or(false);
        if is_current {
            self.by_peer_id.remove(peer_id);
            let mut prefix = [0u8; 16];
            prefix.copy_from_slice(&peer_id[..16]);
            self.by_prefix.remove(&prefix);
            true
        } else {
            false
        }
    }

    pub fn get_by_peer_id(&self, peer_id: &PeerId) -> Option<RouteEntry> {
        self.by_peer_id.get(peer_id).cloned()
    }

    pub fn get_by_prefix(&self, prefix: &RouteId) -> Option<RouteEntry> {
        self.by_prefix.get(prefix).cloned()
    }

    pub fn active_count(&self) -> usize {
        self.by_peer_id.len()
    }
}

pub type RouteRegistry = Arc<RwLock<RouteRegistryInner>>;

pub struct PrefixedStream<S> {
    prefix: Cursor<Vec<u8>>,
    stream: S,
}
impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, stream: S) -> Self { Self { prefix: Cursor::new(prefix), stream } }
}
impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let pos = self.prefix.position() as usize;
        let bytes = self.prefix.get_ref();
        if pos < bytes.len() {
            let n = (bytes.len() - pos).min(buf.remaining());
            buf.put_slice(&bytes[pos..pos+n]);
            self.prefix.set_position((pos+n) as u64);
            Poll::Ready(Ok(()))
        } else { Pin::new(&mut self.stream).poll_read(cx, buf) }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> { Pin::new(&mut self.stream).poll_write(cx, buf) }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> { Pin::new(&mut self.stream).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> { Pin::new(&mut self.stream).poll_shutdown(cx) }
}

pub struct RelayListener {
    listener: TcpListener,
    semaphore: Arc<Semaphore>,
    config: Arc<ListenerConfig>,
    validator: TokenValidator,
    routes: RouteRegistry,
}

impl RelayListener {
    pub async fn bind(config: ListenerConfig) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(config.bind_addr).await?;
        let semaphore = Arc::new(Semaphore::new(config.max_connections));
        let mut validator = TokenValidator::new(config.secret_token.clone());
        if config.insecure_no_token { validator = validator.with_insecure_no_token(true); }
        info!(local_addr=%listener.local_addr()?, max_connections=config.max_connections, insecure_no_token=config.insecure_no_token, "echomesh routed listener bound");
        Ok(Self { listener, semaphore, config: Arc::new(config), validator, routes: Arc::new(RwLock::new(RouteRegistryInner::new())) })
    }
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> { self.listener.local_addr() }
    pub fn active_connections(&self) -> usize { self.config.max_connections - self.semaphore.available_permits() }
    pub fn secrets(&self) -> &RelaySecrets { &self.config.secrets }
    pub fn secret_token(&self) -> &[u8] { &self.config.secrets.secret_token }
    pub fn public_key_hex(&self) -> &str { &self.config.secrets.public_key_hex }
    pub fn public_key_base64(&self) -> &str { &self.config.secrets.public_key_base64 }
    pub fn config(&self) -> &ListenerConfig { &self.config }
    pub async fn run(&self) -> Result<(), std::io::Error> { let (_tx, rx)=watch::channel(false); self.run_with_shutdown(rx).await }
    pub async fn run_with_shutdown(&self, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), std::io::Error> {
        loop {
            let (stream, peer_addr) = tokio::select! {
                accept=self.listener.accept()=>match accept { Ok(v)=>v, Err(err)=>{warn!(?err,"failed to accept client");continue;} },
                changed=shutdown_rx.changed()=>{ if changed.is_ok() && *shutdown_rx.borrow(){break;} continue; }
            };
            let permit = tokio::select! {
                permit=self.semaphore.clone().acquire_owned()=>match permit {Ok(v)=>v,Err(_)=>break},
                _=shutdown_rx.changed()=>{if *shutdown_rx.borrow(){break;}continue;}
            };
            let config=Arc::clone(&self.config); let validator=self.validator.clone(); let routes=Arc::clone(&self.routes);
            tokio::spawn(async move { let _permit=permit; if let Err(err)=handle_connection(stream,config,validator,routes,peer_addr).await { debug!(?err,"connection ended"); } });
        }
        Ok(())
    }
}

async fn handle_connection(
    mut client_stream: TcpStream,
    config: Arc<ListenerConfig>,
    validator: TokenValidator,
    routes: RouteRegistry,
    peer_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut initial=vec![0u8;1024];
    let n=tokio::time::timeout(config.handshake_timeout,client_stream.read(&mut initial)).await.map_err(|_|std::io::Error::new(std::io::ErrorKind::TimedOut,"initial read timeout"))??;
    if n==0{return Ok(());} initial.truncate(n);

    if initial[0]==TLS_HANDSHAKE_CONTENT_TYPE {
        let mut consumed_len=0usize;
        let authenticated=loop {
            match parse_client_hello(&initial) {
                ClientHelloStatus::Complete(parsed)=>{
                    if initial.len()>=5 { let record_len=u16::from_be_bytes([initial[3],initial[4]]) as usize; consumed_len=5+record_len; }
                    let dev_mode=validator.is_insecure_no_token() || std::env::var("ECHOMESH_INSECURE_NO_AUTH").map(|v|v=="1"||v.eq_ignore_ascii_case("true")).unwrap_or(false);
                    break dev_mode || validator.validate(&parsed);
                }
                ClientHelloStatus::NeedMoreData{expected_record_len}=>{
                    if expected_record_len>MAX_CLIENT_HELLO_SIZE || expected_record_len<=initial.len(){break false;}
                    let mut rest=vec![0u8;expected_record_len-initial.len()];
                    tokio::time::timeout(config.handshake_timeout,client_stream.read_exact(&mut rest)).await.map_err(|_|std::io::Error::new(std::io::ErrorKind::TimedOut,"ClientHello timeout"))??;
                    initial.extend_from_slice(&rest);
                }
                ClientHelloStatus::Invalid(_)=>break false,
            }
        };
        if !authenticated { fall_through_proxy(client_stream,&config.fallback_target,&initial).await; return Ok(()); }
        let leftover=if initial.len()>consumed_len{initial[consumed_len..].to_vec()}else{Vec::new()};
        let stream=PrefixedStream::new(leftover,client_stream);
        return handle_routed_noise_session(stream,&config.secrets.private_key,routes,peer_addr).await;
    }

    let msg_len=if initial.len()>=2{u16::from_be_bytes([initial[0],initial[1]]) as usize}else{0};
    if config.insecure_no_token && (32..=128).contains(&msg_len) {
        let stream=PrefixedStream::new(initial,client_stream);
        handle_routed_noise_session(stream,&config.secrets.private_key,routes,peer_addr).await
    } else {
        fall_through_proxy(client_stream,&config.fallback_target,&initial).await;
        Ok(())
    }
}

async fn fall_through_proxy(mut client_stream: TcpStream, fallback_target: &str, initial: &[u8]) {
    if fallback_target.trim().is_empty(){return;}
    let upstream=tokio::time::timeout(Duration::from_secs(3),TcpStream::connect(fallback_target)).await;
    let Ok(Ok(mut upstream))=upstream else{return;};
    if !initial.is_empty() && upstream.write_all(initial).await.is_err(){return;}
    let _=upstream.flush().await;
    let _=tokio::time::timeout(Duration::from_secs(30),tokio::io::copy_bidirectional(&mut client_stream,&mut upstream)).await;
}

async fn handle_routed_noise_session<S>(
    mut stream:S,
    server_private_key:&[u8],
    routes:RouteRegistry,
    _peer_addr:SocketAddr,
)->Result<(),Box<dyn std::error::Error+Send+Sync>>
where S:AsyncRead+AsyncWrite+Unpin+Send+'static {
    let session=server_noise_handshake(&mut stream,server_private_key,None).await?;
    let session=Arc::new(tokio::sync::Mutex::new(session));
    let (mut reader,mut writer)=tokio::io::split(stream);
    let (out_tx,mut out_rx)=mpsc::channel::<Frame>(256);
    let connection_id=NEXT_CONNECTION_ID.fetch_add(1,Ordering::Relaxed);
    let writer_session = Arc::clone(&session);
    let writer_conn_id = connection_id;
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            let msg_id = format!("msg_{}", u64::from_be_bytes(frame.nonce));
            info!(
                "[server] MESSAGE_FORWARD message_id={} connection_id={} write_started=true",
                msg_id, writer_conn_id
            );
            let packet = {
                let mut noise = writer_session.lock().await;
                noise.encrypt_frame(&frame)
            }?;
            if let Err(err) = writer.write_all(&packet).await {
                warn!(
                    "[server] MESSAGE_FORWARD_RESULT message_id={} success=false error={}",
                    msg_id, err
                );
                return Err(err.into());
            }
            if let Err(err) = writer.flush().await {
                warn!(
                    "[server] MESSAGE_FORWARD_RESULT message_id={} success=false error={}",
                    msg_id, err
                );
                return Err(err.into());
            }
            info!(
                "[server] MESSAGE_FORWARD_RESULT message_id={} success=true",
                msg_id
            );
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });

    let mut registered_peer: Option<PeerId> = None;
    loop {
        let len = match reader.read_u16().await {
            Ok(v) => v as usize,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(Box::new(err)),
        };
        if len == 0 || len > ENCRYPTED_FRAME_SIZE {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid encrypted frame length: {}", len),
            )));
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        let frame = {
            let mut noise: tokio::sync::MutexGuard<'_, NoiseSession> = session.lock().await;
            noise.decrypt_frame(&buf)?
        };

        // 1. Route registration frame
        if frame.session_id == ROUTE_REGISTRATION_ID {
            if frame.payload.len() != 32 {
                warn!(payload_len = frame.payload.len(), "invalid route registration payload");
                continue;
            }
            let mut peer_id = [0u8; 32];
            peer_id.copy_from_slice(&frame.payload[..32]);
            let previous = routes.write().await.insert(
                peer_id,
                connection_id,
                out_tx.clone(),
            );
            let id_hex = hex::encode(&peer_id);
            info!(
                "[server] REGISTER user={} connection=conn-{}",
                id_hex, connection_id
            );
            if let Some(previous) = previous {
                info!(
                    "[server] RECONNECT user={} old_conn=conn-{} new_conn=conn-{}",
                    id_hex, previous.connection_id, connection_id
                );
            }
            registered_peer = Some(peer_id);
            continue;
        }

        // 2. Reject echo route - EchoMesh is a routed messenger, not an echo server
        if frame.session_id == ECHO_ROUTE_ID {
            warn!("[server] ECHO_ROUTE_REJECTED connection=conn-{} echo loopback is disabled", connection_id);
            continue;
        }

        // 3. Authenticated sender verification
        let Some(source_peer_id) = registered_peer else {
            warn!("[server] DROP unregistered client frame connection=conn-{}", connection_id);
            continue;
        };

        let mut source_prefix = [0u8; 16];
        source_prefix.copy_from_slice(&source_peer_id[..16]);

        // 4. Check if frame payload is a structured MessageEnvelope
        if let Ok((envelope, client_msg)) = crate::protocol::codec::EnvelopeCodec::decode_client_message(&frame.payload) {
            match client_msg {
                crate::protocol::messages::ClientToServerMessage::SendMessage { recipient_id, data } => {
                    let msg_id = envelope.message_id;
                    let sender_hex = hex::encode(source_peer_id);
                    let recipient_hex = hex::encode(recipient_id);

                    info!(
                        "[server] SEND_REQUEST message_id={} sender={} recipient={}",
                        msg_id, sender_hex, recipient_hex
                    );

                    // Anti-self-messaging rule
                    if source_peer_id == recipient_id {
                        warn!(
                            "[server] PROTOCOL_ERROR self_messaging_rejected message_id={} sender==recipient={}",
                            msg_id, sender_hex
                        );
                        let resp = crate::protocol::messages::ServerToClientMessage::SendMessageResponse {
                            message_id: msg_id,
                            accepted: false,
                        };
                        if let Ok(resp_env) = crate::protocol::envelope::MessageEnvelope::new(
                            resp.message_type(),
                            msg_id,
                            msg_id,
                            envelope.timestamp,
                            resp.encode(),
                        ) {
                            if let Ok(resp_bytes) = resp_env.to_bytes() {
                                if let Ok(resp_frame) = Frame::new(source_prefix, [0u8; 8], resp_bytes) {
                                    let _ = out_tx.send(resp_frame).await;
                                }
                            }
                        }
                        continue;
                    }

                    let target_entry = routes.read().await.get_by_peer_id(&recipient_id);
                    if let Some(entry) = target_entry {
                        info!(
                            "[server] ROUTE recipient={} connection=conn-{}",
                            recipient_hex, entry.connection_id
                        );

                        // 1. Send SendMessageResponse { accepted: true } to sender
                        let resp = crate::protocol::messages::ServerToClientMessage::SendMessageResponse {
                            message_id: msg_id,
                            accepted: true,
                        };
                        if let Ok(resp_env) = crate::protocol::envelope::MessageEnvelope::new(
                            resp.message_type(),
                            msg_id,
                            msg_id,
                            envelope.timestamp,
                            resp.encode(),
                        ) {
                            if let Ok(resp_bytes) = resp_env.to_bytes() {
                                if let Ok(resp_frame) = Frame::new(source_prefix, [0u8; 8], resp_bytes) {
                                    let _ = out_tx.send(resp_frame).await;
                                }
                            }
                        }

                        // 2. Send IncomingMessageEvent to recipient
                        let evt = crate::protocol::messages::ServerToClientMessage::IncomingMessageEvent {
                            sender_id: source_peer_id,
                            data,
                        };
                        if let Ok(evt_env) = crate::protocol::envelope::MessageEnvelope::new(
                            evt.message_type(),
                            msg_id,
                            0,
                            envelope.timestamp,
                            evt.encode(),
                        ) {
                            if let Ok(evt_bytes) = evt_env.to_bytes() {
                                if let Ok(evt_frame) = Frame::new(source_prefix, frame.nonce, evt_bytes) {
                                    if entry.tx.send(evt_frame).await.is_ok() {
                                        info!("[server] FORWARD_OK message_id={}", msg_id);
                                    } else {
                                        routes.write().await.remove_connection(&entry.peer_id, entry.connection_id);
                                    }
                                }
                            }
                        }
                    } else {
                        info!(
                            "[server] ROUTE recipient={} recipient_found=false",
                            recipient_hex
                        );
                        // Offline recipient: Send SendMessageResponse { accepted: false }, DO NOT ECHO
                        let resp = crate::protocol::messages::ServerToClientMessage::SendMessageResponse {
                            message_id: msg_id,
                            accepted: false,
                        };
                        if let Ok(resp_env) = crate::protocol::envelope::MessageEnvelope::new(
                            resp.message_type(),
                            msg_id,
                            msg_id,
                            envelope.timestamp,
                            resp.encode(),
                        ) {
                            if let Ok(resp_bytes) = resp_env.to_bytes() {
                                if let Ok(resp_frame) = Frame::new(source_prefix, [0u8; 8], resp_bytes) {
                                    let _ = out_tx.send(resp_frame).await;
                                }
                            }
                        }
                    }
                    continue;
                }
                crate::protocol::messages::ClientToServerMessage::Ack { acknowledged_message_id } => {
                    info!("[server] DELIVERED message_id={}", acknowledged_message_id);
                    let target_prefix = frame.session_id;
                    if let Some(entry) = routes.read().await.get_by_prefix(&target_prefix) {
                        let evt = crate::protocol::messages::ServerToClientMessage::DeliveryStatusEvent {
                            message_id: acknowledged_message_id,
                            status: crate::protocol::messages::DeliveryStatus::Delivered,
                        };
                        if let Ok(evt_env) = crate::protocol::envelope::MessageEnvelope::new(
                            evt.message_type(),
                            acknowledged_message_id,
                            acknowledged_message_id,
                            envelope.timestamp,
                            evt.encode(),
                        ) {
                            if let Ok(evt_bytes) = evt_env.to_bytes() {
                                if let Ok(evt_frame) = Frame::new(source_prefix, [0u8; 8], evt_bytes) {
                                    let _ = entry.tx.send(evt_frame).await;
                                }
                            }
                        }
                    }
                    continue;
                }
                crate::protocol::messages::ClientToServerMessage::Heartbeat { sequence } => {
                    let resp = crate::protocol::messages::ServerToClientMessage::HeartbeatResponse { sequence };
                    if let Ok(resp_env) = crate::protocol::envelope::MessageEnvelope::new(
                        resp.message_type(),
                        envelope.message_id,
                        envelope.message_id,
                        envelope.timestamp,
                        resp.encode(),
                    ) {
                        if let Ok(resp_bytes) = resp_env.to_bytes() {
                            if let Ok(resp_frame) = Frame::new(source_prefix, [0u8; 8], resp_bytes) {
                                let _ = out_tx.send(resp_frame).await;
                            }
                        }
                    }
                    continue;
                }
                _ => {}
            }
        }

        // 5. Raw frame routing (compatible with standard wire frames and delivery ACK)
        let target = frame.session_id;
        let msg_id = format!("msg_{}", u64::from_be_bytes(frame.nonce));
        let sender_hex = hex::encode(source_prefix);
        let recipient_hex = hex::encode(target);

        // Anti-self-messaging rule
        if source_prefix == target {
            warn!(
                "[server] SELF_MESSAGING_DETECTED message_id={} sender_id==recipient_id={}",
                msg_id, sender_hex
            );
            continue; // Dropped without echoing
        }

        let is_ack = frame.payload.first() == Some(&0x06);
        if is_ack {
            let ack_id = String::from_utf8_lossy(&frame.payload[1..]).to_string();
            info!(
                "[server] DELIVERED message_id={} to_sender={}",
                ack_id, recipient_hex
            );
        } else {
            info!(
                "[server] SEND_REQUEST message_id={} sender={} recipient={}",
                msg_id, sender_hex, recipient_hex
            );
        }

        let target_entry = routes.read().await.get_by_prefix(&target);
        if let Some(entry) = target_entry {
            info!(
                "[server] ROUTE recipient={} recipient_found=true recipient_connection_id=conn-{}",
                recipient_hex, entry.connection_id
            );
            let mut routed = frame;
            routed.session_id = source_prefix;
            if entry.tx.send(routed).await.is_ok() {
                if !is_ack {
                    info!("[server] FORWARD_OK message_id={}", msg_id);
                }
            } else {
                routes.write().await.remove_connection(&entry.peer_id, entry.connection_id);
            }
        } else {
            info!(
                "[server] ROUTE recipient={} recipient_found=false",
                recipient_hex
            );
            // RECIPIENT OFFLINE: DO NOT ECHO BACK TO SENDER
        }
    }

    if let Some(peer_id) = registered_peer {
        let removed = routes.write().await.remove_connection(&peer_id, connection_id);
        if removed {
            info!(
                "[server] UNREGISTER user={} connection=conn-{}",
                hex::encode(&peer_id), connection_id
            );
        }
    }
    drop(out_tx);
    let _ = writer_task.await;
    Ok(())
}