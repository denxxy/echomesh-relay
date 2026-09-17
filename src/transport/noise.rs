use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::frame::{Frame, FrameCodec, FRAME_SIZE};
use crate::protocol::ProtocolError;

/// Noise Protocol handshake pattern: Noise_NK_25519_ChaChaPoly_BLAKE2s
pub const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

/// Noise protocol prologue (empty by default for both server and client)
pub const NOISE_PROLOGUE: &[u8] = b"";

/// Maximum Noise message size per specification (65535 bytes).
pub const MAX_NOISE_MSG_LEN: usize = 65535;

/// Poly1305 authentication tag overhead in bytes.
pub const NOISE_TAG_LEN: usize = 16;

/// Encrypted frame size on wire (1420 frame + 16 tag = 1436 bytes).
pub const ENCRYPTED_FRAME_SIZE: usize = FRAME_SIZE + NOISE_TAG_LEN;

/// Errors in the Noise transport and handshake layer.
#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error("Noise cryptographic error: {0}")]
    Snow(#[from] snow::Error),

    #[error("I/O error during Noise communication: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol frame error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("Unexpected message size: expected {expected}, got {actual}")]
    BadMessageSize { expected: usize, actual: usize },

    #[error("Stream closed unexpectedly")]
    StreamClosed,
}

/// An active Noise transport session with encrypted state.
pub struct NoiseSession {
    transport: snow::TransportState,
}

impl fmt::Debug for NoiseSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact cryptographic state per security invariant
        f.debug_struct("NoiseSession")
            .field("pattern", &NOISE_PATTERN)
            .field("state", &"[ENCRYPTED]")
            .finish()
    }
}

impl NoiseSession {
    /// Creates a new `NoiseSession` wrapping an established `snow::TransportState`.
    pub fn new(transport: snow::TransportState) -> Self {
        Self { transport }
    }

    /// Encrypts an outgoing EchoMesh binary frame into a framed buffer.
    pub fn encrypt_frame(&mut self, frame: &Frame) -> Result<Vec<u8>, NoiseError> {
        let mut raw_frame = bytes::BytesMut::with_capacity(FRAME_SIZE);
        let mut codec = FrameCodec::new();
        tokio_util::codec::Encoder::encode(&mut codec, frame.clone(), &mut raw_frame)?;

        let mut cipher_text = vec![0u8; raw_frame.len() + NOISE_TAG_LEN];
        let n = self.transport.write_message(&raw_frame, &mut cipher_text)?;
        cipher_text.truncate(n);

        // Prepend 2-byte big endian length prefix for stream framing
        let mut packet = Vec::with_capacity(2 + cipher_text.len());
        packet.extend_from_slice(&(cipher_text.len() as u16).to_be_bytes());
        packet.extend_from_slice(&cipher_text);

        Ok(packet)
    }

    /// Decrypts an incoming cipher buffer into an EchoMesh `Frame`.
    pub fn decrypt_frame(&mut self, cipher_text: &[u8]) -> Result<Frame, NoiseError> {
        let mut plain_buf = vec![0u8; cipher_text.len()];
        let n = self.transport.read_message(cipher_text, &mut plain_buf)?;
        plain_buf.truncate(n);

        let frame = Frame::from_slice(&plain_buf)?;
        Ok(frame)
    }

    /// Encrypts raw bytes.
    pub fn encrypt(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, NoiseError> {
        let len = self.transport.write_message(payload, out)?;
        Ok(len)
    }

    /// Decrypts raw bytes.
    pub fn decrypt(&mut self, packet: &[u8], out: &mut [u8]) -> Result<usize, NoiseError> {
        let len = self.transport.read_message(packet, out)?;
        Ok(len)
    }
}

/// Formats a `snow::Error` into its exact enum variant name for diagnostics.
pub fn snow_error_enum(err: &snow::Error) -> String {
    match err {
        snow::Error::Pattern(p) => format!("Pattern({:?})", p),
        snow::Error::Init(i) => format!("Init({:?})", i),
        snow::Error::Prereq(p) => format!("Prereq({:?})", p),
        snow::Error::State(s) => format!("State({:?})", s),
        snow::Error::Input => "Input".to_string(),
        snow::Error::Decrypt => "Decrypt".to_string(),
        other => format!("{:?}", other),
    }
}

/// Helper to execute the server-side Noise handshake over an async stream.
pub async fn server_noise_handshake<S>(
    stream: &mut S,
    server_private_key: &[u8],
    _peer_addr: Option<std::net::SocketAddr>,
) -> Result<NoiseSession, NoiseError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut builder = snow::Builder::new(
        NOISE_PATTERN
            .parse()
            .map_err(|e: snow::Error| NoiseError::Snow(e))?,
    );
    if !NOISE_PROLOGUE.is_empty() {
        builder = builder.prologue(NOISE_PROLOGUE)?;
    }
    let mut responder = match builder
        .local_private_key(server_private_key)
        .and_then(|b| b.build_responder())
    {
        Ok(r) => r,
        Err(e) => {
            let err_enum = snow_error_enum(&e);
            tracing::error!(
                error = ?e,
                snow_error = %err_enum,
                "Failed building Noise responder with snow::Error enum: {}",
                err_enum
            );
            return Err(NoiseError::Snow(e));
        }
    };

    tracing::debug!("Noise responder initialized (pattern: {}), waiting for message 1", NOISE_PATTERN);

    let handshake_timeout = std::time::Duration::from_secs(5);

    // 1. Read message 1 length and payload from client (-> e, es) with 5s timeout
    let read_res = tokio::time::timeout(handshake_timeout, async {
        let msg1_len = stream.read_u16().await.map_err(NoiseError::Io)? as usize;
        let mut msg1 = vec![0u8; msg1_len];
        stream.read_exact(&mut msg1).await.map_err(NoiseError::Io)?;
        Ok::<_, NoiseError>((msg1_len, msg1))
    })
    .await;

    let (msg1_len, msg1) = match read_res {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            tracing::error!(error = ?e, "Failed reading Noise message 1 from stream");
            return Err(e);
        }
        Err(_) => {
            tracing::warn!("Handshake timed out waiting for relay response");
            return Err(NoiseError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Handshake timed out waiting for relay response",
            )));
        }
    };

    tracing::info!(
        bytes_len = msg1.len(),
        "Noise message 1 received"
    );

    let mut dummy_payload = [0u8; 128];
    if let Err(e) = responder.read_message(&msg1, &mut dummy_payload) {
        let err_enum = snow_error_enum(&e);
        tracing::error!(
            error = ?e,
            snow_error = %err_enum,
            msg1_len,
            "Noise responder.read_message() failed on message 1 with snow::Error enum: {}",
            err_enum
        );
        return Err(NoiseError::Snow(e));
    }
    tracing::debug!(msg1_len, "Noise handshake message 1 processed successfully");

    // 2. Generate and write message 2 to client (<- e, ee)
    let mut msg2 = vec![0u8; 128];
    let n2 = match responder.write_message(&[], &mut msg2) {
        Ok(n) => n,
        Err(e) => {
            let err_enum = snow_error_enum(&e);
            tracing::error!(
                error = ?e,
                snow_error = %err_enum,
                "Noise responder.write_message() failed on message 2 with snow::Error enum: {}",
                err_enum
            );
            return Err(NoiseError::Snow(e));
        }
    };
    msg2.truncate(n2);

    stream.write_u16(n2 as u16).await?;
    stream.write_all(&msg2).await?;
    stream.flush().await?;
    tracing::debug!(msg2_len = n2, "Noise handshake message 2 sent to client");

    let transport = responder.into_transport_mode()?;
    tracing::debug!("Noise handshake completed successfully; entered transport mode");
    Ok(NoiseSession::new(transport))
}

/// Helper to execute the client-side Noise handshake over an async stream.
pub async fn client_noise_handshake<S>(
    stream: &mut S,
    server_public_key: &[u8],
) -> Result<NoiseSession, NoiseError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut builder = snow::Builder::new(
        NOISE_PATTERN
            .parse()
            .map_err(|e: snow::Error| NoiseError::Snow(e))?,
    );
    if !NOISE_PROLOGUE.is_empty() {
        builder = builder.prologue(NOISE_PROLOGUE)?;
    }
    let mut initiator = builder
        .remote_public_key(server_public_key)?
        .build_initiator()?;

    // 1. Generate and send message 1 (-> e, es)
    let mut msg1 = vec![0u8; 128];
    let n1 = initiator.write_message(&[], &mut msg1)?;
    msg1.truncate(n1);

    stream.write_u16(n1 as u16).await?;
    stream.write_all(&msg1).await?;
    stream.flush().await?;

    // 2. Read message 2 from server (<- e, ee)
    let msg2_len = stream.read_u16().await? as usize;
    let mut msg2 = vec![0u8; msg2_len];
    stream.read_exact(&mut msg2).await?;

    let mut dummy_payload = [0u8; 128];
    initiator.read_message(&msg2, &mut dummy_payload)?;

    let transport = initiator.into_transport_mode()?;
    Ok(NoiseSession::new(transport))
}

/// Async transport helper for reading and writing encrypted EchoMesh frames over a stream.
pub struct NoiseFramedStream<S> {
    stream: S,
    session: NoiseSession,
}

impl<S> NoiseFramedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S, session: NoiseSession) -> Self {
        Self { stream, session }
    }

    /// Sends an encrypted frame.
    pub async fn send_frame(&mut self, frame: &Frame) -> Result<(), NoiseError> {
        let packet = self.session.encrypt_frame(frame)?;
        self.stream.write_all(&packet).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Receives and decrypts a frame.
    pub async fn recv_frame(&mut self) -> Result<Option<Frame>, NoiseError> {
        let len = match self.stream.read_u16().await {
            Ok(len) => len as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(NoiseError::Io(e)),
        };

        if len > ENCRYPTED_FRAME_SIZE {
            return Err(NoiseError::BadMessageSize {
                expected: ENCRYPTED_FRAME_SIZE,
                actual: len,
            });
        }

        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        let frame = self.session.decrypt_frame(&buf)?;
        Ok(Some(frame))
    }

    pub fn session(&self) -> &NoiseSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut NoiseSession {
        &mut self.session
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_noise_handshake_and_frame_exchange() {
        let (mut client_io, mut server_io) = duplex(4096);

        let builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
        let server_keypair = builder.generate_keypair().unwrap();
        let server_pub = server_keypair.public.clone();
        let server_priv = server_keypair.private.clone();

        let client_task = tokio::spawn(async move {
            let session = client_noise_handshake(&mut client_io, &server_pub)
                .await
                .unwrap();
            let mut framed = NoiseFramedStream::new(client_io, session);

            let frame = Frame::new(
                [0x42; 16],
                [1, 2, 3, 4, 5, 6, 7, 8],
                Bytes::from_static(b"Hello Noise Security!"),
            )
            .unwrap();

            framed.send_frame(&frame).await.unwrap();
            let response = framed.recv_frame().await.unwrap().unwrap();
            assert_eq!(response.payload, Bytes::from_static(b"Noise Echo Response"));
        });

        let server_task = tokio::spawn(async move {
            let session = server_noise_handshake(&mut server_io, &server_priv, None)
                .await
                .unwrap();
            let mut framed = NoiseFramedStream::new(server_io, session);

            let frame = framed.recv_frame().await.unwrap().unwrap();
            assert_eq!(
                frame.payload,
                Bytes::from_static(b"Hello Noise Security!")
            );

            let reply = Frame::new(
                frame.session_id,
                [8, 7, 6, 5, 4, 3, 2, 1],
                Bytes::from_static(b"Noise Echo Response"),
            )
            .unwrap();
            framed.send_frame(&reply).await.unwrap();
        });

        let (c, s) = tokio::join!(client_task, server_task);
        c.unwrap();
        s.unwrap();
    }
}
