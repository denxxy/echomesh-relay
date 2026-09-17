use crate::error::CryptoError;
use crate::protocol::frame::{Frame, FrameCodec, FRAME_SIZE};
use crate::transport::noise::{NoiseError, NoiseSession, NOISE_TAG_LEN};
use crate::transport::traits::Transport;

/// Bridges a generic `Transport` with a `NoiseSession`, providing encrypted `Frame` exchange.
pub struct SecureTransport<T> {
    transport: T,
    session: NoiseSession,
}

impl<T: Transport> SecureTransport<T> {
    pub fn new(transport: T, session: NoiseSession) -> Self {
        Self { transport, session }
    }

    /// Encrypts an EchoMesh `Frame` and transmits it across the transport.
    pub async fn send_frame(&mut self, frame: &Frame) -> Result<(), CryptoError> {
        let mut raw_frame = bytes::BytesMut::with_capacity(FRAME_SIZE);
        let mut codec = FrameCodec::new();
        tokio_util::codec::Encoder::encode(&mut codec, frame.clone(), &mut raw_frame)
            .map_err(|_| CryptoError::Key("frame encoding failed".to_string()))?;

        let mut cipher_text = vec![0u8; raw_frame.len() + NOISE_TAG_LEN];
        let n = self.session.encrypt(&raw_frame, &mut cipher_text)
            .map_err(|e: NoiseError| match e {
                NoiseError::Snow(s) => CryptoError::Snow(s),
                _ => CryptoError::DecryptionFailed,
            })?;
        cipher_text.truncate(n);

        self.transport
            .send(&cipher_text)
            .await
            .map_err(|_| CryptoError::Key("transport send failed".to_string()))?;

        Ok(())
    }

    /// Receives an encrypted packet from the transport and decrypts it into a `Frame`.
    pub async fn recv_frame(&mut self) -> Result<Option<Frame>, CryptoError> {
        let packet = match self.transport.receive().await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(_) => return Err(CryptoError::Key("transport recv failed".to_string())),
        };

        let mut plain_buf = vec![0u8; packet.len()];
        let n = self.session.decrypt(&packet, &mut plain_buf)
            .map_err(|e: NoiseError| match e {
                NoiseError::Snow(s) => CryptoError::Snow(s),
                _ => CryptoError::DecryptionFailed,
            })?;
        plain_buf.truncate(n);

        let frame = Frame::from_slice(&plain_buf)
            .map_err(|_| CryptoError::Key("frame parsing failed".to_string()))?;

        Ok(Some(frame))
    }

    pub fn session(&self) -> &NoiseSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut NoiseSession {
        &mut self.session
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn into_parts(self) -> (T, NoiseSession) {
        (self.transport, self.session)
    }
}
