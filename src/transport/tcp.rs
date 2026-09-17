use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::TransportError;
use crate::transport::noise::MAX_NOISE_MSG_LEN;
use crate::transport::traits::Transport;

/// Asynchronous stream transport with 2-byte Big Endian length-prefix framing.
pub struct TcpTransport<S> {
    stream: S,
    max_frame_size: usize,
}

impl<S> TcpTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            max_frame_size: MAX_NOISE_MSG_LEN,
        }
    }

    pub fn with_max_frame_size(mut self, max: usize) -> Self {
        self.max_frame_size = max;
        self
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> Transport for TcpTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    async fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > self.max_frame_size || frame.len() > u16::MAX as usize {
            return Err(TransportError::Oversized {
                actual: frame.len(),
                max: self.max_frame_size,
            });
        }

        let len_bytes = (frame.len() as u16).to_be_bytes();
        self.stream.write_all(&len_bytes).await?;
        self.stream.write_all(frame).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Option<Bytes>, TransportError> {
        let mut len_buf = [0u8; 2];
        match self.stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(TransportError::Io(e)),
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        if len > self.max_frame_size {
            return Err(TransportError::Oversized {
                actual: len,
                max: self.max_frame_size,
            });
        }

        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        Ok(Some(Bytes::from(buf)))
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.stream.shutdown().await?;
        Ok(())
    }
}
