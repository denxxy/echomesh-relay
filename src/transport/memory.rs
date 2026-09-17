use bytes::Bytes;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::error::TransportError;
use crate::transport::traits::Transport;

/// An in-memory, zero-copy, fully bidirectional transport using Tokio channels.
///
/// Ideal for unit tests, benchmarking, and high-performance in-process messaging
/// without needing real OS network sockets.
pub struct MemoryTransport {
    tx: Sender<Bytes>,
    rx: Receiver<Bytes>,
    closed: bool,
}

impl MemoryTransport {
    /// Creates a pair of interconnected in-memory transports: (Client, Server).
    pub fn pair(buffer_size: usize) -> (Self, Self) {
        let (tx_a, rx_b) = channel(buffer_size);
        let (tx_b, rx_a) = channel(buffer_size);

        let side_a = Self {
            tx: tx_a,
            rx: rx_a,
            closed: false,
        };
        let side_b = Self {
            tx: tx_b,
            rx: rx_b,
            closed: false,
        };

        (side_a, side_b)
    }
}

impl Transport for MemoryTransport {
    async fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::ConnectionClosed);
        }

        let bytes = Bytes::copy_from_slice(frame);
        self.tx
            .send(bytes)
            .await
            .map_err(|_| TransportError::ConnectionClosed)
    }

    async fn receive(&mut self) -> Result<Option<Bytes>, TransportError> {
        if self.closed {
            return Ok(None);
        }

        match self.rx.recv().await {
            Some(bytes) => Ok(Some(bytes)),
            None => {
                self.closed = true;
                Ok(None)
            }
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_transport_exchange() {
        let (mut client, mut server) = MemoryTransport::pair(16);

        client.send(b"ping").await.expect("send ping");
        let received = server.receive().await.expect("recv ping").expect("some");
        assert_eq!(&received[..], b"ping");

        server.send(b"pong").await.expect("send pong");
        let received = client.receive().await.expect("recv pong").expect("some");
        assert_eq!(&received[..], b"pong");

        drop(client);
        assert!(server.receive().await.expect("recv eof").is_none());
    }
}
