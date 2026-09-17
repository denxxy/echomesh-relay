use std::future::Future;
use bytes::Bytes;
use crate::error::TransportError;

/// Core transport abstraction.
///
/// Neither the protocol layer nor the application layer knows or depends on
/// the underlying physical medium (TCP, Memory duplex, WebSockets, Bluetooth, etc.).
pub trait Transport: Send + Sync {
    /// Sends a discrete framed packet across the transport.
    fn send(&mut self, frame: &[u8]) -> impl Future<Output = Result<(), TransportError>> + Send;

    /// Receives the next discrete framed packet from the transport.
    /// Returns `Ok(None)` when the remote end has cleanly closed the transport.
    fn receive(&mut self) -> impl Future<Output = Result<Option<Bytes>, TransportError>> + Send;

    /// Closes the transport gracefully.
    fn close(&mut self) -> impl Future<Output = Result<(), TransportError>> + Send;
}
