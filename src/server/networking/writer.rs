use tokio::sync::mpsc::Receiver;
use tracing::{debug, warn};

use crate::protocol::frame::Frame;
use crate::transport::noise::NoiseFramedStream;

/// Actor that serializes outbound frame writes to the underlying stream.
///
/// Prevents uncontrolled concurrent socket writes, guarantees frame boundary
/// integrity, and provides natural backpressure via bounded channels.
pub struct OutboundWriter;

impl OutboundWriter {
    /// Runs the outbound write loop for a stream.
    pub async fn run<S>(
        mut framed_stream: NoiseFramedStream<S>,
        mut outbound_rx: Receiver<Frame>,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        while let Some(frame) = outbound_rx.recv().await {
            if let Err(err) = framed_stream.send_frame(&frame).await {
                warn!("failed to send frame to client: {:?}", err);
                break;
            }
        }
        debug!("outbound writer loop finished cleanly");
    }
}
