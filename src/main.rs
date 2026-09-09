#![forbid(unsafe_code)]

//! EchoMesh Stateless Relay Binary Entrypoint.

use echomesh_relay::protocol::{FrameCodec, FRAME_SIZE};
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Security invariant: tracing must strictly omit IP addresses, payloads, and session identifiers.
    info!(
        frame_size = FRAME_SIZE,
        "echomesh-relay initialized successfully"
    );

    let _codec = FrameCodec::new();
}
