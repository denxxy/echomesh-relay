#![forbid(unsafe_code)]

//! EchoMesh Stateless Relay
//!
//! High-throughput, zero-knowledge, DPI-resistant relay proxy following the
//! EchoMesh Stateless Relay Specification in ARCHITECTURE.md.

pub mod protocol;

pub use protocol::{Frame, FrameCodec, ProtocolError, FRAME_SIZE, MAX_PAYLOAD_SIZE};
