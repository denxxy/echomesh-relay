#![forbid(unsafe_code)]

//! EchoMesh Stateless Relay
//!
//! High-throughput, zero-knowledge, DPI-resistant relay proxy following the
//! EchoMesh Stateless Relay Specification in ARCHITECTURE.md.

pub mod protocol;
pub mod server;
pub mod transport;

pub use protocol::{Frame, FrameCodec, ProtocolError, FRAME_SIZE, MAX_PAYLOAD_SIZE};
pub use server::{ListenerConfig, PrefixedStream, RelayListener};
pub use transport::{
    client_noise_handshake, server_noise_handshake, ClientHelloStatus, NoiseFramedStream,
    NoiseSession, ParsedClientHello, PseudoTlsBuilder, TokenValidator,
};
