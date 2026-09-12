#![forbid(unsafe_code)]

//! EchoMesh Stateless Relay
//!
//! High-throughput, zero-knowledge, DPI-resistant relay proxy following the
//! EchoMesh Stateless Relay Specification in ARCHITECTURE.md.

pub mod config;
pub mod crypto;
pub mod protocol;
pub mod server;
pub mod transport;

pub use config::{DEFAULT_SECRET_TOKEN, ECHO_PEER_ID, ECHO_SERVICE_PEER_ID};

pub use crypto::{
    base64_decode, base64_encode, default_key_path, derive_pubkey_path, derive_public_key,
    generate_keypair, load_or_generate_keypair, parse_key_file_arg, resolve_key_file_path,
    KeyError, KeyPair, DEFAULT_KEY_FILE, FALLBACK_KEY_FILE,
};

pub use protocol::{Frame, FrameCodec, ProtocolError, FRAME_SIZE, MAX_PAYLOAD_SIZE};
pub use server::{ListenerConfig, PrefixedStream, RelayListener, RelaySecrets};
pub use transport::{
    client_noise_handshake, hex_decode, hex_encode, server_noise_handshake, ClientHelloStatus,
    NoiseFramedStream, NoiseSession, ParsedClientHello, PseudoTlsBuilder, TokenValidator,
};

