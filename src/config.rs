//! EchoMesh Relay Global Constants and Configuration Defaults.

/// No production authentication secret is compiled into the binary.
/// Operators must provision a token explicitly or use the persisted generated credential.
pub const DEFAULT_SECRET_TOKEN: &[u8] = b"";

/// Static identifier of the internal echo loopback service (32 bytes of 0xEE).
pub const ECHO_PEER_ID: [u8; 32] = [0xEE; 32];
pub const ECHO_SERVICE_PEER_ID: [u8; 32] = ECHO_PEER_ID;
