//! EchoMesh Relay Global Constants and Configuration Defaults.

pub const DEFAULT_SECRET_TOKEN: &[u8] = b"echomesh_secret_mesh_token_2026";

/// Static identifier of the internal echo loopback service (32 bytes of 0xEE).
pub const ECHO_SERVICE_PEER_ID: [u8; 32] = [0xEE; 32];
