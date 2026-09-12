//! EchoMesh Relay Global Constants and Configuration Defaults.

/// No shared production authentication secret is compiled into EchoMesh.
/// A relay generates and persists a unique token on first provisioning, or an
/// operator supplies one explicitly.
pub const DEFAULT_SECRET_TOKEN: &[u8] = &[];

/// Static identifier of the internal echo loopback service (32 bytes of 0xEE).
pub const ECHO_PEER_ID: [u8; 32] = [0xEE; 32];
pub const ECHO_SERVICE_PEER_ID: [u8; 32] = ECHO_PEER_ID;
