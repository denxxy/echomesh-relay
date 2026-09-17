use std::fmt;

/// Top-level unified error enum for the EchoMesh system.
#[derive(Debug, thiserror::Error)]
pub enum EchoMeshError {
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("authentication error: {0}")]
    Authentication(#[from] AuthenticationError),

    #[error("authorization error: {0}")]
    Authorization(#[from] AuthorizationError),

    #[error("routing error: {0}")]
    Routing(#[from] RoutingError),

    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("application error: {0}")]
    Application(#[from] ApplicationError),
}

/// Errors originating at the physical or logical network transport layer.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("underlying I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("transport connection closed unexpectedly")]
    ConnectionClosed,

    #[error("operation timed out")]
    Timeout,

    #[error("buffer overflow or oversized frame: {actual} bytes > maximum {max} bytes")]
    Oversized { actual: usize, max: usize },

    #[error("malformed transport header: {0}")]
    MalformedHeader(String),

    #[error("transport not connected")]
    NotConnected,
}

/// Errors related to wire protocol parsing, envelopes, framing, and versioning.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("frame too short: expected {expected} bytes, got {actual}")]
    FrameTooShort { expected: usize, actual: usize },

    #[error("payload length {actual} exceeds maximum allowed size of {max} bytes")]
    PayloadTooLarge { actual: usize, max: usize },

    #[error("unsupported protocol version: expected {expected}, got {actual}")]
    UnsupportedVersion { expected: u8, actual: u8 },

    #[error("unknown or invalid message type ID: {0}")]
    UnknownMessageType(u8),

    #[error("malformed message envelope: {0}")]
    MalformedEnvelope(&'static str),

    #[error("unexpected message direction or role")]
    UnexpectedDirection,

    #[error("general I/O protocol error")]
    Io,
}

impl From<std::io::Error> for ProtocolError {
    fn from(_: std::io::Error) -> Self {
        ProtocolError::Io
    }
}

/// Errors related to validation of message fields, bounds, and parameters.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("field '{field}' is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },

    #[error("payload exceeds maximum size: {actual} > {max}")]
    PayloadTooLarge { actual: usize, max: usize },

    #[error("message timestamp is out of acceptable time window: timestamp={timestamp}, now={now}")]
    TimestampSkew { timestamp: u64, now: u64 },

    #[error("duplicate message ID detected: {0}")]
    DuplicateMessageId(u64),

    #[error("missing required correlation ID for response")]
    MissingCorrelationId,
}

/// Errors encountered during authentication or pseudo-TLS camouflage verification.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AuthenticationError {
    #[error("invalid secret token")]
    InvalidToken,

    #[error("unauthenticated handshake attempt")]
    Unauthenticated,

    #[error("handshake timed out")]
    HandshakeTimeout,

    #[error("session expired or revoked")]
    SessionExpired,
}

/// Errors related to permissions or forbidden operations.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("permission denied for action '{action}' on target '{target}'")]
    PermissionDenied {
        action: &'static str,
        target: String,
    },

    #[error("unauthorized peer identity")]
    UnauthorizedPeer,
}

/// Errors encountered while routing messages across inbound and outbound pipelines.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RoutingError {
    #[error("no route found for destination peer: {0}")]
    DestinationNotFound(String),

    #[error("unhandled message type: {0}")]
    UnhandledMessageType(u8),

    #[error("pending request not found for correlation ID: {0}")]
    CorrelationNotFound(u64),

    #[error("handler execution failed: {0}")]
    HandlerFailed(String),

    #[error("outbound channel is closed or full")]
    ChannelClosed,
}

/// Errors originating from cryptographic operations (Noise, keys, ciphers).
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Noise cryptographic failure: {0}")]
    Snow(#[from] snow::Error),

    #[error("key error: {0}")]
    Key(String),

    #[error("MAC or authentication tag verification failed")]
    MacMismatch,

    #[error("decryption failed")]
    DecryptionFailed,
}

/// Domain / service-level application errors.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ApplicationError {
    #[error("service unavailable: {0}")]
    ServiceUnavailable(&'static str),

    #[error("internal service failure: {0}")]
    Internal(&'static str),

    #[error("service-specific error: code={code}, message={message}")]
    Custom { code: u32, message: String },
}

/// Safe protocol error payload returned to clients across the network wire.
/// Internal diagnostic strings remain in server logs and are never leaked here.
#[derive(Clone, PartialEq, Eq)]
pub struct ErrorResponsePayload {
    pub code: u32,
    pub correlation_id: u64,
    pub message: String,
}

impl fmt::Debug for ErrorResponsePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorResponsePayload")
            .field("code", &self.code)
            .field("correlation_id", &self.correlation_id)
            .field("message", &self.message)
            .finish()
    }
}

impl ErrorResponsePayload {
    pub fn new(code: u32, correlation_id: u64, message: impl Into<String>) -> Self {
        Self {
            code,
            correlation_id,
            message: message.into(),
        }
    }
}
