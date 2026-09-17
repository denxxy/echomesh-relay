# EchoMesh Relay: Networking Architecture

## 1. Executive Summary & Architecture Overview

EchoMesh Relay implements a modular, high-throughput, memory-safe, and cryptographically secure asynchronous networking stack designed in Rust.

The architecture enforces strict separation of concerns across directional boundaries:
- **`CLIENT → SERVER`**: Requests, authentication tokens, connection management, commands, and inbound data.
- **`SERVER → CLIENT`**: Explicit correlated responses and push-based asynchronous server events.

No mixed responsibilities exist across transport, framing, serialization, routing, or business logic. All interactions are strictly typed, bounded, and conform to the 10 Core Architectural Invariants.

---

## 2. Directional Pipelines & Data Flow

### 2.1 CLIENT → SERVER Pipeline

```
+-------------------------------------------------------------------------------+
|                             CLIENT PIPELINE                                   |
+-------------------------------------------------------------------------------+
| 1. High-Level API (EchoMeshClient)                                            |
|    - send_message(payload) -> CorrelationId                                   |
|    - ping() -> CorrelationId                                                  |
|    - send_echo(payload) -> CorrelationId                                      |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 2. Client Outbound Router (ClientOutboundRouter)                              |
|    - Wraps message in ClientToServerMessage                                   |
|    - Allocates monotonically increasing correlation_id                        |
|    - Registers pending response Oneshot Sender (correlation_map)             |
|    - Converts to MessageEnvelope (with session_id, timestamp)                 |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 3. Outbound Serialization (EnvelopeCodec / Frame)                             |
|    - Encodes MessageEnvelope into 30-byte header + binary payload             |
|    - Encapsulates into standard 1420-byte wire Frame                          |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 4. Security & Cryptographic Boundary (SecureTransport)                        |
|    - Noise Protocol NK handshake (Noise_NK_25519_ChaChaPoly_BLAKE2s)          |
|    - ChaCha20-Poly1305 AEAD encryption + 16-byte authentication tag           |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 5. Transport Layer (Transport: TcpTransport / MemoryTransport)                |
|    - SNI Obfuscation / Pseudo-TLS ClientHello preamble (if configured)        |
|    - Asynchronous byte stream delivery over wire                              |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
                               [ NETWORK WIRE ]
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
|                             SERVER PIPELINE                                   |
+-------------------------------------------------------------------------------+
| 6. Transport Layer (TcpTransport / MemoryTransport)                           |
|    - Pseudo-TLS camouflage parser & token validator                           |
|    - Non-compliant scanners routed to camouflage HTTP fallback                |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 7. Security Boundary Decryption (SecureTransport)                             |
|    - Noise AEAD ChaCha20-Poly1305 decryption and tag verification             |
|    - Unauthenticated or corrupted packets dropped immediately                 |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 8. Server Networking Pipeline (ServerPipeline)                                |
|    - Parses 1420-byte Frame from wire                                         |
|    - Validates Frame magic, bounds, and payload size                          |
|    - Decodes MessageEnvelope using EnvelopeCodec                              |
|    - Validates envelope schema (Validate::validate)                           |
|    - Verifies Session ID against active SessionManager                        |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 9. Server Inbound Router (ServerInboundRouter)                                |
|    - Routes ClientToServerMessage by MessageType discriminant                 |
|    - Dispatches to registered ServerInboundHandler:                           |
|      * AuthHandler (MessageType::AuthRequest)                                 |
|      * HeartbeatHandler (MessageType::Heartbeat)                              |
|      * MessageHandler (MessageType::SendMessage)                              |
|      * EchoHandler (MessageType::RawEcho)                                     |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 10. Application Services (e.g., EchoService)                                  |
|    - Executes business logic                                                  |
|    - Produces ServerToClientMessage response or ServerEvent                   |
+-------------------------------------------------------------------------------+
```

---

### 2.2 SERVER → CLIENT Pipeline

```
+-------------------------------------------------------------------------------+
| 1. Application Service / Handler Output                                       |
|    - ServerToClientMessage::Response { correlation_id, ... }                  |
|    - ServerToClientMessage::Event { event: ServerEvent::* }                   |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 2. Server Outbound Router (ServerOutboundRouter)                              |
|    - Builds MessageEnvelope:                                                  |
|      * Sets session_id of destination client                                  |
|      * Preserves correlation_id for responses (or sets 0 for async events)   |
|      * Stamps UTC timestamp                                                   |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 3. Serialized Connection Writer Actor (OutboundWriter)                        |
|    - Enqueues envelope into bounded mpsc channel per connection               |
|    - Single writer task guarantees serialized, interleaved-safe socket writes |
|    - Encodes envelope into wire Frame                                         |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 4. Security Layer (SecureTransport)                                           |
|    - ChaCha20-Poly1305 AEAD frame encryption with Noise transport keys        |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 5. Transport Layer (Transport: TcpTransport / MemoryTransport)                |
|    - Sends encrypted frame through underlying async stream                    |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
                               [ NETWORK WIRE ]
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 6. Client Inbound Router (ClientInboundRouter)                                |
|    - Decrypts and unpacks Frame -> MessageEnvelope -> ServerToClientMessage   |
|    - Inspects message variant:                                                |
|      ├─> Response: looks up correlation_id in pending_requests map,           |
|      │   notifies waiting async caller via oneshot channel                    |
|      └─> Event: dispatches ServerEvent to registered broadcast event handlers |
+-------------------------------------------------------------------------------+
```

---

## 3. Architecture Layers in Detail

### 3.1 Transport Layer (`crate::transport`)
The transport layer abstracts byte-oriented bidirectional communication.
- **`Transport` Trait** (`src/transport/traits.rs`):
  ```rust
  pub trait Transport: Send + Sync + 'static {
      fn send<'a>(&'a mut self, data: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + 'a>>;
      fn receive<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<Option<BytesMut>, TransportError>> + Send + 'a>>;
      fn close<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + 'a>>;
  }
  ```
- **Implementations**:
  - `TcpTransport`: Encapsulates `tokio::net::TcpStream` with keepalive, nodelay, and graceful shutdown.
  - `MemoryTransport`: In-memory bidirectional channel (`tokio::io::DuplexStream`), allowing deterministic unit and integration tests without network I/O or open ports.
  - `SecureTransport<T>`: Wraps any underlying `Transport`, transparently executing Noise NK handshakes and encrypting/decrypting payload frames with zero cipher leakage.
  - `Pseudo-TLS Obfuscator`: Disguises traffic as TLS 1.3 ClientHello records with token validation embedded in SNI or session IDs.

### 3.2 Protocol Layer (`crate::protocol`)
The protocol layer enforces zero-allocation deserialization, wire bounds, and strict schema validation.
- **Envelope Header (`src/protocol/envelope.rs`)**:
  - 30-byte fixed header:
    - `version` (`u8`): Protocol version (`0x01`).
    - `message_type` (`u8`): Message opcode discriminant.
    - `session_id` (`[u8; 16]`): Client session identifier.
    - `correlation_id` (`u32`): Request/response correlation identifier.
    - `timestamp` (`u64`): Milliseconds epoch timestamp.
- **Envelope Codec (`src/protocol/codec/mod.rs`)**:
  - Binary encoding into standard 1420-byte wire frames (`Frame`).
  - Zero-heap allocation framing and overflow checks.
- **Message Typings**:
  - `ClientToServerMessage` (`src/protocol/messages/client_to_server/`): Opcodes `0x01` through `0x7F`.
  - `ServerToClientMessage` (`src/protocol/messages/server_to_client/`): Opcodes `0x80` through `0xFF`.
- **Validation (`src/protocol/validation/mod.rs`)**:
  - `Validate` trait checks message invariants (e.g. response correlation ID != 0, timestamp skew within bounds).

### 3.3 Routing Layer (`crate::server::routing`, `crate::client::routing`)
- **Server Inbound Router (`ServerInboundRouter`)**:
  - Maintains a map of `MessageType -> Box<dyn ServerInboundHandler>`.
  - Handlers execute business actions in isolated async futures.
- **Server Outbound Router (`ServerOutboundRouter`)**:
  - Routes envelopes to appropriate connection queues via `ConnectionManager`.
- **Client Inbound Router (`ClientInboundRouter`)**:
  - Manages pending request table: `correlation_id -> oneshot::Sender<ServerToClientMessage>`.
  - Maintains asynchronous event listener subscribers (`tokio::sync::broadcast`).

### 3.4 Connection & Session Management (`crate::server::connections`, `crate::server::sessions`)
- **`Connection` & `ConnectionId`**:
  - Wraps peer address, creation timestamp, and serialized write sender (`OutboundWriter`).
- **`Session` & `SessionManager`**:
  - Cryptographic session state, peer public keys, authenticated identity, and activity timeouts.
  - Periodic reaping of inactive sessions to prevent state exhaustion attacks.

### 3.5 Client High-Level API (`crate::client::api::EchoMeshClient`)
- Idiomatic, ergonomic async client:
  - `connect(server_addr, auth_token, server_public_key)`: Connects, performs pseudo-TLS handshake, Noise NK key exchange, and authentication.
  - `send_message(payload)`: Sends request and awaits matching response future.
  - `ping()`: Sends heartbeat and returns latency.
  - `send_echo(payload)`: High-speed echo benchmarking.
  - `add_event_handler(subscriber)`: Subscribes to unsolicited server push events.

---

## 4. Connection & Session Lifecycle

```
[Disconnected]
      │
      │ 1. TcpStream::connect / MemoryTransport::pair
      ▼
[Transport Connected]
      │
      │ 2. Pseudo-TLS ClientHello with Auth Token
      ▼
[Obfuscation Verified]
      │ (Invalid token -> routed to Camouflage HTTP website)
      │ 3. Noise_NK Handshake (server static key known)
      ▼
[Secure Channel Established]
      │
      │ 4. Register Connection & Session in SessionManager
      ▼
[Active Session]
      │ ◄──────────┐
      │ Ping/Pong  │ Request/Response & Events
      │            │
      ▼ ───────────┘
[Idle Timeout / Disconnect / Error]
      │
      │ 5. Session dropped, Connection closed, Writer aborted
      ▼
[Closed & Cleaned Up]
```

---

## 5. Error Handling Model

All errors follow a unified, strictly typed hierarchy rooted at `EchoMeshError` (`src/error.rs`):

```
EchoMeshError
  ├── TransportError     (ConnectionReset, Closed, TimedOut, Io)
  ├── ProtocolError      (InvalidMagic, PayloadTooLarge, CorruptFrame, Zero-Alloc Copy)
  ├── ValidationError    (MissingCorrelationId, TimestampSkew, PayloadEmpty)
  ├── AuthenticationError(InvalidToken, CamouflageTriggered, HandshakeFailed)
  ├── AuthorizationError (PermissionDenied, SessionTerminated)
  ├── RoutingError       (HandlerNotFound, RequestTimeout, CorrelationMismatch)
  ├── CryptoError        (AeadError, KeyExchangeFailed, InvalidKey)
  └── ApplicationError   (ServiceUnavailable, InternalError)
```

### Wire Error Responses
Internal errors are **never** leaked verbatim to clients. Instead, they are converted into sanitized, machine-readable `ErrorResponsePayload` structures:
- `error_code`: High-level category (e.g. `"UNAUTHENTICATED"`, `"VALIDATION_FAILED"`).
- `message`: Sanitized human-readable description.
- `retryable`: Boolean indicating if the client can safely retry.

---

## 6. Security Boundaries & Redaction

1. **Camouflage Layer**:
   - Unauthorized internet scans see a standard HTTPS website (Camouflage Fallback).
2. **Noise NK Cryptography**:
   - All frame payloads encrypted using ChaCha20-Poly1305 with 128-bit authentication tags.
   - Forward secrecy over transport frames.
3. **Debug Redaction**:
   - All cryptographic private keys, auth tokens, session keys, and raw payloads implement custom `fmt::Debug` printing `[REDACTED]` to prevent secret leakage in logs.

---

## 7. Request Correlation & Events vs Responses

| Aspect | Response | Event |
|---|---|---|
| **Origin** | Triggered by client request | Server-initiated asynchronous push |
| **Correlation ID** | Non-zero, matches client's request ID | Always `0` |
| **Client Handling** | Resolves pending `oneshot` channel | Dispatched to `broadcast` subscribers |
| **Message Type** | `0x80` - `0xBF` | `0xC0` - `0xFF` |

---

## 8. Extensibility Guides

### 8.1 How to Add a New Message Type

1. **Define the message payload** in `src/protocol/messages/client_to_server/mod.rs` (if C2S) or `server_to_client/mod.rs` (if S2C):
   ```rust
   #[derive(Clone, PartialEq, Serialize, Deserialize)]
   pub struct StatusReportRequest {
       pub system_metrics: Vec<u8>,
   }
   ```
2. **Assign an opcode** in `MessageType` (`src/protocol/envelope.rs`):
   ```rust
   pub const STATUS_REPORT_REQUEST: u8 = 0x0A;
   ```
3. **Implement validation** in `src/protocol/validation/mod.rs`.
4. **Implement a handler** in `src/server/handlers/`:
   ```rust
   pub struct StatusReportHandler;
   impl ServerInboundHandler for StatusReportHandler {
       fn handle<'a>(&'a self, ctx: &'a mut HandlerContext, msg: &'a ClientToServerMessage) -> BoxFuture<'a, Result<Option<ServerToClientMessage>, EchoMeshError>> {
           Box::pin(async move {
               // Process status report
               Ok(Some(ServerToClientMessage::StatusReportResponse(...)))
           })
       }
   }
   ```
5. **Register the handler** in `ServerInboundRouter::with_default_handlers`.

### 8.2 How to Add a New Transport

1. **Implement the `Transport` trait** (`src/transport/traits.rs`):
   ```rust
   pub struct WebSocketTransport { ... }

   impl Transport for WebSocketTransport {
       fn send<'a>(&'a mut self, data: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + 'a>> {
           Box::pin(async move {
               // implementation
               Ok(())
           })
       }
       fn receive<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<Option<BytesMut>, TransportError>> + Send + 'a>> {
           Box::pin(async move {
               // implementation
               Ok(Some(bytes))
           })
       }
       fn close<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + 'a>> {
           Box::pin(async move {
               // implementation
               Ok(())
           })
       }
   }
   ```
2. **Wrap in `SecureTransport<WebSocketTransport>`** to automatically inherit Noise encryption.
3. Pass directly to `ServerPipeline` or `EchoMeshClient`.
