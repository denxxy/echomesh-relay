# EchoMesh Relay (`echomesh-relay`)

High-throughput, zero-knowledge, DPI-resistant relay proxy following the [EchoMesh Stateless Relay Specification](ARCHITECTURE.md).

## Features

- **Fixed-Size Wire Format**: Strictly 1420 bytes (`FRAME_SIZE`) with constant-size padding to defeat packet-length analysis.
- **Packet Structure**:
  - `SessionId` (16 bytes)
  - `Nonce` (8 bytes)
  - `PayloadLength` (2 bytes, Big Endian)
  - `Payload` (variable size, up to 1394 bytes)
  - `Padding` (zero/random padding up to 1420 bytes)
- **Zero-Allocation Error Handling**: Custom `ProtocolError` enum implementing `Copy` with zero heap allocations on error paths.
- **Tokio Codec Integration**: Full `tokio_util::codec::{Encoder, Decoder}` support for streaming and fragmented buffer processing.
- **Strict Security Invariants**:
  - `#![forbid(unsafe_code)]`
  - Constant-time validation (`constant_time_eq`, `session_id_eq`) to mitigate timing side-channel attacks.
  - Sensitive metadata protection: `Frame` debug representation redacts `session_id` and payload contents in logs.

## Building & Testing

```bash
# Run unit tests
cargo test

# Run clippy checks
cargo clippy -- -D warnings

# Build release binary (LTO enabled, single codegen unit)
cargo build --release
```
