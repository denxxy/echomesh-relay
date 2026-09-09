# EchoMesh Stateless Relay Specification

## 1. Core Architecture
- Purpose: Zero-knowledge, high-throughput, DPI-resistant relay proxy.
- State model: Purely ephemeral (in-memory only). No SQLite, no logs with IP/payload, no disk persistence.
- Concurrency: Tokio async runtime with bounded channels and explicit backpressure.
- Wire format: Fixed-size framed packets (1420 bytes MTU-friendly) with constant-size padding to defeat packet-length analysis.
- Cryptography: Noise Protocol Framework (Noise_NK or Noise_XX using X25519, ChaCha20-Poly1305, BLAKE2s).

## 2. Security Invariants
- Zero unsafe code unless strictly isolated and justified with a safety comment.
- Constant-time validation on all MAC/auth checks (no timing side-channels).
- Drop packets with unknown session IDs silently without returning error payloads (prevents active scanning/probing).
- No sensitive metadata in logs: `tracing` must strictly omit IP addresses, payloads, and session identifiers.