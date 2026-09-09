# syntax=docker/dockerfile:1

# Stage 1: Multi-stage builder on rust:alpine (multi-arch compatible: amd64, arm64)
FROM --platform=$BUILDPLATFORM rust:alpine AS builder

# Install build dependencies for musl static compilation
RUN apk add --no-cache musl-dev gcc libc-dev

# Create unprivileged system user (UID 10001) for scratch runtime
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid 10001 \
    echomesh

WORKDIR /build

# Pre-cache cargo dependencies for faster layer caching
COPY Cargo.toml Cargo.lock ./
RUN mkdir src benches && \
    echo "pub fn dummy() {}" > src/lib.rs && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > benches/throughput.rs && \
    cargo build --release && \
    rm -rf src benches

# Copy full repository source code
COPY src ./src
COPY benches ./benches
COPY ARCHITECTURE.md ./

# Compile statically linked release binary with LTO and symbols stripped
RUN touch src/lib.rs src/main.rs && \
    cargo build --release --bin echomesh-relay && \
    strip target/release/echomesh-relay

# Stage 2: Final minimal scratch container image
FROM scratch

# Copy minimal user and group definitions
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy CA certificates for HTTPS/TLS fallback connections
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy statically linked zero-dependency binary
COPY --from=builder /build/target/release/echomesh-relay /echomesh-relay

# Run as non-root unprivileged user
USER 10001:10001

# Expose default service port
EXPOSE 8443

# Stateless immutable container configuration
ENTRYPOINT ["/echomesh-relay"]
