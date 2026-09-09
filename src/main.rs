#![forbid(unsafe_code)]

//! EchoMesh Stateless Relay Binary Entrypoint.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info};

use echomesh_relay::server::{ListenerConfig, RelayListener};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let bind_str = std::env::var("ECHOMESH_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8443".to_string());
    let bind_addr: SocketAddr = bind_str.parse().map_err(|e| {
        error!("invalid bind address '{}': {}", bind_str, e);
        e
    })?;

    let secret_token = std::env::var("ECHOMESH_SECRET")
        .unwrap_or_else(|_| "echomesh_default_pre_shared_secret_32bytes".to_string())
        .into_bytes();

    let fallback_target = std::env::var("ECHOMESH_FALLBACK_TARGET")
        .unwrap_or_else(|_| "cloudflare.com:443".to_string());

    let max_connections: usize = std::env::var("ECHOMESH_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4096);

    let config = ListenerConfig::new(bind_addr, secret_token)
        .with_fallback_target(fallback_target)
        .with_max_connections(max_connections)
        .with_handshake_timeout(Duration::from_secs(5));

    let listener = RelayListener::bind(config).await?;
    info!("echomesh-relay started on {}", bind_addr);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            info!("shutdown signal received, closing listener...");
            let _ = shutdown_tx.send(true);
        }
    });

    listener.run_with_shutdown(shutdown_rx).await?;
    info!("echomesh-relay stopped cleanly");

    Ok(())
}
