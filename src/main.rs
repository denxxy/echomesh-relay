#![forbid(unsafe_code)]

//! EchoMesh Stateless Relay Binary Entrypoint.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info};

use echomesh_relay::crypto::{load_or_generate_keypair, resolve_key_file_path};
use echomesh_relay::server::{ListenerConfig, RelayListener, RelaySecrets};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing-subscriber with fallback to INFO level
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let key_file = resolve_key_file_path(&args);

    // Handle CLI inspection flags: --show-public-key or subcommand show-key
    if args.iter().any(|arg| arg == "--show-public-key" || arg == "show-key") {
        let keypair = load_or_generate_keypair(&key_file)?;
        println!("{}", keypair.public_key_base64);
        return Ok(());
    }

    let bind_str = std::env::var("ECHOMESH_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8443".to_string());
    let bind_addr: SocketAddr = bind_str.parse().map_err(|e| {
        error!("invalid bind address '{}': {}", bind_str, e);
        e
    })?;

    let secret_token_opt = std::env::var("ECHOMESH_SECRET")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.into_bytes());

    let fallback_target = std::env::var("ECHOMESH_FALLBACK_TARGET")
        .unwrap_or_else(|_| "cloudflare.com:443".to_string());

    let max_connections: usize = std::env::var("ECHOMESH_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4096);

    let secrets = RelaySecrets::load_or_generate(&key_file, bind_addr, secret_token_opt)?;

    // Handle CLI inspection flags: --secrets or --show-secrets or --json
    let wants_json = args.iter().any(|arg| arg == "--json");
    if args.iter().any(|arg| arg == "--secrets" || arg == "--show-secrets") {
        if wants_json {
            println!(
                r#"{{"url":"{}","public_key_hex":"{}","public_key_base64":"{}","secret_token_hex":"{}","secret_token":"{}","key_file":"{}"}}"#,
                secrets.url,
                secrets.public_key_hex,
                secrets.public_key_base64,
                secrets.secret_token_hex,
                String::from_utf8_lossy(&secrets.secret_token),
                key_file.display()
            );
        } else {
            println!("{}", secrets);
        }
        return Ok(());
    }

    let config = ListenerConfig::new_with_secrets(bind_addr, secrets.clone())
        .with_fallback_target(fallback_target)
        .with_max_connections(max_connections)
        .with_handshake_timeout(Duration::from_secs(5));

    let listener = RelayListener::bind(config).await?;

    let startup_banner = format!(
        "======================================================\n\
EchoMesh Relay started\n\
Bind Address: {}\n\
Server Noise Public Key (Base64): {}\n\
Key file: {}\n\
======================================================",
        bind_addr,
        secrets.public_key_base64,
        key_file.display()
    );

    // Guaranteed banner output to both tracing and stderr
    info!("{}", startup_banner);
    eprintln!("{}", startup_banner);

    // Return secrets prominently on startup to stdout
    if wants_json {
        println!(
            r#"{{"url":"{}","public_key_hex":"{}","public_key_base64":"{}","secret_token_hex":"{}","secret_token":"{}","key_file":"{}"}}"#,
            secrets.url,
            secrets.public_key_hex,
            secrets.public_key_base64,
            secrets.secret_token_hex,
            String::from_utf8_lossy(&secrets.secret_token),
            key_file.display()
        );
    } else {
        println!(
            r#"
================================================================================
                    ECHOMESH STATELESS RELAY INITIALIZED
================================================================================
  Server Bind:                 {}
  Fallback Camouflage:         {}
  Max Connections:             {}
  Key File:                    {}

  [AUTHENTICATION & CRYPTO SECRETS]
  Secret Token (Raw):          {}
  Secret Token (Hex):          {}
  Public Key (Hex):            {}
  Public Key (Base64):         {}

  [CLIENT CONFIGURATION / MTGRAM SETTINGS]
  Relay URL:                   {}
  Relay Public Key:            {}
  Noise Static Public (Base64):{}
================================================================================
"#,
            bind_addr,
            listener.config().fallback_target,
            listener.config().max_connections,
            key_file.display(),
            String::from_utf8_lossy(&secrets.secret_token),
            secrets.secret_token_hex,
            secrets.public_key_hex,
            secrets.public_key_base64,
            secrets.url,
            secrets.public_key_hex,
            secrets.public_key_base64,
        );
    }

    info!(
        url = %secrets.url,
        public_key_hex = %secrets.public_key_hex,
        public_key_base64 = %secrets.public_key_base64,
        secret_token_hex = %secrets.secret_token_hex,
        key_file = %key_file.display(),
        "echomesh-relay started successfully"
    );

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
