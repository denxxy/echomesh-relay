#![forbid(unsafe_code)]

//! EchoMesh relay binary entrypoint.
//! Secrets are never printed during normal daemon startup.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info};

use echomesh_relay::crypto::{load_or_generate_keypair, resolve_key_file_path};
use echomesh_relay::server::{ListenerConfig, RelayListener, RelaySecrets};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|arg| arg == "--show-public-key" || arg == "show-key") {
        let key_file = resolve_key_file_path(&args);
        let keypair = load_or_generate_keypair(&key_file)?;
        println!("{}", keypair.public_key_base64);
        return Ok(());
    }

    // Explicit credential export remains available for provisioning, but it is never
    // emitted by daemon startup or tracing. Protect stdout at the process boundary.
    if args.iter().any(|arg| arg == "--show-credentials") {
        let key_file = resolve_key_file_path(&args);
        let dummy_bind: SocketAddr = "0.0.0.0:8443".parse().unwrap();
        let secrets = load_secure_secrets(&key_file, dummy_bind, resolve_secret_token(&args))?;
        println!(
            "{{\"public_key_base64\":\"{}\",\"secret_token_hex\":\"{}\"}}",
            secrets.public_key_base64,
            secrets.secret_token_hex
        );
        return Ok(());
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_daemon(args))
}

fn load_secure_secrets(
    key_file: &std::path::Path,
    bind_addr: SocketAddr,
    configured_token: Option<Vec<u8>>,
) -> Result<RelaySecrets, echomesh_relay::crypto::KeyError> {
    let first = RelaySecrets::load_or_generate(key_file, bind_addr, configured_token.clone())?;
    if !first.secret_token.is_empty() {
        return Ok(first);
    }

    // Migration path from the historical compiled default: generate a fresh random
    // credential once and persist it through RelaySecrets' secure file writer.
    let builder = snow::Builder::new(
        echomesh_relay::transport::NOISE_PATTERN
            .parse()
            .map_err(echomesh_relay::crypto::KeyError::Snow)?,
    );
    let random = builder
        .generate_keypair()
        .map_err(echomesh_relay::crypto::KeyError::Snow)?
        .public;
    RelaySecrets::load_or_generate(key_file, bind_addr, Some(random))
}

async fn run_daemon(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let key_file = resolve_key_file_path(&args);
    let bind_str = std::env::var("ECHOMESH_BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8443".to_string());
    let bind_addr: SocketAddr = bind_str.parse().map_err(|e| {
        error!("invalid bind address '{}': {}", bind_str, e);
        e
    })?;

    let fallback_target = std::env::var("ECHOMESH_FALLBACK_TARGET")
        .unwrap_or_else(|_| "cloudflare.com:443".to_string());
    let max_connections: usize = std::env::var("ECHOMESH_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4096);

    let insecure_no_token = args.iter().any(|arg| {
        arg == "--insecure-no-auth" || arg == "--insecure-no-token" || arg == "--dev-mode"
    }) || std::env::var("ECHOMESH_INSECURE_NO_AUTH")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        || std::env::var("ECHOMESH_INSECURE_NO_TOKEN")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    if insecure_no_token {
        tracing::warn!("INSECURE MODE ACTIVE: Pseudo-TLS token validation is disabled");
    }

    let secrets = load_secure_secrets(&key_file, bind_addr, resolve_secret_token(&args))?;
    let config = ListenerConfig::new_with_secrets(bind_addr, secrets.clone())
        .with_fallback_target(fallback_target)
        .with_max_connections(max_connections)
        .with_handshake_timeout(Duration::from_secs(5))
        .with_insecure_no_token(insecure_no_token);

    let listener = RelayListener::bind(config).await?;

    println!("EchoMesh Relay Active");
    println!("Bind: {}", bind_addr);
    println!("Noise Public Key: {}", secrets.public_key_base64);
    println!("Credentials: hidden (use --show-credentials explicitly for provisioning)");
    info!(
        bind = %bind_addr,
        public_key_base64 = %secrets.public_key_base64,
        key_file = %key_file.display(),
        "echomesh-relay started successfully"
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("shutdown signal received");
            let _ = shutdown_tx.send(true);
        }
    });

    listener.run_with_shutdown(shutdown_rx).await?;
    info!("echomesh-relay stopped cleanly");
    Ok(())
}

fn resolve_secret_token(args: &[String]) -> Option<Vec<u8>> {
    args.windows(2)
        .find_map(|w| {
            if w[0] == "--secret" || w[0] == "--secret-token" {
                Some(w[1].clone().into_bytes())
            } else {
                None
            }
        })
        .or_else(|| {
            args.iter().find_map(|a| {
                a.strip_prefix("--secret=")
                    .or_else(|| a.strip_prefix("--secret-token="))
                    .map(|s| s.as_bytes().to_vec())
            })
        })
        .or_else(|| {
            std::env::var("ECHOMESH_SECRET")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.into_bytes())
        })
}
