#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info};

use echomesh_relay::crypto::{
    derive_relay_json_path, derive_token_path, load_or_generate_keypair, resolve_key_file_path,
};
use echomesh_relay::server::{ListenerConfig, RelayListener, RelaySecrets};
use echomesh_relay::transport::obfuscation::{hex_decode, hex_encode};

// Migration marker only. This legacy credential is public and is never accepted
// as a production default; persisted copies are rotated on startup.
const LEGACY_SHARED_TOKEN_HEX: &str =
    "6563686f6d6573685f7365637265745f6d6573685f746f6b656e5f32303236";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|arg| arg == "--show-public-key" || arg == "show-key") {
        let key_file = resolve_key_file_path(&args);
        let keypair = load_or_generate_keypair(&key_file)?;
        println!("{}", keypair.public_key_base64);
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--show-secret-token") {
        let key_file = resolve_key_file_path(&args);
        let dummy_bind: SocketAddr = "0.0.0.0:8443".parse().unwrap();
        let secrets = RelaySecrets::load_or_generate(
            &key_file,
            dummy_bind,
            Some(resolve_or_generate_secret_token(&args, &key_file)?),
        )?;
        println!("{}", secrets.secret_token_hex);
        return Ok(());
    }

    if args.iter().any(|arg| {
        arg == "--show-credentials" || arg == "--secrets" || arg == "--show-secrets"
    }) {
        let key_file = resolve_key_file_path(&args);
        let dummy_bind: SocketAddr = "0.0.0.0:8443".parse().unwrap();
        let secrets = RelaySecrets::load_or_generate(
            &key_file,
            dummy_bind,
            Some(resolve_or_generate_secret_token(&args, &key_file)?),
        )?;
        println!(
            r#"{{"url":"{}","public_key_hex":"{}","public_key_base64":"{}","secret_token_hex":"[REDACTED]","key_file":"{}"}}"#,
            secrets.url,
            secrets.public_key_hex,
            secrets.public_key_base64,
            key_file.display()
        );
        return Ok(());
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_daemon(args))
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
        error!("invalid bind address: {}", e);
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
    }) || env_true("ECHOMESH_INSECURE_NO_AUTH")
        || env_true("ECHOMESH_INSECURE_NO_TOKEN");

    if insecure_no_token {
        tracing::warn!("INSECURE MODE ACTIVE: pseudo-TLS token validation is disabled");
    }

    let secrets = RelaySecrets::load_or_generate(
        &key_file,
        bind_addr,
        Some(resolve_or_generate_secret_token(&args, &key_file)?),
    )?;
    let config = ListenerConfig::new_with_secrets(bind_addr, secrets.clone())
        .with_fallback_target(fallback_target)
        .with_max_connections(max_connections)
        .with_handshake_timeout(Duration::from_secs(5))
        .with_insecure_no_token(insecure_no_token);
    let listener = RelayListener::bind(config).await?;

    println!(
        "EchoMesh Relay Active\nBind: {}\nNoise Public Key: {}\nCredentials: [REDACTED]",
        bind_addr, secrets.public_key_base64
    );
    info!(
        public_key_base64 = %secrets.public_key_base64,
        max_connections,
        "echomesh relay started"
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("shutdown signal received");
            let _ = shutdown_tx.send(true);
        }
    });

    listener.run_with_shutdown(shutdown_rx).await?;
    info!("echomesh relay stopped cleanly");
    Ok(())
}

fn env_true(name: &str) -> bool {
    std::env::var(name)
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn resolve_or_generate_secret_token(
    args: &[String],
    key_file: &Path,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(explicit) = resolve_secret_token(args) {
        return Ok(explicit);
    }

    if let Some(saved) = read_persisted_secret_token(key_file)? {
        if hex_encode(&saved).eq_ignore_ascii_case(LEGACY_SHARED_TOKEN_HEX) {
            // The old repository-wide credential is already public. Rotate it
            // immediately and let `load_or_generate` overwrite persisted files.
            return generate_secret_token();
        }
        return Ok(saved);
    }

    // First provisioning gets a unique cryptographically random 32-byte token.
    generate_secret_token()
}

fn read_persisted_secret_token(
    key_file: &Path,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let token_path = derive_token_path(key_file);
    if token_path.exists() {
        let raw = std::fs::read(&token_path)?;
        if raw.len() == 32 {
            return Ok(Some(raw));
        }
        let text = String::from_utf8_lossy(&raw).trim().to_owned();
        if let Some(decoded) = hex_decode(&text).filter(|token| !token.is_empty()) {
            return Ok(Some(decoded));
        }
        if !text.is_empty() {
            return Ok(Some(text.into_bytes()));
        }
        return Err(format!("empty persisted relay token: {}", token_path.display()).into());
    }

    let json_path = derive_relay_json_path(key_file);
    if json_path.exists() {
        let content = std::fs::read_to_string(&json_path)?;
        for key in &["\"secret_token_hex\":", "\"secret_token\":"] {
            if let Some(pos) = content.find(key) {
                let rest = &content[pos + key.len()..];
                let start = rest
                    .find('"')
                    .ok_or_else(|| format!("invalid relay credentials: {}", json_path.display()))?
                    + 1;
                let tail = &rest[start..];
                let end = tail
                    .find('"')
                    .ok_or_else(|| format!("invalid relay credentials: {}", json_path.display()))?;
                let value = tail[..end].trim();
                if let Some(decoded) = hex_decode(value).filter(|token| !token.is_empty()) {
                    return Ok(Some(decoded));
                }
                if !value.is_empty() && value != "[REDACTED]" {
                    return Ok(Some(value.as_bytes().to_vec()));
                }
                return Err(
                    format!("empty or redacted persisted relay token: {}", json_path.display())
                        .into(),
                );
            }
        }
        return Err(
            format!("relay credentials contain no token: {}", json_path.display()).into(),
        );
    }

    Ok(None)
}

fn generate_secret_token() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Snow uses the platform CSPRNG for key generation. We only need the
    // resulting 32 random bytes as a bearer token and discard the keypair.
    let builder = snow::Builder::new(echomesh_relay::transport::noise::NOISE_PATTERN.parse()?);
    Ok(builder.generate_keypair()?.public)
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
            args.iter().find_map(|arg| {
                arg.strip_prefix("--secret=")
                    .or_else(|| arg.strip_prefix("--secret-token="))
                    .map(|value| value.as_bytes().to_vec())
            })
        })
        .or_else(|| {
            std::env::var("ECHOMESH_SECRET")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(|value| value.into_bytes())
        })
}
