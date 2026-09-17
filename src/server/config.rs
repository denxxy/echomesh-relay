use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::crypto::{
    base64_encode, derive_relay_json_path, derive_token_path, load_or_generate_keypair, KeyError,
    KeyPair,
};
use crate::transport::noise::NOISE_PATTERN;
use crate::transport::obfuscation::{hex_decode, hex_encode};

#[derive(Clone, PartialEq, Eq)]
pub struct RelaySecrets {
    pub secret_token: Vec<u8>,
    pub secret_token_hex: String,
    pub public_key: Vec<u8>,
    pub public_key_hex: String,
    pub public_key_base64: String,
    pub private_key: Vec<u8>,
    pub private_key_hex: String,
    pub url: String,
    pub key_file: Option<PathBuf>,
}

impl fmt::Debug for RelaySecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelaySecrets")
            .field("url", &self.url)
            .field("public_key_hex", &self.public_key_hex)
            .field("public_key_base64", &self.public_key_base64)
            .field("secret_token", &"[REDACTED]")
            .field("private_key", &"[REDACTED]")
            .field("key_file", &self.key_file)
            .finish()
    }
}

impl fmt::Display for RelaySecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EchoMesh Relay: {} (public key: {})",
            self.url, self.public_key_base64
        )
    }
}

impl RelaySecrets {
    pub fn new(
        secret_token: Vec<u8>,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        url: impl Into<String>,
    ) -> Self {
        Self {
            secret_token_hex: hex_encode(&secret_token),
            public_key_hex: hex_encode(&public_key),
            public_key_base64: base64_encode(&public_key),
            private_key_hex: hex_encode(&private_key),
            secret_token,
            public_key,
            private_key,
            url: url.into(),
            key_file: None,
        }
    }

    pub fn generate(
        bind_addr: SocketAddr,
        secret_token: Option<Vec<u8>>,
    ) -> Result<Self, snow::Error> {
        let builder = snow::Builder::new(NOISE_PATTERN.parse()?);
        let keypair = builder.generate_keypair()?;
        let token = match secret_token.filter(|v| !v.is_empty()) {
            Some(v) => v,
            None => builder.generate_keypair()?.public,
        };
        Ok(Self::new(
            token,
            keypair.public,
            keypair.private,
            format!("https://{}", bind_addr),
        ))
    }

    pub fn from_keypair(
        bind_addr: SocketAddr,
        keypair: KeyPair,
        secret_token: Option<Vec<u8>>,
    ) -> Result<Self, snow::Error> {
        let token = match secret_token.filter(|v| !v.is_empty()) {
            Some(v) => v,
            None => {
                let builder = snow::Builder::new(NOISE_PATTERN.parse()?);
                builder.generate_keypair()?.public
            }
        };
        let mut secrets = Self::new(
            token,
            keypair.public_key,
            keypair.private_key,
            format!("https://{}", bind_addr),
        );
        secrets.public_key_base64 = keypair.public_key_base64;
        secrets.key_file = Some(keypair.key_path);
        Ok(secrets)
    }

    pub fn load_or_generate(
        key_path: &Path,
        bind_addr: SocketAddr,
        configured_token: Option<Vec<u8>>,
    ) -> Result<Self, KeyError> {
        let keypair = load_or_generate_keypair(key_path)?;
        let token = if let Some(token) = configured_token.filter(|v| !v.is_empty()) {
            token
        } else if let Some(token) = read_saved_token(key_path) {
            token
        } else {
            let builder = snow::Builder::new(NOISE_PATTERN.parse()?) ;
            builder.generate_keypair()?.public
        };

        persist_token(key_path, &token, &keypair.public_key_base64)?;
        let mut secrets = Self::new(
            token,
            keypair.public_key,
            keypair.private_key,
            format!("https://{}", bind_addr),
        );
        secrets.public_key_base64 = keypair.public_key_base64;
        secrets.key_file = Some(keypair.key_path);
        Ok(secrets)
    }
}

#[derive(Clone, Debug)]
pub struct ListenerConfig {
    pub bind_addr: SocketAddr,
    pub max_connections: usize,
    pub fallback_target: String,
    pub secret_token: Vec<u8>,
    pub handshake_timeout: Duration,
    pub secrets: RelaySecrets,
    pub insecure_no_token: bool,
}

impl ListenerConfig {
    pub fn new(bind_addr: SocketAddr, secret_token: impl Into<Vec<u8>>) -> Self {
        let token = secret_token.into();
        let secrets = RelaySecrets::generate(bind_addr, Some(token.clone()))
            .expect("relay key generation failed");
        Self::new_with_secrets(bind_addr, secrets)
    }

    pub fn new_with_secrets(bind_addr: SocketAddr, secrets: RelaySecrets) -> Self {
        Self {
            bind_addr,
            max_connections: 1024,
            fallback_target: "cloudflare.com:443".into(),
            secret_token: secrets.secret_token.clone(),
            handshake_timeout: Duration::from_secs(5),
            secrets,
            insecure_no_token: false,
        }
    }

    pub fn with_secrets(mut self, secrets: RelaySecrets) -> Self {
        self.secret_token = secrets.secret_token.clone();
        self.secrets = secrets;
        self
    }
    pub fn with_fallback_target(mut self, target: impl Into<String>) -> Self { self.fallback_target = target.into(); self }
    pub fn with_max_connections(mut self, max: usize) -> Self { self.max_connections = max.max(1); self }
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self { self.handshake_timeout = timeout; self }
    pub fn with_insecure_no_token(mut self, enabled: bool) -> Self { self.insecure_no_token = enabled; self }
    pub fn with_insecure_no_auth(self, enabled: bool) -> Self { self.with_insecure_no_token(enabled) }
}

fn read_saved_token(key_path: &Path) -> Option<Vec<u8>> {
    let json_path = derive_relay_json_path(key_path);
    if let Ok(content) = std::fs::read_to_string(json_path) {
        if let Some(marker) = content.find("\"secret_token_hex\"") {
            let tail = &content[marker + "\"secret_token_hex\"".len()..];
            if let Some(colon) = tail.find(':') {
                let tail = tail[colon + 1..].trim_start();
                if let Some(value) = tail.strip_prefix('"').and_then(|v| v.split('"').next()) {
                    if let Some(decoded) = hex_decode(value) { if !decoded.is_empty() { return Some(decoded); } }
                }
            }
        }
    }
    let token_path = derive_token_path(key_path);
    let raw = std::fs::read(token_path).ok()?;
    let text = String::from_utf8_lossy(&raw).trim().to_string();
    if text.is_empty() { return None; }
    hex_decode(&text).or_else(|| Some(text.into_bytes()))
}

fn persist_token(key_path: &Path, token: &[u8], public_key_base64: &str) -> Result<(), std::io::Error> {
    let token_hex = hex_encode(token);
    let token_path = derive_token_path(key_path);
    let json_path = derive_relay_json_path(key_path);
    write_private(&token_path, format!("{}\n", token_hex).as_bytes())?;
    let json = format!(
        "{{\n  \"public_key_base64\": \"{}\",\n  \"secret_token_hex\": \"{}\"\n}}\n",
        public_key_base64, token_hex
    );
    write_private(&json_path, json.as_bytes())
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() { if !parent.as_os_str().is_empty() { std::fs::create_dir_all(parent)?; } }
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(path)?;
        file.write_all(data)?;
        file.flush()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn debug_and_display_redact_credentials() {
        let secrets = RelaySecrets::new(vec![0xAA; 32], vec![1; 32], vec![2; 32], "https://127.0.0.1:1");
        let token_hex = hex_encode(&[0xAA; 32]);
        assert!(!format!("{:?}", secrets).contains(&token_hex));
        assert!(!format!("{}", secrets).contains(&token_hex));
        assert!(!format!("{:?}", secrets).contains(&hex_encode(&[2; 32])));
    }
}
