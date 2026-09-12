use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use snow::params::DHChoice;
use snow::resolvers::{CryptoResolver, DefaultResolver};

use crate::transport::{hex_decode, hex_encode};
use crate::transport::noise::NOISE_PATTERN;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Noise cryptographic error: {0}")]
    Snow(#[from] snow::Error),

    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

pub const DEFAULT_KEY_FILE: &str = "/etc/echomesh/relay.key";
pub const FALLBACK_KEY_FILE: &str = "./relay.key";

const BASE64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        result.push(BASE64_ALPHABET[(b0 >> 2) as usize] as char);
        result.push(BASE64_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            result.push(BASE64_ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(BASE64_ALPHABET[(b2 & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Some(Vec::new());
    }
    let mut buffer = 0u32;
    let mut bits_collected = 0;
    let mut output = Vec::with_capacity(trimmed.len() * 3 / 4);
    for &b in trimmed.as_bytes() {
        if b == b'=' {
            break;
        }
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b' ' | b'\r' | b'\n' | b'\t' => continue,
            _ => return None,
        };
        buffer = (buffer << 6) | val as u32;
        bits_collected += 6;
        if bits_collected >= 8 {
            bits_collected -= 8;
            output.push((buffer >> bits_collected) as u8);
            buffer &= (1 << bits_collected) - 1;
        }
    }
    Some(output)
}

pub fn derive_public_key(private_key: &[u8]) -> Result<Vec<u8>, snow::Error> {
    if private_key.len() != 32 {
        return Err(snow::Error::Init(snow::error::InitStage::GetDhImpl));
    }
    let resolver = DefaultResolver;
    let mut dh = resolver
        .resolve_dh(&DHChoice::Curve25519)
        .ok_or(snow::Error::Init(snow::error::InitStage::GetDhImpl))?;
    dh.set(private_key);
    Ok(dh.pubkey().to_vec())
}

pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), snow::Error> {
    let builder = snow::Builder::new(NOISE_PATTERN.parse()?);
    let keypair = builder.generate_keypair()?;
    Ok((keypair.private, keypair.public))
}

#[derive(Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub public_key_base64: String,
    pub key_path: PathBuf,
    pub pub_path: PathBuf,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key_base64", &self.public_key_base64)
            .field("key_path", &self.key_path)
            .field("pub_path", &self.pub_path)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

pub fn default_key_path() -> PathBuf {
    let etc_key = Path::new(DEFAULT_KEY_FILE);
    if etc_key.exists() {
        return etc_key.to_path_buf();
    }
    if let Some(parent) = etc_key.parent() {
        if parent.is_dir() {
            return etc_key.to_path_buf();
        }
    }
    PathBuf::from(FALLBACK_KEY_FILE)
}

pub fn parse_key_file_arg(args: &[String]) -> Option<PathBuf> {
    for i in 0..args.len() {
        if args[i] == "--key-file" && i + 1 < args.len() {
            return Some(PathBuf::from(&args[i + 1]));
        }
        if let Some(path) = args[i].strip_prefix("--key-file=") {
            return Some(PathBuf::from(path));
        }
    }
    None
}

pub fn resolve_key_file_path(args: &[String]) -> PathBuf {
    if let Some(cli_path) = parse_key_file_arg(args) {
        return cli_path;
    }
    if let Ok(env_path) = std::env::var("ECHOMESH_KEY_FILE") {
        let trimmed = env_path.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    default_key_path()
}

pub fn derive_pubkey_path(key_path: &Path) -> PathBuf {
    let parent = key_path.parent().unwrap_or_else(|| Path::new(""));
    if parent.as_os_str().is_empty() {
        PathBuf::from("relay.pub")
    } else {
        parent.join("relay.pub")
    }
}

pub fn derive_token_path(key_path: &Path) -> PathBuf {
    let stem_token = key_path.with_extension("token");
    if stem_token != key_path {
        return stem_token;
    }
    let parent = key_path.parent().unwrap_or_else(|| Path::new(""));
    if parent.as_os_str().is_empty() {
        PathBuf::from("relay.token")
    } else {
        parent.join("relay.token")
    }
}

pub fn derive_relay_json_path(key_path: &Path) -> PathBuf {
    let stem_json = key_path.with_extension("json");
    if stem_json != key_path {
        return stem_json;
    }
    let parent = key_path.parent().unwrap_or_else(|| Path::new(""));
    if parent.as_os_str().is_empty() {
        PathBuf::from("relay.json")
    } else {
        parent.join("relay.json")
    }
}

fn parse_private_key_bytes(raw: &[u8]) -> Result<Vec<u8>, KeyError> {
    if raw.len() == 32 {
        return Ok(raw.to_vec());
    }
    let text = String::from_utf8_lossy(raw).trim().to_string();
    if text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Some(decoded) = hex_decode(&text) {
            if decoded.len() == 32 {
                return Ok(decoded);
            }
        }
    }
    if let Some(decoded) = base64_decode(&text) {
        if decoded.len() == 32 {
            return Ok(decoded);
        }
    }
    Err(KeyError::InvalidKey(format!(
        "expected 32 bytes (raw, 64-char hex, or base64), got {} bytes",
        raw.len()
    )))
}

fn write_private_key_file(key_path: &Path, private_key: &[u8]) -> Result<(), KeyError> {
    write_secret_file(key_path, private_key)
}

fn write_secret_file(path: &Path, data: &[u8]) -> Result<(), KeyError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
        file.flush()?;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    #[cfg(not(unix))]
    {
        let mut file = File::create(path)?;
        file.write_all(data)?;
        file.flush()?;
    }
    Ok(())
}

fn write_public_key_file(
    key_path: &Path,
    pub_path: &Path,
    public_key_base64: &str,
) -> Result<(), KeyError> {
    let content = format!("{}\n", public_key_base64);
    std::fs::write(pub_path, &content)?;
    let stem_pub = key_path.with_extension("pub");
    if stem_pub != pub_path {
        let _ = std::fs::write(&stem_pub, &content);
    }
    Ok(())
}

fn parse_saved_token_value(raw: &str) -> Option<Vec<u8>> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(decoded) = hex_decode(value) {
        if !decoded.is_empty() {
            return Some(decoded);
        }
    }
    Some(value.as_bytes().to_vec())
}

fn read_existing_auth_token(key_path: &Path) -> Option<Vec<u8>> {
    let json_path = derive_relay_json_path(key_path);
    if let Ok(content) = std::fs::read_to_string(&json_path) {
        for key in &["\"secret_token_hex\":", "\"secret_token\":"] {
            if let Some(pos) = content.find(key) {
                let rest = &content[pos + key.len()..];
                let start = rest.find('"')? + 1;
                let tail = &rest[start..];
                let end = tail.find('"')?;
                if let Some(token) = parse_saved_token_value(&tail[..end]) {
                    return Some(token);
                }
            }
        }
    }

    let token_path = derive_token_path(key_path);
    let raw = std::fs::read(&token_path).ok()?;
    if raw.len() == 32 && raw.iter().any(|byte| *byte != 0) {
        return Some(raw);
    }
    let text = String::from_utf8_lossy(&raw);
    parse_saved_token_value(&text)
}

fn ensure_auth_token_files(keypair: &KeyPair) -> Result<(), KeyError> {
    if read_existing_auth_token(&keypair.key_path).is_some() {
        return Ok(());
    }

    // Reuse Snow's CSPRNG-backed key generation to obtain 32 fresh random bytes.
    // The generated pair is discarded; only its public bytes become the relay auth token.
    let (_, token) = generate_keypair()?;
    let token_hex = hex_encode(&token);
    let token_path = derive_token_path(&keypair.key_path);
    write_secret_file(&token_path, format!("{}\n", token_hex).as_bytes())?;

    let json = format!(
        "{{\n  \"public_key_base64\": \"{}\",\n  \"secret_token_hex\": \"{}\"\n}}\n",
        keypair.public_key_base64, token_hex
    );
    write_secret_file(&derive_relay_json_path(&keypair.key_path), json.as_bytes())?;
    Ok(())
}

pub fn load_or_generate_keypair(key_path: &Path) -> Result<KeyPair, KeyError> {
    let pub_path = derive_pubkey_path(key_path);
    let keypair = if key_path.exists() {
        let mut file = File::open(key_path)?;
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)?;
        let private_key = parse_private_key_bytes(&raw)?;
        let public_key = derive_public_key(&private_key)?;
        let public_key_base64 = base64_encode(&public_key);
        let _ = write_public_key_file(key_path, &pub_path, &public_key_base64);
        KeyPair {
            private_key,
            public_key,
            public_key_base64,
            key_path: key_path.to_path_buf(),
            pub_path,
        }
    } else {
        let (private_key, public_key) = generate_keypair()?;
        let public_key_base64 = base64_encode(&public_key);
        write_private_key_file(key_path, &private_key)?;
        write_public_key_file(key_path, &pub_path, &public_key_base64)?;
        KeyPair {
            private_key,
            public_key,
            public_key_base64,
            key_path: key_path.to_path_buf(),
            pub_path,
        }
    };

    ensure_auth_token_files(&keypair)?;
    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode_decode_roundtrip() {
        let vectors: &[&[u8]] = &[
            b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar",
            &[0u8; 32], &[0xff; 32], b"EchoMesh Stateless Relay Key Persistence!",
        ];
        for &vec in vectors {
            let encoded = base64_encode(vec);
            let decoded = base64_decode(&encoded).expect("decode valid base64");
            assert_eq!(decoded, vec, "Failed roundtrip for vector: {:?}", vec);
        }
    }

    #[test]
    fn test_derive_public_key_matches_generated() {
        let (private_key, expected_public) = generate_keypair().expect("generate keypair");
        let derived_public = derive_public_key(&private_key).expect("derive public key");
        assert_eq!(derived_public, expected_public);
    }

    #[test]
    fn test_parse_key_file_arg_variants() {
        let args1 = vec![
            "echomesh-relay".to_string(),
            "--key-file".to_string(),
            "/path/to/relay.key".to_string(),
        ];
        assert_eq!(parse_key_file_arg(&args1), Some(PathBuf::from("/path/to/relay.key")));
        let args2 = vec![
            "echomesh-relay".to_string(),
            "--key-file=/custom/relay.key".to_string(),
        ];
        assert_eq!(parse_key_file_arg(&args2), Some(PathBuf::from("/custom/relay.key")));
        let args3 = vec!["echomesh-relay".to_string(), "--show-secrets".to_string()];
        assert_eq!(parse_key_file_arg(&args3), None);
    }

    #[test]
    fn first_run_generates_non_empty_persisted_auth_token() {
        let dir = std::env::temp_dir().join(format!(
            "echomesh-token-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("relay.key");
        let pair = load_or_generate_keypair(&key_path).unwrap();
        let token = read_existing_auth_token(&key_path).expect("generated token");
        assert_eq!(token.len(), 32);
        assert!(token.iter().any(|byte| *byte != 0));
        assert_ne!(token, pair.private_key);
        let pair2 = load_or_generate_keypair(&key_path).unwrap();
        let token2 = read_existing_auth_token(&key_path).unwrap();
        assert_eq!(pair.public_key, pair2.public_key);
        assert_eq!(token, token2, "auth token must persist across restarts");
        let _ = std::fs::remove_dir_all(dir);
    }
}
