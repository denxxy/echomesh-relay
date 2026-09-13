use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::fmt;

pub use crate::config::DEFAULT_SECRET_TOKEN;
pub use crate::config::DEFAULT_SECRET_TOKEN as DEFAULT_AUTH_TOKEN;

pub const MAX_CLIENT_HELLO_SIZE: usize = 4096;
pub const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
pub const TLS_CLIENT_HELLO_HANDSHAKE_TYPE: u8 = 0x01;
pub const TLS_LEGACY_RECORD_VERSION: u16 = 0x0301;
pub const TLS_LEGACY_CLIENT_VERSION: u16 = 0x0303;
pub const TLS_1_3_VERSION: u16 = 0x0304;
pub const TLS_EXT_SERVER_NAME: u16 = 0x0000;
pub const TLS_EXT_SUPPORTED_GROUPS: u16 = 0x000a;
pub const TLS_EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
pub const TLS_EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
pub const TLS_EXT_KEY_SHARE: u16 = 0x0033;
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

const COVER_AUTH_CONTEXT: &[u8] = b"EchoMesh pseudo-TLS auth v1";
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum ObfuscationError {
    #[error("packet buffer too short")]
    BufferTooShort,
    #[error("packet is not a TLS handshake record")]
    NotTlsHandshake,
    #[error("handshake is not a ClientHello")]
    NotClientHello,
    #[error("malformed TLS record or extension data")]
    MalformedData,
    #[error("packet exceeds maximum allowed size")]
    PacketTooLarge,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ParsedClientHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub sni: Option<String>,
    pub is_tls13: bool,
}

impl fmt::Debug for ParsedClientHello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedClientHello")
            .field("legacy_version", &format_args!("{:#06x}", self.legacy_version))
            .field("random", &"[REDACTED]")
            .field("session_id", &"[REDACTED]")
            .field("cipher_suites_count", &self.cipher_suites.len())
            .field("sni", &self.sni)
            .field("is_tls13", &self.is_tls13)
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClientHelloStatus {
    Complete(ParsedClientHello),
    NeedMoreData { expected_record_len: usize },
    Invalid(ObfuscationError),
}

pub fn parse_client_hello(src: &[u8]) -> ClientHelloStatus {
    if src.len() < 5 {
        return ClientHelloStatus::NeedMoreData { expected_record_len: 5 };
    }
    if src[0] != TLS_HANDSHAKE_CONTENT_TYPE {
        return ClientHelloStatus::Invalid(ObfuscationError::NotTlsHandshake);
    }

    let record_len = u16::from_be_bytes([src[3], src[4]]) as usize;
    let total_len = 5 + record_len;
    if total_len > MAX_CLIENT_HELLO_SIZE {
        return ClientHelloStatus::Invalid(ObfuscationError::PacketTooLarge);
    }
    if src.len() < total_len {
        return ClientHelloStatus::NeedMoreData { expected_record_len: total_len };
    }

    let mut body = &src[5..total_len];
    if body.is_empty() || body[0] != TLS_CLIENT_HELLO_HANDSHAKE_TYPE {
        return ClientHelloStatus::Invalid(ObfuscationError::NotClientHello);
    }
    body.advance(1);
    if body.len() < 3 {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let hs_len = ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | body[2] as usize;
    body.advance(3);
    if body.len() < hs_len {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let mut hs_body = &body[..hs_len];

    if hs_body.len() < 34 {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let legacy_version = hs_body.get_u16();
    let mut random = [0u8; 32];
    hs_body.copy_to_slice(&mut random);

    if hs_body.is_empty() {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let session_id_len = hs_body.get_u8() as usize;
    if hs_body.len() < session_id_len {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let session_id = hs_body[..session_id_len].to_vec();
    hs_body.advance(session_id_len);

    if hs_body.len() < 2 {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let cipher_suites_len = hs_body.get_u16() as usize;
    if hs_body.len() < cipher_suites_len || cipher_suites_len % 2 != 0 {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let mut cipher_suites = Vec::with_capacity(cipher_suites_len / 2);
    let mut cs = &hs_body[..cipher_suites_len];
    while cs.remaining() >= 2 {
        cipher_suites.push(cs.get_u16());
    }
    hs_body.advance(cipher_suites_len);

    if hs_body.is_empty() {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let compression_len = hs_body.get_u8() as usize;
    if hs_body.len() < compression_len {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    hs_body.advance(compression_len);

    let mut sni = None;
    let mut is_tls13 = false;
    if hs_body.len() >= 2 {
        let extensions_len = hs_body.get_u16() as usize;
        if hs_body.len() < extensions_len {
            return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
        }
        let mut extensions = &hs_body[..extensions_len];
        while extensions.remaining() >= 4 {
            let ext_type = extensions.get_u16();
            let ext_len = extensions.get_u16() as usize;
            if extensions.remaining() < ext_len {
                return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
            }
            let ext_data = &extensions[..ext_len];
            extensions.advance(ext_len);
            match ext_type {
                TLS_EXT_SERVER_NAME if ext_data.len() >= 5 => {
                    let mut names = ext_data;
                    let _list_len = names.get_u16();
                    if names.remaining() >= 3 {
                        let name_type = names.get_u8();
                        let name_len = names.get_u16() as usize;
                        if name_type == 0 && names.remaining() >= name_len {
                            if let Ok(host) = std::str::from_utf8(&names[..name_len]) {
                                sni = Some(host.to_ascii_lowercase());
                            }
                        }
                    }
                }
                TLS_EXT_SUPPORTED_VERSIONS if !ext_data.is_empty() => {
                    let mut versions = ext_data;
                    let versions_len = versions.get_u8() as usize;
                    if versions.remaining() >= versions_len {
                        let mut list = &versions[..versions_len];
                        while list.remaining() >= 2 {
                            if list.get_u16() == TLS_1_3_VERSION {
                                is_tls13 = true;
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    ClientHelloStatus::Complete(ParsedClientHello {
        legacy_version,
        random,
        session_id,
        cipher_suites,
        sni,
        is_tls13,
    })
}

#[derive(Clone)]
pub struct TokenValidator {
    secret: Vec<u8>,
    expected_sni: Option<String>,
    insecure_no_token: bool,
}

impl fmt::Debug for TokenValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenValidator")
            .field("secret", &"[REDACTED]")
            .field("expected_sni", &self.expected_sni)
            .field("insecure_no_token", &self.insecure_no_token)
            .finish()
    }
}

impl TokenValidator {
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
            expected_sni: None,
            insecure_no_token: false,
        }
    }

    pub fn with_expected_sni(mut self, sni: impl Into<String>) -> Self {
        self.expected_sni = Some(sni.into().to_ascii_lowercase());
        self
    }

    pub fn with_insecure_no_token(mut self, enabled: bool) -> Self {
        self.insecure_no_token = enabled;
        self
    }

    pub fn with_insecure_no_auth(self, enabled: bool) -> Self {
        self.with_insecure_no_token(enabled)
    }

    pub fn is_insecure_no_token(&self) -> bool {
        self.insecure_no_token
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Verifies a challenge-response proof. The reusable token itself is never
    /// serialized into ClientHello.random, SNI, session-id, or any other wire field.
    pub fn validate(&self, client_hello: &ParsedClientHello) -> bool {
        if self.insecure_no_token {
            return true;
        }
        if self.secret.is_empty() || client_hello.session_id.len() != 32 {
            return false;
        }

        let sni = client_hello.sni.as_deref().unwrap_or("");
        if let Some(expected) = &self.expected_sni {
            if sni != expected {
                return false;
            }
        }

        let Ok(mut mac) = HmacSha256::new_from_slice(&self.secret) else {
            return false;
        };
        mac.update(COVER_AUTH_CONTEXT);
        mac.update(&client_hello.random);
        mac.update(sni.as_bytes());
        mac.verify_slice(&client_hello.session_id).is_ok()
    }
}

pub struct PseudoTlsBuilder {
    secret_token: Vec<u8>,
    sni_host: String,
    cipher_suites: Vec<u16>,
}

impl PseudoTlsBuilder {
    pub fn new(secret_token: impl Into<Vec<u8>>, sni_host: impl Into<String>) -> Self {
        Self {
            secret_token: secret_token.into(),
            sni_host: sni_host.into().to_ascii_lowercase(),
            cipher_suites: vec![
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
            ],
        }
    }

    /// Legacy compatibility knob. Secret-in-SNI is deliberately disabled:
    /// enabling it no longer changes the safe challenge-response wire format.
    pub fn embed_in_sni(self, _enabled: bool) -> Self {
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random);

        let mut mac = HmacSha256::new_from_slice(&self.secret_token)
            .expect("HMAC accepts arbitrary key lengths");
        mac.update(COVER_AUTH_CONTEXT);
        mac.update(&random);
        mac.update(self.sni_host.as_bytes());
        let auth_tag = mac.finalize().into_bytes();

        let mut hs_body = BytesMut::with_capacity(512);
        hs_body.put_u16(TLS_LEGACY_CLIENT_VERSION);
        hs_body.put_slice(&random);
        hs_body.put_u8(32);
        hs_body.put_slice(&auth_tag);
        hs_body.put_u16((self.cipher_suites.len() * 2) as u16);
        for suite in &self.cipher_suites {
            hs_body.put_u16(*suite);
        }
        hs_body.put_u8(1);
        hs_body.put_u8(0);

        let mut extensions = BytesMut::with_capacity(256);
        let sni_bytes = self.sni_host.as_bytes();
        let sni_list_len = 1 + 2 + sni_bytes.len();
        extensions.put_u16(TLS_EXT_SERVER_NAME);
        extensions.put_u16((2 + sni_list_len) as u16);
        extensions.put_u16(sni_list_len as u16);
        extensions.put_u8(0);
        extensions.put_u16(sni_bytes.len() as u16);
        extensions.put_slice(sni_bytes);

        extensions.put_u16(TLS_EXT_SUPPORTED_VERSIONS);
        extensions.put_u16(5);
        extensions.put_u8(4);
        extensions.put_u16(TLS_1_3_VERSION);
        extensions.put_u16(TLS_LEGACY_CLIENT_VERSION);

        extensions.put_u16(TLS_EXT_SUPPORTED_GROUPS);
        extensions.put_u16(6);
        extensions.put_u16(4);
        extensions.put_u16(0x001d);
        extensions.put_u16(0x0017);

        extensions.put_u16(TLS_EXT_SIGNATURE_ALGORITHMS);
        extensions.put_u16(8);
        extensions.put_u16(6);
        extensions.put_u16(0x0403);
        extensions.put_u16(0x0804);
        extensions.put_u16(0x0807);

        let mut key_share = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_share);
        extensions.put_u16(TLS_EXT_KEY_SHARE);
        extensions.put_u16(38);
        extensions.put_u16(36);
        extensions.put_u16(0x001d);
        extensions.put_u16(32);
        extensions.put_slice(&key_share);

        hs_body.put_u16(extensions.len() as u16);
        hs_body.put_slice(&extensions);

        let hs_len = hs_body.len();
        let total_record_len = 4 + hs_len;
        let mut record = Vec::with_capacity(5 + total_record_len);
        record.push(TLS_HANDSHAKE_CONTENT_TYPE);
        record.extend_from_slice(&TLS_LEGACY_RECORD_VERSION.to_be_bytes());
        record.extend_from_slice(&(total_record_len as u16).to_be_bytes());
        record.push(TLS_CLIENT_HELLO_HANDSHAKE_TYPE);
        record.push(((hs_len >> 16) & 0xff) as u8);
        record.push(((hs_len >> 8) & 0xff) as u8);
        record.push((hs_len & 0xff) as u8);
        record.extend_from_slice(&hs_body);
        record
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&s[i..i + 2], 16).ok()?);
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_cover_auth_round_trip_without_wire_secret() {
        let secret = b"my_secret_token_1234";
        let bytes = PseudoTlsBuilder::new(secret.to_vec(), "cloudflare.com").build();
        assert_eq!(bytes[0], TLS_HANDSHAKE_CONTENT_TYPE);
        assert!(!bytes.windows(secret.len()).any(|window| window == secret));

        let parsed = match parse_client_hello(&bytes) {
            ClientHelloStatus::Complete(parsed) => parsed,
            other => panic!("expected Complete, got {other:?}"),
        };
        assert_eq!(parsed.sni.as_deref(), Some("cloudflare.com"));
        assert!(parsed.is_tls13);
        assert_eq!(parsed.session_id.len(), 32);
        assert!(TokenValidator::new(secret.to_vec()).validate(&parsed));
        assert!(!TokenValidator::new(b"wrong_token".to_vec()).validate(&parsed));
    }

    #[test]
    fn cover_proof_is_fresh_and_legacy_sni_mode_never_leaks_secret() {
        let secret = b"supersecret";
        let first = PseudoTlsBuilder::new(secret.to_vec(), "microsoft.com")
            .embed_in_sni(true)
            .build();
        let second = PseudoTlsBuilder::new(secret.to_vec(), "microsoft.com").build();
        assert_ne!(first, second);
        assert!(!first.windows(secret.len()).any(|window| window == secret));
        assert!(!second.windows(secret.len()).any(|window| window == secret));
        for bytes in [&first, &second] {
            let parsed = match parse_client_hello(bytes) {
                ClientHelloStatus::Complete(parsed) => parsed,
                other => panic!("expected Complete, got {other:?}"),
            };
            assert_eq!(parsed.sni.as_deref(), Some("microsoft.com"));
            assert!(TokenValidator::new(secret.to_vec()).validate(&parsed));
        }
    }

    #[test]
    fn tampered_challenge_or_proof_is_rejected() {
        let secret = b"server-token";
        let bytes = PseudoTlsBuilder::new(secret.to_vec(), "cloudflare.com").build();
        let mut parsed = match parse_client_hello(&bytes) {
            ClientHelloStatus::Complete(parsed) => parsed,
            other => panic!("expected Complete, got {other:?}"),
        };
        let validator = TokenValidator::new(secret.to_vec());
        assert!(validator.validate(&parsed));
        parsed.random[0] ^= 1;
        assert!(!validator.validate(&parsed));
    }

    #[test]
    fn non_tls_and_short_packets() {
        let http_probe = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            parse_client_hello(http_probe),
            ClientHelloStatus::Invalid(ObfuscationError::NotTlsHandshake)
        );
        assert_eq!(
            parse_client_hello(&[0x16, 0x03, 0x01]),
            ClientHelloStatus::NeedMoreData { expected_record_len: 5 }
        );
    }

    #[test]
    fn insecure_bypass_remains_explicit() {
        let parsed = match parse_client_hello(
            &PseudoTlsBuilder::new(b"attacker".to_vec(), "cloudflare.com").build(),
        ) {
            ClientHelloStatus::Complete(parsed) => parsed,
            other => panic!("expected Complete, got {other:?}"),
        };
        let validator = TokenValidator::new(b"expected".to_vec());
        assert!(!validator.validate(&parsed));
        assert!(validator.with_insecure_no_token(true).validate(&parsed));
    }
}