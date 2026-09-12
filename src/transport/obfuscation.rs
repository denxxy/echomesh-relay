use bytes::{Buf, BufMut, BytesMut};
use std::fmt;

use crate::protocol::frame::constant_time_eq;
pub use crate::config::DEFAULT_SECRET_TOKEN;
pub use crate::config::DEFAULT_SECRET_TOKEN as DEFAULT_AUTH_TOKEN;

/// Maximum size of initial TLS handshake record we accept (4KB is plenty for ClientHello).
pub const MAX_CLIENT_HELLO_SIZE: usize = 4096;

/// TLS Content Type for Handshake records.
pub const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;

/// TLS Handshake Type for ClientHello.
pub const TLS_CLIENT_HELLO_HANDSHAKE_TYPE: u8 = 0x01;

/// Legacy TLS record version commonly sent in TLS 1.3 ClientHello (TLS 1.0 = 0x0301).
pub const TLS_LEGACY_RECORD_VERSION: u16 = 0x0301;

/// Legacy ClientHello version (TLS 1.2 = 0x0303).
pub const TLS_LEGACY_CLIENT_VERSION: u16 = 0x0303;

/// TLS 1.3 version identifier (0x0304).
pub const TLS_1_3_VERSION: u16 = 0x0304;

/// TLS Extension Type: Server Name Indication (SNI).
pub const TLS_EXT_SERVER_NAME: u16 = 0x0000;

/// TLS Extension Type: Supported Groups.
pub const TLS_EXT_SUPPORTED_GROUPS: u16 = 0x000a;

/// TLS Extension Type: Signature Algorithms.
pub const TLS_EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;

/// TLS Extension Type: Supported Versions.
pub const TLS_EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// TLS Extension Type: Key Share.
pub const TLS_EXT_KEY_SHARE: u16 = 0x0033;

/// Standard TLS 1.3 Cipher Suites
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// Errors that can occur when parsing or generating pseudo-TLS packets.
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

/// A parsed TLS ClientHello message.
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
        // Redact random and session_id per architecture security invariant
        f.debug_struct("ParsedClientHello")
            .field("legacy_version", &format_args!("{:#06x}", self.legacy_version))
            .field("random", &"[REDACTED]")
            .field("session_id_len", &self.session_id.len())
            .field("cipher_suites_count", &self.cipher_suites.len())
            .field("sni", &self.sni)
            .field("is_tls13", &self.is_tls13)
            .finish()
    }
}

/// Parsing status for streaming inspection.
#[derive(Debug, PartialEq, Eq)]
pub enum ClientHelloStatus {
    /// Full valid ClientHello parsed.
    Complete(ParsedClientHello),
    /// Incomplete buffer: need more bytes from stream.
    NeedMoreData { expected_record_len: usize },
    /// Clearly not a TLS ClientHello record (e.g. plain HTTP GET or scanner garbage).
    Invalid(ObfuscationError),
}

/// Parses a TLS 1.3 / 1.2 ClientHello from an input byte slice.
pub fn parse_client_hello(src: &[u8]) -> ClientHelloStatus {
    if src.len() < 5 {
        return ClientHelloStatus::NeedMoreData {
            expected_record_len: 5,
        };
    }

    // Record header:
    // byte 0: ContentType (0x16 for Handshake)
    if src[0] != TLS_HANDSHAKE_CONTENT_TYPE {
        return ClientHelloStatus::Invalid(ObfuscationError::NotTlsHandshake);
    }

    let record_len = u16::from_be_bytes([src[3], src[4]]) as usize;
    let total_len = 5 + record_len;

    if total_len > MAX_CLIENT_HELLO_SIZE {
        return ClientHelloStatus::Invalid(ObfuscationError::PacketTooLarge);
    }

    if src.len() < total_len {
        return ClientHelloStatus::NeedMoreData {
            expected_record_len: total_len,
        };
    }

    let mut body = &src[5..total_len];

    // Handshake header:
    // byte 0: HandshakeType (0x01 for ClientHello)
    if body.is_empty() || body[0] != TLS_CLIENT_HELLO_HANDSHAKE_TYPE {
        return ClientHelloStatus::Invalid(ObfuscationError::NotClientHello);
    }
    body.advance(1);

    if body.len() < 3 {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let hs_len = ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | (body[2] as usize);
    body.advance(3);

    if body.len() < hs_len {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let mut hs_body = &body[..hs_len];

    // legacy_version (2 bytes)
    if hs_body.len() < 2 {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let legacy_version = hs_body.get_u16();

    // random (32 bytes)
    if hs_body.len() < 32 {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let mut random = [0u8; 32];
    hs_body.copy_to_slice(&mut random);

    // legacy_session_id (1 byte len + bytes)
    if hs_body.is_empty() {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let session_id_len = hs_body.get_u8() as usize;
    if hs_body.len() < session_id_len {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let session_id = hs_body[..session_id_len].to_vec();
    hs_body.advance(session_id_len);

    // cipher_suites (2 bytes len + u16 entries)
    if hs_body.len() < 2 {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let cipher_suites_len = hs_body.get_u16() as usize;
    if hs_body.len() < cipher_suites_len || !cipher_suites_len.is_multiple_of(2) {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let mut cipher_suites = Vec::with_capacity(cipher_suites_len / 2);
    let mut cs_slice = &hs_body[..cipher_suites_len];
    while cs_slice.remaining() >= 2 {
        cipher_suites.push(cs_slice.get_u16());
    }
    hs_body.advance(cipher_suites_len);

    // legacy_compression_methods (1 byte len + bytes)
    if hs_body.is_empty() {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    let comp_len = hs_body.get_u8() as usize;
    if hs_body.len() < comp_len {
        return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
    }
    hs_body.advance(comp_len);

    let mut sni: Option<String> = None;
    let mut is_tls13 = false;

    // extensions (optional 2 bytes len + extensions)
    if hs_body.len() >= 2 {
        let extensions_len = hs_body.get_u16() as usize;
        if hs_body.len() < extensions_len {
            return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
        }
        let mut ext_buf = &hs_body[..extensions_len];

        while ext_buf.remaining() >= 4 {
            let ext_type = ext_buf.get_u16();
            let ext_len = ext_buf.get_u16() as usize;
            if ext_buf.remaining() < ext_len {
                return ClientHelloStatus::Invalid(ObfuscationError::MalformedData);
            }

            let ext_data = &ext_buf[..ext_len];
            ext_buf.advance(ext_len);

            match ext_type {
                TLS_EXT_SERVER_NAME => {
                    // SNI extension structure:
                    // server_name_list_length (2 bytes)
                    // name_type (1 byte, 0 = host_name)
                    // name_length (2 bytes)
                    // name (name_length bytes)
                    if ext_data.len() >= 5 {
                        let mut sni_slice = ext_data;
                        let _list_len = sni_slice.get_u16();
                        if sni_slice.remaining() >= 3 {
                            let name_type = sni_slice.get_u8();
                            let name_len = sni_slice.get_u16() as usize;
                            if name_type == 0 && sni_slice.remaining() >= name_len {
                                if let Ok(host) = std::str::from_utf8(&sni_slice[..name_len]) {
                                    sni = Some(host.to_ascii_lowercase());
                                }
                            }
                        }
                    }
                }
                TLS_EXT_SUPPORTED_VERSIONS if !ext_data.is_empty() => {
                    // Client supported_versions structure:
                    // versions_length (1 byte)
                    // list of u16 versions
                    let mut ver_slice = ext_data;
                    let ver_len = ver_slice.get_u8() as usize;
                    if ver_slice.remaining() >= ver_len {
                        let mut list = &ver_slice[..ver_len];
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

/// Constant-time validator for pre-shared secret tokens.
#[derive(Clone)]
pub struct TokenValidator {
    secret: Vec<u8>,
    expected_sni: Option<String>,
    insecure_no_token: bool,
}

impl fmt::Debug for TokenValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact secret per security invariant
        f.debug_struct("TokenValidator")
            .field("secret", &"[REDACTED]")
            .field("expected_sni", &self.expected_sni)
            .field("insecure_no_token", &self.insecure_no_token)
            .finish()
    }
}

impl TokenValidator {
    /// Creates a new validator with the given secret token.
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
            expected_sni: None,
            insecure_no_token: false,
        }
    }

    /// Sets an expected SNI host for token verification in SNI.
    pub fn with_expected_sni(mut self, sni: impl Into<String>) -> Self {
        self.expected_sni = Some(sni.into().to_ascii_lowercase());
        self
    }

    /// Enables or disables insecure bypass of token validation (dev/debug mode).
    pub fn with_insecure_no_token(mut self, enabled: bool) -> Self {
        self.insecure_no_token = enabled;
        self
    }

    /// Alias for `with_insecure_no_token` for `--insecure-no-auth`.
    pub fn with_insecure_no_auth(self, enabled: bool) -> Self {
        self.with_insecure_no_token(enabled)
    }

    /// Returns whether insecure token bypass is enabled.
    pub fn is_insecure_no_token(&self) -> bool {
        self.insecure_no_token
    }

    /// Validates whether the `ParsedClientHello` contains the valid pre-shared secret token
    /// in `ClientHello.random` or in the `SNI` field.
    ///
    /// Checks are executed using constant-time comparison to prevent timing side-channel attacks.
    pub fn validate(&self, client_hello: &ParsedClientHello) -> bool {
        if self.insecure_no_token {
            return true;
        }

        if self.secret.is_empty() {
            return false;
        }

        // 1. Check in ClientHello.random:
        // Secret is matched against the prefix or exact bytes of ClientHello.random (up to 32 bytes)
        let check_len = self.secret.len().min(32);
        let random_valid = if check_len > 0 {
            constant_time_eq(&client_hello.random[..check_len], &self.secret[..check_len])
        } else {
            false
        };

        if random_valid {
            return true;
        }

        // 2. Check in ClientHello.sni:
        if let Some(sni) = &client_hello.sni {
            let sni_bytes = sni.as_bytes();
            // Direct match with secret
            if constant_time_eq(sni_bytes, &self.secret) {
                return true;
            }
            // Subdomain match: "<secret>.<domain>"
            if sni_bytes.len() > self.secret.len()
                && sni_bytes[self.secret.len()] == b'.'
                && constant_time_eq(&sni_bytes[..self.secret.len()], &self.secret)
            {
                return true;
            }
            // Explicit expected SNI check
            if let Some(expected) = &self.expected_sni {
                if constant_time_eq(sni_bytes, expected.as_bytes()) {
                    return true;
                }
            }
        }

        false
    }
}

/// Builder for generating authentic TLS 1.3 ClientHello messages (Pseudo-TLS Handshake)
/// with embedded secret tokens to bypass passive DPI inspection.
pub struct PseudoTlsBuilder {
    secret_token: Vec<u8>,
    sni_host: String,
    token_in_sni: bool,
    cipher_suites: Vec<u16>,
}

impl PseudoTlsBuilder {
    /// Creates a new builder with the given secret token and SNI disguise host (e.g. "cloudflare.com").
    pub fn new(secret_token: impl Into<Vec<u8>>, sni_host: impl Into<String>) -> Self {
        Self {
            secret_token: secret_token.into(),
            sni_host: sni_host.into(),
            token_in_sni: false,
            cipher_suites: vec![
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
            ],
        }
    }

    /// Configure embedding secret token into the SNI host (e.g. "<hex_token>.cloudflare.com").
    pub fn embed_in_sni(mut self, enabled: bool) -> Self {
        self.token_in_sni = enabled;
        self
    }

    /// Builds the complete binary TLS 1.3 ClientHello record ready for transmission over TCP.
    pub fn build(&self) -> Vec<u8> {
        let mut random = [0x5au8; 32];
        let secret_token = if self.secret_token.is_empty() {
            DEFAULT_SECRET_TOKEN
        } else {
            &self.secret_token[..]
        };
        // Embed token in random if token_in_sni is false
        if !self.token_in_sni {
            let copy_len = secret_token.len().min(32);
            random[..copy_len].copy_from_slice(&secret_token[..copy_len]);
        }

        let sni_string = if self.token_in_sni {
            let hex_token = hex_encode(&self.secret_token);
            format!("{}.{}", hex_token, self.sni_host)
        } else {
            self.sni_host.clone()
        };

        let mut hs_body = BytesMut::with_capacity(512);

        // legacy_version = 0x0303
        hs_body.put_u16(TLS_LEGACY_CLIENT_VERSION);

        // random (32 bytes)
        hs_body.put_slice(&random);

        // legacy_session_id (32 bytes middlebox compat)
        hs_body.put_u8(32);
        hs_body.put_bytes(0x22, 32);

        // cipher_suites
        hs_body.put_u16((self.cipher_suites.len() * 2) as u16);
        for cs in &self.cipher_suites {
            hs_body.put_u16(*cs);
        }

        // legacy_compression_methods (1 byte len, 0x00)
        hs_body.put_u8(1);
        hs_body.put_u8(0);

        // Build extensions
        let mut ext_buf = BytesMut::with_capacity(256);

        // 1. SNI extension (0x0000)
        let sni_bytes = sni_string.as_bytes();
        let sni_list_len = 1 + 2 + sni_bytes.len();
        let sni_ext_len = 2 + sni_list_len;
        ext_buf.put_u16(TLS_EXT_SERVER_NAME);
        ext_buf.put_u16(sni_ext_len as u16);
        ext_buf.put_u16(sni_list_len as u16);
        ext_buf.put_u8(0); // host_name type
        ext_buf.put_u16(sni_bytes.len() as u16);
        ext_buf.put_slice(sni_bytes);

        // 2. Supported Versions extension (0x002b) -> TLS 1.3 (0x0304) and TLS 1.2 (0x0303)
        ext_buf.put_u16(TLS_EXT_SUPPORTED_VERSIONS);
        ext_buf.put_u16(5); // ext len: 1 byte list len + 4 bytes versions
        ext_buf.put_u8(4); // 2 versions = 4 bytes
        ext_buf.put_u16(TLS_1_3_VERSION);
        ext_buf.put_u16(TLS_LEGACY_CLIENT_VERSION);

        // 3. Supported Groups extension (0x000a) -> x25519 (0x001d), secp256r1 (0x0017)
        ext_buf.put_u16(TLS_EXT_SUPPORTED_GROUPS);
        ext_buf.put_u16(6);
        ext_buf.put_u16(4);
        ext_buf.put_u16(0x001d); // x25519
        ext_buf.put_u16(0x0017); // secp256r1

        // 4. Signature Algorithms extension (0x000d)
        ext_buf.put_u16(TLS_EXT_SIGNATURE_ALGORITHMS);
        ext_buf.put_u16(8);
        ext_buf.put_u16(6);
        ext_buf.put_u16(0x0403); // ecdsa_secp256r1_sha256
        ext_buf.put_u16(0x0804); // rsa_pss_rsae_sha256
        ext_buf.put_u16(0x0807); // ed25519

        // 5. Key Share extension (0x0033) -> dummy x25519 public key (32 bytes)
        ext_buf.put_u16(TLS_EXT_KEY_SHARE);
        ext_buf.put_u16(2 + 2 + 2 + 32); // 38 bytes
        ext_buf.put_u16(2 + 2 + 32); // client_shares_len: 36 bytes
        ext_buf.put_u16(0x001d); // x25519 group
        ext_buf.put_u16(32); // key_exchange_len
        ext_buf.put_bytes(0x42, 32); // dummy public key share

        // Put extensions into hs_body
        hs_body.put_u16(ext_buf.len() as u16);
        hs_body.put_slice(&ext_buf);

        // Now wrap Handshake message in TLS Record:
        let hs_len = hs_body.len();
        let total_record_len = 4 + hs_len;

        let mut record = Vec::with_capacity(5 + total_record_len);
        // Record header (5 bytes)
        record.push(TLS_HANDSHAKE_CONTENT_TYPE);
        record.extend_from_slice(&TLS_LEGACY_RECORD_VERSION.to_be_bytes());
        record.extend_from_slice(&(total_record_len as u16).to_be_bytes());

        // Handshake header (4 bytes: 1 byte type + 3 bytes length)
        record.push(TLS_CLIENT_HELLO_HANDSHAKE_TYPE);
        record.push(((hs_len >> 16) & 0xFF) as u8);
        record.push(((hs_len >> 8) & 0xFF) as u8);
        record.push((hs_len & 0xFF) as u8);

        // Handshake body
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
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pseudo_tls_client_hello_build_and_parse() {
        let secret = b"my_secret_token_1234";
        let builder = PseudoTlsBuilder::new(secret.to_vec(), "cloudflare.com");
        let bytes = builder.build();

        assert!(bytes.len() > 5);
        assert_eq!(bytes[0], TLS_HANDSHAKE_CONTENT_TYPE);

        let status = parse_client_hello(&bytes);
        match status {
            ClientHelloStatus::Complete(parsed) => {
                assert_eq!(parsed.legacy_version, TLS_LEGACY_CLIENT_VERSION);
                assert!(parsed.is_tls13);
                assert_eq!(parsed.sni.as_deref(), Some("cloudflare.com"));
                assert_eq!(&parsed.random[..secret.len()], secret);
                assert_eq!(parsed.cipher_suites.len(), 3);

                // Token validator check
                let validator = TokenValidator::new(secret.to_vec());
                assert!(validator.validate(&parsed));

                // Wrong token check
                let bad_validator = TokenValidator::new(b"wrong_token".to_vec());
                assert!(!bad_validator.validate(&parsed));
            }
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    #[test]
    fn test_token_in_sni_mode() {
        let secret = b"supersecret";
        let builder = PseudoTlsBuilder::new(secret.to_vec(), "microsoft.com").embed_in_sni(true);
        let bytes = builder.build();

        let status = parse_client_hello(&bytes);
        match status {
            ClientHelloStatus::Complete(parsed) => {
                assert!(parsed.sni.is_some());
                let hex_sec = hex_encode(secret);
                assert!(parsed.sni.as_ref().unwrap().starts_with(&hex_sec));

                // Validator matching hex secret
                let validator = TokenValidator::new(hex_sec.as_bytes().to_vec());
                assert!(validator.validate(&parsed));
            }
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    #[test]
    fn test_non_tls_and_short_packets() {
        // Plain HTTP GET probe (e.g. scanner or curl http)
        let http_probe = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let status = parse_client_hello(http_probe);
        assert_eq!(
            status,
            ClientHelloStatus::Invalid(ObfuscationError::NotTlsHandshake)
        );

        // Incomplete TLS record header
        let partial_header = &[0x16, 0x03, 0x01];
        let status = parse_client_hello(partial_header);
        assert_eq!(
            status,
            ClientHelloStatus::NeedMoreData {
                expected_record_len: 5
            }
        );

        // Incomplete TLS record body
        let partial_body = &[0x16, 0x03, 0x01, 0x00, 0x50, 0x01, 0x00];
        let status = parse_client_hello(partial_body);
        assert_eq!(
            status,
            ClientHelloStatus::NeedMoreData {
                expected_record_len: 5 + 0x50
            }
        );
    }

    #[test]
    fn test_insecure_no_token_bypass() {
        let builder = PseudoTlsBuilder::new(b"attacker_invalid_secret".to_vec(), "cloudflare.com");
        let bytes = builder.build();
        let status = parse_client_hello(&bytes);
        if let ClientHelloStatus::Complete(parsed) = status {
            let strict_validator = TokenValidator::new(b"expected_server_token".to_vec());
            assert!(!strict_validator.validate(&parsed));

            let bypass_validator = strict_validator.with_insecure_no_token(true);
            assert!(bypass_validator.validate(&parsed));
        } else {
            panic!("expected Complete parsed client hello");
        }
    }
}
