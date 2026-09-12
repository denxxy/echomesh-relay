use echomesh_relay::config::DEFAULT_SECRET_TOKEN;
use echomesh_relay::transport::{
    parse_client_hello, ClientHelloStatus, PseudoTlsBuilder, TokenValidator,
};

#[test]
fn test_token_compat_client_hello() {
    // Build ClientHello using default secret token
    let tls_builder = PseudoTlsBuilder::new(DEFAULT_SECRET_TOKEN, "cloudflare.com");
    let client_hello_buf = tls_builder.build();

    // Parse the generated TLS record
    let status = parse_client_hello(&client_hello_buf);
    let parsed = match status {
        ClientHelloStatus::Complete(p) => p,
        other => panic!("Expected ClientHelloStatus::Complete, got {:?}", other),
    };

    // Validate using server TokenValidator configured with DEFAULT_SECRET_TOKEN
    let validator = TokenValidator::new(DEFAULT_SECRET_TOKEN);
    let valid = validator.validate(&parsed);
    assert!(
        valid,
        "Server TokenValidator must successfully validate ClientHello generated with DEFAULT_SECRET_TOKEN"
    );
}

#[test]
fn test_token_compat_custom_token() {
    let custom_token = b"custom_secret_test_token_123456";
    let tls_builder = PseudoTlsBuilder::new(custom_token.to_vec(), "cloudflare.com");
    let client_hello_buf = tls_builder.build();

    let status = parse_client_hello(&client_hello_buf);
    let parsed = match status {
        ClientHelloStatus::Complete(p) => p,
        other => panic!("Expected ClientHelloStatus::Complete, got {:?}", other),
    };

    let validator = TokenValidator::new(custom_token);
    let valid = validator.validate(&parsed);
    assert!(valid, "Server TokenValidator must validate matching custom secret");

    let wrong_validator = TokenValidator::new(b"different_secret_token_abcdefgh");
    assert!(!wrong_validator.validate(&parsed), "Server TokenValidator must reject mismatching token");
}
