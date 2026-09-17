use echomesh_relay::config::DEFAULT_SECRET_TOKEN;
use echomesh_relay::transport::{
    parse_client_hello, ClientHelloStatus, PseudoTlsBuilder, TokenValidator,
};

#[test]
fn test_default_token_does_not_authenticate() {
    // Production builds intentionally compile with no default authentication secret.
    assert!(
        DEFAULT_SECRET_TOKEN.is_empty(),
        "DEFAULT_SECRET_TOKEN must remain empty so no production secret is compiled into the binary"
    );

    let tls_builder = PseudoTlsBuilder::new(DEFAULT_SECRET_TOKEN, "cloudflare.com");
    let client_hello_buf = tls_builder.build();

    let status = parse_client_hello(&client_hello_buf);
    let parsed = match status {
        ClientHelloStatus::Complete(p) => p,
        other => panic!("Expected ClientHelloStatus::Complete, got {:?}", other),
    };

    // An empty token is not valid authentication. Operators must provision a token
    // explicitly (or opt into the insecure bypass for local development).
    let validator = TokenValidator::new(DEFAULT_SECRET_TOKEN);
    assert!(
        !validator.validate(&parsed),
        "TokenValidator must reject authentication when no token is configured"
    );

    let insecure_validator = TokenValidator::new(DEFAULT_SECRET_TOKEN)
        .with_insecure_no_token(true);
    assert!(
        insecure_validator.validate(&parsed),
        "Explicit insecure bypass must remain available for development"
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
    assert!(
        !wrong_validator.validate(&parsed),
        "Server TokenValidator must reject mismatching token"
    );
}
