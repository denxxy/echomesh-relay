use echomesh_relay::config::DEFAULT_SECRET_TOKEN;
use echomesh_relay::transport::{
    parse_client_hello, ClientHelloStatus, PseudoTlsBuilder, TokenValidator,
};

#[test]
fn test_pseudo_tls_compat_client_hello() {
    // 1. Client PseudoTlsBuilder generates ClientHello buffer
    let tls_builder = PseudoTlsBuilder::new(DEFAULT_SECRET_TOKEN, "cloudflare.com");
    let client_hello_buf = tls_builder.build();

    // 2. Server parses ClientHello
    let status = parse_client_hello(&client_hello_buf);
    let parsed = match status {
        ClientHelloStatus::Complete(p) => p,
        other => panic!("Expected ClientHelloStatus::Complete, got {:?}", other),
    };

    // 3. Server TokenValidator validates against DEFAULT_SECRET_TOKEN
    let validator = TokenValidator::new(DEFAULT_SECRET_TOKEN);
    let is_valid = validator.validate(&parsed);

    assert!(
        is_valid,
        "TokenValidator::new(DEFAULT_SECRET_TOKEN).validate(&parsed) must return true"
    );
}
