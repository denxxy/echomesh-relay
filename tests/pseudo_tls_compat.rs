use echomesh_relay::transport::{
    parse_client_hello, ClientHelloStatus, PseudoTlsBuilder, TokenValidator,
};

const TEST_SECRET_TOKEN: &[u8] = b"pseudo-tls-compat-test-token";

#[test]
fn test_pseudo_tls_compat_client_hello() {
    // 1. Client PseudoTlsBuilder generates ClientHello buffer using an explicit test-only credential.
    let tls_builder = PseudoTlsBuilder::new(TEST_SECRET_TOKEN, "cloudflare.com");
    let client_hello_buf = tls_builder.build();

    // 2. Server parses ClientHello.
    let status = parse_client_hello(&client_hello_buf);
    let parsed = match status {
        ClientHelloStatus::Complete(p) => p,
        other => panic!("Expected ClientHelloStatus::Complete, got {:?}", other),
    };

    // 3. Server validates the same explicitly provisioned test-only credential.
    let validator = TokenValidator::new(TEST_SECRET_TOKEN);
    let is_valid = validator.validate(&parsed);

    assert!(
        is_valid,
        "TokenValidator must accept an explicitly matching test-only credential"
    );
}
