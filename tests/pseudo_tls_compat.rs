use echomesh_relay::config::DEFAULT_SECRET_TOKEN;
use echomesh_relay::transport::{
    parse_client_hello, ClientHelloStatus, PseudoTlsBuilder, TokenValidator,
};

#[test]
fn test_pseudo_tls_compat_client_hello() {
    let token = b"pseudo-tls-compat-test-token";
    let client_hello_buf = PseudoTlsBuilder::new(token.to_vec(), "cloudflare.com").build();

    let parsed = match parse_client_hello(&client_hello_buf) {
        ClientHelloStatus::Complete(p) => p,
        other => panic!("Expected ClientHelloStatus::Complete, got {other:?}"),
    };

    assert!(TokenValidator::new(token.to_vec()).validate(&parsed));
    assert!(
        DEFAULT_SECRET_TOKEN.is_empty(),
        "production default must not be a shared compiled-in credential"
    );
    assert!(
        !TokenValidator::new(DEFAULT_SECRET_TOKEN).validate(&parsed),
        "empty production default must never authenticate a client"
    );
}
