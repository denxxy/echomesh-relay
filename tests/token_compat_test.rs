use echomesh_relay::config::DEFAULT_SECRET_TOKEN;
use echomesh_relay::transport::{
    parse_client_hello, ClientHelloStatus, PseudoTlsBuilder, TokenValidator,
};

#[test]
fn test_default_token_is_not_a_shared_credential() {
    assert!(DEFAULT_SECRET_TOKEN.is_empty());

    let client_hello_buf = PseudoTlsBuilder::new(DEFAULT_SECRET_TOKEN, "cloudflare.com").build();
    let parsed = match parse_client_hello(&client_hello_buf) {
        ClientHelloStatus::Complete(p) => p,
        other => panic!("Expected ClientHelloStatus::Complete, got {other:?}"),
    };

    assert!(
        !TokenValidator::new(DEFAULT_SECRET_TOKEN).validate(&parsed),
        "empty production default must never authenticate"
    );
}

#[test]
fn test_token_compat_custom_token() {
    let custom_token = b"custom_secret_test_token_123456";
    let client_hello_buf =
        PseudoTlsBuilder::new(custom_token.to_vec(), "cloudflare.com").build();

    let parsed = match parse_client_hello(&client_hello_buf) {
        ClientHelloStatus::Complete(p) => p,
        other => panic!("Expected ClientHelloStatus::Complete, got {other:?}"),
    };

    assert!(TokenValidator::new(custom_token.to_vec()).validate(&parsed));
    assert!(
        !TokenValidator::new(b"different_secret_token_abcdefgh".to_vec()).validate(&parsed),
        "server must reject a mismatching credential"
    );
}
