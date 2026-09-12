use std::net::SocketAddr;
use std::time::Duration;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use echomesh_relay::protocol::{Frame, SessionId};
use echomesh_relay::server::{ListenerConfig, RelayListener};
use echomesh_relay::transport::{
    client_noise_handshake, hex_decode, hex_encode, NoiseFramedStream, PseudoTlsBuilder,
};

/// Helper: starts a dummy camouflage target simulating Cloudflare / Microsoft.
async fn spawn_mock_camouflage_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut buf).await {
                        if n > 0 {
                            let response = b"HTTP/1.1 200 OK\r\nServer: cloudflare\r\nContent-Length: 10\r\nConnection: close\r\n\r\nCamouflage";
                            let _ = stream.write_all(response).await;
                            let _ = stream.flush().await;
                        }
                    }
                });
            }
        }
    });

    (addr, handle)
}

#[tokio::test]
async fn test_full_handshake_with_valid_token_success() {
    let raw_secret = b"valid_token_32_bytes_length_ok!";
    let secret_token_hex = hex_encode(raw_secret);
    let decoded_secret = hex_decode(&secret_token_hex).expect("decode hex token");

    let (mock_addr, _mock_handle) = spawn_mock_camouflage_server().await;

    // 1. Start RelayListener with valid token
    let listener_config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), raw_secret.to_vec())
        .with_fallback_target(mock_addr.to_string())
        .with_max_connections(50);

    let relay_listener = RelayListener::bind(listener_config).await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    let server_pub = relay_listener.secrets().public_key.clone();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(async move {
        let _ = relay_listener.run_with_shutdown(shutdown_rx).await;
    });

    // 2. Client connects and sends Pseudo-TLS ClientHello with secret_token
    let mut client_stream = TcpStream::connect(relay_addr).await.unwrap();
    let tls_builder = PseudoTlsBuilder::new(decoded_secret, "cloudflare.com");
    let client_hello = tls_builder.build();
    client_stream.write_all(&client_hello).await.unwrap();
    client_stream.flush().await.unwrap();

    // 3. Client executes Noise handshake
    let noise_session = client_noise_handshake(&mut client_stream, &server_pub)
        .await
        .expect("Noise handshake must succeed with valid token");
    let mut framed = NoiseFramedStream::new(client_stream, noise_session);

    // 4. Exchange encrypted Noise frames
    let session_id: SessionId = [0xAA; 16];
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
    let payload = Bytes::from_static(b"Secret validated frame payload!");
    let frame = Frame::new(session_id, nonce, payload.clone()).unwrap();

    framed.send_frame(&frame).await.unwrap();

    let echo_frame = framed
        .recv_frame()
        .await
        .unwrap()
        .expect("must receive echoed frame from relay");
    assert_eq!(echo_frame.session_id, session_id);
    assert_eq!(echo_frame.nonce, nonce);
    assert_eq!(echo_frame.payload, payload);

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
}

#[tokio::test]
async fn test_full_handshake_with_invalid_token_diverted_to_fallback() {
    let server_secret = b"correct_server_token_secret_123";
    let wrong_client_token = b"wrong_attacker_token_secret_999";

    let (mock_addr, _mock_handle) = spawn_mock_camouflage_server().await;

    // 1. Start RelayListener
    let listener_config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), server_secret.to_vec())
        .with_fallback_target(mock_addr.to_string())
        .with_handshake_timeout(Duration::from_secs(2));

    let relay_listener = RelayListener::bind(listener_config).await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    let server_pub = relay_listener.secrets().public_key.clone();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(async move {
        let _ = relay_listener.run_with_shutdown(shutdown_rx).await;
    });

    // 2. Client connects and sends ClientHello with WRONG token
    let mut client_stream = TcpStream::connect(relay_addr).await.unwrap();
    let tls_builder = PseudoTlsBuilder::new(wrong_client_token.to_vec(), "cloudflare.com");
    let client_hello = tls_builder.build();
    client_stream.write_all(&client_hello).await.unwrap();
    client_stream.flush().await.unwrap();

    // 3. Client attempts Noise handshake. Because the relay routed to mock camouflage fallback,
    // client will either fail to get a valid Noise message 2 (unexpected EOF or HTTP data parse error).
    let handshake_res = client_noise_handshake(&mut client_stream, &server_pub).await;
    assert!(
        handshake_res.is_err(),
        "Noise handshake must fail when client sends invalid secret token"
    );

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
}

#[tokio::test]
async fn test_insecure_no_token_bypass_allows_connection_without_valid_token() {
    let server_secret = b"strict_server_token_secret_1234";
    let wrong_client_token = b"any_random_unauthorized_token";

    let (mock_addr, _mock_handle) = spawn_mock_camouflage_server().await;

    // Start RelayListener with insecure_no_token = true
    let listener_config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), server_secret.to_vec())
        .with_fallback_target(mock_addr.to_string())
        .with_insecure_no_token(true);

    let relay_listener = RelayListener::bind(listener_config).await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    let server_pub = relay_listener.secrets().public_key.clone();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(async move {
        let _ = relay_listener.run_with_shutdown(shutdown_rx).await;
    });

    // Client connects with wrong token
    let mut client_stream = TcpStream::connect(relay_addr).await.unwrap();
    let tls_builder = PseudoTlsBuilder::new(wrong_client_token.to_vec(), "cloudflare.com");
    let client_hello = tls_builder.build();
    client_stream.write_all(&client_hello).await.unwrap();
    client_stream.flush().await.unwrap();

    // Noise handshake succeeds because insecure_no_token bypassed check
    let noise_session = client_noise_handshake(&mut client_stream, &server_pub)
        .await
        .expect("Noise handshake must succeed when insecure_no_token is enabled");
    let mut framed = NoiseFramedStream::new(client_stream, noise_session);

    let session_id: SessionId = [0xBB; 16];
    let nonce = [0, 0, 0, 0, 0, 0, 0, 1];
    let payload = Bytes::from_static(b"Bypass test frame payload");
    let frame = Frame::new(session_id, nonce, payload.clone()).unwrap();

    framed.send_frame(&frame).await.unwrap();
    let echo_frame = framed.recv_frame().await.unwrap().unwrap();
    assert_eq!(echo_frame.payload, payload);

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
}
