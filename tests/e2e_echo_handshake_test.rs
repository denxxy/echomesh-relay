use std::net::SocketAddr;
use std::time::Duration;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use echomesh_relay::config::{DEFAULT_SECRET_TOKEN, ECHO_SERVICE_PEER_ID};
use echomesh_relay::protocol::{Frame, SessionId};
use echomesh_relay::server::{ListenerConfig, RelayListener};
use echomesh_relay::transport::{
    client_noise_handshake, NoiseFramedStream, PseudoTlsBuilder,
};

async fn spawn_mock_fallback_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
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
async fn test_e2e_echo_handshake_and_routing() {
    let (fallback_addr, _fallback_handle) = spawn_mock_fallback_server().await;

    // 1. Launch relay instance with production token validator
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), DEFAULT_SECRET_TOKEN.to_vec())
        .with_fallback_target(fallback_addr.to_string())
        .with_max_connections(100);

    let listener = RelayListener::bind(config).await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let server_pub = listener.secrets().public_key.clone();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(async move {
        let _ = listener.run_with_shutdown(shutdown_rx).await;
    });

    // 2. Client connects with Pseudo-TLS disguise token
    let mut client_stream = TcpStream::connect(relay_addr).await.unwrap();
    let tls_builder = PseudoTlsBuilder::new(DEFAULT_SECRET_TOKEN.to_vec(), "cloudflare.com");
    let client_hello = tls_builder.build();
    client_stream.write_all(&client_hello).await.unwrap();
    client_stream.flush().await.unwrap();

    // 3. Handshake completes without triggering fallback
    let noise_session = client_noise_handshake(&mut client_stream, &server_pub)
        .await
        .expect("Noise handshake must succeed with matching DEFAULT_SECRET_TOKEN");
    let mut framed = NoiseFramedStream::new(client_stream, noise_session);

    // 4. Send frame to ECHO_SERVICE_PEER_ID ([0xEE; 16])
    let echo_session_id: SessionId = [0xEE; 16];
    assert_eq!(&echo_session_id, &ECHO_SERVICE_PEER_ID[..16]);
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
    let payload = Bytes::from_static(b"E2E Echo Payload Test 1420b Wire");
    let echo_frame = Frame::new(echo_session_id, nonce, payload.clone()).unwrap();

    framed.send_frame(&echo_frame).await.unwrap();

    // 5. Verify echo response returned
    let reply = framed
        .recv_frame()
        .await
        .unwrap()
        .expect("relay must return echoed frame for ECHO_SERVICE_PEER_ID");
    assert_eq!(reply.session_id, echo_session_id);
    assert_eq!(reply.payload, payload);

    // 6. Test that frame to an unknown recipient is dropped (not echoed)
    let unknown_session_id: SessionId = [0x42; 16];
    let unknown_frame = Frame::new(unknown_session_id, [0; 8], Bytes::from_static(b"drop me")).unwrap();
    framed.send_frame(&unknown_frame).await.unwrap();

    let timeout_res = tokio::time::timeout(Duration::from_millis(300), framed.recv_frame()).await;
    assert!(
        timeout_res.is_err(),
        "Relay must drop packets to unknown recipient without echoing"
    );

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
}
