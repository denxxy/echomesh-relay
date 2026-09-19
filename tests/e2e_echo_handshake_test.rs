use std::net::SocketAddr;
use std::time::Duration;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use echomesh_relay::protocol::{Frame, SessionId};
use echomesh_relay::server::{ListenerConfig, RelayListener};
use echomesh_relay::transport::{
    client_noise_handshake, NoiseFramedStream, PseudoTlsBuilder,
};

const TEST_SECRET_TOKEN: &[u8] = b"integration-only-relay-token";

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

    // Production behavior requires an explicitly provisioned credential. The test
    // uses a test-only value rather than relying on any compiled application secret.
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), TEST_SECRET_TOKEN.to_vec())
        .with_fallback_target(fallback_addr.to_string())
        .with_max_connections(100);

    let listener = RelayListener::bind(config).await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let server_pub = listener.secrets().public_key.clone();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(async move {
        let _ = listener.run_with_shutdown(shutdown_rx).await;
    });

    let mut client_stream = TcpStream::connect(relay_addr).await.unwrap();
    let tls_builder = PseudoTlsBuilder::new(TEST_SECRET_TOKEN.to_vec(), "cloudflare.com");
    let client_hello = tls_builder.build();
    client_stream.write_all(&client_hello).await.unwrap();
    client_stream.flush().await.unwrap();

    let noise_session = client_noise_handshake(&mut client_stream, &server_pub)
        .await
        .expect("Noise handshake must succeed with explicitly matching test credential");
    let mut framed = NoiseFramedStream::new(client_stream, noise_session);

    let alice_id = [0xA1u8; 32];
    let bob_id = [0xB2u8; 32];

    // 1. Alice registers route
    let reg_alice = Frame::new(
        echomesh_relay::server::ROUTE_REGISTRATION_ID,
        [0; 8],
        Bytes::copy_from_slice(&alice_id),
    )
    .unwrap();
    framed.send_frame(&reg_alice).await.unwrap();

    // 2. Connect Bob and register route
    let mut bob_stream = TcpStream::connect(relay_addr).await.unwrap();
    let bob_hello = PseudoTlsBuilder::new(TEST_SECRET_TOKEN.to_vec(), "cloudflare.com").build();
    bob_stream.write_all(&bob_hello).await.unwrap();
    bob_stream.flush().await.unwrap();

    let bob_noise = client_noise_handshake(&mut bob_stream, &server_pub).await.unwrap();
    let mut bob_framed = NoiseFramedStream::new(bob_stream, bob_noise);
    let reg_bob = Frame::new(
        echomesh_relay::server::ROUTE_REGISTRATION_ID,
        [0; 8],
        Bytes::copy_from_slice(&bob_id),
    )
    .unwrap();
    bob_framed.send_frame(&reg_bob).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Alice sends message to Bob
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
    let payload = Bytes::from_static(b"E2E Routed Payload Test 1420b Wire");
    let msg_frame = Frame::new(bob_id[..16].try_into().unwrap(), nonce, payload.clone()).unwrap();
    framed.send_frame(&msg_frame).await.unwrap();

    // 4. Bob receives Alice's message
    let bob_reply = bob_framed
        .recv_frame()
        .await
        .unwrap()
        .expect("Bob must receive routed frame from Alice");
    assert_eq!(bob_reply.session_id, alice_id[..16]);
    assert_eq!(bob_reply.payload, payload);

    // 5. Alice MUST NOT receive her own message back (No Echo loopback)
    let alice_echo_timeout = tokio::time::timeout(Duration::from_millis(300), framed.recv_frame()).await;
    assert!(alice_echo_timeout.is_err(), "Relay must NOT echo message back to Alice");

    // 6. Unknown recipient dropped
    let unknown_session_id: SessionId = [0x42; 16];
    let unknown_frame = Frame::new(unknown_session_id, [0; 8], Bytes::from_static(b"drop me")).unwrap();
    framed.send_frame(&unknown_frame).await.unwrap();

    let timeout_res = tokio::time::timeout(Duration::from_millis(300), framed.recv_frame()).await;
    assert!(timeout_res.is_err(), "Relay must drop packets to unknown recipient without echoing");

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
}
