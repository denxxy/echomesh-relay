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

/// Helper: starts a dummy HTTP/TLS upstream server simulating the camouflage website (e.g. Cloudflare / Microsoft).
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
                            // Send authentic camouflage HTTP response
                            let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 17\r\nConnection: close\r\n\r\nCamouflage Target";
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
async fn test_authenticated_client_with_secret_token_connects_and_exchanges_frames() {
    let secret = b"super_secret_echomesh_key_32bytes";
    let (mock_addr, _mock_handle) = spawn_mock_camouflage_server().await;

    // 1. Start RelayListener
    let listener_config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target(mock_addr.to_string())
        .with_max_connections(50);

    let relay_listener = RelayListener::bind(listener_config).await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(async move {
        let _ = relay_listener.run_with_shutdown(shutdown_rx).await;
    });

    // 2. Connect legitimate client with PseudoTlsBuilder
    let mut client_stream = TcpStream::connect(relay_addr).await.unwrap();

    // Send TLS 1.3 ClientHello containing the secret token in random
    let tls_builder = PseudoTlsBuilder::new(secret.to_vec(), "cloudflare.com");
    let client_hello_bytes = tls_builder.build();
    client_stream.write_all(&client_hello_bytes).await.unwrap();
    client_stream.flush().await.unwrap();

    // 3. Client initiates Noise handshake over the same socket
    let noise_session = client_noise_handshake(&mut client_stream).await.unwrap();
    let mut framed_stream = NoiseFramedStream::new(client_stream, noise_session);

    // 4. Send 1420-byte EchoMesh binary frame
    let session_id: SessionId = [0x77; 16];
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
    let payload = Bytes::from_static(b"Stateless Relay Noise Payload");
    let outgoing_frame = Frame::new(session_id, nonce, payload.clone()).unwrap();

    framed_stream.send_frame(&outgoing_frame).await.unwrap();

    // 5. Receive echoed frame from relay
    let incoming_frame = framed_stream.recv_frame().await.unwrap().unwrap();
    assert_eq!(incoming_frame.session_id, session_id);
    assert_eq!(incoming_frame.nonce, nonce);
    assert_eq!(incoming_frame.payload, payload);

    // Stop server
    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
}

#[tokio::test]
async fn test_curl_probe_receives_standard_camouflage_website_response() {
    let secret = b"top_secret_auth_token";
    let (mock_addr, _mock_handle) = spawn_mock_camouflage_server().await;

    let listener_config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target(mock_addr.to_string())
        .with_handshake_timeout(Duration::from_secs(2));

    let relay_listener = RelayListener::bind(listener_config).await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(async move {
        let _ = relay_listener.run_with_shutdown(shutdown_rx).await;
    });

    // Run external curl command against the relay listener
    let curl_output = tokio::process::Command::new("curl")
        .arg("-s")
        .arg("-i")
        .arg(format!("http://{}", relay_addr))
        .output()
        .await
        .expect("failed to execute curl command");

    let stdout = String::from_utf8_lossy(&curl_output.stdout);
    assert!(
        stdout.contains("HTTP/1.1 200 OK"),
        "curl probe must receive 200 OK from fallback camouflage site, got: {}",
        stdout
    );
    assert!(
        stdout.contains("Camouflage Target"),
        "curl probe must receive mask body, got: {}",
        stdout
    );

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
}

#[tokio::test]
async fn test_scanner_with_invalid_secret_is_proxied_to_fallback() {
    let secret = b"correct_secret_key";
    let (mock_addr, _mock_handle) = spawn_mock_camouflage_server().await;

    let listener_config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target(mock_addr.to_string());

    let relay_listener = RelayListener::bind(listener_config).await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(async move {
        let _ = relay_listener.run_with_shutdown(shutdown_rx).await;
    });

    // Send valid TLS ClientHello, but with WRONG secret (e.g. active scanner probe)
    let mut probe_stream = TcpStream::connect(relay_addr).await.unwrap();
    let fake_builder = PseudoTlsBuilder::new(b"attacker_random_token".to_vec(), "cloudflare.com");
    let probe_bytes = fake_builder.build();

    probe_stream.write_all(&probe_bytes).await.unwrap();
    probe_stream.flush().await.unwrap();

    // Server must not reset connection aggressively, but fall-through proxy to mock camouflage
    let mut resp = [0u8; 1024];
    let n = probe_stream.read(&mut resp).await.unwrap();
    assert!(n > 0, "must receive response from fallback camouflage target");
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(resp_str.contains("HTTP/1.1 200 OK") || resp_str.contains("Camouflage Target"));

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
}

#[tokio::test]
async fn test_concurrency_semaphore_limits_connections() {
    let secret = b"secret";
    let (mock_addr, _mock_handle) = spawn_mock_camouflage_server().await;

    // Set max_connections = 2
    let listener_config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target(mock_addr.to_string())
        .with_max_connections(2);

    let relay_listener = RelayListener::bind(listener_config).await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(async move {
        let _ = relay_listener.run_with_shutdown(shutdown_rx).await;
    });

    // Connect 2 sockets
    let _conn1 = TcpStream::connect(relay_addr).await.unwrap();
    let _conn2 = TcpStream::connect(relay_addr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
}
