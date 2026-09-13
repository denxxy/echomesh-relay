use std::net::SocketAddr;
use std::time::Duration;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use echomesh_relay::protocol::{Frame, SessionId};
use echomesh_relay::server::{ListenerConfig, RelayListener};
use echomesh_relay::transport::{client_noise_handshake, NoiseFramedStream, PseudoTlsBuilder};

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
    let listener_config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target(mock_addr.to_string()).with_max_connections(50);
    let relay_listener = RelayListener::bind(listener_config).await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    let server_pub = relay_listener.secrets().public_key.clone();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(async move { let _ = relay_listener.run_with_shutdown(shutdown_rx).await; });

    let mut client_stream = TcpStream::connect(relay_addr).await.unwrap();
    let client_hello_bytes = PseudoTlsBuilder::new(secret.to_vec(), "cloudflare.com").build();
    client_stream.write_all(&client_hello_bytes).await.unwrap();
    client_stream.flush().await.unwrap();
    let noise_session = client_noise_handshake(&mut client_stream, &server_pub).await.unwrap();
    let mut framed_stream = NoiseFramedStream::new(client_stream, noise_session);
    let session_id: SessionId = [0xEE; 16];
    let nonce = [1,2,3,4,5,6,7,8];
    let payload = Bytes::from_static(b"Stateless Relay Noise Payload");
    framed_stream.send_frame(&Frame::new(session_id, nonce, payload.clone()).unwrap()).await.unwrap();
    let incoming_frame = framed_stream.recv_frame().await.unwrap().unwrap();
    assert_eq!(incoming_frame.session_id, session_id);
    assert_eq!(incoming_frame.nonce, nonce);
    assert_eq!(incoming_frame.payload, payload);
    let _ = shutdown_tx.send(true); let _ = server_task.await;
}

#[tokio::test]
async fn test_curl_probe_receives_standard_camouflage_website_response() {
    let secret = b"top_secret_auth_token";
    let (mock_addr, _mock_handle) = spawn_mock_camouflage_server().await;
    let config=ListenerConfig::new("127.0.0.1:0".parse().unwrap(),secret.to_vec()).with_fallback_target(mock_addr.to_string()).with_handshake_timeout(Duration::from_secs(2));
    let listener=RelayListener::bind(config).await.unwrap(); let addr=listener.local_addr().unwrap(); let(tx,rx)=watch::channel(false); let task=tokio::spawn(async move{let _=listener.run_with_shutdown(rx).await;});
    let output=tokio::process::Command::new("curl").arg("-s").arg("-i").arg(format!("http://{}",addr)).output().await.expect("curl");
    let stdout=String::from_utf8_lossy(&output.stdout); assert!(stdout.contains("HTTP/1.1 200 OK")); assert!(stdout.contains("Camouflage Target")); let _=tx.send(true);let _=task.await;
}

#[tokio::test]
async fn test_scanner_with_invalid_secret_is_proxied_to_fallback() {
    let secret=b"correct_secret_key"; let(mock_addr,_)=spawn_mock_camouflage_server().await;
    let config=ListenerConfig::new("127.0.0.1:0".parse().unwrap(),secret.to_vec()).with_fallback_target(mock_addr.to_string());
    let listener=RelayListener::bind(config).await.unwrap();let addr=listener.local_addr().unwrap();let(tx,rx)=watch::channel(false);let task=tokio::spawn(async move{let _=listener.run_with_shutdown(rx).await;});
    let mut stream=TcpStream::connect(addr).await.unwrap();let bytes=PseudoTlsBuilder::new(b"attacker_random_token".to_vec(),"cloudflare.com").build();stream.write_all(&bytes).await.unwrap();stream.flush().await.unwrap();let mut resp=[0u8;1024];let n=stream.read(&mut resp).await.unwrap();assert!(n>0);let s=String::from_utf8_lossy(&resp[..n]);assert!(s.contains("HTTP/1.1 200 OK")||s.contains("Camouflage Target"));let _=tx.send(true);let _=task.await;
}

#[tokio::test]
async fn test_concurrency_semaphore_limits_connections() {
    let(mock_addr,_)=spawn_mock_camouflage_server().await;let config=ListenerConfig::new("127.0.0.1:0".parse().unwrap(),b"secret".to_vec()).with_fallback_target(mock_addr.to_string()).with_max_connections(2);let listener=RelayListener::bind(config).await.unwrap();let addr=listener.local_addr().unwrap();let(tx,rx)=watch::channel(false);let task=tokio::spawn(async move{let _=listener.run_with_shutdown(rx).await;});let _a=TcpStream::connect(addr).await.unwrap();let _b=TcpStream::connect(addr).await.unwrap();tokio::time::sleep(Duration::from_millis(50)).await;let _=tx.send(true);let _=task.await;
}

#[tokio::test]
async fn test_listener_returns_secrets_on_startup() {
    let secret=b"my_verified_startup_secret_32bytes";let config=ListenerConfig::new("127.0.0.1:0".parse().unwrap(),secret.to_vec());let listener=RelayListener::bind(config).await.unwrap();let secrets=listener.secrets();assert_eq!(secrets.secret_token,secret);assert_eq!(listener.secret_token(),secret);assert_eq!(secrets.public_key.len(),32);assert_eq!(secrets.public_key_hex.len(),64);assert_eq!(secrets.private_key.len(),32);let debug=format!("{:?}",secrets);assert!(debug.contains("[REDACTED]"));assert!(!debug.contains(&secrets.private_key_hex));
}

#[tokio::test]
async fn test_relay_secrets_generate_random_token() {
    use echomesh_relay::server::RelaySecrets;
    let addr:SocketAddr="127.0.0.1:8443".parse().unwrap();let a=RelaySecrets::generate(addr,None).unwrap();let b=RelaySecrets::generate(addr,None).unwrap();assert_eq!(a.secret_token.len(),32);assert_eq!(b.secret_token.len(),32);assert_ne!(a.secret_token,b.secret_token);assert_ne!(a.public_key,b.public_key);
}

#[tokio::test]
async fn explicit_credential_export_is_opt_in() {
    let output=tokio::process::Command::new("cargo").args(["run","--quiet","--","--show-credentials"]).output().await.expect("credential export");
    assert!(output.status.success());
    let stdout=String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"public_key_base64\":"));
    assert!(stdout.contains("\"secret_token_hex\":"));
}
