use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::watch;

use echomesh_relay::protocol::Frame;
use echomesh_relay::server::{ListenerConfig, RelayListener, ROUTE_REGISTRATION_ID};
use echomesh_relay::transport::{client_noise_handshake, NoiseFramedStream, PseudoTlsBuilder};

async fn connect_client(
    relay_addr: std::net::SocketAddr,
    server_public: &[u8],
    secret: &[u8],
    peer_id: [u8; 32],
) -> NoiseFramedStream<TcpStream> {
    let mut stream = TcpStream::connect(relay_addr).await.unwrap();
    let hello = PseudoTlsBuilder::new(secret.to_vec(), "cloudflare.com").build();
    stream.write_all(&hello).await.unwrap();
    stream.flush().await.unwrap();
    let session = client_noise_handshake(&mut stream, server_public).await.unwrap();
    let mut framed = NoiseFramedStream::new(stream, session);
    framed.send_frame(&Frame::new(ROUTE_REGISTRATION_ID, [0;8], Bytes::copy_from_slice(&peer_id)).unwrap()).await.unwrap();
    framed
}

#[tokio::test]
async fn routes_between_registered_clients_and_rewrites_source_route() {
    let secret = b"routing-test-secret-32-bytes-long!!";
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target("");
    let listener = RelayListener::bind(config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let public = listener.secrets().public_key.clone();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move { listener.run_with_shutdown(shutdown_rx).await.unwrap(); });

    let alice_id = [0xA1;32];
    let bob_id = [0xB2;32];
    let mut alice = connect_client(addr, &public, secret, alice_id).await;
    let mut bob = connect_client(addr, &public, secret, bob_id).await;
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;

    let payload = Bytes::from_static(b"opaque-e2ee-envelope");
    alice.send_frame(&Frame::new(bob_id[..16].try_into().unwrap(), [1;8], payload.clone()).unwrap()).await.unwrap();
    let received = tokio::time::timeout(std::time::Duration::from_secs(2), bob.recv_frame()).await.unwrap().unwrap().unwrap();
    assert_eq!(received.session_id, alice_id[..16]);
    assert_eq!(received.payload, payload);

    let _ = shutdown_tx.send(true);
    let _ = task.await;
}
