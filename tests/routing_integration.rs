use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::sync::watch;

use echomesh_relay::protocol::Frame;
use echomesh_relay::server::router::{
    ROUTER_CONTROL_ID, ROUTE_REGISTERED_MAGIC, ROUTE_REGISTER_MAGIC,
    ROUTE_REGISTRATION_CONTEXT,
};
use echomesh_relay::server::{ListenerConfig, RelayListener};
use echomesh_relay::transport::{client_noise_handshake, NoiseFramedStream};

#[tokio::test]
async fn routes_between_two_registered_noise_clients() {
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), b"routing-test-secret".to_vec())
        .with_insecure_no_auth(true)
        .with_fallback_target("");
    let relay = RelayListener::bind(config).await.unwrap();
    let address = relay.local_addr().unwrap();
    let server_public_key = relay.secrets().public_key.clone();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(async move {
        relay.run_with_shutdown(shutdown_rx).await.unwrap();
    });

    let (mut alice, route_a) = connect_and_register(address, &server_public_key, [0xA1; 32]).await;
    let (mut bob, route_b) = connect_and_register(address, &server_public_key, [0xB2; 32]).await;

    let outgoing = Frame::new(route_a, [9u8; 8], Bytes::from_static(b"opaque-client-e2ee")).unwrap();
    bob.send_frame(&outgoing).await.unwrap();

    let delivered = tokio::time::timeout(std::time::Duration::from_secs(2), alice.recv_frame())
        .await
        .expect("routing timed out")
        .unwrap()
        .expect("relay closed Alice connection");
    assert_eq!(delivered.session_id, route_b, "relay must stamp authenticated sender route");
    assert_eq!(delivered.nonce, [9u8; 8]);
    assert_eq!(&delivered.payload[..], b"opaque-client-e2ee");

    let _ = shutdown_tx.send(true);
    server.await.unwrap();
}

async fn connect_and_register(
    address: std::net::SocketAddr,
    server_public_key: &[u8],
    seed: [u8; 32],
) -> (NoiseFramedStream<TcpStream>, [u8; 16]) {
    let signing = SigningKey::from_bytes(&seed);
    let peer_id = signing.verifying_key().to_bytes();
    let digest = Sha256::digest(peer_id);
    let mut route = [0u8; 16];
    route.copy_from_slice(&digest[..16]);

    let mut signed = Vec::with_capacity(ROUTE_REGISTRATION_CONTEXT.len() + 48);
    signed.extend_from_slice(ROUTE_REGISTRATION_CONTEXT);
    signed.extend_from_slice(&route);
    signed.extend_from_slice(&peer_id);
    let signature = signing.sign(&signed);

    let mut payload = Vec::with_capacity(116);
    payload.extend_from_slice(ROUTE_REGISTER_MAGIC);
    payload.extend_from_slice(&route);
    payload.extend_from_slice(&peer_id);
    payload.extend_from_slice(&signature.to_bytes());
    let registration = Frame::new(ROUTER_CONTROL_ID, [0u8; 8], Bytes::from(payload)).unwrap();

    let mut stream = TcpStream::connect(address).await.unwrap();
    let noise = client_noise_handshake(&mut stream, server_public_key).await.unwrap();
    let mut framed = NoiseFramedStream::new(stream, noise);
    framed.send_frame(&registration).await.unwrap();
    let ack = framed.recv_frame().await.unwrap().unwrap();
    assert_eq!(ack.session_id, ROUTER_CONTROL_ID);
    assert_eq!(&ack.payload[..4], ROUTE_REGISTERED_MAGIC);
    assert_eq!(&ack.payload[4..], &route);
    (framed, route)
}
