use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::sync::watch;

use echomesh_relay::protocol::Frame;
use echomesh_relay::server::router::{registration_frame, ROUTER_CONTROL_ID};
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

    let route_a = [0xA1; 16];
    let route_b = [0xB2; 16];
    let mut alice = connect_and_register(address, &server_public_key, route_a).await;
    let mut bob = connect_and_register(address, &server_public_key, route_b).await;

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
    route: [u8; 16],
) -> NoiseFramedStream<TcpStream> {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let noise = client_noise_handshake(&mut stream, server_public_key).await.unwrap();
    let mut framed = NoiseFramedStream::new(stream, noise);
    framed.send_frame(&registration_frame(route)).await.unwrap();
    let ack = framed.recv_frame().await.unwrap().unwrap();
    assert_eq!(ack.session_id, ROUTER_CONTROL_ID);
    assert_eq!(&ack.payload[..4], b"EMA1");
    assert_eq!(&ack.payload[4..], &route);
    framed
}
