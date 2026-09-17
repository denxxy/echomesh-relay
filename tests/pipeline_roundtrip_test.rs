use std::time::Duration;
use bytes::Bytes;
use tokio::sync::watch;

use echomesh_relay::client::EchoMeshClient;
use echomesh_relay::config::DEFAULT_SECRET_TOKEN;
use echomesh_relay::protocol::messages::ServerToClientMessage;
use echomesh_relay::server::{ListenerConfig, RelayListener};

#[tokio::test]
async fn test_full_client_server_pipeline_roundtrip() {
    let secret = DEFAULT_SECRET_TOKEN.to_vec();

    // 1. Bind server listener
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.clone())
        .with_fallback_target("")
        .with_max_connections(50);

    let listener = RelayListener::bind(config).await.expect("bind listener");
    let server_addr = listener.local_addr().expect("local addr");
    let server_pub = listener.secrets().public_key.clone();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(async move {
        let _ = listener.run_with_shutdown(shutdown_rx).await;
    });

    // 2. Connect client via high-level Client API
    let mut client = EchoMeshClient::connect(server_addr, secret, &server_pub)
        .await
        .expect("client connect");

    // 3. Test Heartbeat / Ping roundtrip
    let seq = client
        .ping(Duration::from_secs(2))
        .await
        .expect("ping roundtrip");
    assert_eq!(seq, 42);

    // 4. Test SendMessage request-response correlation
    let recipient: [u8; 32] = [0xAA; 32];
    let payload = Bytes::from_static(b"Strict Pipeline Structured Data");
    let response = client
        .send_message(recipient, payload.clone(), Duration::from_secs(2))
        .await
        .expect("send_message roundtrip");

    match response {
        ServerToClientMessage::SendMessageResponse { accepted, .. } => {
            assert!(accepted, "server must accept valid message");
        }
        other => panic!("expected SendMessageResponse, got {:?}", other),
    }

    // 5. Test Echo payload roundtrip
    client
        .send_echo(Bytes::from_static(b"Loopback Echo Payload Test"))
        .await
        .expect("send echo");

    // 6. Disconnect client cleanly
    client.disconnect().expect("client disconnect");

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
}
