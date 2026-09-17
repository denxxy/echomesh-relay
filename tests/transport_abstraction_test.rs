use std::sync::Arc;
use bytes::Bytes;

use echomesh_relay::protocol::frame::{Frame, SessionId};
use echomesh_relay::server::connections::ConnectionManager;
use echomesh_relay::server::networking::ServerPipeline;
use echomesh_relay::server::routing::{ServerInboundRouter, ServerOutboundRouter};
use echomesh_relay::server::sessions::SessionManager;
use echomesh_relay::transport::memory::MemoryTransport;
use echomesh_relay::transport::noise::{NoiseSession, NOISE_PATTERN};
use echomesh_relay::transport::secure::SecureTransport;

fn create_in_memory_noise_pair() -> (NoiseSession, NoiseSession) {
    let builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
    let server_keypair = builder.generate_keypair().unwrap();
    let server_pub = server_keypair.public.clone();
    let server_priv = server_keypair.private.clone();

    let mut initiator = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
        .remote_public_key(&server_pub)
        .unwrap()
        .build_initiator()
        .unwrap();

    let mut responder = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
        .local_private_key(&server_priv)
        .unwrap()
        .build_responder()
        .unwrap();

    let mut msg1 = vec![0u8; 128];
    let n1 = initiator.write_message(&[], &mut msg1).unwrap();
    msg1.truncate(n1);

    let mut dummy = [0u8; 128];
    responder.read_message(&msg1, &mut dummy).unwrap();

    let mut msg2 = vec![0u8; 128];
    let n2 = responder.write_message(&[], &mut msg2).unwrap();
    msg2.truncate(n2);

    initiator.read_message(&msg2, &mut dummy).unwrap();

    (
        NoiseSession::new(initiator.into_transport_mode().unwrap()),
        NoiseSession::new(responder.into_transport_mode().unwrap()),
    )
}

#[tokio::test]
async fn test_secure_transport_over_memory_transport() {
    let (mem_client, mem_server) = MemoryTransport::pair(32);
    let (noise_client, noise_server) = create_in_memory_noise_pair();

    let mut secure_client = SecureTransport::new(mem_client, noise_client);
    let mut secure_server = SecureTransport::new(mem_server, noise_server);

    let session_id: SessionId = [0x55; 16];
    let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
    let payload = Bytes::from_static(b"Memory Transport Secure Frame Exchange");
    let frame = Frame::new(session_id, nonce, payload.clone()).unwrap();

    // Client sends encrypted frame over MemoryTransport
    secure_client.send_frame(&frame).await.expect("send frame ok");

    // Server receives and decrypts from MemoryTransport
    let received_frame = secure_server
        .recv_frame()
        .await
        .expect("recv frame ok")
        .expect("some frame");

    assert_eq!(received_frame.session_id, session_id);
    assert_eq!(received_frame.nonce, nonce);
    assert_eq!(received_frame.payload, payload);
}

#[tokio::test]
async fn test_server_pipeline_in_memory() {
    let connection_manager = ConnectionManager::new();
    let session_manager = SessionManager::new();

    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel(16);
    let dummy_addr = "127.0.0.1:9999".parse().unwrap();
    let conn_id = connection_manager.register(dummy_addr, outbound_tx.clone()).await;

    let session_id: SessionId = [0xEE; 16];
    let session = session_manager.create_session(session_id, None).await;
    connection_manager.bind_session(conn_id, session_id, None).await;

    let inbound_router = Arc::new(ServerInboundRouter::standard_relay());
    let outbound_router = ServerOutboundRouter::new(connection_manager.clone());

    let mut pipeline = ServerPipeline::new(
        conn_id,
        session,
        outbound_tx,
        inbound_router,
        outbound_router,
        connection_manager,
        session_manager,
    );

    // Send raw echo frame through pipeline
    let echo_frame = Frame::new(
        session_id,
        [0u8; 8],
        Bytes::from_static(b"Pipeline In-Memory Echo Test"),
    )
    .unwrap();

    pipeline.process_frame(echo_frame).await.unwrap();

    // Outbound channel receives reply frame
    let reply = outbound_rx.recv().await.expect("received reply frame");
    assert_eq!(reply.payload, Bytes::from_static(b"Pipeline In-Memory Echo Test"));
}
