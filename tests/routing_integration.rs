use bytes::Bytes;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
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

#[tokio::test]
async fn reconnect_overwrites_stale_route() {
    let secret = b"routing-test-secret";
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target("");
    let listener = RelayListener::bind(config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let public = listener.secrets().public_key.clone();
    let _task = tokio::spawn(async move { listener.run().await.unwrap(); });

    let alice_id = [0xA1;32];
    let bob_id = [0xB2;32];

    let mut alice = connect_client(addr, &public, secret, alice_id).await;
    {
        // Bob connects
        let bob1 = connect_client(addr, &public, secret, bob_id).await;
        // Bob disconnects abruptly
        drop(bob1);
    }
    
    // Give relay a moment to process disconnect (or not, if it's lagging)
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    
    // Bob reconnects
    let mut bob2 = connect_client(addr, &public, secret, bob_id).await;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // Alice sends to Bob
    let payload = Bytes::from_static(b"hello bob 2!");
    alice.send_frame(&Frame::new(bob_id[..16].try_into().unwrap(), [1;8], payload.clone()).unwrap()).await.unwrap();
    
    // Bob should receive it on his new connection
    let received = tokio::time::timeout(std::time::Duration::from_secs(2), bob2.recv_frame()).await.unwrap().unwrap().unwrap();
    assert_eq!(received.payload, payload);
}

#[tokio::test]
async fn echo_route_is_rejected_no_loopback() {
    let secret = b"routing-test-secret";
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target("");
    let listener = RelayListener::bind(config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let public = listener.secrets().public_key.clone();
    let _task = tokio::spawn(async move { listener.run().await.unwrap(); });

    let alice_id = [0xA1;32];
    let mut alice = connect_client(addr, &public, secret, alice_id).await;
    
    let echo_id = [0xEE; 16];
    let payload = Bytes::from_static(b"echoing this");
    alice.send_frame(&Frame::new(echo_id, [42;8], payload.clone()).unwrap()).await.unwrap();

    // Server must NOT echo back to alice - timeout expected
    let received = tokio::time::timeout(std::time::Duration::from_millis(300), alice.recv_frame()).await;
    assert!(received.is_err(), "relay must NOT echo frame back to sender");
}

/// Disconnect cleanup: after a peer disconnects, frames sent to its route ID
/// should be silently dropped (not crash the relay).
#[tokio::test]
async fn frames_to_disconnected_peer_are_dropped() {
    let secret = b"routing-test-secret";
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target("");
    let listener = RelayListener::bind(config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let public = listener.secrets().public_key.clone();
    let _task = tokio::spawn(async move { listener.run().await.unwrap(); });

    let alice_id = [0xA1;32];
    let bob_id = [0xB2;32];

    let mut alice = connect_client(addr, &public, secret, alice_id).await;
    let bob = connect_client(addr, &public, secret, bob_id).await;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // Bob drops (simulates abrupt disconnect)
    drop(bob);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Alice sends to disconnected Bob — relay should drop it silently
    let payload = Bytes::from_static(b"message for ghost");
    alice.send_frame(&Frame::new(bob_id[..16].try_into().unwrap(), [1;8], payload).unwrap()).await.unwrap();

    // Alice should not receive any error or extra data — timeout means relay stayed silent
    let no_frame = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        alice.recv_frame(),
    ).await;
    assert!(no_frame.is_err() || matches!(no_frame, Ok(Ok(None))), "relay should not forward to disconnected peer");
}

/// Concurrent peers: multiple peers routing simultaneously.
#[tokio::test]
async fn multiple_concurrent_peers_route_correctly() {
    let secret = b"routing-test-secret";
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target("");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let listener = RelayListener::bind(config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let public = listener.secrets().public_key.clone();
    let _task = tokio::spawn(async move { listener.run_with_shutdown(shutdown_rx).await.unwrap(); });

    const N: usize = 8;
    let mut peers: Vec<([u8; 32], NoiseFramedStream<TcpStream>)> = Vec::new();
    for i in 0..N {
        let mut id = [0u8; 32];
        id[0] = i as u8;
        id[1] = 0xCC;
        let conn = connect_client(addr, &public, secret, id).await;
        peers.push((id, conn));
    }
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;

    // Each peer sends to the next in a ring
    for i in 0..N {
        let recipient_id = peers[(i + 1) % N].0;
        let payload = Bytes::copy_from_slice(&[i as u8; 16]);
        peers[i].1.send_frame(
            &Frame::new(recipient_id[..16].try_into().unwrap(), [i as u8; 8], payload).unwrap()
        ).await.unwrap();
    }

    // Each peer receives from the previous — verify routing is correct
    for i in 0..N {
        let expected_sender = peers[(i + N - 1) % N].0;
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peers[i].1.recv_frame(),
        ).await.unwrap().unwrap().unwrap();
        // session_id is rewritten to sender's route prefix
        assert_eq!(received.session_id, expected_sender[..16]);
    }

    let _ = shutdown_tx.send(true);
}

/// Malformed raw bytes from a non-Noise client should cause the relay to fall
/// through to the proxy path (or close the connection), not panic.
#[tokio::test]
async fn malformed_connection_does_not_crash_relay() {
    let secret = b"routing-test-secret";
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target(""); // no fallback target → just closes
    let listener = RelayListener::bind(config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _task = tokio::spawn(async move { listener.run().await.unwrap(); });

    // Send garbage that looks neither like TLS nor a valid Noise intro
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"\x00\x00\x00garbage bytes that are not valid TLS or Noise").await.unwrap();
    stream.flush().await.unwrap();

    // Connection should be terminated (EOF or immediate close), not hang
    let mut buf = [0u8; 16];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read(&mut buf),
    ).await.expect("relay should close connection, not hang").ok();
}

/// Wrong token → relay must fall through (proxy or close), never accept.
#[tokio::test]
async fn wrong_token_rejected() {
    let secret = b"correct-secret-token";
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target("");
    let listener = RelayListener::bind(config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let public = listener.secrets().public_key.clone();
    let _task = tokio::spawn(async move { listener.run().await.unwrap(); });

    // Use a wrong token — Noise handshake should fail or connection get dropped
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let bad_hello = PseudoTlsBuilder::new(b"WRONG-TOKEN".to_vec(), "cloudflare.com").build();
    stream.write_all(&bad_hello).await.unwrap();
    stream.flush().await.unwrap();

    // Relay proxies or closes — Noise handshake must NOT succeed
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_noise_handshake(&mut stream, &public),
    ).await;
    assert!(result.is_err() || result.unwrap().is_err(),
        "relay must not complete Noise handshake for wrong token");
}

#[tokio::test]
async fn client_to_client_delivery_ack_exchange() {
    let secret = b"routing-ack-test-secret-32-bytes";
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target("");
    let listener = RelayListener::bind(config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let public = listener.secrets().public_key.clone();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move { listener.run_with_shutdown(shutdown_rx).await.unwrap(); });

    let alice_id = [0xAA; 32];
    let bob_id = [0xBB; 32];

    let mut alice = connect_client(addr, &public, secret, alice_id).await;
    let mut bob = connect_client(addr, &public, secret, bob_id).await;
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;

    // 1. Alice sends chat message to Bob
    let msg_id = b"msg_1726700000000";
    let text_payload = Bytes::from_static(b"Hello Bob from Alice!");
    let send_nonce = 1726700000000u64.to_be_bytes();
    alice.send_frame(&Frame::new(bob_id[..16].try_into().unwrap(), send_nonce, text_payload.clone()).unwrap()).await.unwrap();

    // 2. Bob receives message
    let bob_received = tokio::time::timeout(std::time::Duration::from_secs(2), bob.recv_frame()).await.unwrap().unwrap().unwrap();
    assert_eq!(bob_received.session_id, alice_id[..16]);
    assert_eq!(bob_received.payload, text_payload);
    assert_eq!(bob_received.nonce, send_nonce);

    // 3. Bob sends Delivery ACK back to Alice with discriminator 0x06 + msg_id
    let mut ack_payload = vec![0x06u8];
    ack_payload.extend_from_slice(msg_id);
    let ack_nonce = 1726700000050u64.to_be_bytes();
    bob.send_frame(&Frame::new(bob_received.session_id, ack_nonce, Bytes::from(ack_payload)).unwrap()).await.unwrap();

    // 4. Alice receives Delivery ACK
    let alice_received = tokio::time::timeout(std::time::Duration::from_secs(2), alice.recv_frame()).await.unwrap().unwrap().unwrap();
    assert_eq!(alice_received.session_id, bob_id[..16]);
    assert_eq!(alice_received.payload.first(), Some(&0x06));
    assert_eq!(&alice_received.payload[1..], msg_id);

    // 5. Verify symmetrical exchange: Bob sends to Alice, Alice ACKs to Bob
    let bob_text = Bytes::from_static(b"Hello Alice from Bob!");
    let bob_nonce = 1726700000100u64.to_be_bytes();
    bob.send_frame(&Frame::new(alice_id[..16].try_into().unwrap(), bob_nonce, bob_text.clone()).unwrap()).await.unwrap();

    let alice_received_msg = tokio::time::timeout(std::time::Duration::from_secs(2), alice.recv_frame()).await.unwrap().unwrap().unwrap();
    assert_eq!(alice_received_msg.session_id, bob_id[..16]);
    assert_eq!(alice_received_msg.payload, bob_text);

    let mut alice_ack_payload = vec![0x06u8];
    alice_ack_payload.extend_from_slice(b"msg_1726700000100");
    alice.send_frame(&Frame::new(alice_received_msg.session_id, [0; 8], Bytes::from(alice_ack_payload)).unwrap()).await.unwrap();

    let bob_received_ack = tokio::time::timeout(std::time::Duration::from_secs(2), bob.recv_frame()).await.unwrap().unwrap().unwrap();
    assert_eq!(bob_received_ack.session_id, alice_id[..16]);
    assert_eq!(bob_received_ack.payload.first(), Some(&0x06));
    assert_eq!(&bob_received_ack.payload[1..], b"msg_1726700000100");

    let _ = shutdown_tx.send(true);
    let _ = task.await;
}

