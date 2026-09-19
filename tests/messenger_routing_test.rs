use bytes::Bytes;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::watch;

use echomesh_relay::protocol::envelope::{MessageEnvelope, MessageType};
use echomesh_relay::protocol::messages::{ClientToServerMessage, ServerToClientMessage};
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
    framed
        .send_frame(&Frame::new(ROUTE_REGISTRATION_ID, [0; 8], Bytes::copy_from_slice(&peer_id)).unwrap())
        .await
        .unwrap();
    framed
}

#[tokio::test]
async fn test_online_delivery_alice_to_bob() {
    let secret = b"messenger-routing-test-secret-32b";
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target("");
    let listener = RelayListener::bind(config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let public = listener.secrets().public_key.clone();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move { listener.run_with_shutdown(shutdown_rx).await.unwrap(); });

    let alice_id = [0x11; 32];
    let bob_id = [0x22; 32];
    let mut alice = connect_client(addr, &public, secret, alice_id).await;
    let mut bob = connect_client(addr, &public, secret, bob_id).await;
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Alice sends structured SendMessage to Bob
    let text_payload = Bytes::from_static(b"hello bob!");
    let send_msg = ClientToServerMessage::SendMessage {
        recipient_id: bob_id,
        data: text_payload.clone(),
    };
    let envelope = MessageEnvelope::new(send_msg.message_type(), 1001, 0, 1720000000, send_msg.encode()).unwrap();
    let frame = Frame::new(alice_id[..16].try_into().unwrap(), [1; 8], envelope.to_bytes().unwrap()).unwrap();
    alice.send_frame(&frame).await.unwrap();

    // Alice must receive SendMessageResponse { accepted: true }
    let alice_resp_frame = tokio::time::timeout(Duration::from_secs(2), alice.recv_frame())
        .await
        .expect("Alice response timeout")
        .unwrap()
        .expect("Alice got frame");

    let (resp_env, alice_resp) = echomesh_relay::protocol::codec::EnvelopeCodec::decode_server_message(&alice_resp_frame.payload)
        .expect("decode Alice response");
    assert_eq!(resp_env.message_type, MessageType::SendMessageResponse);
    match alice_resp {
        ServerToClientMessage::SendMessageResponse { message_id, accepted } => {
            assert_eq!(message_id, 1001);
            assert!(accepted, "Message must be accepted by server");
        }
        other => panic!("Expected SendMessageResponse, got {:?}", other),
    }

    // Bob must receive IncomingMessageEvent with sender == Alice
    let bob_frame = tokio::time::timeout(Duration::from_secs(2), bob.recv_frame())
        .await
        .expect("Bob message timeout")
        .unwrap()
        .expect("Bob got frame");

    let (bob_env, bob_msg) = echomesh_relay::protocol::codec::EnvelopeCodec::decode_server_message(&bob_frame.payload)
        .expect("decode Bob message");
    assert_eq!(bob_env.message_type, MessageType::IncomingMessageEvent);
    match bob_msg {
        ServerToClientMessage::IncomingMessageEvent { sender_id, data } => {
            assert_eq!(sender_id, alice_id);
            assert_eq!(data, text_payload);
        }
        other => panic!("Expected IncomingMessageEvent, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
    let _ = task.await;
}

#[tokio::test]
async fn test_reverse_delivery_bob_to_alice() {
    let secret = b"messenger-routing-test-secret-32b";
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target("");
    let listener = RelayListener::bind(config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let public = listener.secrets().public_key.clone();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move { listener.run_with_shutdown(shutdown_rx).await.unwrap(); });

    let alice_id = [0x11; 32];
    let bob_id = [0x22; 32];
    let mut alice = connect_client(addr, &public, secret, alice_id).await;
    let mut bob = connect_client(addr, &public, secret, bob_id).await;
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Bob sends structured SendMessage to Alice
    let reply_payload = Bytes::from_static(b"hello alice!");
    let send_msg = ClientToServerMessage::SendMessage {
        recipient_id: alice_id,
        data: reply_payload.clone(),
    };
    let envelope = MessageEnvelope::new(send_msg.message_type(), 2002, 0, 1720000005, send_msg.encode()).unwrap();
    let frame = Frame::new(bob_id[..16].try_into().unwrap(), [2; 8], envelope.to_bytes().unwrap()).unwrap();
    bob.send_frame(&frame).await.unwrap();

    // Bob gets SendMessageResponse
    let bob_resp_frame = tokio::time::timeout(Duration::from_secs(2), bob.recv_frame())
        .await
        .expect("Bob response timeout")
        .unwrap()
        .expect("Bob got frame");

    let (_, bob_resp) = echomesh_relay::protocol::codec::EnvelopeCodec::decode_server_message(&bob_resp_frame.payload).unwrap();
    match bob_resp {
        ServerToClientMessage::SendMessageResponse { message_id, accepted } => {
            assert_eq!(message_id, 2002);
            assert!(accepted);
        }
        other => panic!("Expected SendMessageResponse, got {:?}", other),
    }

    // Alice gets IncomingMessageEvent with sender == Bob
    let alice_frame = tokio::time::timeout(Duration::from_secs(2), alice.recv_frame())
        .await
        .expect("Alice message timeout")
        .unwrap()
        .expect("Alice got frame");

    let (_, alice_msg) = echomesh_relay::protocol::codec::EnvelopeCodec::decode_server_message(&alice_frame.payload).unwrap();
    match alice_msg {
        ServerToClientMessage::IncomingMessageEvent { sender_id, data } => {
            assert_eq!(sender_id, bob_id);
            assert_eq!(data, reply_payload);
        }
        other => panic!("Expected IncomingMessageEvent, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
    let _ = task.await;
}

#[tokio::test]
async fn test_no_echo_regression() {
    let secret = b"messenger-routing-test-secret-32b";
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target("");
    let listener = RelayListener::bind(config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let public = listener.secrets().public_key.clone();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move { listener.run_with_shutdown(shutdown_rx).await.unwrap(); });

    let alice_id = [0x11; 32];
    let bob_id = [0x22; 32];
    let mut alice = connect_client(addr, &public, secret, alice_id).await;
    let mut bob = connect_client(addr, &public, secret, bob_id).await;
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Alice sends to Bob
    let text = Bytes::from_static(b"private message for Bob only");
    let send_msg = ClientToServerMessage::SendMessage {
        recipient_id: bob_id,
        data: text.clone(),
    };
    let envelope = MessageEnvelope::new(send_msg.message_type(), 3003, 0, 1720000010, send_msg.encode()).unwrap();
    let frame = Frame::new(alice_id[..16].try_into().unwrap(), [3; 8], envelope.to_bytes().unwrap()).unwrap();
    alice.send_frame(&frame).await.unwrap();

    // Alice receives SendMessageResponse { accepted: true }
    let alice_frame = tokio::time::timeout(Duration::from_secs(2), alice.recv_frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let (env, msg) = echomesh_relay::protocol::codec::EnvelopeCodec::decode_server_message(&alice_frame.payload).unwrap();
    assert_ne!(env.message_type, MessageType::IncomingMessageEvent, "Alice MUST NOT receive IncomingMessageEvent!");
    assert_eq!(env.message_type, MessageType::SendMessageResponse);
    match msg {
        ServerToClientMessage::SendMessageResponse { accepted, .. } => assert!(accepted),
        _ => panic!("Expected SendMessageResponse"),
    }

    // Ensure Alice has no additional frames pending (no echoed payload!)
    let second_frame = tokio::time::timeout(Duration::from_millis(200), alice.recv_frame()).await;
    assert!(second_frame.is_err(), "Alice must NOT receive any echoed frame!");

    // Bob receives the message
    let bob_frame = tokio::time::timeout(Duration::from_secs(2), bob.recv_frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let (_, bob_msg) = echomesh_relay::protocol::codec::EnvelopeCodec::decode_server_message(&bob_frame.payload).unwrap();
    match bob_msg {
        ServerToClientMessage::IncomingMessageEvent { sender_id, data } => {
            assert_eq!(sender_id, alice_id);
            assert_eq!(data, text);
        }
        _ => panic!("Expected IncomingMessageEvent"),
    }

    let _ = shutdown_tx.send(true);
    let _ = task.await;
}

#[tokio::test]
async fn test_offline_or_unknown_recipient() {
    let secret = b"messenger-routing-test-secret-32b";
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target("");
    let listener = RelayListener::bind(config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let public = listener.secrets().public_key.clone();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move { listener.run_with_shutdown(shutdown_rx).await.unwrap(); });

    let alice_id = [0x11; 32];
    let offline_bob_id = [0x99; 32];
    let mut alice = connect_client(addr, &public, secret, alice_id).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Alice sends to offline recipient
    let send_msg = ClientToServerMessage::SendMessage {
        recipient_id: offline_bob_id,
        data: Bytes::from_static(b"are you there?"),
    };
    let envelope = MessageEnvelope::new(send_msg.message_type(), 4004, 0, 1720000020, send_msg.encode()).unwrap();
    let frame = Frame::new(alice_id[..16].try_into().unwrap(), [4; 8], envelope.to_bytes().unwrap()).unwrap();
    alice.send_frame(&frame).await.unwrap();

    // Alice gets SendMessageResponse with accepted = false (offline recipient), not an echo
    let alice_frame = tokio::time::timeout(Duration::from_secs(2), alice.recv_frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let (env, msg) = echomesh_relay::protocol::codec::EnvelopeCodec::decode_server_message(&alice_frame.payload).unwrap();
    assert_eq!(env.message_type, MessageType::SendMessageResponse);
    match msg {
        ServerToClientMessage::SendMessageResponse { message_id, accepted } => {
            assert_eq!(message_id, 4004);
            assert!(!accepted, "Message to offline recipient must have accepted = false");
        }
        other => panic!("Expected SendMessageResponse, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
    let _ = task.await;
}

#[tokio::test]
async fn test_self_messaging_rejected() {
    let secret = b"messenger-routing-test-secret-32b";
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target("");
    let listener = RelayListener::bind(config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let public = listener.secrets().public_key.clone();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move { listener.run_with_shutdown(shutdown_rx).await.unwrap(); });

    let alice_id = [0x11; 32];
    let mut alice = connect_client(addr, &public, secret, alice_id).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Alice sends to HERSELF
    let send_msg = ClientToServerMessage::SendMessage {
        recipient_id: alice_id,
        data: Bytes::from_static(b"talking to myself"),
    };
    let envelope = MessageEnvelope::new(send_msg.message_type(), 5005, 0, 1720000030, send_msg.encode()).unwrap();
    let frame = Frame::new(alice_id[..16].try_into().unwrap(), [5; 8], envelope.to_bytes().unwrap()).unwrap();
    alice.send_frame(&frame).await.unwrap();

    // Server must reject self messaging
    let alice_frame = tokio::time::timeout(Duration::from_secs(2), alice.recv_frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let (env, msg) = echomesh_relay::protocol::codec::EnvelopeCodec::decode_server_message(&alice_frame.payload).unwrap();
    assert_eq!(env.message_type, MessageType::SendMessageResponse);
    match msg {
        ServerToClientMessage::SendMessageResponse { accepted, .. } => {
            assert!(!accepted, "Self messaging must be rejected");
        }
        _ => panic!("Expected rejection response"),
    }

    let _ = shutdown_tx.send(true);
    let _ = task.await;
}
