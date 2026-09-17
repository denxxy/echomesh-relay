use bytes::{Bytes, BytesMut};

use echomesh_relay::error::{ProtocolError, ValidationError};
use echomesh_relay::protocol::codec::EnvelopeCodec;
use echomesh_relay::protocol::envelope::{
    MessageEnvelope, MessageType, ENVELOPE_HEADER_SIZE, MAX_ENVELOPE_PAYLOAD_SIZE,
};
use echomesh_relay::protocol::messages::{
    ClientToServerMessage, DeliveryStatus, PeerStatus, ServerToClientMessage,
};
use echomesh_relay::protocol::validation::Validate;
use echomesh_relay::protocol::versioning::ProtocolVersion;

#[test]
fn test_message_envelope_encoding_and_decoding_roundtrip() {
    let payload = Bytes::from_static(b"Encapsulated Protocol Payload 2026");
    let envelope = MessageEnvelope::new(
        MessageType::SendMessage,
        1001,
        2002,
        1712345678,
        payload.clone(),
    )
    .expect("valid envelope");

    let mut buf = BytesMut::new();
    envelope.encode(&mut buf).expect("encode ok");
    assert_eq!(buf.len(), ENVELOPE_HEADER_SIZE + payload.len());

    let decoded = MessageEnvelope::decode(&buf).expect("decode ok");
    assert_eq!(decoded.version, ProtocolVersion::V1);
    assert_eq!(decoded.message_type, MessageType::SendMessage);
    assert_eq!(decoded.message_id, 1001);
    assert_eq!(decoded.correlation_id, 2002);
    assert_eq!(decoded.timestamp, 1712345678);
    assert_eq!(decoded.payload, payload);
}

#[test]
fn test_envelope_codec_client_to_server_messages() {
    // 1. AuthRequest
    let auth_msg = ClientToServerMessage::AuthRequest {
        token: b"client_auth_secret_key".to_vec(),
        client_version: 100,
    };
    let encoded = EnvelopeCodec::encode_client_message(&auth_msg, 1, 0, 1000).unwrap();
    let (env, decoded_msg) = EnvelopeCodec::decode_client_message(&encoded).unwrap();
    assert_eq!(env.message_type, MessageType::AuthRequest);
    assert_eq!(decoded_msg, auth_msg);

    // 2. ConnectRequest
    let connect_msg = ClientToServerMessage::ConnectRequest {
        peer_id: [0x77; 32],
    };
    let encoded = EnvelopeCodec::encode_client_message(&connect_msg, 2, 0, 1000).unwrap();
    let (_, decoded_msg) = EnvelopeCodec::decode_client_message(&encoded).unwrap();
    assert_eq!(decoded_msg, connect_msg);

    // 3. SendMessage
    let send_msg = ClientToServerMessage::SendMessage {
        recipient_id: [0x88; 32],
        data: Bytes::from_static(b"Secret Encrypted Message Body"),
    };
    let encoded = EnvelopeCodec::encode_client_message(&send_msg, 3, 0, 1000).unwrap();
    let (_, decoded_msg) = EnvelopeCodec::decode_client_message(&encoded).unwrap();
    assert_eq!(decoded_msg, send_msg);

    // 4. Heartbeat
    let hb_msg = ClientToServerMessage::Heartbeat { sequence: 999 };
    let encoded = EnvelopeCodec::encode_client_message(&hb_msg, 4, 0, 1000).unwrap();
    let (_, decoded_msg) = EnvelopeCodec::decode_client_message(&encoded).unwrap();
    assert_eq!(decoded_msg, hb_msg);
}

#[test]
fn test_envelope_codec_server_to_client_messages() {
    // 1. AuthResponse (Response)
    let auth_resp = ServerToClientMessage::AuthResponse {
        success: true,
        session_id: [0x55; 16],
    };
    let encoded = EnvelopeCodec::encode_server_message(&auth_resp, 10, 1, 2000).unwrap();
    let (env, decoded_msg) = EnvelopeCodec::decode_server_message(&encoded).unwrap();
    assert_eq!(env.correlation_id, 1);
    assert!(env.message_type.is_response());
    assert!(!env.message_type.is_event());
    assert_eq!(decoded_msg, auth_resp);

    // 2. IncomingMessageEvent (Event)
    let incoming_event = ServerToClientMessage::IncomingMessageEvent {
        sender_id: [0x44; 32],
        data: Bytes::from_static(b"Incoming Event Stream"),
    };
    let encoded = EnvelopeCodec::encode_server_message(&incoming_event, 11, 0, 2000).unwrap();
    let (env, decoded_msg) = EnvelopeCodec::decode_server_message(&encoded).unwrap();
    assert_eq!(env.correlation_id, 0);
    assert!(env.message_type.is_event());
    assert!(!env.message_type.is_response());
    assert_eq!(decoded_msg, incoming_event);

    // 3. DeliveryStatusEvent (Event)
    let delivery_event = ServerToClientMessage::DeliveryStatusEvent {
        message_id: 42,
        status: DeliveryStatus::Delivered,
    };
    let encoded = EnvelopeCodec::encode_server_message(&delivery_event, 12, 0, 2000).unwrap();
    let (_, decoded_msg) = EnvelopeCodec::decode_server_message(&encoded).unwrap();
    assert_eq!(decoded_msg, delivery_event);

    // 4. PeerEvent (Event)
    let peer_event = ServerToClientMessage::PeerEvent {
        peer_id: [0x33; 32],
        status: PeerStatus::Online,
    };
    let encoded = EnvelopeCodec::encode_server_message(&peer_event, 13, 0, 2000).unwrap();
    let (_, decoded_msg) = EnvelopeCodec::decode_server_message(&encoded).unwrap();
    assert_eq!(decoded_msg, peer_event);
}

#[test]
fn test_envelope_error_conditions() {
    // 1. Frame / Header too short
    let short_bytes = vec![1u8; 15]; // less than 30 bytes header
    let err = MessageEnvelope::decode(&short_bytes).unwrap_err();
    assert_eq!(
        err,
        ProtocolError::FrameTooShort {
            expected: ENVELOPE_HEADER_SIZE,
            actual: 15
        }
    );

    // 2. Oversized payload rejected
    let huge_payload = Bytes::from(vec![0u8; MAX_ENVELOPE_PAYLOAD_SIZE + 10]);
    let err = MessageEnvelope::new(MessageType::SendMessage, 1, 0, 0, huge_payload).unwrap_err();
    assert_eq!(
        err,
        ProtocolError::PayloadTooLarge {
            actual: MAX_ENVELOPE_PAYLOAD_SIZE + 10,
            max: MAX_ENVELOPE_PAYLOAD_SIZE,
        }
    );

    // 3. Unsupported protocol version
    let mut valid_envelope_bytes = MessageEnvelope::new(
        MessageType::SendMessage,
        1,
        0,
        0,
        Bytes::from_static(b"test"),
    )
    .unwrap()
    .to_bytes()
    .unwrap()
    .to_vec();

    valid_envelope_bytes[0] = 99; // Corrupt version
    let err = MessageEnvelope::decode(&valid_envelope_bytes).unwrap_err();
    assert_eq!(
        err,
        ProtocolError::UnsupportedVersion {
            expected: 1,
            actual: 99
        }
    );

    // 4. Unknown message type
    valid_envelope_bytes[0] = 1; // restore valid version
    valid_envelope_bytes[1] = 0xFE; // Invalid message type
    let err = MessageEnvelope::decode(&valid_envelope_bytes).unwrap_err();
    assert_eq!(err, ProtocolError::UnknownMessageType(0xFE));
}

#[test]
fn test_validation_rules() {
    // Response envelope missing correlation_id must fail validation
    let response_envelope = MessageEnvelope::new(
        MessageType::AuthResponse,
        1,
        0, // Missing correlation ID!
        0,
        Bytes::new(),
    )
    .unwrap();

    let val_res = response_envelope.validate();
    assert_eq!(val_res, Err(ValidationError::MissingCorrelationId));

    // Response envelope with valid correlation_id must pass validation
    let valid_response = MessageEnvelope::new(
        MessageType::AuthResponse,
        1,
        42, // Valid correlation ID
        0,
        Bytes::new(),
    )
    .unwrap();
    assert_eq!(valid_response.validate(), Ok(()));
}

#[test]
fn test_envelope_debug_redaction() {
    let secret = Bytes::from_static(b"VERY_SECRET_PLAINTEXT_PAYLOAD");
    let envelope = MessageEnvelope::new(MessageType::SendMessage, 1, 0, 0, secret).unwrap();
    let debug_output = format!("{:?}", envelope);

    assert!(debug_output.contains("[REDACTED]"));
    assert!(!debug_output.contains("VERY_SECRET_PLAINTEXT_PAYLOAD"));
}
