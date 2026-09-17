use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use tokio_util::codec::{Decoder, Encoder};

/// Fixed total size of a frame in bytes (MTU-friendly wire format).
pub const FRAME_SIZE: usize = 1420;

/// Size of the SessionId field in bytes.
pub const SESSION_ID_SIZE: usize = 16;

/// Size of the Nonce field in bytes.
pub const NONCE_SIZE: usize = 8;

/// Size of the PayloadLength field in bytes.
pub const PAYLOAD_LEN_SIZE: usize = 2;

/// Total size of the frame header in bytes (16 + 8 + 2 = 26).
pub const HEADER_SIZE: usize = SESSION_ID_SIZE + NONCE_SIZE + PAYLOAD_LEN_SIZE;

/// Maximum allowed payload size in bytes: 1420 - 16 - 8 - 2 = 1394.
pub const MAX_PAYLOAD_SIZE: usize = FRAME_SIZE - HEADER_SIZE;

/// Session identifier (16 bytes).
pub type SessionId = [u8; SESSION_ID_SIZE];

/// Packet nonce (8 bytes).
pub type Nonce = [u8; NONCE_SIZE];

pub use crate::error::ProtocolError;

/// A parsed protocol frame.
///
/// Custom `Debug` implementation adheres to the security invariant:
/// "No sensitive metadata in logs: `tracing` must strictly omit IP addresses,
/// payloads, and session identifiers."
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    pub session_id: SessionId,
    pub nonce: Nonce,
    pub payload: Bytes,
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact session_id and payload content to avoid leaking sensitive data in logs
        f.debug_struct("Frame")
            .field("session_id", &"[REDACTED]")
            .field("nonce", &self.nonce)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl Frame {
    /// Creates a new `Frame` validating that the payload does not exceed `MAX_PAYLOAD_SIZE`.
    pub fn new(
        session_id: SessionId,
        nonce: Nonce,
        payload: impl Into<Bytes>,
    ) -> Result<Self, ProtocolError> {
        let payload = payload.into();
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }
        Ok(Self {
            session_id,
            nonce,
            payload,
        })
    }

    /// Parses a complete frame from a slice of at least `FRAME_SIZE` bytes.
    ///
    /// Returns `ProtocolError::FrameTooShort` without allocation if `slice.len() < FRAME_SIZE`.
    pub fn from_slice(slice: &[u8]) -> Result<Self, ProtocolError> {
        if slice.len() < FRAME_SIZE {
            return Err(ProtocolError::FrameTooShort {
                expected: FRAME_SIZE,
                actual: slice.len(),
            });
        }

        let mut buf = &slice[..FRAME_SIZE];

        let mut session_id = [0u8; SESSION_ID_SIZE];
        session_id.copy_from_slice(&buf[..SESSION_ID_SIZE]);
        buf.advance(SESSION_ID_SIZE);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&buf[..NONCE_SIZE]);
        buf.advance(NONCE_SIZE);

        let payload_len = buf.get_u16() as usize;
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload_len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let payload = Bytes::copy_from_slice(&buf[..payload_len]);

        Ok(Self {
            session_id,
            nonce,
            payload,
        })
    }

    /// Parses a complete frame from a `BytesMut` buffer.
    ///
    /// Splits off exactly `FRAME_SIZE` bytes from `src`.
    /// Returns `ProtocolError::FrameTooShort` without allocation if `src.len() < FRAME_SIZE`.
    pub fn parse(src: &mut BytesMut) -> Result<Self, ProtocolError> {
        if src.len() < FRAME_SIZE {
            return Err(ProtocolError::FrameTooShort {
                expected: FRAME_SIZE,
                actual: src.len(),
            });
        }

        let mut frame_bytes = src.split_to(FRAME_SIZE);

        let mut session_id = [0u8; SESSION_ID_SIZE];
        session_id.copy_from_slice(&frame_bytes[..SESSION_ID_SIZE]);
        frame_bytes.advance(SESSION_ID_SIZE);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&frame_bytes[..NONCE_SIZE]);
        frame_bytes.advance(NONCE_SIZE);

        let payload_len = frame_bytes.get_u16() as usize;
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload_len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let payload = frame_bytes.split_to(payload_len).freeze();

        Ok(Self {
            session_id,
            nonce,
            payload,
        })
    }
}

/// Constant-time slice comparison to prevent timing side-channels
/// (Architecture Invariant: Constant-time validation on all MAC/auth checks).
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut res = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        res |= x ^ y;
    }
    res == 0
}

/// Constant-time comparison for Session IDs.
#[inline]
pub fn session_id_eq(a: &SessionId, b: &SessionId) -> bool {
    constant_time_eq(a, b)
}

/// Codec for encoding and decoding fixed-size 1420-byte binary frames.
#[derive(Debug, Default, Clone, Copy)]
pub struct FrameCodec;

impl FrameCodec {
    /// Creates a new `FrameCodec`.
    pub fn new() -> Self {
        Self
    }

    /// Decodes an exact frame from `src`, returning `FrameTooShort` if fewer than 1420 bytes are available.
    pub fn decode_exact(&mut self, src: &mut BytesMut) -> Result<Frame, ProtocolError> {
        if src.len() < FRAME_SIZE {
            return Err(ProtocolError::FrameTooShort {
                expected: FRAME_SIZE,
                actual: src.len(),
            });
        }
        self.decode(src)?
            .ok_or(ProtocolError::FrameTooShort {
                expected: FRAME_SIZE,
                actual: src.len(),
            })
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = ProtocolError;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload_len = item.payload.len();
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload_len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        dst.reserve(FRAME_SIZE);
        dst.put_slice(&item.session_id);
        dst.put_slice(&item.nonce);
        dst.put_u16(payload_len as u16);
        dst.put_slice(&item.payload);

        let padding_needed = MAX_PAYLOAD_SIZE - payload_len;
        if padding_needed > 0 {
            dst.put_bytes(0, padding_needed);
        }

        Ok(())
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < FRAME_SIZE {
            // Fragmented / incomplete buffer: wait for more bytes from the stream
            return Ok(None);
        }

        // Strictly extract FRAME_SIZE bytes
        let mut frame_bytes = src.split_to(FRAME_SIZE);

        let mut session_id = [0u8; SESSION_ID_SIZE];
        session_id.copy_from_slice(&frame_bytes[..SESSION_ID_SIZE]);
        frame_bytes.advance(SESSION_ID_SIZE);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&frame_bytes[..NONCE_SIZE]);
        frame_bytes.advance(NONCE_SIZE);

        let payload_len = frame_bytes.get_u16() as usize;
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload_len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let payload = frame_bytes.split_to(payload_len).freeze();
        // Remaining padding bytes in frame_bytes are dropped

        Ok(Some(Frame {
            session_id,
            nonce,
            payload,
        }))
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode(buf)? {
            Some(frame) => Ok(Some(frame)),
            None => {
                if buf.is_empty() {
                    Ok(None)
                } else {
                    Err(ProtocolError::FrameTooShort {
                        expected: FRAME_SIZE,
                        actual: buf.len(),
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_valid_frame() {
        let mut codec = FrameCodec::new();
        let session_id: SessionId = [42u8; SESSION_ID_SIZE];
        let nonce: Nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let payload = Bytes::from_static(b"Hello, EchoMesh Relay Protocol!");

        let frame = Frame::new(session_id, nonce, payload.clone()).expect("valid frame");

        let mut buffer = BytesMut::new();
        codec.encode(frame.clone(), &mut buffer).expect("encode succeeds");

        // Must strictly produce 1420 bytes
        assert_eq!(buffer.len(), FRAME_SIZE);

        // Verify headers
        assert_eq!(&buffer[..16], &session_id);
        assert_eq!(&buffer[16..24], &nonce);
        assert_eq!(&buffer[24..26], &(payload.len() as u16).to_be_bytes());

        // Decode
        let decoded = codec.decode(&mut buffer).expect("decode succeeds");
        assert_eq!(decoded, Some(frame));
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_encode_decode_empty_payload() {
        let mut codec = FrameCodec::new();
        let session_id: SessionId = [1u8; SESSION_ID_SIZE];
        let nonce: Nonce = [0u8; NONCE_SIZE];
        let frame = Frame::new(session_id, nonce, Bytes::new()).expect("empty payload frame");

        let mut buffer = BytesMut::new();
        codec.encode(frame.clone(), &mut buffer).expect("encode succeeds");
        assert_eq!(buffer.len(), FRAME_SIZE);

        let decoded = codec.decode(&mut buffer).expect("decode succeeds");
        assert_eq!(decoded, Some(frame));
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_encode_decode_max_payload() {
        let mut codec = FrameCodec::new();
        let session_id: SessionId = [7u8; SESSION_ID_SIZE];
        let nonce: Nonce = [9u8; NONCE_SIZE];
        let payload = Bytes::from(vec![0xAA; MAX_PAYLOAD_SIZE]);
        let frame = Frame::new(session_id, nonce, payload.clone()).expect("max payload frame");

        let mut buffer = BytesMut::new();
        codec.encode(frame.clone(), &mut buffer).expect("encode succeeds");
        assert_eq!(buffer.len(), FRAME_SIZE);

        let decoded = codec.decode(&mut buffer).expect("decode succeeds");
        assert_eq!(decoded, Some(frame));
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_fragmented_packet_handling() {
        let mut codec = FrameCodec::new();
        let session_id: SessionId = [0xAB; SESSION_ID_SIZE];
        let nonce: Nonce = [0xCD; NONCE_SIZE];
        let payload = Bytes::from_static(b"Fragmented packet test data stream");
        let original_frame = Frame::new(session_id, nonce, payload).expect("valid frame");

        let mut full_buffer = BytesMut::new();
        codec
            .encode(original_frame.clone(), &mut full_buffer)
            .expect("encode succeeds");
        assert_eq!(full_buffer.len(), FRAME_SIZE);

        let mut stream_buffer = BytesMut::new();

        // 1. First fragment: 300 bytes
        stream_buffer.extend_from_slice(&full_buffer[..300]);
        let res = codec.decode(&mut stream_buffer).expect("decode ok");
        assert_eq!(res, None, "Incomplete buffer must return Ok(None)");
        assert_eq!(stream_buffer.len(), 300);

        // 2. Second fragment: another 500 bytes (total 800 bytes)
        stream_buffer.extend_from_slice(&full_buffer[300..800]);
        let res = codec.decode(&mut stream_buffer).expect("decode ok");
        assert_eq!(res, None, "Incomplete buffer must return Ok(None)");
        assert_eq!(stream_buffer.len(), 800);

        // 3. Final fragment: remaining 620 bytes (total 1420 bytes)
        stream_buffer.extend_from_slice(&full_buffer[800..FRAME_SIZE]);
        let res = codec.decode(&mut stream_buffer).expect("decode ok");
        assert_eq!(res, Some(original_frame));
        assert!(stream_buffer.is_empty(), "Buffer must be consumed after frame decoded");
    }

    #[test]
    fn test_payload_overflow_protection() {
        let mut codec = FrameCodec::new();
        let session_id: SessionId = [1u8; SESSION_ID_SIZE];
        let nonce: Nonce = [2u8; NONCE_SIZE];

        // Oversized payload: MAX_PAYLOAD_SIZE + 1 = 1395 bytes
        let oversized_payload = Bytes::from(vec![0xFF; MAX_PAYLOAD_SIZE + 1]);

        // 1. Protection in Frame::new
        let new_err = Frame::new(session_id, nonce, oversized_payload.clone()).unwrap_err();
        assert_eq!(
            new_err,
            ProtocolError::PayloadTooLarge {
                actual: 1395,
                max: MAX_PAYLOAD_SIZE,
            }
        );

        // 2. Protection in FrameCodec::encode
        let frame = Frame {
            session_id,
            nonce,
            payload: oversized_payload,
        };
        let mut buf = BytesMut::new();
        let encode_err = codec.encode(frame, &mut buf).unwrap_err();
        assert_eq!(
            encode_err,
            ProtocolError::PayloadTooLarge {
                actual: 1395,
                max: MAX_PAYLOAD_SIZE,
            }
        );

        // 3. Protection during decoding wire frame with PayloadLength > 1394
        let mut wire_buffer = BytesMut::zeroed(FRAME_SIZE);
        wire_buffer[..16].copy_from_slice(&session_id);
        wire_buffer[16..24].copy_from_slice(&nonce);
        wire_buffer[24..26].copy_from_slice(&1395u16.to_be_bytes());

        let decode_err = codec.decode(&mut wire_buffer).unwrap_err();
        assert_eq!(
            decode_err,
            ProtocolError::PayloadTooLarge {
                actual: 1395,
                max: MAX_PAYLOAD_SIZE,
            }
        );

        // 4. Protection against u16::MAX
        let mut wire_buffer_max = BytesMut::zeroed(FRAME_SIZE);
        wire_buffer_max[24..26].copy_from_slice(&u16::MAX.to_be_bytes());
        let decode_max_err = codec.decode(&mut wire_buffer_max).unwrap_err();
        assert_eq!(
            decode_max_err,
            ProtocolError::PayloadTooLarge {
                actual: 65535,
                max: MAX_PAYLOAD_SIZE,
            }
        );
    }

    #[test]
    fn test_frame_too_short_detection() {
        let mut codec = FrameCodec::new();

        // 1. Direct parsing via Frame::from_slice
        let short_data = vec![0u8; 1000];
        let err = Frame::from_slice(&short_data).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::FrameTooShort {
                expected: FRAME_SIZE,
                actual: 1000,
            }
        );

        // 2. Direct parsing via Frame::parse
        let mut short_buf = BytesMut::from(&short_data[..]);
        let err = Frame::parse(&mut short_buf).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::FrameTooShort {
                expected: FRAME_SIZE,
                actual: 1000,
            }
        );

        // 3. decode_exact on codec
        let mut short_buf2 = BytesMut::from(&short_data[..]);
        let err = codec.decode_exact(&mut short_buf2).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::FrameTooShort {
                expected: FRAME_SIZE,
                actual: 1000,
            }
        );

        // 4. decode_eof on codec with remaining bytes < FRAME_SIZE
        let mut eof_buf = BytesMut::from(&short_data[..]);
        let err = codec.decode_eof(&mut eof_buf).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::FrameTooShort {
                expected: FRAME_SIZE,
                actual: 1000,
            }
        );

        // 5. decode_eof with empty buffer returns Ok(None)
        let mut empty_buf = BytesMut::new();
        let res = codec.decode_eof(&mut empty_buf).expect("empty eof ok");
        assert_eq!(res, None);
    }

    #[test]
    fn test_zero_allocation_errors() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<ProtocolError>();

        let err = ProtocolError::PayloadTooLarge {
            actual: 2000,
            max: MAX_PAYLOAD_SIZE,
        };
        let err_copy = err;
        assert_eq!(err, err_copy);
    }

    #[test]
    fn test_security_invariants_and_redaction() {
        let session_id: SessionId = [0x55; SESSION_ID_SIZE];
        let nonce: Nonce = [0x77; NONCE_SIZE];
        let payload = Bytes::from_static(b"SECRET_PAYLOAD_DATA");

        let frame = Frame::new(session_id, nonce, payload).expect("valid frame");
        let debug_str = format!("{:?}", frame);

        // Ensure session ID and payload are redacted in logs/debug
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("SECRET_PAYLOAD_DATA"));
        assert!(debug_str.contains("payload_len: 19"));

        // Constant time comparison
        let same_id: SessionId = [0x55; SESSION_ID_SIZE];
        let diff_id: SessionId = [0x56; SESSION_ID_SIZE];
        assert!(session_id_eq(&session_id, &same_id));
        assert!(!session_id_eq(&session_id, &diff_id));
    }
}
