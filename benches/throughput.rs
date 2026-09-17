use bytes::BytesMut;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use echomesh_relay::protocol::{Frame, FrameCodec, FRAME_SIZE};
use echomesh_relay::transport::{NoiseSession, NOISE_PATTERN};
use tokio_util::codec::{Decoder, Encoder};

const BATCH_SIZE_100K: usize = 100_000;

fn create_sample_frames(count: usize) -> Vec<Frame> {
    let payload = vec![0x5A; 1000];
    (0..count)
        .map(|i| {
            let session_id = [((i >> 8) & 0xFF) as u8; 16];
            let nonce = (i as u64).to_be_bytes();
            Frame::new(session_id, nonce, payload.clone()).expect("valid frame")
        })
        .collect()
}

fn create_noise_session_pair() -> (NoiseSession, NoiseSession) {
    let pattern: snow::params::NoiseParams = NOISE_PATTERN.parse().expect("valid noise pattern");
    let keypair = snow::Builder::new(pattern.clone())
        .generate_keypair()
        .expect("generate keypair");
    let mut initiator = snow::Builder::new(pattern.clone())
        .remote_public_key(&keypair.public)
        .expect("set remote pub key")
        .build_initiator()
        .expect("initiator builder");
    let mut responder = snow::Builder::new(pattern)
        .local_private_key(&keypair.private)
        .expect("set local priv key")
        .build_responder()
        .expect("responder builder");

    // Handshake message 1 (-> e)
    let mut msg1 = vec![0u8; 128];
    let len1 = initiator.write_message(&[], &mut msg1).expect("msg1 write");
    msg1.truncate(len1);

    let mut dummy = [0u8; 128];
    responder
        .read_message(&msg1, &mut dummy)
        .expect("msg1 read");

    // Handshake message 2 (<- e, ee)
    let mut msg2 = vec![0u8; 128];
    let len2 = responder.write_message(&[], &mut msg2).expect("msg2 write");
    msg2.truncate(len2);

    initiator
        .read_message(&msg2, &mut dummy)
        .expect("msg2 read");

    let init_transport = initiator
        .into_transport_mode()
        .expect("initiator transport");
    let resp_transport = responder
        .into_transport_mode()
        .expect("responder transport");

    (
        NoiseSession::new(init_transport),
        NoiseSession::new(resp_transport),
    )
}

fn bench_frame_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_throughput_100k");
    group.sample_size(10);
    group.throughput(Throughput::Elements(BATCH_SIZE_100K as u64));

    let frames = create_sample_frames(BATCH_SIZE_100K);

    // Pre-encode frames into serialized byte buffers for parsing benchmark
    let mut codec = FrameCodec::new();
    let mut raw_frames = Vec::with_capacity(BATCH_SIZE_100K);
    for frame in &frames {
        let mut buf = BytesMut::with_capacity(FRAME_SIZE);
        codec.encode(frame.clone(), &mut buf).expect("encode frame");
        raw_frames.push(buf.to_vec());
    }

    // 1. Benchmark serialization of 100,000 frames
    group.bench_function("serialization_100k_frames", |b| {
        b.iter(|| {
            let mut codec = FrameCodec::new();
            let mut buffer = BytesMut::with_capacity(FRAME_SIZE);
            for frame in &frames {
                buffer.clear();
                codec
                    .encode(black_box(frame.clone()), &mut buffer)
                    .expect("encode succeeds");
                black_box(buffer.len());
            }
        })
    });

    // 2. Benchmark parsing 100,000 frames using Frame::from_slice
    group.bench_function("parsing_from_slice_100k_frames", |b| {
        b.iter(|| {
            for raw in &raw_frames {
                let parsed = Frame::from_slice(black_box(raw)).expect("valid slice");
                black_box(parsed);
            }
        })
    });

    // 3. Benchmark parsing 100,000 frames using FrameCodec::decode
    group.bench_function("parsing_codec_decode_100k_frames", |b| {
        b.iter(|| {
            let mut codec = FrameCodec::new();
            for raw in &raw_frames {
                let mut buf = BytesMut::from(&raw[..]);
                let parsed = codec.decode(&mut buf).expect("decode succeeds").expect("frame present");
                black_box(parsed);
            }
        })
    });

    group.finish();
}

fn bench_noise_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("noise_latency");
    let sample_frame = Frame::new(
        [0x42; 16],
        [1, 2, 3, 4, 5, 6, 7, 8],
        vec![0x7A; 1000],
    )
    .expect("valid frame");

    // 1. Single frame encryption latency
    let (mut alice_enc, _) = create_noise_session_pair();
    group.bench_function("noise_encrypt_single_frame", |b| {
        b.iter(|| {
            let packet = alice_enc.encrypt_frame(black_box(&sample_frame)).expect("encrypt succeeds");
            black_box(packet);
        })
    });

    // 2. Single frame roundtrip (encrypt + decrypt) latency
    let (mut alice_rt, mut bob_rt) = create_noise_session_pair();
    group.bench_function("noise_encrypt_decrypt_roundtrip_single_frame", |b| {
        b.iter(|| {
            let packet = alice_rt.encrypt_frame(black_box(&sample_frame)).expect("encrypt succeeds");
            let decrypted = bob_rt.decrypt_frame(black_box(&packet[2..])).expect("decrypt succeeds");
            black_box(decrypted);
        })
    });

    // 3. Single frame decryption latency
    group.bench_function("noise_decrypt_single_frame", |b| {
        b.iter_batched(
            || {
                let (mut alice, bob) = create_noise_session_pair();
                let batch: Vec<Vec<u8>> = (0..50)
                    .map(|_| alice.encrypt_frame(&sample_frame).expect("encrypt frame"))
                    .collect();
                (batch, bob)
            },
            |(batch, mut bob)| {
                for packet in batch {
                    let frame = bob.decrypt_frame(black_box(&packet[2..])).expect("decrypt frame");
                    black_box(frame);
                }
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, bench_frame_throughput, bench_noise_latency);
criterion_main!(benches);
