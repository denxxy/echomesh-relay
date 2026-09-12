use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use echomesh_relay::server::{ListenerConfig, RelayListener};
use echomesh_relay::transport::PseudoTlsBuilder;

const TOTAL_CONNECTIONS: usize = 5_000;
const MAX_MEMORY_LIMIT_BYTES: usize = 150 * 1024 * 1024; // 150 MB

/// Returns the number of currently open file descriptors where the platform
/// exposes them through a proc/dev filesystem. Windows returns 0 and skips the
/// descriptor-count assertion instead of compiling Unix APIs there.
fn get_open_fd_count() -> usize {
    if let Ok(entries) = std::fs::read_dir("/dev/fd") {
        entries.count()
    } else if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
        entries.count()
    } else {
        0
    }
}

/// Returns resident/high-water memory usage in bytes when a portable primitive
/// is available. Returning 0 means "measurement unavailable" and callers skip
/// the memory assertion on that platform.
fn get_resident_memory_bytes() -> usize {
    #[cfg(target_os = "macos")]
    unsafe {
        use std::mem::MaybeUninit;
        let mut info: libc::mach_task_basic_info = MaybeUninit::zeroed().assume_init();
        let mut count = (std::mem::size_of::<libc::mach_task_basic_info>()
            / std::mem::size_of::<libc::natural_t>()) as libc::mach_msg_type_number_t;
        #[allow(deprecated)]
        let kret = libc::task_info(
            libc::mach_task_self(),
            libc::MACH_TASK_BASIC_INFO,
            &mut info as *mut _ as *mut libc::integer_t,
            &mut count,
        );
        if kret == libc::KERN_SUCCESS {
            info.resident_size as usize
        } else {
            0
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    unsafe {
        use std::mem::MaybeUninit;
        let mut usage: libc::rusage = MaybeUninit::zeroed().assume_init();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) == 0 {
            // Linux and the Unix CI targets used here report ru_maxrss in KiB.
            (usage.ru_maxrss as usize) * 1024
        } else {
            0
        }
    }

    #[cfg(not(unix))]
    {
        0
    }
}

/// Generates pseudo-random garbage patterns simulating DPI scanners and corrupt packets.
fn generate_fuzz_payload(index: usize) -> Vec<u8> {
    match index % 7 {
        0 => {
            let len = 10 + (index * 37) % 500;
            (0..len).map(|i| ((index + i * 17) & 0xFF) as u8).collect()
        }
        1 => {
            let mut buf = vec![0x16, 0x03, 0x01, 0x00, 0x80];
            buf.extend((0..40).map(|i| (i * 3) as u8));
            buf
        }
        2 => {
            format!(
                "GET /probe_{} HTTP/1.1\r\nHost: scanner.test\r\nUser-Agent: DPI-Probe/2.1\r\n\r\n",
                index
            )
            .into_bytes()
        }
        3 => {
            let fake_token = format!("unauthorized_token_{}", index).into_bytes();
            let builder = PseudoTlsBuilder::new(fake_token, "legit-site.com");
            builder.build()
        }
        4 => {
            let mut buf = PseudoTlsBuilder::new(
                format!("token_{}", index).into_bytes(),
                "example.com",
            )
            .build();
            if buf.len() > 20 {
                buf[15] ^= 0xFF;
                buf[20] ^= 0x80;
            }
            buf
        }
        5 => vec![0u8; 5 + (index % 64)],
        _ => vec![0xFFu8; 7 + (index % 96)],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_thousands_of_concurrent_connections() {
    let config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), b"stress-secret".to_vec())
        .with_max_connections(512)
        .with_fallback_target("")
        .with_handshake_timeout(Duration::from_millis(250));
    let relay = RelayListener::bind(config).await.unwrap();
    let addr = relay.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(async move {
        relay.run_with_shutdown(shutdown_rx).await.unwrap();
    });

    let initial_fds = get_open_fd_count();
    let initial_memory = get_resident_memory_bytes();
    let completed = Arc::new(AtomicUsize::new(0));
    let concurrency = Arc::new(Semaphore::new(256));
    let mut joins = JoinSet::new();

    for index in 0..TOTAL_CONNECTIONS {
        let permit = concurrency.clone().acquire_owned().await.unwrap();
        let completed = completed.clone();
        joins.spawn(async move {
            let _permit = permit;
            if let Ok(mut stream) = TcpStream::connect(addr).await {
                let payload = generate_fuzz_payload(index);
                let _ = stream.write_all(&payload).await;
                let _ = stream.flush().await;
                let mut sink = [0u8; 64];
                let _ = tokio::time::timeout(Duration::from_millis(50), stream.read(&mut sink)).await;
            }
            completed.fetch_add(1, Ordering::Relaxed);
        });
    }

    while joins.join_next().await.is_some() {}
    assert_eq!(completed.load(Ordering::Relaxed), TOTAL_CONNECTIONS);

    tokio::time::sleep(Duration::from_millis(300)).await;
    let final_fds = get_open_fd_count();
    let final_memory = get_resident_memory_bytes();

    if initial_fds != 0 && final_fds != 0 {
        assert!(
            final_fds <= initial_fds + 64,
            "file descriptor leak: initial={initial_fds}, final={final_fds}"
        );
    }
    if initial_memory != 0 && final_memory != 0 {
        let growth = final_memory.saturating_sub(initial_memory);
        assert!(
            growth <= MAX_MEMORY_LIMIT_BYTES,
            "memory growth exceeded limit: {growth} bytes"
        );
    }

    let _ = shutdown_tx.send(true);
    server.await.unwrap();
}
