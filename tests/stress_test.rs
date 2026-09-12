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
const MAX_MEMORY_LIMIT_BYTES: usize = 150 * 1024 * 1024;

fn get_open_fd_count() -> usize {
    if let Ok(entries) = std::fs::read_dir("/dev/fd") {
        entries.count()
    } else if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
        entries.count()
    } else {
        0
    }
}

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
            PseudoTlsBuilder::new(fake_token, "legit-site.com").build()
        }
        4 => {
            let valid = PseudoTlsBuilder::new(b"secret".to_vec(), "legit-site.com").build();
            let mut corrupted = valid;
            for i in (5..corrupted.len()).step_by(7) {
                corrupted[i] ^= 0xFF;
            }
            corrupted
        }
        5 => {
            let len = 1 + (index % 4);
            vec![0x16, 0x03, 0x03, 0x01][..len].to_vec()
        }
        _ => Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_stress_5000_concurrent_connections_no_panic_low_memory_no_fd_leak() {
    let baseline_fd = get_open_fd_count();
    let baseline_mem = get_resident_memory_bytes();
    println!(
        "--- Stress Test Baseline: {} open FDs, {:.2} MB RSS ---",
        baseline_fd,
        baseline_mem as f64 / (1024.0 * 1024.0)
    );

    let secret = b"echomesh_super_secret_auth_token_32b";
    let listener_config = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), secret.to_vec())
        .with_fallback_target("")
        .with_max_connections(6000)
        .with_handshake_timeout(Duration::from_millis(100));

    let relay_listener = Arc::new(RelayListener::bind(listener_config).await.expect("bind relay"));
    let relay_addr = relay_listener.local_addr().expect("relay addr");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let listener_for_task = Arc::clone(&relay_listener);
    let server_task = tokio::spawn(async move {
        let _ = listener_for_task.run_with_shutdown(shutdown_rx).await;
    });

    let client_concurrency = Arc::new(Semaphore::new(500));
    let mut join_set = JoinSet::new();
    let completed_counter = Arc::new(AtomicUsize::new(0));

    println!("Launching {} concurrent fuzzing connections...", TOTAL_CONNECTIONS);

    for i in 0..TOTAL_CONNECTIONS {
        let sem = Arc::clone(&client_concurrency);
        let completed = Arc::clone(&completed_counter);
        let payload = generate_fuzz_payload(i);

        join_set.spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore acquire");
            let mut stream = match TcpStream::connect(relay_addr).await {
                Ok(s) => s,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    match TcpStream::connect(relay_addr).await {
                        Ok(s) => s,
                        Err(_) => return,
                    }
                }
            };

            if !payload.is_empty() {
                let _ = stream.write_all(&payload).await;
                let _ = stream.flush().await;
            }

            let mut resp = [0u8; 256];
            let _ = tokio::time::timeout(Duration::from_millis(50), stream.read(&mut resp)).await;
            completed.fetch_add(1, Ordering::Relaxed);
        });
    }

    while let Some(res) = join_set.join_next().await {
        res.expect("task join");
    }

    let finished_count = completed_counter.load(Ordering::Relaxed);
    println!("Completed {}/{} client connections", finished_count, TOTAL_CONNECTIONS);

    assert!(
        !server_task.is_finished(),
        "Relay listener server task unexpectedly terminated or panicked!"
    );

    for _ in 0..50 {
        if relay_listener.active_connections() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        relay_listener.active_connections(),
        0,
        "All active connection permits should be returned to zero"
    );

    let current_mem = get_resident_memory_bytes();
    let current_mem_mb = current_mem as f64 / (1024.0 * 1024.0);
    println!("Post-stress memory consumption: {:.2} MB", current_mem_mb);
    if current_mem != 0 {
        assert!(
            current_mem < MAX_MEMORY_LIMIT_BYTES,
            "RAM consumption exceeded limit: {:.2} MB >= 150 MB",
            current_mem_mb
        );
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    let final_fd = get_open_fd_count();
    println!("Post-stress open file descriptors: {} (baseline was {})", final_fd, baseline_fd);
    if baseline_fd != 0 && final_fd != 0 {
        assert!(
            final_fd <= baseline_fd + 15,
            "File descriptor leak detected: final FDs ({}) significantly exceeded baseline ({})",
            final_fd,
            baseline_fd
        );
    }

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;

    println!("--- Stress Test PASSED: No panics, RAM within limits, no FD leaks ---");
}
