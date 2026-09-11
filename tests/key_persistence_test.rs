use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use echomesh_relay::crypto::{
    base64_decode, load_or_generate_keypair, resolve_key_file_path, KeyPair,
};
use echomesh_relay::server::RelaySecrets;

/// RAII helper to clean up test directories
struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let unique = format!(
            "echomesh_test_{}_{}_{}",
            prefix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).expect("create temp test dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn test_new_key_creation_and_file_permissions_0600() {
    let temp_dir = TempDirGuard::new("perms");
    let key_path = temp_dir.path().join("relay.key");
    let pub_path = temp_dir.path().join("relay.pub");

    assert!(!key_path.exists(), "Key file must not exist before test");
    assert!(!pub_path.exists(), "Public key file must not exist before test");

    let keypair: KeyPair = load_or_generate_keypair(&key_path).expect("generate fresh keypair");

    // 1. Verify private key file existence and length
    assert!(key_path.is_file(), "Private key file must be created");
    let priv_bytes = fs::read(&key_path).expect("read generated private key file");
    assert_eq!(priv_bytes.len(), 32, "Private key must be exactly 32 bytes");
    assert_eq!(priv_bytes, keypair.private_key);

    // 2. Verify Unix file permissions are strictly 0600
    #[cfg(unix)]
    {
        let metadata = fs::metadata(&key_path).expect("metadata of private key file");
        let permissions = metadata.permissions();
        let mode = permissions.mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "Private key file permissions must be 0600, got {:o}",
            mode
        );
    }

    // 3. Verify public key companion file (relay.pub)
    assert!(pub_path.is_file(), "Companion relay.pub file must be created");
    let pub_content = fs::read_to_string(&pub_path).expect("read relay.pub file");
    let trimmed_pub = pub_content.trim();
    assert_eq!(
        trimmed_pub, keypair.public_key_base64,
        "relay.pub must match public_key_base64"
    );

    // 4. Verify Base64 decodes back to the 32-byte public key
    let decoded_pub = base64_decode(trimmed_pub).expect("decode base64 from pub file");
    assert_eq!(decoded_pub.len(), 32);
    assert_eq!(decoded_pub, keypair.public_key);
}

#[test]
fn test_repeated_key_reading_preserves_public_key() {
    let temp_dir = TempDirGuard::new("repeat");
    let key_path = temp_dir.path().join("sub/dir/relay.key");

    // First call: generates new keypair
    let keypair1 = load_or_generate_keypair(&key_path).expect("first load_or_generate");

    // Subsequent calls: must read existing key and yield identical keys
    for i in 1..=5 {
        let keypair_next =
            load_or_generate_keypair(&key_path).unwrap_or_else(|e| panic!("iteration {} failed: {}", i, e));

        assert_eq!(
            keypair1.private_key, keypair_next.private_key,
            "Private key mutated on read {}",
            i
        );
        assert_eq!(
            keypair1.public_key, keypair_next.public_key,
            "Public key mutated on read {}",
            i
        );
        assert_eq!(
            keypair1.public_key_base64, keypair_next.public_key_base64,
            "Base64 public key mutated on read {}",
            i
        );
    }
}

#[test]
fn test_cli_show_public_key_flag() {
    let temp_dir = TempDirGuard::new("cli_flag");
    let key_path = temp_dir.path().join("relay.key");

    // Pre-create a known keypair
    let keypair = load_or_generate_keypair(&key_path).expect("generate initial keypair");

    // Run: echomesh-relay --show-public-key --key-file <PATH>
    let output = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--",
            "--show-public-key",
            "--key-file",
            key_path.to_str().unwrap(),
        ])
        .output()
        .expect("execute cargo run with --show-public-key");

    assert!(
        output.status.success(),
        "Process exited with failure: {:?}",
        output
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed_stdout = stdout.trim();

    // Verify stdout contains ONLY the clean Base64 string, nothing else
    assert_eq!(
        trimmed_stdout, keypair.public_key_base64,
        "stdout must contain exactly the clean Base64 public key"
    );
}

#[test]
fn test_cli_show_key_subcommand() {
    let temp_dir = TempDirGuard::new("cli_subcmd");
    let key_path = temp_dir.path().join("relay.key");

    let keypair = load_or_generate_keypair(&key_path).expect("generate initial keypair");

    // Run: echomesh-relay show-key --key-file=<PATH>
    let arg_flag = format!("--key-file={}", key_path.to_str().unwrap());
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--", "show-key", &arg_flag])
        .output()
        .expect("execute cargo run with show-key");

    assert!(output.status.success(), "Process failed: {:?}", output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed_stdout = stdout.trim();

    assert_eq!(trimmed_stdout, keypair.public_key_base64);
}

#[test]
fn test_relay_secrets_load_or_generate_preserves_keys() {
    let temp_dir = TempDirGuard::new("secrets");
    let key_path = temp_dir.path().join("relay.key");
    let addr = "127.0.0.1:8443".parse().unwrap();

    let secrets1 =
        RelaySecrets::load_or_generate(&key_path, addr, None).expect("load_or_generate secrets 1");
    let secrets2 =
        RelaySecrets::load_or_generate(&key_path, addr, None).expect("load_or_generate secrets 2");

    assert_eq!(secrets1.public_key, secrets2.public_key);
    assert_eq!(secrets1.public_key_hex, secrets2.public_key_hex);
    assert_eq!(secrets1.public_key_base64, secrets2.public_key_base64);
    assert_eq!(secrets1.private_key, secrets2.private_key);
}

#[test]
fn test_resolve_key_file_path() {
    let args1 = vec![
        "binary".to_string(),
        "--key-file".to_string(),
        "/opt/echomesh.key".to_string(),
    ];
    assert_eq!(
        resolve_key_file_path(&args1),
        PathBuf::from("/opt/echomesh.key")
    );

    let args2 = vec![
        "binary".to_string(),
        "--key-file=/var/relay.key".to_string(),
    ];
    assert_eq!(
        resolve_key_file_path(&args2),
        PathBuf::from("/var/relay.key")
    );
}

#[test]
fn test_show_public_key_works_when_port_is_already_bound() {

    let temp_dir = TempDirGuard::new("port_bound");
    let key_path = temp_dir.path().join("relay.key");
    let keypair = load_or_generate_keypair(&key_path).expect("generate initial keypair");

    // Bind a TCP listener to occupy an address
    let occupied_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind occupied port");
    let occupied_addr = occupied_listener.local_addr().expect("local addr");

    // Execute show-public-key with ECHOMESH_BIND_ADDR pointing to the already occupied address.
    // If the binary attempted to bind or touch the network, it would fail with AddrInUse (os error 98).
    let output = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--",
            "--show-public-key",
            "--key-file",
            key_path.to_str().unwrap(),
        ])
        .env("ECHOMESH_BIND_ADDR", occupied_addr.to_string())
        .output()
        .expect("run show-public-key with occupied bind addr");

    assert!(
        output.status.success(),
        "Command failed when port was occupied: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), keypair.public_key_base64);
}

