use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("echomesh_{prefix}_{stamp}"));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_relay(args: &[&str]) -> String {
    let output = Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .arg("--")
        .args(args)
        .output()
        .expect("run relay cli");
    assert!(output.status.success(), "relay cli failed: {output:?}");
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

#[test]
fn credentials_are_redacted_but_explicit_secret_export_is_persistent() {
    let temp = TempDirGuard::new("secret_redaction");
    let key_path = temp.path().join("relay.key");
    let key = key_path.to_str().unwrap();

    let credentials = run_relay(&["--show-credentials", "--key-file", key]);
    assert!(credentials.contains("\"secret_token_hex\":\"[REDACTED]\""));
    assert!(!credentials.contains("echomesh_secret_mesh_token_2026"));

    let token_before = run_relay(&["--show-secret-token", "--key-file", key]);
    let token_before = token_before.trim().to_string();
    assert!(!token_before.is_empty());
    assert_ne!(token_before, "[REDACTED]");

    let credentials_after = run_relay(&["--show-credentials", "--key-file", key]);
    assert!(credentials_after.contains("\"secret_token_hex\":\"[REDACTED]\""));
    assert!(!credentials_after.contains(&token_before));

    let token_after = run_relay(&["--show-secret-token", "--key-file", key]);
    assert_eq!(token_after.trim(), token_before);
}
