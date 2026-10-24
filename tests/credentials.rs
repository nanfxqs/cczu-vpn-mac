#![cfg(target_os = "macos")]

use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Service {
    child: Child,
    dir: PathBuf,
    socket: PathBuf,
}

impl Service {
    fn start(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("cc-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("control.sock");
        let child = Command::new(env!("CARGO_BIN_EXE_cczu-vpn-proto"))
            .args(["daemon", "--test-socket", socket.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut service = Self { child, dir, socket };
        let start = Instant::now();
        while !service.socket.exists() {
            assert!(service.child.try_wait().unwrap().is_none());
            assert!(start.elapsed() < Duration::from_secs(5));
            thread::sleep(Duration::from_millis(20));
        }
        service
    }

    fn cli(&self, args: &[&str], input: Option<Value>) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_cczu-vpn-proto"))
            .args(["--json", "--socket", self.socket.to_str().unwrap()])
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(value) = input {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(value.to_string().as_bytes())
                .unwrap();
        }
        child.wait_with_output().unwrap()
    }

    fn restart(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        self.child = Command::new(env!("CARGO_BIN_EXE_cczu-vpn-proto"))
            .args(["daemon", "--test-socket", self.socket.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let start = Instant::now();
        while !self.cli(&["status"], None).status.success() {
            assert!(self.child.try_wait().unwrap().is_none());
            assert!(start.elapsed() < Duration::from_secs(5));
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn response(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn agent_can_save_update_and_delete_credentials_without_exposing_password() {
    let service = Service::start("saved");
    let before = response(&service.cli(&["credentials", "status"], None));
    assert_eq!(before["data"]["configured"], false);
    for password in ["first-secret", "updated-secret"] {
        let output = service.cli(
            &["credentials", "set", "--stdin", "--save"],
            Some(json!({"user": "student", "password": password})),
        );
        let value = response(&output);
        assert_eq!(value["data"]["saved"], true);
        assert!(!String::from_utf8_lossy(&output.stdout).contains(password));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(password));
    }
    let status = response(&service.cli(&["credentials", "status"], None));
    assert_eq!(status["data"]["configured"], true);
    assert_eq!(status["data"]["saved"], true);
    assert!(!status.to_string().contains("secret"));
    for _ in 0..2 {
        response(&service.cli(&["credentials", "delete"], None));
    }
    let after = response(&service.cli(&["credentials", "status"], None));
    assert_eq!(after["data"]["configured"], false);
}

#[test]
fn temporary_credentials_are_available_only_until_service_restart() {
    let mut service = Service::start("temporary");
    let output = service.cli(
        &["credentials", "set", "--stdin"],
        Some(json!({"user": "student", "password": "temporary-secret"})),
    );
    let value = response(&output);
    assert_eq!(value["data"]["saved"], false);
    let status = response(&service.cli(&["credentials", "status", "--ignore-saved"], None));
    assert_eq!(status["data"]["configured"], true);
    assert_eq!(status["data"]["temporary"], true);
    service.restart();
    let after = response(&service.cli(&["credentials", "status"], None));
    assert_eq!(after["data"]["configured"], false);
}

#[test]
fn missing_or_invalid_noninteractive_credentials_fail_without_echoing_input() {
    let service = Service::start("invalid");
    let missing = service.cli(&["credentials", "set"], None);
    assert_eq!(missing.status.code(), Some(5));
    let value: Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(value["code"], "credentials_required");
    let invalid = service.cli(
        &["credentials", "set", "--stdin", "--save"],
        Some(json!({"user": "", "password": "do-not-echo"})),
    );
    assert_eq!(invalid.status.code(), Some(5));
    let value: Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(value["code"], "invalid_credentials");
    assert!(!String::from_utf8_lossy(&invalid.stdout).contains("do-not-echo"));
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains("do-not-echo"));
    assert_eq!(
        response(&service.cli(&["credentials", "status"], None))["data"]["configured"],
        false
    );
}

#[test]
fn saved_credentials_survive_restart_and_can_be_ignored() {
    let mut service = Service::start("restart");
    response(&service.cli(
        &["credentials", "set", "--stdin", "--save"],
        Some(json!({"user": "student", "password": "persisted-secret"})),
    ));
    service.restart();
    let saved = response(&service.cli(&["credentials", "status"], None));
    assert_eq!(saved["data"]["configured"], true);
    assert_eq!(saved["data"]["temporary"], false);
    let ignored = response(&service.cli(&["credentials", "status", "--ignore-saved"], None));
    assert_eq!(ignored["data"]["configured"], false);
    assert_eq!(ignored["data"]["saved"], true);
    assert!(!ignored.to_string().contains("persisted-secret"));

    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let directory = fs::metadata(service.dir.join("data")).unwrap();
    let file = fs::metadata(service.dir.join("data/credentials.json")).unwrap();
    assert_eq!(directory.permissions().mode() & 0o777, 0o700);
    assert_eq!(file.permissions().mode() & 0o777, 0o600);
    assert_eq!(file.uid(), unsafe { libc::geteuid() });
}
