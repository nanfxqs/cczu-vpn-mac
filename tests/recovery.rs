#![cfg(target_os = "macos")]

use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Daemon {
    child: Child,
    dir: PathBuf,
}
impl Daemon {
    fn start(dir: PathBuf) -> Self {
        fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("control.sock");
        let mut child = Command::new(env!("CARGO_BIN_EXE_cczu-vpn-proto"))
            .args([
                "daemon",
                "--test-socket",
                socket.to_str().unwrap(),
                "--test-scenario",
                "ready",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(child.try_wait().unwrap().is_none(), "daemon exited");
            if socket.exists() && call(&dir, &["status"], None).0 == 0 {
                break;
            }
            assert!(Instant::now() < deadline, "daemon startup timeout");
            thread::sleep(Duration::from_millis(20));
        }
        Self { child, dir }
    }
    fn connect(&self) {
        let (code, result) = call(
            &self.dir,
            &["connect", "--stdin"],
            Some(json!({"user":"test","password":"private"})),
        );
        assert_eq!(code, 0, "{result}");
    }
    fn kill(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn temp() -> PathBuf {
    std::env::temp_dir().join(format!(
        "cr-{}-{:08x}",
        std::process::id(),
        rand::random::<u32>()
    ))
}
fn call(dir: &Path, args: &[&str], input: Option<Value>) -> (i32, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cczu-vpn-proto"))
        .args([
            "--json",
            "--socket",
            dir.join("control.sock").to_str().unwrap(),
        ])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = input {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
    } else {
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap(),
        serde_json::from_slice(&out.stdout).unwrap(),
    )
}
#[test]
fn killed_daemon_recovers_owned_routes_without_reconnecting() {
    let dir = temp();
    let mut daemon = Daemon::start(dir.clone());
    daemon.connect();
    let table = dir.join("data/offline-routes.json");
    assert!(
        table.exists(),
        "offline backend must use durable route ownership algorithm"
    );
    let before: Value = serde_json::from_slice(&fs::read(&table).unwrap()).unwrap();
    assert!(!before.as_array().unwrap().is_empty());
    daemon.kill();
    let restarted = Daemon::start(dir.clone());
    let status = call(&dir, &["status"], None).1;
    assert_eq!(status["data"]["connection"], "disconnected");
    let after: Value = serde_json::from_slice(&fs::read(&table).unwrap()).unwrap();
    assert_eq!(after, json!([]));
    assert_eq!(call(&dir, &["disconnect"], None).0, 0);
    drop(restarted);
    drop(daemon);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn journal_from_another_boot_cannot_delete_a_matching_route() {
    let dir = temp();
    let mut daemon = Daemon::start(dir.clone());
    daemon.connect();
    daemon.kill();
    let path = dir.join("data/network-journal.json");
    let mut journal: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    journal["boot"] = json!(-1);
    fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
    let table = dir.join("data/offline-routes.json");
    let before = fs::read(&table).unwrap();
    let restarted = Daemon::start(dir.clone());
    let status = call(&dir, &["status"], None).1;
    assert_eq!(status["data"]["connection"], "failed");
    assert!(
        status["data"]["last_error"]
            .as_str()
            .unwrap()
            .contains("another boot")
    );
    assert_eq!(fs::read(&table).unwrap(), before);
    drop(restarted);
    drop(daemon);
    fs::remove_dir_all(dir).unwrap();
}
