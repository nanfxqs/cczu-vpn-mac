#![cfg(target_os = "macos")]

use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Fixture {
    child: Child,
    directory: PathBuf,
    socket: PathBuf,
}
impl Fixture {
    fn start(scenario: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "cc-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        fs::create_dir_all(&directory).unwrap();
        let socket = directory.join("control.sock");
        let mut child = Command::new(env!("CARGO_BIN_EXE_cczu-vpn-proto"))
            .args([
                "daemon",
                "--test-socket",
                socket.to_str().unwrap(),
                "--test-scenario",
                scenario,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            assert!(child.try_wait().unwrap().is_none(), "test daemon exited");
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(20));
        }
        Self {
            child,
            directory,
            socket,
        }
    }
    fn call(&self, args: &[&str], input: Option<Value>) -> (i32, Value) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cczu-vpn-proto"));
        command
            .args(["--json", "--socket", self.socket.to_str().unwrap()])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
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
        let output = child.wait_with_output().unwrap();
        (
            output.status.code().unwrap(),
            serde_json::from_slice(&output.stdout).unwrap(),
        )
    }
    fn pending(&self, args: &[&str]) -> Pending {
        Pending(Some(
            Command::new(env!("CARGO_BIN_EXE_cczu-vpn-proto"))
                .args(["--json", "--socket", self.socket.to_str().unwrap()])
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ))
    }
    fn credentials(&self) {
        assert_eq!(
            self.call(
                &["credentials", "set", "--stdin", "--save"],
                Some(json!({"user":"campus","password":"not-logged"}))
            )
            .0,
            0
        );
    }
    fn wait_for(&self, connection: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let (_, status) = self.call(&["status"], None);
            if status["data"]["connection"] == connection {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "Expected {connection}, received {status}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}
struct Pending(Option<Child>);
impl Pending {
    fn finish(mut self) -> (i32, Value) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "offline CLI operation did not finish"
            );
            thread::sleep(Duration::from_millis(20));
        }
        let output = self.0.take().unwrap().wait_with_output().unwrap();
        (
            output.status.code().unwrap(),
            serde_json::from_slice(&output.stdout).unwrap(),
        )
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn agent_connects_waits_for_readiness_and_disconnects_using_saved_credentials() {
    let fixture = Fixture::start("ready");
    let (code, missing) = fixture.call(&["connect"], None);
    assert_eq!(code, 5);
    assert_eq!(missing["code"], "credentials_required");
    assert_eq!(
        fixture
            .call(
                &["credentials", "set", "--stdin", "--save"],
                Some(json!({"user":"campus", "password":"private"}))
            )
            .0,
        0
    );
    let started = Instant::now();
    let (code, connected) = fixture.call(&["connect"], None);
    assert_eq!(code, 0, "{connected}");
    assert!(
        started.elapsed() >= Duration::from_millis(80),
        "connect must wait for backend readiness"
    );
    assert_eq!(connected["data"]["connection"], "connected");
    assert_eq!(
        connected["data"]["connection_info"]["interface"],
        "utun-test"
    );
    assert_eq!(
        fixture.call(&["status"], None).1["data"]["connection"],
        "connected"
    );
    assert_eq!(
        fixture.call(&["disconnect"], None).1["data"]["connection"],
        "disconnected"
    );
    let status = fixture.call(&["status"], None).1;
    assert_eq!(status["data"]["service"], "running");
    assert_eq!(status["data"]["connection_info"], Value::Null);
    assert!(!status.to_string().contains("private"));
}

#[test]
fn failed_setup_rolls_back_and_temporary_credentials_do_not_persist() {
    let fixture = Fixture::start("setup-failure");
    let (code, failed) = fixture.call(
        &["connect", "--stdin", "--ignore-saved"],
        Some(json!({"user":"campus", "password":"temporary-secret"})),
    );
    assert_eq!(code, 5);
    assert_eq!(failed["code"], "connection_failed");
    let status = fixture.call(&["status"], None).1;
    assert_eq!(status["data"]["connection"], "failed");
    assert_eq!(status["data"]["connection_info"], Value::Null);
    assert!(!status.to_string().contains("temporary-secret"));
    assert!(!fixture.directory.join("data/credentials.json").exists());
    assert_eq!(fixture.call(&["disconnect"], None).0, 0);
    assert_eq!(
        fixture.call(&["status"], None).1["data"]["connection"],
        "disconnected"
    );
}

#[test]
fn unsafe_server_routes_fail_before_publishing_connected_state() {
    for scenario in ["unsafe-default", "local-overlap", "invalid-mask"] {
        let fixture = Fixture::start(scenario);
        let (code, failed) = fixture.call(
            &["connect", "--stdin"],
            Some(json!({"user":"campus", "password":"not-logged"})),
        );
        assert_eq!(code, 5);
        assert_eq!(failed["code"], "connection_failed");
        assert_eq!(
            fixture.call(&["status"], None).1["data"]["connection"],
            "failed"
        );
        assert_eq!(fixture.call(&["disconnect"], None).0, 0);
    }
}

#[test]
fn broader_campus_route_preserves_a_more_specific_local_network() {
    let fixture = Fixture::start("broad-campus");
    let (code, ready) = fixture.call(
        &["connect", "--stdin"],
        Some(json!({"user":"campus", "password":"private"})),
    );
    assert_eq!(code, 0, "{ready}");
    assert!(
        ready["data"]["connection_info"]["routes"]
            .as_array()
            .unwrap()
            .contains(&json!("172.16.0.0/12"))
    );
    assert_eq!(fixture.call(&["disconnect"], None).0, 0);
}

#[test]
fn disconnect_cancels_all_waiters_and_startup_cannot_publish_late_success() {
    let fixture = Fixture::start("slow-ready");
    fixture.credentials();
    let first = fixture.pending(&["connect"]);
    fixture.wait_for("connecting");
    let second = fixture.pending(&["connect"]);
    thread::sleep(Duration::from_millis(60));
    let started = Instant::now();
    assert_eq!(fixture.call(&["disconnect"], None).0, 0);
    assert!(
        started.elapsed() < Duration::from_millis(600),
        "disconnect must cancel rather than wait for slow startup"
    );
    for pending in [first, second] {
        let (code, result) = pending.finish();
        assert_eq!(code, 5);
        assert_eq!(result["code"], "connection_cancelled");
    }
    thread::sleep(Duration::from_millis(2100));
    assert_eq!(
        fixture.call(&["status"], None).1["data"]["connection"],
        "disconnected"
    );
}

#[test]
fn startup_deadline_cleans_up_and_preserves_a_machine_readable_timeout() {
    let fixture = Fixture::start("startup-timeout");
    fixture.credentials();
    let started = Instant::now();
    let (code, result) = fixture.pending(&["connect"]).finish();
    assert_eq!(code, 5);
    assert_eq!(result["code"], "connection_timeout");
    assert!(started.elapsed() < Duration::from_secs(2));
    let failed = fixture.wait_for("failed");
    assert!(
        failed["data"]["last_error"]
            .as_str()
            .unwrap()
            .contains("timed out")
    );
    assert_eq!(fixture.call(&["disconnect"], None).0, 0);
}

#[test]
fn concurrent_connects_share_one_attempt_and_idle_connections_stay_connected() {
    let fixture = Fixture::start("slow-ready");
    fixture.credentials();
    let first = fixture.pending(&["connect"]);
    fixture.wait_for("connecting");
    let second = fixture.pending(&["connect"]);
    for pending in [first, second] {
        let (code, ready) = pending.finish();
        assert_eq!(code, 0, "{ready}");
        assert_eq!(ready["data"]["generation"], 1);
    }
    assert_eq!(fixture.call(&["credentials", "delete"], None).0, 0);
    assert_eq!(
        fixture.call(&["connect"], None).1["data"]["generation"],
        1,
        "idempotent connect must not require deleted credentials"
    );
    thread::sleep(Duration::from_millis(400));
    assert_eq!(
        fixture.call(&["status"], None).1["data"]["connection"],
        "connected"
    );
    let first = fixture.pending(&["disconnect"]);
    let second = fixture.pending(&["disconnect"]);
    assert_eq!(first.finish().0, 0);
    assert_eq!(second.finish().0, 0);
    assert_eq!(
        fixture.call(&["status"], None).1["data"]["connection"],
        "disconnected"
    );
}

#[test]
fn forwarding_failure_is_cleaned_without_polling_and_does_not_auto_reconnect() {
    let fixture = Fixture::start("forward-failure");
    fixture.credentials();
    assert_eq!(fixture.call(&["connect"], None).0, 0);
    thread::sleep(Duration::from_millis(500));
    let failed = fixture.call(&["status"], None).1;
    assert_eq!(failed["data"]["connection"], "failed");
    assert!(
        failed["data"]["last_error"]
            .as_str()
            .unwrap()
            .contains("EOF")
    );
    assert_eq!(failed["data"]["generation"], 1);
    thread::sleep(Duration::from_millis(300));
    assert_eq!(fixture.call(&["status"], None).1["data"]["generation"], 1);
    assert_eq!(fixture.call(&["disconnect"], None).0, 0);
    assert_eq!(
        fixture.call(&["status"], None).1["data"]["last_error"],
        failed["data"]["last_error"]
    );
    assert_eq!(fixture.call(&["connect"], None).1["data"]["generation"], 2);
}
