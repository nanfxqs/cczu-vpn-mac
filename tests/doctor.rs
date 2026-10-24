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
    fn start() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "cd-{}-{:08x}",
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
                "ready",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            assert!(child.try_wait().unwrap().is_none());
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
        let mut child = Command::new(env!("CARGO_BIN_EXE_cczu-vpn-proto"))
            .args(["--json", "--socket", self.socket.to_str().unwrap()])
            .args(args)
            .stdin(Stdio::piped())
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
        } else {
            drop(child.stdin.take());
        }
        let output = child.wait_with_output().unwrap();
        (
            output.status.code().unwrap(),
            serde_json::from_slice(&output.stdout).unwrap(),
        )
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
fn doctor_reports_missing_credentials_and_disconnected_vpn_without_probing_network() {
    let fixture = Fixture::start();
    let (code, report) = fixture.call(&["doctor"], None);
    assert_eq!(code, 5);
    assert_eq!(report["code"], "diagnostic_issues");
    assert_eq!(report["data"]["service"]["status"], "passed");
    assert_eq!(report["data"]["credentials"]["status"], "missing");
    assert_eq!(report["data"]["connection"]["state"], "disconnected");
    assert_eq!(report["data"]["routes"]["status"], "skipped");
    assert_eq!(report["data"]["http"]["transport"], "skipped");
    assert_eq!(report["data"]["environment"], "offline_test");
    assert!(!report.to_string().contains("password"));
}

#[test]
fn connected_offline_diagnostics_label_simulation_and_separate_http_response_from_transport() {
    let fixture = Fixture::start();
    assert_eq!(
        fixture
            .call(
                &["connect", "--stdin"],
                Some(json!({"user":"campus", "password":"not-visible"}))
            )
            .0,
        0
    );
    let (code, report) = fixture.call(&["doctor", "--domain", "library.cczu.edu.cn"], None);
    assert_eq!(code, 5, "simulation is not a real network health guarantee");
    assert_eq!(report["data"]["connection"]["state"], "connected");
    assert_eq!(report["data"]["routes"]["status"], "simulated");
    assert_eq!(report["data"]["http"]["transport"], "simulated");
    assert_eq!(report["data"]["http"]["status_code"], 503);
    assert_eq!(report["data"]["http"]["business"], "non_success_response");
    assert_eq!(
        report["data"]["dns"]["active_mihomo_policy"],
        "not_verified"
    );
    assert!(!report.to_string().contains("not-visible"));
}

#[test]
fn dns_override_requires_connected_native_dns_and_never_publishes_fixture_as_real() {
    let fixture = Fixture::start();
    let (code, missing) = fixture.call(
        &[
            "doctor",
            "--dns-override",
            "--domain",
            "library.cczu.edu.cn",
        ],
        None,
    );
    assert_eq!(code, 5);
    assert_eq!(missing["code"], "connection_required");
    assert_eq!(
        fixture
            .call(
                &["connect", "--stdin"],
                Some(json!({"user":"campus", "password":"not-visible"}))
            )
            .0,
        0
    );
    let (code, simulated) = fixture.call(
        &[
            "doctor",
            "--dns-override",
            "--domain",
            "library.cczu.edu.cn",
        ],
        None,
    );
    assert_eq!(code, 5);
    assert_eq!(simulated["code"], "unverified_dns_source");
    assert_eq!(simulated["data"], Value::Null);
    assert!(!simulated.to_string().contains("172.22.0.53"));
}

#[test]
fn doctor_distinguishes_unavailable_service_from_vpn_or_website_failure() {
    let mut fixture = Fixture::start();
    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();
    let (code, report) = fixture.call(&["doctor"], None);
    assert_eq!(code, 3);
    assert_eq!(report["code"], "service_unavailable");
    assert_eq!(report["data"]["service"]["status"], "failed");
    assert_eq!(report["data"]["credentials"]["status"], "unknown");
    assert_eq!(report["data"]["http"]["transport"], "skipped");
}

#[test]
fn human_doctor_output_includes_failed_check_details() {
    let fixture = Fixture::start();
    let output = Command::new(env!("CARGO_BIN_EXE_cczu-vpn-proto"))
        .args(["--socket", fixture.socket.to_str().unwrap(), "doctor"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("\"http\""));
    assert!(text.contains("\"disconnected\""));
}
