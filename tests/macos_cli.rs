#![cfg(target_os = "macos")]

use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cczu-vpn-proto"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn temp(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("cv-{}-{}", std::process::id(), name));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn unavailable_service_is_a_machine_readable_error() {
    let path = temp("missing").join("control.sock");
    let output = cli(&["--json", "--socket", path.to_str().unwrap(), "status"]);
    assert_eq!(output.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["ok"], false);
    assert_eq!(value["code"], "service_unavailable");
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn isolated_daemon_reports_disconnected_and_rejects_a_second_instance() {
    let dir = temp("daemon");
    let socket = dir.join("control.sock");
    let mut child = Daemon(
        Command::new(env!("CARGO_BIN_EXE_cczu-vpn-proto"))
            .args(["daemon", "--test-socket", socket.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    while !socket.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "daemon exited before creating socket"
        );
        assert!(start.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(20));
    }
    let args = ["--json", "--socket", socket.to_str().unwrap(), "status"];
    let output = cli(&args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["data"]["service"], "running");
    assert_eq!(value["data"]["connection"], "disconnected");
    let plain = cli(&["--socket", socket.to_str().unwrap(), "status"]);
    assert!(String::from_utf8_lossy(&plain.stdout).contains("disconnected"));
    let duplicate = cli(&[
        "--json",
        "daemon",
        "--test-socket",
        socket.to_str().unwrap(),
    ]);
    assert!(!duplicate.status.success());
    assert!(
        cli(&args).status.success(),
        "second daemon must not remove the live socket"
    );
    drop(child);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn invalid_json_command_returns_a_structured_error() {
    let output = cli(&["--json", "not-a-command"]);
    assert_eq!(output.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["code"], "invalid_arguments");
}

#[test]
fn installation_can_be_staged_repeatedly_and_uninstalled_without_launchd() {
    let dir = temp("install");
    let args = [
        "--json",
        "service",
        "install",
        "--staging-dir",
        dir.to_str().unwrap(),
    ];
    for _ in 0..2 {
        let output = cli(&args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["data"]["staged"], true);
    }
    let plist = fs::read_to_string(dir.join("Library/LaunchDaemons/edu.cczu.vpn.plist")).unwrap();
    assert!(plist.contains("<string>/usr/local/libexec/cczu-vpn-proto</string>"));
    assert!(plist.contains("<key>RunAtLoad</key><true/>"));
    assert!(
        !plist.contains("connect"),
        "startup must not establish a VPN connection"
    );
    let validation = Command::new("/usr/bin/plutil")
        .args([
            "-lint",
            dir.join("Library/LaunchDaemons/edu.cczu.vpn.plist")
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert!(validation.status.success());
    fs::write(dir.join("unrelated"), "keep").unwrap();
    let args = [
        "--json",
        "service",
        "uninstall",
        "--staging-dir",
        dir.to_str().unwrap(),
    ];
    for _ in 0..2 {
        assert!(cli(&args).status.success());
    }
    assert_eq!(fs::read_to_string(dir.join("unrelated")).unwrap(), "keep");
    assert!(!dir.join("usr/local/libexec/cczu-vpn-proto").exists());
    assert!(
        !dir.join("Library/LaunchDaemons/edu.cczu.vpn.plist")
            .exists()
    );
    fs::remove_dir_all(dir).unwrap();
}
