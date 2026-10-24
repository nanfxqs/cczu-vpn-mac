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

#[test]
fn staged_uninstall_recovers_owned_resources_and_preserves_saved_credentials() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp();
    let stage = dir.join("stage");
    let mut daemon = Daemon::start(dir.clone());
    daemon.connect();
    daemon.kill();
    fs::create_dir(&stage).unwrap();
    assert_eq!(
        call(
            &dir,
            &[
                "service",
                "install",
                "--staging-dir",
                stage.to_str().unwrap()
            ],
            None
        )
        .0,
        0
    );
    let data = stage.join("var/db/cczu-vpn");
    fs::create_dir_all(&data).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["network-journal.json", "offline-routes.json"] {
        fs::copy(dir.join("data").join(name), data.join(name)).unwrap();
    }
    fs::write(
        data.join("credentials.json"),
        br#"{"user":"test","password":"retained"}"#,
    )
    .unwrap();
    for _ in 0..2 {
        let (code, response) = call(
            &dir,
            &[
                "service",
                "uninstall",
                "--staging-dir",
                stage.to_str().unwrap(),
            ],
            None,
        );
        assert_eq!(code, 0, "{response}");
    }
    let table: Value =
        serde_json::from_slice(&fs::read(data.join("offline-routes.json")).unwrap()).unwrap();
    assert_eq!(table, json!([]));
    assert!(data.join("credentials.json").exists());
    drop(daemon);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn uninstall_refuses_to_remove_a_replaced_executable() {
    let dir = temp();
    fs::create_dir(&dir).unwrap();
    assert_eq!(
        call(
            &dir,
            &["service", "install", "--staging-dir", dir.to_str().unwrap()],
            None
        )
        .0,
        0
    );
    let binary = dir.join("usr/local/libexec/cczu-vpn-proto");
    fs::write(&binary, b"third-party executable").unwrap();
    let (code, response) = call(
        &dir,
        &[
            "service",
            "uninstall",
            "--staging-dir",
            dir.to_str().unwrap(),
        ],
        None,
    );
    assert_ne!(code, 0, "{response}");
    assert_eq!(fs::read(&binary).unwrap(), b"third-party executable");
    assert!(
        dir.join("Library/LaunchDaemons/edu.cczu.vpn.plist")
            .exists()
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn hangup_preserves_connection_and_normal_service_stop_cleans_routes() {
    let dir = temp();
    let mut daemon = Daemon::start(dir.clone());
    daemon.connect();
    assert_eq!(
        unsafe { libc::kill(daemon.child.id() as i32, libc::SIGHUP) },
        0
    );
    thread::sleep(Duration::from_millis(50));
    assert_eq!(
        call(&dir, &["status"], None).1["data"]["connection"],
        "connected"
    );
    assert_eq!(
        unsafe { libc::kill(daemon.child.id() as i32, libc::SIGTERM) },
        0
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = daemon.child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "service shutdown did not finish");
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(dir.join("data/offline-routes.json")).unwrap())
            .unwrap(),
        json!([])
    );
    drop(daemon);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn changed_routes_survive_restart_and_block_new_connections_until_conflict_is_removed() {
    let dir = temp();
    let mut daemon = Daemon::start(dir.clone());
    daemon.connect();
    daemon.kill();
    let path = dir.join("data/offline-routes.json");
    let mut table: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    table[0]["interface"] = json!("utun-foreign");
    table[0]["owner"] = json!("another-service");
    let foreign = table[0].clone();
    fs::write(&path, serde_json::to_vec(&table).unwrap()).unwrap();
    let mut restarted = Daemon::start(dir.clone());
    let status = call(&dir, &["status"], None).1;
    assert_eq!(status["data"]["connection"], "failed");
    assert!(
        status["data"]["last_error"]
            .as_str()
            .unwrap()
            .contains("changed")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap(),
        json!([foreign])
    );
    assert_ne!(
        call(
            &dir,
            &["connect", "--stdin"],
            Some(json!({"user":"test","password":"secret"}))
        )
        .0,
        0
    );
    restarted.kill();
    fs::write(&path, b"[]").unwrap();
    let last = Daemon::start(dir.clone());
    assert_eq!(
        call(&dir, &["status"], None).1["data"]["connection"],
        "disconnected"
    );
    drop(last);
    drop(restarted);
    drop(daemon);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn disconnect_never_adopts_matching_preexisting_routes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp();
    let daemon = Daemon::start(dir.clone());
    let path = dir.join("data/offline-routes.json");
    let foreign = json!([{"network":{"destination":"172.22.0.0","netmask":"255.255.0.0"},"interface":"utun-test","gateway":null,"marked":true,"owner":"third-party"}]);
    fs::write(&path, serde_json::to_vec(&foreign).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    daemon.connect();
    assert_eq!(call(&dir, &["disconnect"], None).0, 0);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap(),
        foreign
    );
    drop(daemon);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn recovery_reconciles_write_ahead_intent_with_current_resource_ownership() {
    let dir = temp();
    let mut daemon = Daemon::start(dir.clone());
    daemon.connect();
    daemon.kill();
    let path = dir.join("data/network-journal.json");
    let mut journal: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    // Model the native physical endpoint route, which has no offline owner token.
    // Kernel add succeeded before the confirmation write. This exercises native
    // attribution, rather than the offline backend's stronger ownership evidence.
    journal["routes"] = json!([journal["routes"][0].clone()]);
    journal["routes"][0]["network"] =
        json!({"destination":"211.65.64.100","netmask":"255.255.255.255"});
    journal["routes"][0]["interface"] = json!("en0");
    journal["routes"][0]["gateway"] = json!("192.0.2.1");
    let table_path = dir.join("data/offline-routes.json");
    let mut table: Value = serde_json::from_slice(&fs::read(&table_path).unwrap()).unwrap();
    table = json!([table[0].clone()]);
    table[0]["network"] = journal["routes"][0]["network"].clone();
    table[0]["interface"] = json!("en0");
    table[0]["gateway"] = json!("192.0.2.1");
    table[0]["owner"] = Value::Null;
    fs::write(&table_path, serde_json::to_vec(&table).unwrap()).unwrap();
    journal["pending"] = json!([journal["routes"][0]["network"].clone()]);
    fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
    let restarted = Daemon::start(dir.clone());
    assert_eq!(
        call(&dir, &["status"], None).1["data"]["connection"],
        "disconnected"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(dir.join("data/offline-routes.json")).unwrap())
            .unwrap(),
        json!([])
    );
    drop(restarted);
    drop(daemon);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn native_attribution_preserves_reused_utun_unmarked_and_changed_routes() {
    for conflict in ["reused-utun", "unmarked", "changed-gateway"] {
        let dir = temp();
        let mut daemon = Daemon::start(dir.clone());
        daemon.connect();
        daemon.kill();
        let journal_path = dir.join("data/network-journal.json");
        let table_path = dir.join("data/offline-routes.json");
        let mut journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
        let network = json!({"destination":"211.65.64.100","netmask":"255.255.255.255"});
        let interface = if conflict == "reused-utun" {
            "utun8"
        } else {
            "en0"
        };
        journal["routes"] =
            json!([{"network":network,"interface":interface,"gateway":"192.0.2.1"}]);
        journal["pending"] = json!([network]);
        let table = json!([{"network":network,"interface":interface,
            "gateway":if conflict == "changed-gateway" {"192.0.2.2"} else {"192.0.2.1"},
            "marked":conflict != "unmarked","owner":null}]);
        fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
        fs::write(&table_path, serde_json::to_vec(&table).unwrap()).unwrap();
        let restarted = Daemon::start(dir.clone());
        assert_eq!(
            call(&dir, &["status"], None).1["data"]["connection"],
            "failed",
            "{conflict}"
        );
        assert_ne!(call(&dir, &["disconnect"], None).0, 0);
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&table_path).unwrap()).unwrap(),
            table
        );
        // Once the foreign resource disappears, retry finishes without service recovery.
        fs::write(&table_path, b"[]").unwrap();
        assert_eq!(call(&dir, &["disconnect"], None).0, 0);
        drop(restarted);
        drop(daemon);
        fs::remove_dir_all(dir).unwrap();
    }
}
