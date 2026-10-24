use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};

use super::{Response, SOCKET};

const MAX_MESSAGE: u64 = 64 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Status {
    pub service: String,
    pub connection: String,
    pub last_error: Option<String>,
}

pub struct DaemonState {
    pub status: Mutex<Status>,
}

impl DaemonState {
    fn new() -> Self {
        Self {
            status: Mutex::new(Status {
                service: "running".into(),
                connection: "disconnected".into(),
                last_error: None,
            }),
        }
    }
}

pub fn effective_uid() -> u32 {
    // geteuid has no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

pub async fn request(socket: &Path, request: &Request) -> Response {
    let result = tokio::time::timeout(CONTROL_TIMEOUT, async {
        let mut stream = UnixStream::connect(socket).await?;
        let mut encoded = serde_json::to_vec(request)?;
        encoded.push(b'\n');
        stream.write_all(&encoded).await?;
        let mut line = Vec::new();
        BufReader::new(stream)
            .take(MAX_MESSAGE + 1)
            .read_until(b'\n', &mut line)
            .await?;
        ensure!(
            line.len() as u64 <= MAX_MESSAGE && line.last() == Some(&b'\n'),
            "invalid or oversized service response"
        );
        Ok::<Response, anyhow::Error>(serde_json::from_slice(&line)?)
    })
    .await;
    match result {
        Ok(Ok(response)) => response,
        _ => {
            let mut response = Response::error(
                "service_unavailable",
                "VPN background service unavailable; install/start it with service install",
            );
            response.data = json!({"service": "unavailable", "connection": "unknown"});
            response
        }
    }
}

async fn serve_client(stream: UnixStream, state: Arc<DaemonState>) -> Result<()> {
    let (input, mut output) = stream.into_split();
    let mut line = Vec::new();
    tokio::time::timeout(
        CONTROL_TIMEOUT,
        BufReader::new(input)
            .take(MAX_MESSAGE + 1)
            .read_until(b'\n', &mut line),
    )
    .await??;
    let response = if line.len() as u64 > MAX_MESSAGE || line.last() != Some(&b'\n') {
        Response::error("invalid_arguments", "Invalid or oversized control request")
    } else {
        match serde_json::from_slice::<Request>(&line) {
            Ok(Request::Status) => Response::success(state.status.lock().await.clone()),
            Err(_) => Response::error(
                "invalid_arguments",
                "Unknown command or malformed control request",
            ),
        }
    };
    let mut encoded = serde_json::to_vec(&response)?;
    encoded.push(b'\n');
    tokio::time::timeout(CONTROL_TIMEOUT, output.write_all(&encoded)).await??;
    Ok(())
}

struct SocketGuard {
    path: PathBuf,
    inode: u64,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub async fn run_daemon(test_socket: Option<PathBuf>) -> Result<()> {
    let test_mode = test_socket.is_some();
    ensure!(
        test_mode != (effective_uid() == 0),
        if test_mode {
            "Test daemon must run without root privileges"
        } else {
            "System daemon requires root privileges"
        }
    );
    let socket = test_socket.unwrap_or_else(|| PathBuf::from(SOCKET));
    ensure!(socket.is_absolute(), "Socket path must be absolute");
    let parent = socket.parent().context("Socket has no parent directory")?;
    if !test_mode {
        fs::create_dir_all(parent)?;
    }
    let parent_meta = fs::symlink_metadata(parent)?;
    ensure!(
        parent_meta.is_dir()
            && !parent_meta.file_type().is_symlink()
            && parent_meta.uid() == effective_uid(),
        "Socket directory must be owned by the daemon user and cannot be a symlink"
    );
    ensure!(
        parent_meta.mode() & 0o022 == 0,
        "Socket directory must not be writable by other users"
    );
    if socket.exists() {
        if UnixStream::connect(&socket).await.is_ok() {
            bail!("VPN service already running");
        }
        let metadata = fs::symlink_metadata(&socket)?;
        ensure!(
            metadata.file_type().is_socket() && metadata.uid() == effective_uid(),
            "Refusing to remove an unrelated socket path"
        );
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    let _guard = SocketGuard {
        inode: fs::symlink_metadata(&socket)?.ino(),
        path: socket.clone(),
    };
    fs::set_permissions(
        &socket,
        fs::Permissions::from_mode(if test_mode { 0o600 } else { 0o666 }),
    )?;
    let state = Arc::new(DaemonState::new());
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    // A detached service does not treat an SSH session hangup as a VPN shutdown.
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                let state = state.clone();
                tokio::spawn(async move { let _ = serve_client(stream, state).await; });
            },
            _ = terminate.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
            _ = hangup.recv() => {},
        }
    }
    Ok(())
}
