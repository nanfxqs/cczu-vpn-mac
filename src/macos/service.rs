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

use super::{
    Response, SOCKET,
    connection::{ConnectionInfo, ConnectionManager, TestScenario},
    control::ConnectionControl,
    credentials::{self, CredentialStore, Credentials},
    doctor,
};

const MAX_MESSAGE: u64 = 64 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Doctor {
        #[serde(default)]
        domains: Vec<String>,
        #[serde(default)]
        dns_override: bool,
    },
    Connect {
        credentials: Option<Credentials>,
        #[serde(default)]
        ignore_saved: bool,
    },
    Disconnect,
    Status,
    CredentialsSet {
        credentials: Credentials,
        save: bool,
    },
    CredentialsStatus {
        #[serde(default)]
        ignore_saved: bool,
    },
    CredentialsDelete,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPhase {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Failed,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Status {
    pub generation: u64,
    pub service: String,
    pub connection: ConnectionPhase,
    pub last_error: Option<String>,
    pub last_error_code: Option<String>,
    pub connection_info: Option<ConnectionInfo>,
}

pub struct DaemonState {
    pub test_mode: bool,
    pub status: Arc<Mutex<Status>>,
    pub credentials: Mutex<CredentialStore>,
    pub connection: ConnectionControl,
}

impl DaemonState {
    async fn new(directory: PathBuf, scenario: Option<TestScenario>) -> Self {
        let status = Arc::new(Mutex::new(Status {
            generation: 0,
            service: "running".into(),
            connection: ConnectionPhase::Disconnected,
            last_error: None,
            last_error_code: None,
            connection_info: None,
        }));
        Self {
            test_mode: scenario.is_some(),
            credentials: Mutex::new(CredentialStore::new(directory.clone())),
            connection: ConnectionControl::new(
                ConnectionManager::new(scenario, directory),
                status.clone(),
            )
            .await,
            status,
        }
    }
}

pub fn effective_uid() -> u32 {
    // geteuid has no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

pub async fn request(socket: &Path, request: &Request) -> Response {
    let response_timeout = if matches!(
        request,
        Request::Connect { .. } | Request::Disconnect | Request::Doctor { .. }
    ) {
        Duration::from_secs(100)
    } else {
        CONTROL_TIMEOUT
    };
    let result = tokio::time::timeout(response_timeout, async {
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
        Err(_) => Response::error(
            "operation_timeout",
            "CLI wait timed out; query status before retrying the operation",
        ),
        Ok(Err(_)) => {
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
            Ok(Request::Doctor {
                domains,
                dns_override,
            }) => {
                let status = state.status.lock().await.clone();
                if dns_override {
                    doctor::override_response(&status, &domains)
                } else {
                    let credentials = state.credentials.lock().await.status(false);
                    doctor::run(status, credentials, state.test_mode, domains).await
                }
            }
            Ok(Request::Connect {
                credentials,
                ignore_saved,
            }) => {
                let phase = state.status.lock().await.connection;
                if matches!(
                    phase,
                    ConnectionPhase::Connected | ConnectionPhase::Connecting
                ) {
                    state.connection.connect(None).await
                } else {
                    let resolved = state
                        .credentials
                        .lock()
                        .await
                        .resolve(credentials, ignore_saved);
                    match resolved {
                        Ok(credentials) => state.connection.connect(credentials).await,
                        Err(_) => Response::error(
                            "credential_store_error",
                            "Could not read campus credentials",
                        ),
                    }
                }
            }
            Ok(Request::Disconnect) => state.connection.disconnect().await,
            Ok(Request::Status) => Response::success(state.status.lock().await.clone()),
            Ok(Request::CredentialsSet { credentials, save }) => {
                state.credentials.lock().await.set(credentials, save)
            }
            Ok(Request::CredentialsStatus { ignore_saved }) => {
                state.credentials.lock().await.status(ignore_saved)
            }
            Ok(Request::CredentialsDelete) => state.credentials.lock().await.delete(),
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

pub async fn run_daemon(test_socket: Option<PathBuf>, test_scenario: TestScenario) -> Result<()> {
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
    let credential_directory = if test_mode {
        parent.join("data")
    } else {
        PathBuf::from(credentials::DATA_DIR)
    };
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
    let state = Arc::new(
        DaemonState::new(
            credential_directory,
            if test_mode { Some(test_scenario) } else { None },
        )
        .await,
    );
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
    let shutdown = state.connection.shutdown().await;
    ensure!(shutdown.ok, "{}", shutdown.message);
    Ok(())
}
