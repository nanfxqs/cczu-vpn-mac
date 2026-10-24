use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub mod connection;
pub mod control;
pub mod credentials;
mod install;
pub mod network;
pub mod service;

pub const SOCKET: &str = "/var/run/cczu-vpn/control.sock";

#[derive(Parser)]
#[command(
    name = "cczu-vpn-proto",
    about = "Control the macOS CCZU VPN background service"
)]
pub struct Args {
    #[arg(long, global = true)]
    pub json: bool,
    /// Select an isolated local service socket (primarily for development).
    #[arg(long, global = true, default_value = SOCKET)]
    pub socket: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Establish a campus VPN and wait until its network configuration is ready.
    Connect {
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        ignore_saved: bool,
    },
    /// Disconnect the campus VPN while keeping the control service running.
    Disconnect,
    /// Manage shared campus credentials without a desktop keychain.
    Credentials {
        #[command(subcommand)]
        action: CredentialAction,
    },
    /// Query background service and VPN connection separately.
    Status,
    /// Run the privileged system service (normally launched by launchd).
    Daemon {
        /// Isolated unprivileged service for offline development only.
        #[arg(long, hide = true)]
        test_socket: Option<PathBuf>,
        #[arg(
            long,
            hide = true,
            requires = "test_socket",
            default_value = "disabled"
        )]
        test_scenario: connection::TestScenario,
    },
    /// Install, stop or remove the system service (requires administrator privileges).
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand)]
pub enum CredentialAction {
    /// Read campus credentials as JSON from standard input.
    Set {
        #[arg(long)]
        stdin: bool,
        /// Campus username for an interactive initialization.
        #[arg(long, conflicts_with = "stdin")]
        user: Option<String>,
        /// Explicitly persist credentials for later connections.
        #[arg(long)]
        save: bool,
    },
    /// Report presence only; never reveal stored account or password.
    Status {
        /// Ignore credentials persisted on disk; temporary credentials remain available.
        #[arg(long)]
        ignore_saved: bool,
    },
    /// Forget saved campus credentials.
    Delete,
}

#[derive(Subcommand)]
pub enum ServiceAction {
    Install {
        /// Stage installation artifacts without loading launchd (unprivileged development only).
        #[arg(long)]
        staging_dir: Option<PathBuf>,
    },
    Stop,
    Uninstall {
        #[arg(long)]
        staging_dir: Option<PathBuf>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    pub code: String,
    pub message: String,
    pub data: Value,
}

impl Response {
    pub fn success(data: impl Serialize) -> Self {
        Self {
            ok: true,
            code: "ok".into(),
            message: "Operation completed".into(),
            data: serde_json::to_value(data).expect("serializable response data"),
        }
    }
    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            code: code.into(),
            message: message.into(),
            data: Value::Null,
        }
    }

    pub fn exit_code(&self) -> i32 {
        match (self.ok, self.code.as_str()) {
            (true, _) => 0,
            (_, "invalid_arguments") => 2,
            (_, "service_unavailable" | "protocol_error") => 3,
            (_, "permission_required") => 4,
            _ => 5,
        }
    }
}

pub async fn run() -> i32 {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) => {
            if error.use_stderr() && std::env::args_os().any(|arg| arg == "--json") {
                let response = Response::error(
                    "invalid_arguments",
                    "Invalid command or arguments; use --help",
                );
                println!(
                    "{}",
                    serde_json::to_string(&response).expect("serializable response")
                );
                return 2;
            }
            let code = error.exit_code();
            let _ = error.print();
            return code;
        }
    };
    let response = match args.command {
        Command::Connect {
            stdin,
            ignore_saved,
        } => {
            let explicit = if stdin {
                match credentials::read_stdin() {
                    Ok(credentials) => Some(credentials),
                    Err(_) => {
                        let response = Response::error(
                            "invalid_credentials",
                            "Expected campus user and password JSON on standard input",
                        );
                        return print_response(&response, args.json);
                    }
                }
            } else {
                None
            };
            service::request(
                &args.socket,
                &service::Request::Connect {
                    credentials: explicit,
                    ignore_saved,
                },
            )
            .await
        }
        Command::Disconnect => service::request(&args.socket, &service::Request::Disconnect).await,
        Command::Credentials { action } => {
            let request = match action {
                CredentialAction::Set {
                    stdin: true, save, ..
                } => match credentials::read_stdin() {
                    Ok(credentials) => Ok(service::Request::CredentialsSet { credentials, save }),
                    Err(_) => Err(Response::error(
                        "invalid_credentials",
                        "Expected nonempty campus user and password JSON on standard input",
                    )),
                },
                CredentialAction::Set { user, save, .. } => {
                    match credentials::read_interactive(user, save, args.json) {
                        Ok((credentials, save)) => {
                            Ok(service::Request::CredentialsSet { credentials, save })
                        }
                        Err(_) => Err(Response::error(
                            "credentials_required",
                            "Provide campus credentials with credentials set --stdin, or run interactive initialization in a terminal",
                        )),
                    }
                }
                CredentialAction::Status { ignore_saved } => {
                    Ok(service::Request::CredentialsStatus { ignore_saved })
                }
                CredentialAction::Delete => Ok(service::Request::CredentialsDelete),
            };
            match request {
                Ok(request) => service::request(&args.socket, &request).await,
                Err(response) => response,
            }
        }
        Command::Status => service::request(&args.socket, &service::Request::Status).await,
        Command::Daemon {
            test_socket,
            test_scenario,
        } => match service::run_daemon(test_socket, test_scenario).await {
            Ok(()) => Response::success(json!({"service": "stopped"})),
            Err(err) => Response::error("operation_failed", format!("{err:#}")),
        },
        Command::Service { action } => install::execute(action),
    };
    print_response(&response, args.json)
}

fn print_response(response: &Response, json_mode: bool) -> i32 {
    if json_mode {
        println!(
            "{}",
            serde_json::to_string(response).expect("serializable response")
        );
    } else if response.ok {
        println!(
            "{}",
            serde_json::to_string_pretty(&response.data).expect("serializable response")
        );
    } else {
        eprintln!("{}: {}", response.code, response.message);
    }
    response.exit_code()
}
