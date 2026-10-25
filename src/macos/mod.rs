use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub mod connection;
pub mod control;
pub mod credentials;
pub mod doctor;
mod install;
pub mod network;
pub mod service;

pub const SOCKET: &str = "/var/run/cczu-vpn/control.sock";

#[derive(Parser)]
#[command(
    name = "cczu-vpn",
    about = "Control the macOS CCZU VPN background service"
)]
pub struct Args {
    #[arg(long, global = true, help = "Emit compact JSON (default for cczu-vpn)")]
    pub json: bool,
    /// Select an isolated local service socket (primarily for development).
    #[arg(long, global = true, default_value = SOCKET, hide = true)]
    pub socket: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Inspect service, routing, DNS and the known campus HTTP resource.
    #[command(display_order = 4)]
    Doctor {
        /// Generate a one-time mihomo DNS fragment from the active native session.
        #[arg(long)]
        dns_override: bool,
        /// Optionally check exact campus hostnames, without changing DNS settings.
        #[arg(long = "domain")]
        domains: Vec<String>,
    },
    /// Establish a campus VPN and wait until its network configuration is ready.
    #[command(name = "on", visible_alias = "connect", display_order = 1)]
    Connect {
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        ignore_saved: bool,
    },
    /// Disconnect the campus VPN while keeping the control service running.
    #[command(name = "off", visible_alias = "disconnect", display_order = 2)]
    Disconnect,
    /// Manage shared campus credentials without a desktop keychain.
    #[command(display_order = 5)]
    Credentials {
        #[command(subcommand)]
        action: CredentialAction,
    },
    /// Query background service and VPN connection separately.
    #[command(display_order = 3)]
    Status,
    /// Run the privileged system service (normally launched by launchd).
    #[command(hide = true)]
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
    #[command(display_order = 6)]
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
    let executable = std::env::args_os().next().map(PathBuf::from);
    let default_json = match executable
        .as_ref()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
    {
        Some("cczu-vpn") => true,
        Some("cczu-vpn-proto") => false,
        _ => env!("CARGO_BIN_NAME") == "cczu-vpn",
    };
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) => {
            if error.use_stderr()
                && (default_json || std::env::args_os().any(|arg| arg == "--json"))
            {
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
    let json_mode = args.json || default_json;
    let response = match args.command {
        Command::Doctor {
            domains,
            dns_override,
        } => {
            let response = service::request(
                &args.socket,
                &service::Request::Doctor {
                    domains,
                    dns_override,
                },
            )
            .await;
            if response.code == "service_unavailable" {
                doctor::unavailable(response)
            } else {
                response
            }
        }
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
                        return print_response(&response, json_mode);
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
    print_response(&response, json_mode)
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
        if !response.data.is_null() {
            println!(
                "{}",
                serde_json::to_string_pretty(&response.data).expect("serializable response")
            );
        }
    }
    response.exit_code()
}
