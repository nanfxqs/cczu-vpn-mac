use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod install;
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
    /// Query background service and VPN connection separately.
    Status,
    /// Run the privileged system service (normally launched by launchd).
    Daemon {
        /// Isolated unprivileged service for offline development only.
        #[arg(long, hide = true)]
        test_socket: Option<PathBuf>,
    },
    /// Install, stop or remove the system service (requires administrator privileges).
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
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

#[derive(Serialize, Deserialize)]
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
        Command::Status => service::request(&args.socket, &service::Request::Status).await,
        Command::Daemon { test_socket } => match service::run_daemon(test_socket).await {
            Ok(()) => Response::success(json!({"service": "stopped"})),
            Err(err) => Response::error("operation_failed", format!("{err:#}")),
        },
        Command::Service { action } => install::execute(action),
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string(&response).expect("serializable response")
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
