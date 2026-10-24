#[cfg(not(target_os = "macos"))]
mod cli;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(not(target_os = "macos"))]
use anyhow::Result;

#[tokio::main]
#[cfg(not(target_os = "macos"))]
async fn main() -> Result<()> {
    cli::run().await
}

#[tokio::main]
#[cfg(target_os = "macos")]
async fn main() {
    std::process::exit(macos::run().await);
}
