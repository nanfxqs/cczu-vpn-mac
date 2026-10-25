use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    Response, ServiceAction, credentials::DATA_DIR, network::RouteSet, service::effective_uid,
};

const LABEL: &str = "edu.cczu.vpn";
const BINARY: &str = "/usr/local/libexec/cczu-vpn-proto";
const CLI_LINKS: [&str; 2] = ["/usr/local/bin/cczu-vpn", "/usr/local/bin/cczu-vpn-proto"];
const PLIST: &str = "/Library/LaunchDaemons/edu.cczu.vpn.plist";

fn location(staging: Option<&Path>, path: &str) -> PathBuf {
    staging.map_or_else(
        || PathBuf::from(path),
        |dir| dir.join(path.trim_start_matches('/')),
    )
}

fn directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink() && meta.uid() == effective_uid(),
        "Installation directory must be owned by installer and not a symlink: {}",
        path.display()
    );
    ensure!(
        meta.mode() & 0o022 == 0,
        "Installation directory must not be writable by other users: {}",
        path.display()
    );
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    directory(path.parent().context("Missing install parent")?)?;
    if let Ok(meta) = fs::symlink_metadata(path) {
        ensure!(
            meta.is_file() && !meta.file_type().is_symlink() && meta.uid() == effective_uid(),
            "Refusing to replace unrelated installation file: {}",
            path.display()
        );
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn definition() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{LABEL}</string>
<key>ProgramArguments</key><array><string>{BINARY}</string><string>daemon</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>5</integer>
<key>ProcessType</key><string>Background</string>
<key>StandardOutPath</key><string>/var/log/cczu-vpn.log</string>
<key>StandardErrorPath</key><string>/var/log/cczu-vpn.log</string>
</dict></plist>
"#
    )
}

fn launchctl(args: &[&str]) -> Result<()> {
    let output = Command::new("/bin/launchctl")
        .args(args)
        .output()
        .context("Unable to execute launchctl")?;
    ensure!(
        output.status.success(),
        "launchctl {} failed: {}",
        args.first().unwrap_or(&""),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct BinaryIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified: i64,
    modified_nsec: i64,
    changed: i64,
    changed_nsec: i64,
}

fn binary_identity(path: &Path) -> Result<BinaryIdentity> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.uid() == effective_uid()
            && meta.mode() & 0o022 == 0,
        "Refusing unrelated installation executable"
    );
    Ok(BinaryIdentity {
        device: meta.dev(),
        inode: meta.ino(),
        size: meta.len(),
        modified: meta.mtime(),
        modified_nsec: meta.mtime_nsec(),
        changed: meta.ctime(),
        changed_nsec: meta.ctime_nsec(),
    })
}

fn validate_existing(staging: Option<&Path>) -> Result<bool> {
    let manifest = location(staging, DATA_DIR).join("install.json");
    let identity: Option<BinaryIdentity> = super::network::read_state(&manifest)?;
    let binary = location(staging, BINARY);
    if fs::symlink_metadata(&binary).is_ok() {
        ensure!(
            identity.as_ref() == Some(&binary_identity(&binary)?),
            "Installed executable changed or has no ownership record; left untouched"
        );
    }
    let plist = location(staging, PLIST);
    let mut owned_plist = false;
    if let Ok(meta) = fs::symlink_metadata(&plist) {
        ensure!(
            meta.is_file()
                && !meta.file_type().is_symlink()
                && meta.uid() == effective_uid()
                && fs::read_to_string(&plist)? == definition(),
            "Service definition changed; unrelated configuration left untouched"
        );
        owned_plist = true;
    }
    for name in CLI_LINKS {
        let link = location(staging, name);
        if let Ok(meta) = fs::symlink_metadata(&link) {
            ensure!(
                meta.file_type().is_symlink() && fs::read_link(&link)? == Path::new(BINARY),
                "Unrelated CLI path left untouched"
            );
        }
    }
    Ok(identity.is_some() && owned_plist)
}

fn stop() -> Result<()> {
    let target = format!("system/{LABEL}");
    let loaded = Command::new("/bin/launchctl")
        .args(["print", &target])
        .output()?;
    if loaded.status.success() {
        ensure!(
            validate_existing(None)?,
            "Cannot prove loaded service belongs to this installation"
        );
        launchctl(&["bootout", &target])?;
    }
    Ok(())
}

fn recover(staging: Option<&Path>) -> Result<()> {
    let directory = location(staging, DATA_DIR);
    if !directory.exists() {
        return Ok(());
    }
    let offline = staging.is_some();
    // execute() is called inside the CLI Tokio runtime. Recovery gets its own
    // short-lived runtime so synchronous launchctl management remains unchanged.
    std::thread::spawn(move || -> Result<()> {
        tokio::runtime::Runtime::new()?.block_on(RouteSet::recover(directory, offline))
    })
    .join()
    .map_err(|_| anyhow::anyhow!("Network recovery task failed"))??;
    Ok(())
}

fn install(staging: Option<&Path>) -> Result<()> {
    validate_existing(staging)?;
    if staging.is_none() {
        stop()?;
    }
    recover(staging)?;
    let binary = location(staging, BINARY);
    let link = location(staging, CLI_LINKS[0]);
    directory(link.parent().context("Missing CLI directory")?)?;
    write_atomic(&binary, &fs::read(std::env::current_exe()?)?, 0o755)?;
    directory(
        location(staging, DATA_DIR)
            .parent()
            .context("Missing state parent")?,
    )?;
    super::network::write_state(
        &location(staging, DATA_DIR).join("install.json"),
        &binary_identity(&binary)?,
    )?;
    write_atomic(&location(staging, PLIST), definition().as_bytes(), 0o644)?;
    for name in CLI_LINKS {
        let link = location(staging, name);
        if fs::symlink_metadata(&link).is_err() {
            symlink(BINARY, &link)?;
        }
    }
    if staging.is_none() {
        launchctl(&["enable", &format!("system/{LABEL}")])?;
        launchctl(&["bootstrap", "system", PLIST])?;
    }
    Ok(())
}

fn uninstall(staging: Option<&Path>) -> Result<()> {
    validate_existing(staging)?;
    if staging.is_none() {
        stop()?;
    }
    recover(staging)?;
    let plist = location(staging, PLIST);
    if plist.exists() {
        ensure!(
            fs::read_to_string(&plist)? == definition(),
            "Service definition differs from this tool's definition; refusing to remove unrelated configuration"
        );
    }
    for name in CLI_LINKS {
        let link = location(staging, name);
        if let Ok(meta) = fs::symlink_metadata(&link) {
            ensure!(
                meta.file_type().is_symlink() && fs::read_link(&link)? == Path::new(BINARY),
                "Refusing to remove unrelated CLI path"
            );
            fs::remove_file(link)?;
        }
    }
    for path in [plist, location(staging, BINARY)] {
        if let Ok(meta) = fs::symlink_metadata(&path) {
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink() && meta.uid() == effective_uid(),
                "Refusing to remove unrelated installation file"
            );
            fs::remove_file(path)?;
        }
    }
    let manifest = location(staging, DATA_DIR).join("install.json");
    match fs::remove_file(manifest) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub fn execute(action: ServiceAction) -> Response {
    let staging = match &action {
        ServiceAction::Install { staging_dir } | ServiceAction::Uninstall { staging_dir } => {
            staging_dir.as_deref()
        }
        ServiceAction::Stop => None,
    };
    if (staging.is_some() && effective_uid() == 0) || (staging.is_none() && effective_uid() != 0) {
        return Response::error(
            "permission_required",
            if staging.is_some() {
                "Staging mode must run without root privileges"
            } else {
                "Service installation/management requires sudo; daily VPN commands do not"
            },
        );
    }
    if let Some(path) = staging
        && (!path.is_absolute() || !path.is_dir())
    {
        return Response::error(
            "invalid_arguments",
            "Staging directory must be an existing absolute directory",
        );
    }
    let result = match &action {
        ServiceAction::Install { .. } => install(staging),
        ServiceAction::Stop => stop().and_then(|()| recover(None)),
        ServiceAction::Uninstall { .. } => uninstall(staging),
    };
    match result {
        Ok(()) => Response::success(
            json!({"staged": staging.is_some(), "operation": match action { ServiceAction::Install { .. } => "installed", ServiceAction::Stop => "stopped", ServiceAction::Uninstall { .. } => "uninstalled" }}),
        ),
        Err(err) => Response::error("operation_failed", format!("{err:#}")),
    }
}
