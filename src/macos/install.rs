use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, ensure};
use serde_json::json;

use super::{Response, ServiceAction, service::effective_uid};

const LABEL: &str = "edu.cczu.vpn";
const BINARY: &str = "/usr/local/libexec/cczu-vpn-proto";
const CLI_LINK: &str = "/usr/local/bin/cczu-vpn-proto";
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

fn stop() -> Result<()> {
    let target = format!("system/{LABEL}");
    let loaded = Command::new("/bin/launchctl")
        .args(["print", &target])
        .output()?;
    if loaded.status.success() {
        launchctl(&["bootout", &target])?;
    }
    Ok(())
}

fn install(staging: Option<&Path>) -> Result<()> {
    if staging.is_none() {
        stop()?;
    }
    let binary = location(staging, BINARY);
    let link = location(staging, CLI_LINK);
    directory(link.parent().context("Missing CLI directory")?)?;
    if let Ok(meta) = fs::symlink_metadata(&link) {
        ensure!(
            meta.file_type().is_symlink() && fs::read_link(&link)? == Path::new(BINARY),
            "Refusing to replace unrelated CLI path: {}",
            link.display()
        );
    }
    write_atomic(&binary, &fs::read(std::env::current_exe()?)?, 0o755)?;
    write_atomic(&location(staging, PLIST), definition().as_bytes(), 0o644)?;
    if fs::symlink_metadata(&link).is_err() {
        symlink(BINARY, &link)?;
    }
    if staging.is_none() {
        launchctl(&["enable", &format!("system/{LABEL}")])?;
        launchctl(&["bootstrap", "system", PLIST])?;
    }
    Ok(())
}

fn uninstall(staging: Option<&Path>) -> Result<()> {
    if staging.is_none() {
        stop()?;
    }
    let plist = location(staging, PLIST);
    if plist.exists() {
        ensure!(
            fs::read_to_string(&plist)? == definition(),
            "Service definition differs from this tool's definition; refusing to remove unrelated configuration"
        );
    }
    let link = location(staging, CLI_LINK);
    if let Ok(meta) = fs::symlink_metadata(&link) {
        ensure!(
            meta.file_type().is_symlink() && fs::read_link(&link)? == Path::new(BINARY),
            "Refusing to remove unrelated CLI path"
        );
        fs::remove_file(link)?;
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
        ServiceAction::Stop => stop(),
        ServiceAction::Uninstall { .. } => uninstall(staging),
    };
    match result {
        Ok(()) => Response::success(
            json!({"staged": staging.is_some(), "operation": match action { ServiceAction::Install { .. } => "installed", ServiceAction::Stop => "stopped", ServiceAction::Uninstall { .. } => "uninstalled" }}),
        ),
        Err(err) => Response::error("operation_failed", format!("{err:#}")),
    }
}
