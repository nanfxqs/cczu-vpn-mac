use std::{
    fs::{self, OpenOptions},
    io::{IsTerminal, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{Response, service::effective_uid};

pub const DATA_DIR: &str = "/var/db/cczu-vpn";
pub const MAX_CREDENTIAL_BYTES: u64 = 16 * 1024;

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub user: String,
    pub password: String,
}

impl Credentials {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.user.trim().is_empty() && !self.password.is_empty(),
            "Campus username and password must not be empty"
        );
        ensure!(
            self.user.len() + self.password.len() <= MAX_CREDENTIAL_BYTES as usize / 2,
            "Campus credentials are too long"
        );
        Ok(())
    }
}

pub struct CredentialStore {
    directory: PathBuf,
    temporary: Option<Credentials>,
}

impl CredentialStore {
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            temporary: None,
        }
    }

    fn path(&self) -> PathBuf {
        self.directory.join("credentials.json")
    }

    fn private_directory(&self) -> Result<()> {
        match fs::symlink_metadata(&self.directory) {
            Ok(metadata) => ensure!(
                metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == effective_uid(),
                "Credential directory must be owned by the service and cannot be a symlink"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&self.directory)?;
            }
            Err(error) => return Err(error.into()),
        }
        fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn load(&self) -> Result<Option<Credentials>> {
        if !self.directory.exists() {
            return Ok(None);
        }
        self.private_directory()?;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.path())
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == effective_uid()
                && metadata.mode() & 0o777 == 0o600,
            "Credential file must be owned by the service with permissions 0600"
        );
        let mut encoded = Vec::new();
        file.take(MAX_CREDENTIAL_BYTES + 1)
            .read_to_end(&mut encoded)?;
        ensure!(
            encoded.len() as u64 <= MAX_CREDENTIAL_BYTES,
            "Credential file is too large"
        );
        let credentials: Credentials = serde_json::from_slice(&encoded)
            .map_err(|_| anyhow::anyhow!("Saved credentials are invalid"))?;
        credentials.validate()?;
        Ok(Some(credentials))
    }

    fn save(&self, credentials: &Credentials) -> Result<()> {
        self.private_directory()?;
        let temporary = self
            .directory
            .join(format!(".credentials-{:016x}", rand::random::<u64>()));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&serde_json::to_vec(credentials)?)?;
            file.sync_all()?;
            fs::rename(&temporary, self.path())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub fn set(&mut self, credentials: Credentials, save: bool) -> Response {
        if credentials.validate().is_err() {
            return Response::error(
                "invalid_credentials",
                "Campus username and password must be nonempty and within the size limit",
            );
        }
        if !save {
            self.temporary = Some(credentials);
            return Response::success(
                json!({"configured": true, "saved": false, "temporary": true}),
            );
        }
        match self.save(&credentials) {
            Ok(()) => {
                self.temporary = None;
                Response::success(json!({"configured": true, "saved": true, "temporary": false}))
            }
            Err(_) => Response::error(
                "credential_store_error",
                "Could not save campus credentials; check the service credential directory and permissions",
            ),
        }
    }

    pub fn resolve(
        &self,
        explicit: Option<Credentials>,
        ignore_saved: bool,
    ) -> Result<Option<Credentials>> {
        if let Some(credentials) = explicit {
            credentials.validate()?;
            return Ok(Some(credentials));
        }
        if let Some(credentials) = &self.temporary {
            return Ok(Some(credentials.clone()));
        }
        if ignore_saved { Ok(None) } else { self.load() }
    }

    pub fn status(&self, ignore_saved: bool) -> Response {
        match self
            .load()
            .and_then(|saved| Ok((saved.is_some(), self.resolve(None, ignore_saved)?.is_some())))
        {
            Ok((saved, configured)) => Response::success(
                json!({"configured": configured, "saved": saved, "temporary": self.temporary.is_some(), "ignore_saved": ignore_saved}),
            ),
            Err(_) => Response::error(
                "credential_store_error",
                "Could not read saved campus credentials; check the service credential directory and permissions",
            ),
        }
    }

    pub fn delete(&mut self) -> Response {
        self.temporary = None;
        if !self.directory.exists() {
            return Response::success(json!({"configured": false, "saved": false}));
        }
        if self.private_directory().is_err() {
            return Response::error(
                "credential_store_error",
                "Could not access the service credential directory",
            );
        }
        match fs::remove_file(self.path()) {
            Ok(()) => Response::success(json!({"configured": false, "saved": false})),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Response::success(json!({"configured": false, "saved": false}))
            }
            Err(_) => Response::error(
                "credential_store_error",
                "Could not delete saved campus credentials",
            ),
        }
    }
}

pub fn read_stdin() -> Result<Credentials> {
    let mut encoded = Vec::new();
    std::io::stdin()
        .take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut encoded)?;
    ensure!(
        encoded.len() as u64 <= MAX_CREDENTIAL_BYTES,
        "Credential input is too large"
    );
    let credentials: Credentials = serde_json::from_slice(&encoded).map_err(|_| {
        anyhow::anyhow!("Expected JSON object with user and password on standard input")
    })?;
    credentials.validate()?;
    Ok(credentials)
}

pub fn read_interactive(
    user: Option<String>,
    save: bool,
    json_mode: bool,
) -> Result<(Credentials, bool)> {
    ensure!(
        !json_mode && std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
        "Interactive credential initialization requires a terminal"
    );
    let user = match user {
        Some(user) => user,
        None => {
            eprint!("Campus username: ");
            std::io::stderr().flush()?;
            let mut user = String::new();
            std::io::stdin().read_line(&mut user)?;
            user.trim().to_owned()
        }
    };
    let credentials = Credentials {
        user,
        password: rpassword::prompt_password("Campus password: ")?,
    };
    credentials.validate()?;
    let save = if save {
        true
    } else {
        eprint!("Save campus credentials on this machine? (y/N) ");
        std::io::stderr().flush()?;
        let mut choice = String::new();
        std::io::stdin().read_line(&mut choice)?;
        matches!(choice.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    };
    Ok((credentials, save))
}
