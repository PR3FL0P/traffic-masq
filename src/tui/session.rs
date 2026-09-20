//! Per-user preferences and short-lived credentials for one daemon socket.
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use nix::unistd::{Uid, User};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::api::client::{ApiClient, ClientAuthentication};
use crate::api::model::{Request, Response};
use crate::atomic_file;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct SessionPreferences {
    pub(crate) remember: bool,
    pub(crate) minutes: u64,
    pub(crate) show_dhcp_client: bool,
}

impl Default for SessionPreferences {
    fn default() -> Self {
        Self {
            remember: true,
            minutes: 5,
            show_dhcp_client: false,
        }
    }
}

impl SessionPreferences {
    pub(crate) fn validate(&self) -> Result<()> {
        if !(1..=1440).contains(&self.minutes) {
            bail!("Session duration must be between 1 and 1440 minutes");
        }
        Ok(())
    }

    fn accepts(&self, session: &ClientAuthentication, now: u64) -> bool {
        self.remember
            && self.validate().is_ok()
            && now >= session.authenticated_at
            && now
                < session
                    .authenticated_at
                    .saturating_add(self.minutes.saturating_mul(60))
            && i64::try_from(now).is_ok_and(|now| now < session.absolute_expires_at)
    }
}

pub(crate) struct SessionStore {
    directory: PathBuf,
    key: String,
}

impl SessionStore {
    pub(crate) fn for_client(client: &ApiClient) -> Result<Self> {
        let uid = Uid::effective();
        let home = User::from_uid(uid)?
            .context("cannot find the current user's home directory")?
            .dir;
        let state = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".local/state"));
        let socket = fs::canonicalize(client.socket_path())
            .unwrap_or_else(|_| client.socket_path().to_path_buf());
        if !socket.is_absolute() {
            bail!("cannot identify the daemon socket for session storage");
        }
        Ok(Self {
            directory: state.join("traffic-masq/client"),
            key: format!("{:x}", Sha256::digest(socket.as_os_str().as_bytes())),
        })
    }

    fn path(&self, suffix: &str) -> PathBuf {
        self.directory.join(format!("{}.{suffix}.json", self.key))
    }

    fn check_directory(&self) -> Result<()> {
        for path in self.directory.ancestors() {
            atomic_file::reject_symlink(path)?;
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.directory) {
            if !metadata.is_dir()
                || metadata.uid() != Uid::effective().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                bail!("session directory must be owned by the current user with mode 0700");
            }
        }
        Ok(())
    }

    fn read<T: serde::de::DeserializeOwned>(&self, suffix: &str) -> Result<Option<T>> {
        self.check_directory()?;
        let path = self.path(suffix);
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != Uid::effective().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            bail!("session files must be regular files owned by the current user with mode 0600");
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(16_385).read_to_end(&mut bytes)?;
        if bytes.len() > 16_384 {
            bail!("session file is too large");
        }
        Ok(Some(
            serde_json::from_slice(&bytes).context("invalid saved session or preferences")?,
        ))
    }

    fn write<T: Serialize>(&self, suffix: &str, value: &T) -> Result<()> {
        self.check_directory()?;
        atomic_file::ensure_private_dir(&self.directory, 0o700)?;
        let bytes = Zeroizing::new(serde_json::to_vec(value)?);
        atomic_file::replace(&self.path(suffix), &bytes, 0o600)?;
        Ok(())
    }

    /// Load and validate saved session preferences, using defaults when no file exists.
    pub(crate) fn preferences(&self) -> Result<SessionPreferences> {
        let preferences = self
            .read::<SessionPreferences>("preferences")?
            .unwrap_or_default();
        preferences.validate()?;
        Ok(preferences)
    }

    /// Remove the cached token; a missing session file is already cleared.
    pub(crate) fn clear(&self) -> Result<()> {
        self.check_directory()?;
        match fs::remove_file(self.path("session")) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Validate preferences, remove the previous cached token, and save the new policy.
    /// Cache current credentials only if the updated policy permits it.
    pub(crate) async fn save_preferences(
        &self,
        preferences: &SessionPreferences,
        client: &ApiClient,
    ) -> Result<()> {
        preferences.validate()?;
        // Remove an old cached token even if persisting the new preference later fails.
        self.clear()?;
        self.write("preferences", preferences)?;
        self.remember(client).await?;
        Ok(())
    }

    /// Cache eligible credentials according to session preferences, otherwise clear the saved token.
    pub(crate) async fn remember(&self, client: &ApiClient) -> Result<bool> {
        let preferences = self.preferences()?;
        if let Some(session) = client.authentication().await {
            if preferences.accepts(&session, super::current_unix_time()) {
                self.write("session", &session)?;
                return Ok(true);
            }
        }
        self.clear()?;
        Ok(false)
    }

    /// Load an eligible cached session and verify it through a protected daemon endpoint.
    /// Remove expired or rejected credentials; propagate transport failures.
    pub(crate) async fn restore(&self, client: &ApiClient) -> Result<bool> {
        let preferences = self.preferences()?;
        if !preferences.remember {
            self.clear()?;
            return Ok(false);
        }
        let Some(session) = self.read::<ClientAuthentication>("session")? else {
            return Ok(false);
        };
        if !preferences.accepts(&session, super::current_unix_time()) {
            self.clear()?;
            return Ok(false);
        }
        client.restore_authentication(session).await;
        // Ping is public: only a protected endpoint can validate a saved token.
        match client.request(&Request::GetSecurityConfig).await {
            Ok(Response::SecurityConfig { .. }) => Ok(true),
            Err(_) if !client.is_authenticated().await => {
                self.clear()?;
                Ok(false)
            }
            Err(error) => Err(error),
            Ok(_) => bail!("unexpected response while validating saved session"),
        }
    }
}

/// Cache eligible credentials according to session preferences, otherwise clear the saved token.
pub(crate) async fn remember(client: &ApiClient) -> Result<bool> {
    SessionStore::for_client(client)?.remember(client).await
}

#[cfg(test)]
mod tests;
