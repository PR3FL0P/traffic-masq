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

    pub(crate) fn preferences(&self) -> Result<SessionPreferences> {
        let preferences = self
            .read::<SessionPreferences>("preferences")?
            .unwrap_or_default();
        preferences.validate()?;
        Ok(preferences)
    }

    pub(crate) fn clear(&self) -> Result<()> {
        self.check_directory()?;
        match fs::remove_file(self.path("session")) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

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

pub(crate) async fn remember(client: &ApiClient) -> Result<bool> {
    SessionStore::for_client(client)?.remember(client).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn store(directory: &std::path::Path) -> SessionStore {
        SessionStore {
            directory: directory.join("private"),
            key: "test".into(),
        }
    }

    fn credential(now: u64) -> ClientAuthentication {
        ClientAuthentication {
            token: Zeroizing::new("secret-token".into()),
            authenticated_at: now,
            absolute_expires_at: (now + 3600) as i64,
        }
    }

    #[test]
    fn five_minute_default_is_fixed_from_login_and_respects_server_expiry() {
        let prefs = SessionPreferences::default();
        assert!(prefs.remember);
        assert_eq!(prefs.minutes, 5);
        let mut session = credential(1000);
        assert!(prefs.accepts(&session, 1299));
        assert!(!prefs.accepts(&session, 1300));
        assert!(!prefs.accepts(&session, 999));
        session.absolute_expires_at = 1100;
        assert!(!prefs.accepts(&session, 1100));
        assert!(!SessionPreferences {
            remember: false,
            minutes: 5,
            show_dhcp_client: false,
        }
        .accepts(&session, 1000));
        assert!(SessionPreferences {
            remember: true,
            minutes: 0,
            show_dhcp_client: false,
        }
        .validate()
        .is_err());
    }

    #[tokio::test]
    async fn saving_is_private_relaunch_does_not_extend_and_disabling_clears_token() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let client = ApiClient::new("/test.sock");
        let now = super::super::current_unix_time();
        client.restore_authentication(credential(now - 60)).await;
        assert!(store.remember(&client).await.unwrap());
        assert_eq!(
            fs::metadata(&store.directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(store.path("session"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let saved = store
            .read::<ClientAuthentication>("session")
            .unwrap()
            .unwrap();
        assert_eq!(saved.authenticated_at, now - 60);
        let next = ApiClient::new("/test.sock");
        next.restore_authentication(saved).await;
        assert!(store.remember(&next).await.unwrap());
        assert_eq!(
            store
                .read::<ClientAuthentication>("session")
                .unwrap()
                .unwrap()
                .authenticated_at,
            now - 60
        );
        let prefs = SessionPreferences {
            remember: false,
            minutes: 12,
            show_dhcp_client: false,
        };
        store.save_preferences(&prefs, &next).await.unwrap();
        assert_eq!(store.preferences().unwrap(), prefs);
        assert!(!store.path("session").exists());
        assert!(
            next.is_authenticated().await,
            "disabling affects future launches, not the open TUI"
        );
        assert!(!format!("{next:?}").contains("secret-token"));
    }

    #[tokio::test]
    async fn shortened_duration_and_expired_cache_require_new_login() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let client = ApiClient::new("/test.sock");
        client
            .restore_authentication(credential(super::super::current_unix_time() - 120))
            .await;
        assert!(store.remember(&client).await.unwrap());
        store
            .save_preferences(
                &SessionPreferences {
                    remember: true,
                    minutes: 1,
                    show_dhcp_client: false,
                },
                &client,
            )
            .await
            .unwrap();
        assert!(!store.path("session").exists());
        store
            .write(
                "session",
                &credential(super::super::current_unix_time() - 301),
            )
            .unwrap();
        let next = ApiClient::new("/test.sock");
        assert!(!store.restore(&next).await.unwrap());
        assert!(!next.is_authenticated().await);
        assert!(!store.path("session").exists());
    }

    #[test]
    fn rejects_public_files_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        store.write("session", &credential(1000)).unwrap();
        fs::set_permissions(store.path("session"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.read::<ClientAuthentication>("session").is_err());
        store.clear().unwrap();
        let target = dir.path().join("elsewhere");
        fs::write(&target, "unchanged").unwrap();
        std::os::unix::fs::symlink(&target, store.path("session")).unwrap();
        assert!(store.read::<ClientAuthentication>("session").is_err());
        assert!(store.write("session", &credential(1000)).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "unchanged");
    }

    #[tokio::test]
    async fn restored_token_is_checked_by_daemon_and_revoked_token_is_discarded() {
        use http_body_util::Full;
        use hyper::{body::Bytes, service::service_fn};
        use hyper_util::rt::TokioIo;
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let config = crate::config::AuthConfig {
            database_path: dir.path().join("auth.sqlite3"),
            argon2_memory_kib: 1024,
            argon2_iterations: 1,
            ..Default::default()
        };
        let auth = crate::auth::AuthService::open(&config).await.unwrap();
        auth.initialize_device_password("test device password")
            .await
            .unwrap();
        let login = auth
            .login_device("test device password", None, None)
            .await
            .unwrap();
        let socket = dir.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server_auth = auth.clone();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let auth = server_auth.clone();
                tokio::spawn(async move {
                    let handler =
                        service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                            let auth = auth.clone();
                            async move {
                                assert_eq!(request.uri().path(), "/api/v1/security/settings");
                                let token = request
                                    .headers()
                                    .get("authorization")
                                    .unwrap()
                                    .to_str()
                                    .unwrap()
                                    .strip_prefix("Bearer ")
                                    .unwrap();
                                let valid = auth.authenticate(token).await.is_ok();
                                let body = if valid {
                                    serde_json::to_vec(&Response::SecurityConfig {
                                        active: crate::api::model::SecuritySettings {
                                            rollback_timeout_seconds: 30,
                                        },
                                        desired: crate::api::model::SecuritySettings {
                                            rollback_timeout_seconds: 30,
                                        },
                                        override_active: false,
                                        restart_required: false,
                                    })
                                    .unwrap()
                                } else {
                                    br#"{"message":"authentication required"}"#.to_vec()
                                };
                                Ok::<_, std::convert::Infallible>(
                                    hyper::Response::builder()
                                        .status(if valid { 200 } else { 401 })
                                        .body(Full::new(Bytes::from(body)))
                                        .unwrap(),
                                )
                            }
                        });
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), handler)
                        .await
                        .unwrap();
                });
            }
        });
        let client = ApiClient::new(&socket);
        let mut session = credential(super::super::current_unix_time());
        session.token = Zeroizing::new(login.token.clone());
        session.absolute_expires_at = login.absolute_expires_at;
        client.restore_authentication(session).await;
        store.remember(&client).await.unwrap();
        let next = ApiClient::new(&socket);
        assert!(store.restore(&next).await.unwrap());
        auth.reset_device_password("new test device password")
            .await
            .unwrap();
        let revoked = ApiClient::new(&socket);
        assert!(!store.restore(&revoked).await.unwrap());
        assert!(!revoked.is_authenticated().await);
        assert!(!store.path("session").exists());
        task.abort();
    }

    #[test]
    fn preferences_defaults_to_hidden_dhcp_client_tab_when_unspecified() {
        let json = r#"{"remember": true, "minutes": 10}"#;
        let prefs: SessionPreferences = serde_json::from_str(json).unwrap();
        assert!(!prefs.show_dhcp_client);
        assert!(prefs.remember);
        assert_eq!(prefs.minutes, 10);
    }
}
