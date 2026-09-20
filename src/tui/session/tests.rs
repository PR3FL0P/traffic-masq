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
                let handler = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
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
