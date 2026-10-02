#[tokio::test]
async fn cancelled_password_waiter_keeps_worker_permit() {
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let worker = {
        let semaphore = semaphore.clone();
        tokio::spawn(async move {
            super::password_worker(semaphore, move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
            .await
        })
    };
    started_rx.await.unwrap();
    worker.abort();
    let _ = worker.await;
    let busy = super::password_worker(semaphore.clone(), || ()).await;
    release_tx.send(()).unwrap();
    assert!(matches!(busy, Err(super::AuthError::Busy)));
    let permit = tokio::time::timeout(std::time::Duration::from_secs(5), semaphore.acquire())
        .await
        .unwrap()
        .unwrap();
    drop(permit);
    super::password_worker(semaphore, || ()).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn login_budget_replenishes_without_an_unbounded_queue() {
    let mut budget = super::LoginBudget::new();
    for _ in 0..20 {
        budget.take().unwrap();
    }
    assert!(matches!(budget.take(), Err(super::AuthError::Busy)));
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    budget.take().unwrap();
    assert!(matches!(budget.take(), Err(super::AuthError::Busy)));
}

use sqlx::Row;
use tempfile::TempDir;

use super::*;

fn test_config(temp_dir: &TempDir) -> AuthConfig {
    AuthConfig {
        database_path: temp_dir.path().join("nested/auth.sqlite3"),
        session_idle_seconds: 300,
        session_absolute_seconds: 600,
        argon2_memory_kib: 8,
        argon2_iterations: 1,
        argon2_parallelism: 1,
        max_concurrent_logins: 2,
    }
}

async fn service() -> (TempDir, AuthService) {
    let temp_dir = tempfile::tempdir().expect("create temporary directory");
    let service = AuthService::open(&test_config(&temp_dir))
        .await
        .expect("open auth service");
    (temp_dir, service)
}

#[tokio::test]
async fn initializes_device_then_logs_in_authenticates_and_logs_out() {
    let (_temp_dir, service) = service().await;
    assert!(!service
        .is_initialized()
        .await
        .expect("query initialization"));

    let created = service
        .initialize_device_password("a secure password")
        .await
        .expect("initialize device password");
    assert!(service
        .is_initialized()
        .await
        .expect("query initialization"));

    let login = service
        .login_device("a secure password", Some("test"), Some("local"))
        .await
        .expect("log in");
    assert_eq!(login.principal, created);
    assert_eq!(
        service
            .authenticate(&login.token)
            .await
            .expect("authenticate"),
        created
    );

    service.logout(&login.token).await.expect("log out");
    assert!(matches!(
        service.authenticate(&login.token).await,
        Err(AuthError::InvalidSession)
    ));
}

#[tokio::test]
async fn changing_device_password_revokes_existing_sessions() {
    let (_temp_dir, service) = service().await;
    service
        .initialize_device_password("a secure password")
        .await
        .expect("initialize");
    let session = service
        .login_device("a secure password", None, None)
        .await
        .expect("login");

    service
        .change_device_password("a secure password", "a newer secure password")
        .await
        .expect("change password");
    assert!(matches!(
        service.authenticate(&session.token).await,
        Err(AuthError::InvalidSession)
    ));
    assert!(service
        .login_device("a secure password", None, None)
        .await
        .is_err());
    service
        .login_device("a newer secure password", None, None)
        .await
        .expect("login with new password");
}

#[tokio::test]
async fn rejects_wrong_password_and_uninitialized_login_identically() {
    let (_temp_dir, service) = service().await;
    assert!(matches!(
        service.login_device("wrong password", None, None).await,
        Err(AuthError::InvalidCredentials)
    ));
    service
        .initialize_device_password("a secure password")
        .await
        .expect("initialize");
    assert!(matches!(
        service.login_device("wrong password", None, None).await,
        Err(AuthError::InvalidCredentials)
    ));
}

#[tokio::test]
async fn stores_only_the_token_hash() {
    let (_temp_dir, service) = service().await;
    service
        .initialize_device_password("a secure password")
        .await
        .expect("initialize");
    let login = service
        .login_device("a secure password", None, None)
        .await
        .expect("log in");

    let row = sqlx::query("SELECT token_hash, typeof(token_hash) AS storage_type FROM sessions")
        .fetch_one(&service.inner.pool)
        .await
        .expect("read stored token hash");
    let stored_hash: Vec<u8> = row.get("token_hash");
    assert_eq!(row.get::<String, _>("storage_type"), "blob");
    assert_eq!(stored_hash, hash_token(&login.token));
    assert_ne!(stored_hash, login.token.as_bytes());
}

#[tokio::test]
async fn expires_idle_sessions() {
    let temp_dir = tempfile::tempdir().expect("create temporary directory");
    let mut config = test_config(&temp_dir);
    config.session_idle_seconds = 1;
    config.session_absolute_seconds = 10;
    let service = AuthService::open(&config).await.expect("open auth service");
    service
        .initialize_device_password("a secure password")
        .await
        .expect("initialize");
    let login = service
        .login_device("a secure password", None, None)
        .await
        .expect("log in");

    service
        .authenticate_at(&login.token, login.idle_expires_at - 1)
        .await
        .expect("valid immediately before idle deadline");
    assert!(matches!(
        service
            .authenticate_at(&login.token, login.idle_expires_at)
            .await,
        Err(AuthError::InvalidSession)
    ));
}

#[tokio::test]
async fn idle_refresh_is_capped_by_absolute_expiry() {
    let (_temp_dir, service) = service().await;
    service
        .initialize_device_password("a secure password")
        .await
        .unwrap();
    let login = service
        .login_device("a secure password", None, None)
        .await
        .unwrap();
    let created_at = login.absolute_expires_at - service.inner.session_absolute_seconds;
    // Keep the session active up to the absolute deadline.
    for elapsed in [60, 300, 540, 599] {
        service
            .authenticate_at(&login.token, created_at + elapsed)
            .await
            .unwrap();
        let expiry: i64 = sqlx::query_scalar("SELECT idle_expires_at FROM sessions")
            .fetch_one(&service.inner.pool)
            .await
            .unwrap();
        assert_eq!(
            expiry,
            (created_at + elapsed + service.inner.session_idle_seconds)
                .min(login.absolute_expires_at)
        );
    }
    assert!(matches!(
        service
            .authenticate_at(&login.token, login.absolute_expires_at)
            .await,
        Err(AuthError::InvalidSession)
    ));
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
        .fetch_one(&service.inner.pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn device_password_can_only_be_initialized_once() {
    let (_temp_dir, service) = service().await;
    service
        .initialize_device_password("a secure password")
        .await
        .expect("initialize");
    assert!(matches!(
        service
            .initialize_device_password("another secure password")
            .await,
        Err(AuthError::AlreadyInitialized)
    ));
}

#[tokio::test]
async fn rejects_a_password_shorter_than_the_documented_minimum() {
    let (_temp_dir, service) = service().await;
    let short: String = "a".repeat(MINIMUM_PASSWORD_CHARACTERS - 1);

    assert!(matches!(
        service.initialize_device_password(&short).await,
        Err(AuthError::WeakPassword)
    ));
    assert!(service
        .initialize_device_password(&"a".repeat(MINIMUM_PASSWORD_CHARACTERS))
        .await
        .is_ok());
}

#[tokio::test]
async fn weak_password_message_matches_the_enforced_minimum() {
    assert_eq!(
        AuthError::WeakPassword.to_string(),
        format!("password must contain at least {MINIMUM_PASSWORD_CHARACTERS} characters")
    );
}

#[tokio::test]
async fn purge_removes_expired_sessions_that_were_never_presented_again() {
    let temp_dir = tempfile::tempdir().expect("create temporary directory");
    let mut config = test_config(&temp_dir);
    config.session_idle_seconds = 1;
    config.session_absolute_seconds = 1;
    let service = AuthService::open(&config).await.expect("open auth service");
    service
        .initialize_device_password("a secure password")
        .await
        .expect("initialize");
    let login = service
        .login_device("a secure password", None, None)
        .await
        .expect("log in");

    assert_eq!(
        service
            .purge_expired_sessions_at(login.idle_expires_at - 1)
            .await
            .expect("purge before deadline"),
        0
    );
    assert_eq!(
        service
            .purge_expired_sessions_at(login.idle_expires_at)
            .await
            .expect("purge at deadline"),
        1
    );

    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
        .fetch_one(&service.inner.pool)
        .await
        .expect("count sessions");
    assert_eq!(remaining, 0);
}

#[cfg(unix)]
#[tokio::test]
async fn new_database_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let (temp_dir, _service) = service().await;
    let path = test_config(&temp_dir).database_path;
    let mode = std::fs::metadata(path)
        .expect("database metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}
