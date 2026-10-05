use std::{
    path::Path,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    Row, SqlitePool,
};
use thiserror::Error;
use tokio::sync::Semaphore;

use crate::config::AuthConfig;

const TOKEN_BYTES: usize = 32;
const DEVICE_USERNAME: &str = "device";
const LAST_SEEN_UPDATE_INTERVAL_SECONDS: i64 = 60;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

pub const MINIMUM_PASSWORD_CHARACTERS: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Operator,
    Administrator,
}

impl FromStr for Role {
    type Err = AuthError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "viewer" => Ok(Self::Viewer),
            "operator" => Ok(Self::Operator),
            "administrator" => Ok(Self::Administrator),
            _ => Err(AuthError::InvalidStoredRole),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub user_id: i64,
    pub username: String,
    pub role: Role,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginSession {
    pub token: String,
    pub principal: Principal,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("password must contain at least {MINIMUM_PASSWORD_CHARACTERS} characters")]
    WeakPassword,

    #[error("the device password is already initialized")]
    AlreadyInitialized,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("invalid or expired session")]
    InvalidSession,

    #[error("invalid authentication configuration: {0}")]
    InvalidConfig(String),

    #[error("stored user role is invalid")]
    InvalidStoredRole,

    #[error("password hashing operation failed")]
    PasswordHash,

    #[error("too many authentication attempts; retry later")]
    Busy,

    #[error("authentication worker failed")]
    Worker,

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

struct LoginBudget {
    remaining: u32,
    refill_at: tokio::time::Instant,
}

impl LoginBudget {
    fn new() -> Self {
        Self {
            remaining: 20,
            refill_at: tokio::time::Instant::now(),
        }
    }

    fn take(&mut self) -> Result<(), AuthError> {
        let now = tokio::time::Instant::now();
        let refill = now.duration_since(self.refill_at).as_secs();
        if refill > 0 {
            self.remaining = self.remaining.saturating_add(refill.min(20) as u32).min(20);
            self.refill_at += Duration::from_secs(refill);
        }
        if self.remaining == 0 {
            return Err(AuthError::Busy);
        }
        self.remaining -= 1;
        Ok(())
    }
}

#[derive(Clone)]
pub struct AuthService {
    inner: Arc<AuthServiceInner>,
}

struct AuthServiceInner {
    pool: SqlitePool,
    argon2_params: Params,
    dummy_password_hash: String,
    login_semaphore: Arc<Semaphore>,
    login_budget: tokio::sync::Mutex<LoginBudget>,
    session_idle_seconds: i64,
    session_absolute_seconds: i64,
}

impl AuthService {
    /// Validate authentication settings and open the private SQLite session store.
    /// Initialize the schema, password-hashing parameters, and bounded login workers.
    pub async fn open(config: &AuthConfig) -> Result<Self, AuthError> {
        let session_idle_seconds =
            duration_to_i64("session_idle_seconds", config.session_idle_seconds)?;
        let session_absolute_seconds =
            duration_to_i64("session_absolute_seconds", config.session_absolute_seconds)?;
        if session_idle_seconds == 0 {
            return Err(AuthError::InvalidConfig(
                "session_idle_seconds must be greater than zero".into(),
            ));
        }
        if session_absolute_seconds == 0 {
            return Err(AuthError::InvalidConfig(
                "session_absolute_seconds must be greater than zero".into(),
            ));
        }
        if session_idle_seconds > session_absolute_seconds {
            return Err(AuthError::InvalidConfig(
                "session_idle_seconds cannot exceed session_absolute_seconds".into(),
            ));
        }
        if config.max_concurrent_logins == 0 {
            return Err(AuthError::InvalidConfig(
                "max_concurrent_logins must be greater than zero".into(),
            ));
        }
        if config.database_path.as_os_str().is_empty() {
            return Err(AuthError::InvalidConfig(
                "database_path cannot be empty".into(),
            ));
        }

        let argon2_params = Params::new(
            config.argon2_memory_kib,
            config.argon2_iterations,
            config.argon2_parallelism,
            None,
        )
        .map_err(|error| AuthError::InvalidConfig(format!("invalid Argon2 parameters: {error}")))?;

        create_database_parent(&config.database_path).await?;
        let connect_options = SqliteConnectOptions::new()
            .filename(&config.database_path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(SQLITE_BUSY_TIMEOUT);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(connect_options)
            .await?;

        set_private_file_permissions(&config.database_path).await?;
        initialize_schema(&pool).await?;

        let dummy_password_hash =
            hash_password(argon2_params.clone(), random_dummy_password()).await?;
        let max_concurrent_logins = usize::try_from(config.max_concurrent_logins)
            .map_err(|_| AuthError::InvalidConfig("max_concurrent_logins is too large".into()))?;

        Ok(Self {
            inner: Arc::new(AuthServiceInner {
                pool,
                argon2_params,
                dummy_password_hash,
                login_semaphore: Arc::new(Semaphore::new(max_concurrent_logins)),
                login_budget: tokio::sync::Mutex::new(LoginBudget::new()),
                session_idle_seconds,
                session_absolute_seconds,
            }),
        })
    }

    /// Report whether an enabled device account exists.
    pub async fn is_initialized(&self) -> Result<bool, AuthError> {
        let exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND enabled = 1)",
        )
        .bind(DEVICE_USERNAME)
        .fetch_one(&self.inner.pool)
        .await?;
        Ok(exists != 0)
    }

    /// Create the device administrator once, rejecting an already initialized account.
    /// Disable other users and remove existing sessions in the same database transaction.
    pub async fn initialize_device_password(&self, password: &str) -> Result<Principal, AuthError> {
        validate_password(password)?;
        let password_hash =
            hash_password(self.inner.argon2_params.clone(), password.to_owned()).await?;
        let now = unix_timestamp()?;
        let mut transaction = self.inner.pool.begin().await?;
        let initialized: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND enabled = 1)",
        )
        .bind(DEVICE_USERNAME)
        .fetch_one(&mut *transaction)
        .await?;
        if initialized != 0 {
            return Err(AuthError::AlreadyInitialized);
        }

        let insert = sqlx::query(
            "INSERT INTO users (username, password_hash, role, enabled, created_at) \
             VALUES (?, ?, 'administrator', 1, ?)",
        )
        .bind(DEVICE_USERNAME)
        .bind(password_hash)
        .bind(now)
        .execute(&mut *transaction)
        .await;
        let result = match insert {
            Ok(result) => result,
            Err(error) if is_unique_violation(&error) => return Err(AuthError::AlreadyInitialized),
            Err(error) => return Err(error.into()),
        };
        sqlx::query("UPDATE users SET enabled = 0 WHERE username != ?")
            .bind(DEVICE_USERNAME)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM sessions")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;

        Ok(Principal {
            user_id: result.last_insert_rowid(),
            username: DEVICE_USERNAME.to_string(),
            role: Role::Administrator,
        })
    }

    /// Replace or create the device administrator password and revoke every session atomically.
    /// This recovery entry point does not verify the previous password.
    pub async fn reset_device_password(&self, password: &str) -> Result<Principal, AuthError> {
        validate_password(password)?;
        let password_hash =
            hash_password(self.inner.argon2_params.clone(), password.to_owned()).await?;
        let now = unix_timestamp()?;
        let mut transaction = self.inner.pool.begin().await?;
        sqlx::query(
            "INSERT INTO users (username, password_hash, role, enabled, created_at) \
             VALUES (?, ?, 'administrator', 1, ?) \
             ON CONFLICT(username) DO UPDATE SET \
                 password_hash = excluded.password_hash, \
                 role = 'administrator', enabled = 1",
        )
        .bind(DEVICE_USERNAME)
        .bind(password_hash)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("UPDATE users SET enabled = 0 WHERE username != ?")
            .bind(DEVICE_USERNAME)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM sessions")
            .execute(&mut *transaction)
            .await?;
        let user_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
            .bind(DEVICE_USERNAME)
            .fetch_one(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(Principal {
            user_id,
            username: DEVICE_USERNAME.to_string(),
            role: Role::Administrator,
        })
    }

    /// Verify the device password with rate and concurrency limits, then issue a session token.
    pub async fn login_device(
        &self,
        password: &str,
        client_name: Option<&str>,
        peer: Option<&str>,
    ) -> Result<LoginSession, AuthError> {
        self.login(password, client_name, peer).await
    }

    /// Verify the current password, replace it, and revoke existing sessions.
    /// If replacement fails, remove the temporary verification session.
    pub async fn change_device_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        validate_password(new_password)?;
        let verification = self
            .login_device(current_password, Some("password-change"), None)
            .await?;
        let result = self.reset_device_password(new_password).await.map(|_| ());
        if result.is_err() {
            let _ = self.logout(&verification.token).await;
        }
        result
    }

    /// Apply the login budget, verify the password off the runtime, and store a token hash.
    /// Return the bearer token with idle and absolute expiration times.
    async fn login(
        &self,
        password: &str,
        client_name: Option<&str>,
        peer: Option<&str>,
    ) -> Result<LoginSession, AuthError> {
        self.inner.login_budget.lock().await.take()?;
        let user = sqlx::query(
            "SELECT id, username, password_hash, role, enabled \
             FROM users WHERE username = ?",
        )
        .bind(DEVICE_USERNAME)
        .fetch_optional(&self.inner.pool)
        .await?;

        let candidate_hash = user
            .as_ref()
            .map(|row| row.get::<String, _>("password_hash"))
            .unwrap_or_else(|| self.inner.dummy_password_hash.clone());

        let supplied_password = zeroize::Zeroizing::new(password.to_owned());
        let password_matches = password_worker(self.inner.login_semaphore.clone(), move || {
            verify_password(&candidate_hash, &supplied_password)
        })
        .await?;

        let Some(user) = user else {
            return Err(AuthError::InvalidCredentials);
        };
        let enabled = user.get::<i64, _>("enabled") != 0;
        if !enabled || !password_matches {
            return Err(AuthError::InvalidCredentials);
        }

        let principal = Principal {
            user_id: user.get("id"),
            username: user.get("username"),
            role: user.get::<String, _>("role").parse()?,
        };
        let token = generate_token();
        let token_hash = hash_token(&token);
        let now = unix_timestamp()?;
        let absolute_expires_at = now
            .checked_add(self.inner.session_absolute_seconds)
            .ok_or_else(|| AuthError::InvalidConfig("session expiration overflows".into()))?;
        let idle_expires_at = now
            .checked_add(self.inner.session_idle_seconds)
            .ok_or_else(|| AuthError::InvalidConfig("session expiration overflows".into()))?
            .min(absolute_expires_at);

        sqlx::query(
            "INSERT INTO sessions \
             (token_hash, user_id, client_name, peer, created_at, last_seen_at, \
              idle_expires_at, absolute_expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(token_hash.as_slice())
        .bind(principal.user_id)
        .bind(client_name)
        .bind(peer)
        .bind(now)
        .bind(now)
        .bind(idle_expires_at)
        .bind(absolute_expires_at)
        .execute(&self.inner.pool)
        .await?;

        Ok(LoginSession {
            token,
            principal,
            idle_expires_at,
            absolute_expires_at,
        })
    }

    /// Validate a bearer token and enabled user, reject expired sessions, and refresh idle expiry.
    pub async fn authenticate(&self, token: &str) -> Result<Principal, AuthError> {
        self.authenticate_at(token, unix_timestamp()?).await
    }

    async fn authenticate_at(&self, token: &str, now: i64) -> Result<Principal, AuthError> {
        let token_hash = decode_and_hash_token(token).ok_or(AuthError::InvalidSession)?;
        let row = sqlx::query(
            "SELECT s.user_id, s.last_seen_at, s.idle_expires_at, \
                    s.absolute_expires_at, u.username, u.role, u.enabled \
             FROM sessions s \
             JOIN users u ON u.id = s.user_id \
             WHERE s.token_hash = ?",
        )
        .bind(token_hash.as_slice())
        .fetch_optional(&self.inner.pool)
        .await?;

        let Some(row) = row else {
            return Err(AuthError::InvalidSession);
        };
        let user_id: i64 = row.get("user_id");
        let last_seen_at: i64 = row.get("last_seen_at");
        let idle_expires_at: i64 = row.get("idle_expires_at");
        let absolute_expires_at: i64 = row.get("absolute_expires_at");
        let enabled = row.get::<i64, _>("enabled") != 0;

        if !enabled || now >= idle_expires_at || now >= absolute_expires_at {
            sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
                .bind(token_hash.as_slice())
                .execute(&self.inner.pool)
                .await?;
            return Err(AuthError::InvalidSession);
        }

        if now.saturating_sub(last_seen_at) >= LAST_SEEN_UPDATE_INTERVAL_SECONDS {
            let refreshed_idle_expiry = now
                .saturating_add(self.inner.session_idle_seconds)
                .min(absolute_expires_at);
            sqlx::query(
                "UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? \
                 WHERE token_hash = ? AND last_seen_at = ?",
            )
            .bind(now)
            .bind(refreshed_idle_expiry)
            .bind(token_hash.as_slice())
            .bind(last_seen_at)
            .execute(&self.inner.pool)
            .await?;
        }

        Ok(Principal {
            user_id,
            username: row.get("username"),
            role: row.get::<String, _>("role").parse()?,
        })
    }

    /// Delete the session associated with the supplied token.
    pub async fn logout(&self, token: &str) -> Result<(), AuthError> {
        if let Some(token_hash) = decode_and_hash_token(token) {
            sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
                .bind(token_hash.as_slice())
                .execute(&self.inner.pool)
                .await?;
        }
        Ok(())
    }

    /// Delete all sessions for one user and return the number removed.
    pub async fn revoke_user_sessions(&self, user_id: i64) -> Result<u64, AuthError> {
        let result = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.inner.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Delete sessions past either expiration deadline and return the number removed.
    pub async fn purge_expired_sessions(&self) -> Result<u64, AuthError> {
        self.purge_expired_sessions_at(unix_timestamp()?).await
    }

    async fn purge_expired_sessions_at(&self, now: i64) -> Result<u64, AuthError> {
        let result = sqlx::query(
            "DELETE FROM sessions WHERE absolute_expires_at <= ? OR idle_expires_at <= ?",
        )
        .bind(now)
        .bind(now)
        .execute(&self.inner.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

async fn initialize_schema(pool: &SqlitePool) -> Result<(), AuthError> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            username TEXT NOT NULL UNIQUE,\
            password_hash TEXT NOT NULL,\
            role TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'administrator')),\
            enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),\
            created_at INTEGER NOT NULL\
        )",
    )
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (\
            token_hash BLOB PRIMARY KEY NOT NULL CHECK (length(token_hash) = 32),\
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,\
            client_name TEXT,\
            peer TEXT,\
            created_at INTEGER NOT NULL,\
            last_seen_at INTEGER NOT NULL,\
            idle_expires_at INTEGER NOT NULL,\
            absolute_expires_at INTEGER NOT NULL\
        )",
    )
    .execute(&mut *transaction)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id)")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS sessions_expiry_idx \
         ON sessions(absolute_expires_at, idle_expires_at)",
    )
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn create_database_parent(database_path: &Path) -> Result<(), AuthError> {
    if let Some(parent) = database_path.parent() {
        if !parent.as_os_str().is_empty() {
            crate::atomic_file::create_dir_all_durable_async(parent).await?;
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn set_private_file_permissions(database_path: &Path) -> Result<(), AuthError> {
    use std::os::unix::fs::PermissionsExt;

    tokio::fs::set_permissions(database_path, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_private_file_permissions(_database_path: &Path) -> Result<(), AuthError> {
    Ok(())
}

fn validate_password(password: &str) -> Result<(), AuthError> {
    if password.chars().count() < MINIMUM_PASSWORD_CHARACTERS {
        Err(AuthError::WeakPassword)
    } else {
        Ok(())
    }
}

/// Run password work on the blocking pool while holding a concurrency permit.
async fn password_worker<T: Send + 'static>(
    semaphore: Arc<Semaphore>,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, AuthError> {
    let permit = semaphore.try_acquire_owned().map_err(|_| AuthError::Busy)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| AuthError::Worker)
}

/// Generate a salted Argon2 password hash on a blocking worker.
async fn hash_password(params: Params, password: String) -> Result<String, AuthError> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| AuthError::PasswordHash)
    })
    .await
    .map_err(|_| AuthError::Worker)?
}

/// Check a password against its encoded hash; malformed hashes fail verification.
fn verify_password(encoded_hash: &str, password: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

fn random_dummy_password() -> String {
    let mut bytes = [0_u8; TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_token() -> String {
    let mut bytes = [0_u8; TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode a session token and return its hash, rejecting malformed token encoding.
fn decode_and_hash_token(token: &str) -> Option<[u8; 32]> {
    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    if decoded.len() != TOKEN_BYTES {
        return None;
    }
    Some(hash_token(token))
}

fn hash_token(token: &str) -> [u8; 32] {
    hash_token_bytes(token.as_bytes())
}

fn hash_token_bytes(token: &[u8]) -> [u8; 32] {
    Sha256::digest(token).into()
}

fn unix_timestamp() -> Result<i64, AuthError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::Worker)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| AuthError::Worker)
}

fn duration_to_i64(name: &str, value: u64) -> Result<i64, AuthError> {
    i64::try_from(value).map_err(|_| AuthError::InvalidConfig(format!("{name} is too large")))
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(database_error) if database_error.is_unique_violation())
}

#[cfg(test)]
mod tests;
