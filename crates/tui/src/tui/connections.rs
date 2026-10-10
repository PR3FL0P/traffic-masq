//! Named HTTPS destinations. Credentials stay in the separate endpoint-scoped session store.
use super::{api::client::ApiClient, session::SessionStore};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedConnection {
    pub server: String,
    pub ca_cert: Option<PathBuf>,
}

pub fn list_connections() -> Result<BTreeMap<String, SavedConnection>> {
    Ok(SessionStore::connections()?
        .read("profiles")?
        .unwrap_or_default())
}

pub fn load_connection(name: &str) -> Result<SavedConnection> {
    list_connections()?
        .remove(name)
        .with_context(|| format!("saved connection {name:?} not found"))
}

pub fn save_connection(name: &str, connection: SavedConnection) -> Result<()> {
    save_in(&SessionStore::connections()?, name, connection)
}

pub(super) fn save_in(
    store: &SessionStore,
    name: &str,
    mut connection: SavedConnection,
) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        bail!("connection name must be 1-64 ASCII letters, digits, dots, underscores or hyphens");
    }
    if let Some(path) = &connection.ca_cert {
        connection.ca_cert =
            Some(std::fs::canonicalize(path).context("could not resolve CA file")?);
    }
    let client = ApiClient::https(&connection.server, connection.ca_cert.as_deref())?;
    connection.server = client.endpoint_label();
    let mut saved: BTreeMap<String, SavedConnection> = store.read("profiles")?.unwrap_or_default();
    saved.insert(name.to_string(), connection);
    store.write("profiles", &saved)
}

pub fn delete_connection(name: &str) -> Result<()> {
    let mut saved = list_connections()?;
    if saved.remove(name).is_none() {
        bail!("saved connection {name:?} not found");
    }
    SessionStore::connections()?.write("profiles", &saved)
}
