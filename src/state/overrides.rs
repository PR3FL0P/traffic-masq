use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::atomic_file::{self, PRIVATE_FILE_MODE};
use crate::config::{
    ApiConfig, AppConfig, InterfaceConfig, NetworkConfig, RouterConfig, SecurityConfig,
    VpnPolicyMode,
};

/// Version 4 records interface suppression independently of overrides.
/// Version 3 records router commit identity atomically with committed intent.
/// Version 2 is readable; version 1 contained obsolete derived service maps.
pub const CURRENT_RUNTIME_OVERRIDES_SCHEMA: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOverrides {
    #[serde(default = "current_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_router_transaction: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub committed_interface_transactions: BTreeMap<String, String>,
    #[serde(default)]
    pub router: Option<RouterConfig>,
    #[serde(default)]
    pub api: Option<ApiConfig>,

    #[serde(default)]
    pub security: Option<SecurityConfig>,

    #[serde(default)]
    pub vpn_mode: Option<VpnPolicyMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_enabled: Option<bool>,
    #[serde(default)]
    pub interfaces: BTreeMap<String, InterfaceOverride>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub suppressed_interfaces: BTreeSet<String>,
}

impl Default for RuntimeOverrides {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_RUNTIME_OVERRIDES_SCHEMA,
            revision: 0,
            committed_router_transaction: None,
            committed_interface_transactions: BTreeMap::new(),
            router: None,
            api: None,
            security: None,
            vpn_mode: None,
            vpn_enabled: None,
            interfaces: BTreeMap::new(),
            suppressed_interfaces: BTreeSet::new(),
        }
    }
}

/// Recovery-only view of a persisted override document.
///
/// Loading validates only the JSON envelope and schema. Individual proof fields
/// are decoded independently so damage in one recovery scope cannot suppress an
/// unrelated recovery pass.
#[derive(Debug, Clone)]
pub struct RecoveryCommitProof {
    path: PathBuf,
    object: serde_json::Map<String, serde_json::Value>,
}

impl RecoveryCommitProof {
    pub fn committed_router_transaction(&self) -> Result<Option<String>> {
        match self.object.get("committed_router_transaction") {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(value) => Ok(Some(
                value
                    .as_str()
                    .with_context(|| {
                        format!(
                            "runtime override router commit token in {} is not a string",
                            self.path.display()
                        )
                    })?
                    .to_owned(),
            )),
        }
    }

    pub fn committed_interface_transactions(&self) -> Result<BTreeMap<String, String>> {
        let mut committed = BTreeMap::new();
        let Some(value) = self.object.get("committed_interface_transactions") else {
            return Ok(committed);
        };
        if value.is_null() {
            return Ok(committed);
        }
        let entries = value.as_object().with_context(|| {
            format!(
                "runtime override interface commit proof in {} is not an object",
                self.path.display()
            )
        })?;
        for (interface, token) in entries {
            let token = token.as_str().with_context(|| {
                format!(
                    "runtime override interface commit token for {interface} in {} is not a string",
                    self.path.display()
                )
            })?;
            committed.insert(interface.clone(), token.to_owned());
        }
        Ok(committed)
    }

    /// Decode only state that can affect router rollback/ownership. API, auth,
    /// security and legacy VPN-policy overrides are intentionally excluded.
    pub fn router_recovery_overrides(&self) -> Result<RuntimeOverrides> {
        self.router_recovery_overrides_with_commit_token(self.committed_router_transaction()?)
    }

    /// Decode router recovery state using a commit token that was parsed independently.
    ///
    /// This lets startup recover interface transactions first even when the router proof field is
    /// malformed, and conversely lets router recovery proceed when only interface proof is bad.
    pub fn router_recovery_overrides_with_commit_token(
        &self,
        committed_router_transaction: Option<String>,
    ) -> Result<RuntimeOverrides> {
        let revision = match self.object.get("revision") {
            None => 0,
            Some(value) => value.as_u64().with_context(|| {
                format!(
                    "runtime override recovery revision in {} is not an unsigned integer",
                    self.path.display()
                )
            })?,
        };
        let router = match self.object.get("router") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(serde_json::from_value(value.clone()).with_context(|| {
                format!(
                    "invalid router override required for recovery in {}",
                    self.path.display()
                )
            })?),
        };
        let vpn_enabled = match self.object.get("vpn_enabled") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(value.as_bool().with_context(|| {
                format!(
                    "runtime override vpn_enabled in {} is not a boolean",
                    self.path.display()
                )
            })?),
        };
        let interfaces = match self.object.get("interfaces") {
            None | Some(serde_json::Value::Null) => BTreeMap::new(),
            Some(value) => serde_json::from_value(value.clone()).with_context(|| {
                format!(
                    "invalid interface overrides required for recovery in {}",
                    self.path.display()
                )
            })?,
        };

        let suppressed_interfaces = match self.object.get("suppressed_interfaces") {
            None => BTreeSet::new(),
            Some(value) => serde_json::from_value(value.clone())
                .context("invalid interface suppression required for recovery")?,
        };

        Ok(RuntimeOverrides {
            suppressed_interfaces,
            revision,
            committed_router_transaction,
            router,
            vpn_enabled,
            interfaces,
            ..RuntimeOverrides::default()
        })
    }
}

const fn current_schema_version() -> u32 {
    CURRENT_RUNTIME_OVERRIDES_SCHEMA
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceOverride {
    pub config: InterfaceConfig,
    #[serde(default)]
    pub allow_management_change: bool,
    /// Router-created DHCP enablement; all interface settings follow the base config.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dhcp_client_only: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl RuntimeOverrides {
    fn validate_suppression(&self) -> Result<()> {
        for name in &self.suppressed_interfaces {
            traffic_masq_protocol::validate_interface_name(name).map_err(anyhow::Error::msg)?;
            if self.interfaces.contains_key(name) {
                bail!(
                    "suppressed interface {name:?} conflicts with an override or has an empty name"
                );
            }
        }
        Ok(())
    }

    pub fn forget_interface(&mut self, name: &str) {
        self.interfaces.remove(name);
        self.suppressed_interfaces.insert(name.to_owned());
    }

    pub fn reset_interface_override(&mut self, name: &str) {
        self.interfaces.remove(name);
        self.suppressed_interfaces.remove(name);
    }

    pub fn effective_config(&self, base: &AppConfig) -> Result<AppConfig> {
        let mut effective = base.clone();
        effective.network = self.effective_network(&base.network)?;
        if let Some(router) = &self.router {
            effective.router = router.clone();
        }
        if let Some(api) = &self.api {
            effective.api = api.clone();
        }
        if let Some(security) = &self.security {
            effective.security = security.clone();
        }
        if let Some(enabled) = self.vpn_enabled {
            effective.vpn.enabled = enabled;
        }
        effective.validate()?;
        Ok(effective)
    }

    /// Merge only state required by router recovery and validate only that recovery surface.
    pub fn effective_router_recovery_config(&self, base: &AppConfig) -> Result<AppConfig> {
        let mut effective = base.clone();
        effective.network = self.effective_network(&base.network)?;
        if let Some(router) = &self.router {
            effective.router = router.clone();
        }
        if let Some(enabled) = self.vpn_enabled {
            effective.vpn.enabled = enabled;
        }
        effective.validate_router_recovery()?;
        Ok(effective)
    }

    pub fn effective_network(&self, base: &NetworkConfig) -> Result<NetworkConfig> {
        self.validate_suppression()?;
        let mut effective = base.clone();
        effective
            .interfaces
            .retain(|name, _| !self.suppressed_interfaces.contains(name));
        for (interface, value) in &self.interfaces {
            let config = if value.dhcp_client_only {
                let mut config = base.interfaces.get(interface).cloned().with_context(|| {
                    format!("base interface {interface} for derived DHCP client is missing")
                })?;
                config
                    .dhcp_client
                    .get_or_insert_with(Default::default)
                    .enabled = true;
                config
            } else {
                value.config.clone()
            };
            config.validate(interface)?;
            effective.interfaces.insert(interface.clone(), config);
        }
        effective.validate()?;
        Ok(effective)
    }

    /// Stamped with the current schema version.
    ///
    /// This used to also rebuild `dhcp`/`wifi`/`wifi_client` from `interfaces`
    /// and is all that is left of that: those maps were a persisted cache of
    /// what `interfaces` already determines, and nothing read them.
    pub fn normalized(&self) -> Result<Self> {
        self.validate_suppression()?;
        let mut normalized = self.clone();
        normalized.schema_version = CURRENT_RUNTIME_OVERRIDES_SCHEMA;
        Ok(normalized)
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeOverrideStore {
    path: PathBuf,
}

impl RuntimeOverrideStore {
    pub fn in_state_dir(state_dir: impl AsRef<Path>) -> Self {
        Self {
            path: state_dir.as_ref().join("runtime-overrides.json"),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the recovery proof envelope without decoding unrelated overrides.
    ///
    /// A valid, supported schema is required before persisted transaction tokens
    /// can be trusted. Non-proof fields are intentionally left uninterpreted.
    pub async fn load_recovery_commit_proof(&self) -> Result<RecoveryCommitProof> {
        atomic_file::reject_symlink(&self.path).with_context(|| {
            format!(
                "unsafe runtime override recovery proof path {}",
                self.path.display()
            )
        })?;
        let content = match fs::read(&self.path).await {
            Ok(content) => content,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(RecoveryCommitProof {
                    path: self.path.clone(),
                    object: serde_json::Map::new(),
                });
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to read runtime override recovery proof {}",
                        self.path.display()
                    )
                });
            }
        };

        let value: serde_json::Value = serde_json::from_slice(&content).with_context(|| {
            format!(
                "failed to parse runtime override recovery proof {}",
                self.path.display()
            )
        })?;
        let object = value.as_object().cloned().with_context(|| {
            format!(
                "runtime override recovery proof {} is not an object",
                self.path.display()
            )
        })?;
        let persisted_schema = match object.get("schema_version") {
            None => None,
            Some(value) => Some(value.as_u64().with_context(|| {
                format!(
                    "runtime override schema version in {} is not an unsigned integer",
                    self.path.display()
                )
            })?),
        };
        if let Some(version) = persisted_schema {
            if version > u64::from(CURRENT_RUNTIME_OVERRIDES_SCHEMA) {
                bail!(
                    "runtime overrides {} use unsupported future schema version {version} (current is {})",
                    self.path.display(),
                    CURRENT_RUNTIME_OVERRIDES_SCHEMA
                );
            }
            if !(2..=u64::from(CURRENT_RUNTIME_OVERRIDES_SCHEMA)).contains(&version) {
                bail!(
                    "runtime overrides {} use unsupported schema version {version}",
                    self.path.display()
                );
            }
        }

        Ok(RecoveryCommitProof {
            path: self.path.clone(),
            object,
        })
    }

    pub async fn load(&self) -> Result<RuntimeOverrides> {
        atomic_file::reject_symlink(&self.path)
            .with_context(|| format!("unsafe runtime override path {}", self.path.display()))?;
        let content = match fs::read(&self.path).await {
            Ok(content) => content,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(RuntimeOverrides::default());
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to read runtime overrides {}", self.path.display())
                });
            }
        };

        let value: serde_json::Value = serde_json::from_slice(&content).with_context(|| {
            format!("failed to parse runtime overrides {}", self.path.display())
        })?;
        let persisted_schema = value.get("schema_version").and_then(|value| value.as_u64());
        if let Some(version) = persisted_schema {
            if version > u64::from(CURRENT_RUNTIME_OVERRIDES_SCHEMA) {
                bail!(
                    "runtime overrides {} use unsupported future schema version {version} (current is {})",
                    self.path.display(),
                    CURRENT_RUNTIME_OVERRIDES_SCHEMA
                );
            }
            if !(2..=u64::from(CURRENT_RUNTIME_OVERRIDES_SCHEMA)).contains(&version) {
                bail!(
                    "runtime overrides {} use unsupported schema version {version}",
                    self.path.display()
                );
            }
        }

        let mut overrides: RuntimeOverrides = serde_json::from_value(value).with_context(|| {
            format!("failed to parse runtime overrides {}", self.path.display())
        })?;
        if persisted_schema.is_none() {
            overrides.schema_version = CURRENT_RUNTIME_OVERRIDES_SCHEMA;
            overrides.revision = 0;
        }
        overrides.schema_version = CURRENT_RUNTIME_OVERRIDES_SCHEMA;
        overrides.validate_suppression()?;
        Ok(overrides)
    }

    pub async fn save(&self, overrides: &RuntimeOverrides) -> Result<()> {
        let parent = self.path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "runtime override path has no parent: {}",
                self.path.display()
            )
        })?;
        atomic_file::create_dir_all_durable_async(parent).await?;

        let mut content = serde_json::to_vec_pretty(&overrides.normalized()?)?;
        content.push(b'\n');

        atomic_file::replace_preserving_on_error_async(&self.path, &content, PRIVATE_FILE_MODE)
            .await
            .with_context(|| format!("failed to atomically replace {}", self.path.display()))
    }
}

#[cfg(test)]
mod tests;
