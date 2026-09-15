use std::collections::BTreeMap;
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

/// Version 3 records router commit identity atomically with committed intent.
/// Version 2 is readable; version 1 contained obsolete derived service maps.
pub const CURRENT_RUNTIME_OVERRIDES_SCHEMA: u32 = 3;

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
    #[serde(default)]
    pub interfaces: BTreeMap<String, InterfaceOverride>,
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
            interfaces: BTreeMap::new(),
        }
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
}

impl RuntimeOverrides {
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
        effective.validate()?;
        Ok(effective)
    }

    pub fn effective_network(&self, base: &NetworkConfig) -> Result<NetworkConfig> {
        let mut effective = base.clone();
        for (interface, value) in &self.interfaces {
            value.config.validate(interface)?;
            effective
                .interfaces
                .insert(interface.clone(), value.config.clone());
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

    pub async fn load(&self) -> Result<RuntimeOverrides> {
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
            if version != 2 && version != u64::from(CURRENT_RUNTIME_OVERRIDES_SCHEMA) {
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
        Ok(overrides)
    }

    pub async fn save(&self, overrides: &RuntimeOverrides) -> Result<()> {
        let parent = self.path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "runtime override path has no parent: {}",
                self.path.display()
            )
        })?;
        fs::create_dir_all(parent).await?;

        let mut content = serde_json::to_vec_pretty(overrides)?;
        content.push(b'\n');

        atomic_file::replace_async(&self.path, &content, PRIVATE_FILE_MODE)
            .await
            .with_context(|| format!("failed to atomically replace {}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{InterfaceRole, UplinkConfig, UplinkMode};

    use super::*;

    fn base_config() -> AppConfig {
        AppConfig::default()
    }

    /// The converger has no timer any more, so a change that does not announce
    /// itself is a change that never gets applied.
    fn interface_config(address: &str) -> InterfaceConfig {
        InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some(address.parse().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
            nat: true,
        }
    }

    /// A successful, self-contained mutation, for tests that need the store to
    /// change but do not care what changed. `set_dhcp` used to serve this role.

    #[test]
    fn effective_config_applies_api_override() {
        let mut base = base_config();
        base.api.tcp = Some(crate::config::TcpApiConfig {
            enabled: false,
            listen: "127.0.0.1:8443".parse().expect("socket address"),
            certificate_path: None,
            private_key_path: None,
        });

        let overrides = RuntimeOverrides {
            api: Some(ApiConfig {
                tcp: Some(crate::config::TcpApiConfig {
                    enabled: true,
                    listen: "192.0.2.10:9443".parse().expect("socket address"),
                    certificate_path: Some("/etc/traffic-masq/server.pem".into()),
                    private_key_path: Some("/etc/traffic-masq/server-key.pem".into()),
                }),
            }),
            ..RuntimeOverrides::default()
        };

        let effective = overrides.effective_config(&base).expect("effective config");
        let tcp = effective.api.tcp.expect("api tcp");
        assert!(tcp.enabled);
        assert_eq!(
            tcp.listen,
            "192.0.2.10:9443".parse().expect("socket address")
        );
    }

    #[test]
    fn effective_config_revalidates_router_against_interface_overrides() {
        let mut base = base_config();
        base.network.interfaces.insert(
            "wan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
                nat: true,
            },
        );
        base.network
            .interfaces
            .insert("lan0".to_string(), interface_config("192.168.10.1/24"));
        base.router.enabled = true;
        base.router.uplink = Some(UplinkConfig {
            interface: "wan0".to_string(),
            mode: UplinkMode::External,
        });
        base.validate().expect("base router config");

        let mut overrides = RuntimeOverrides::default();
        overrides.interfaces.insert(
            "wan0".to_string(),
            InterfaceOverride {
                config: InterfaceConfig {
                    role: InterfaceRole::None,
                    managed: false,
                    ipv4: None,
                    dhcp: None,
                    dhcp_client: None,
                    wifi: None,
                    wifi_client: None,
                    nat: true,
                },
                allow_management_change: true,
            },
        );

        assert!(overrides.effective_network(&base.network).is_ok());
        assert!(overrides.effective_config(&base).is_err());
    }
}
