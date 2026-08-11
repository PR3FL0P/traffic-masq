use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::config::{
    ApiConfig, AppConfig, InterfaceConfig, NetworkConfig, RouterConfig, SecurityConfig,
    VpnPolicyMode,
};
use crate::core::router::RouterDesired;
use crate::dhcp::supervisor::DhcpServiceSpec;
use crate::state::candidate::{RouterCandidate, RouterIntentProposal};
use crate::wifi::{WifiApSpec, WifiClientSpec};

pub const CURRENT_RUNTIME_OVERRIDES_SCHEMA: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOverrides {
    #[serde(default = "current_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub router: Option<RouterConfig>,
    #[serde(default)]
    pub api: Option<ApiConfig>,

    #[serde(default)]
    pub security: Option<SecurityConfig>,

    #[serde(default)]
    pub vpn_mode: Option<VpnPolicyMode>,
    #[serde(default)]
    pub dhcp: BTreeMap<String, DhcpOverride>,

    #[serde(default)]
    pub wifi: BTreeMap<String, WifiOverride>,

    #[serde(default)]
    pub wifi_client: BTreeMap<String, WifiClientOverride>,
    #[serde(default)]
    pub interfaces: BTreeMap<String, InterfaceOverride>,
}

impl Default for RuntimeOverrides {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_RUNTIME_OVERRIDES_SCHEMA,
            revision: 0,
            router: None,
            api: None,
            security: None,
            vpn_mode: None,
            dhcp: BTreeMap::new(),
            wifi: BTreeMap::new(),
            wifi_client: BTreeMap::new(),
            interfaces: BTreeMap::new(),
        }
    }
}

const fn current_schema_version() -> u32 {
    CURRENT_RUNTIME_OVERRIDES_SCHEMA
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DhcpOverride {
    Configured { spec: DhcpServiceSpec },
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WifiOverride {
    Configured { spec: WifiApSpec },
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WifiClientOverride {
    Configured { spec: WifiClientSpec },
    Disabled,
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

    pub fn normalized(&self, default_lease_seconds: u32) -> Result<Self> {
        let mut normalized = self.clone();
        normalized.schema_version = CURRENT_RUNTIME_OVERRIDES_SCHEMA;
        normalized.rebuild_derived_dhcp(default_lease_seconds)?;
        normalized.rebuild_derived_wifi()?;
        normalized.rebuild_derived_wifi_client()?;
        Ok(normalized)
    }

    fn rebuild_derived_dhcp(&mut self, default_lease_seconds: u32) -> Result<()> {
        for (interface, value) in &self.interfaces {
            let derived = DhcpServiceSpec::from_interface_config(
                interface,
                &value.config,
                default_lease_seconds,
            )?;
            self.dhcp.insert(
                interface.clone(),
                match derived {
                    Some(spec) => DhcpOverride::Configured { spec },
                    None => DhcpOverride::Disabled,
                },
            );
        }
        Ok(())
    }

    fn validate_derived_dhcp(&self, default_lease_seconds: u32) -> Result<()> {
        let mut canonical = self.clone();
        canonical.rebuild_derived_dhcp(default_lease_seconds)?;
        for interface in self.interfaces.keys() {
            if self.dhcp.get(interface) != canonical.dhcp.get(interface) {
                bail!("persisted DHCP override for {interface} is stale relative to its interface config");
            }
        }
        Ok(())
    }

    fn rebuild_derived_wifi(&mut self) -> Result<()> {
        for (interface, value) in &self.interfaces {
            let derived = WifiApSpec::from_interface_config(interface, &value.config)?;
            self.wifi.insert(
                interface.clone(),
                match derived {
                    Some(spec) => WifiOverride::Configured { spec },
                    None => WifiOverride::Disabled,
                },
            );
        }
        Ok(())
    }

    fn validate_derived_wifi(&self) -> Result<()> {
        let mut canonical = self.clone();
        canonical.rebuild_derived_wifi()?;
        for interface in self.interfaces.keys() {
            let Some(persisted) = self.wifi.get(interface) else {
                continue;
            };
            if Some(persisted) != canonical.wifi.get(interface) {
                bail!("persisted Wi-Fi override for {interface} is stale relative to its interface config");
            }
        }
        Ok(())
    }

    fn rebuild_derived_wifi_client(&mut self) -> Result<()> {
        for (interface, value) in &self.interfaces {
            let derived = WifiClientSpec::from_interface_config(interface, &value.config)?;
            self.wifi_client.insert(
                interface.clone(),
                match derived {
                    Some(spec) => WifiClientOverride::Configured { spec },
                    None => WifiClientOverride::Disabled,
                },
            );
        }
        Ok(())
    }

    fn validate_derived_wifi_client(&self) -> Result<()> {
        let mut canonical = self.clone();
        canonical.rebuild_derived_wifi_client()?;
        for interface in self.interfaces.keys() {
            let Some(persisted) = self.wifi_client.get(interface) else {
                continue;
            };
            if Some(persisted) != canonical.wifi_client.get(interface) {
                bail!("persisted Wi-Fi client override for {interface} is stale relative to its interface config");
            }
        }
        Ok(())
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
            if version != u64::from(CURRENT_RUNTIME_OVERRIDES_SCHEMA) {
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

        let content = serde_json::to_vec_pretty(overrides)?;
        let (temporary, mut file) = create_temporary_file(&self.path).await?;
        let save_result = async {
            file.write_all(&content).await?;
            file.write_all(b"\n").await?;
            file.flush().await?;
            file.sync_all().await?;
            drop(file);
            fs::rename(&temporary, &self.path)
                .await
                .with_context(|| format!("failed to atomically replace {}", self.path.display()))?;
            sync_parent_directory(parent).await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;

        if save_result.is_err() {
            let _ = fs::remove_file(&temporary).await;
        }
        save_result
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeOverrideManager {
    store: RuntimeOverrideStore,
    base: AppConfig,
    state: Arc<Mutex<RuntimeOverrides>>,
}

impl RuntimeOverrideManager {
    pub async fn load(state_dir: impl AsRef<Path>, base: &AppConfig) -> Result<Self> {
        let store = RuntimeOverrideStore::in_state_dir(state_dir);
        let state = store.load().await?;
        state
            .validate_derived_dhcp(base.dhcp.default_lease_seconds)
            .with_context(|| {
                format!(
                    "runtime overrides in {} contain inconsistent derived DHCP state",
                    store.path().display()
                )
            })?;
        state.validate_derived_wifi().with_context(|| {
            format!(
                "runtime overrides in {} contain inconsistent derived Wi-Fi state",
                store.path().display()
            )
        })?;
        state.validate_derived_wifi_client().with_context(|| {
            format!(
                "runtime overrides in {} contain inconsistent derived Wi-Fi client state",
                store.path().display()
            )
        })?;
        validate_candidate(&state, base).with_context(|| {
            format!(
                "runtime overrides in {} are invalid",
                store.path().display()
            )
        })?;
        Ok(Self {
            store,
            base: base.clone(),
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub async fn snapshot(&self) -> RuntimeOverrides {
        self.state.lock().await.clone()
    }

    pub async fn effective_interface(&self, interface: &str) -> Result<Option<InterfaceConfig>> {
        Ok(self
            .state
            .lock()
            .await
            .effective_config(&self.base)?
            .network
            .interfaces
            .get(interface)
            .cloned())
    }

    pub async fn committed_revision(&self) -> u64 {
        self.state.lock().await.revision
    }

    pub async fn effective_api_config(&self) -> Result<ApiConfig> {
        Ok(self.state.lock().await.effective_config(&self.base)?.api)
    }

    pub async fn effective_security_config(&self) -> Result<SecurityConfig> {
        Ok(self
            .state
            .lock()
            .await
            .effective_config(&self.base)?
            .security)
    }

    pub async fn effective_vpn_mode(&self) -> VpnPolicyMode {
        self.state
            .lock()
            .await
            .vpn_mode
            .unwrap_or(self.base.vpn.policy.default_mode)
    }

    pub async fn build_candidate(
        &self,
        proposal: &RouterIntentProposal,
    ) -> Result<RouterCandidate> {
        let state = self.state.lock().await;
        RouterCandidate::build(&self.base, &state, proposal)
    }

    pub async fn commit_candidate(&self, candidate: &RouterCandidate) -> Result<u64> {
        let mut state = self.state.lock().await;
        candidate.ensure_base_revision(state.revision)?;
        self.save_locked(&mut state, candidate.document().clone())
            .await?;
        Ok(state.revision)
    }

    pub async fn save_committed(&self, candidate: RuntimeOverrides) -> Result<()> {
        let mut state = self.state.lock().await;
        self.save_locked(&mut state, candidate).await
    }

    async fn save_locked(
        &self,
        state: &mut RuntimeOverrides,
        candidate: RuntimeOverrides,
    ) -> Result<()> {
        let mut candidate = candidate.normalized(self.base.dhcp.default_lease_seconds)?;
        validate_candidate(&candidate, &self.base)?;
        candidate.revision = state
            .revision
            .checked_add(1)
            .context("runtime override revision overflow")?;
        self.store.save(&candidate).await?;
        *state = candidate;
        Ok(())
    }

    pub async fn set_dhcp(&self, interface: String, value: DhcpOverride) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.dhcp.insert(interface, value);
        self.save_locked(&mut state, candidate).await
    }

    pub async fn set_api_config(&self, api: ApiConfig) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.api = Some(api);
        self.save_locked(&mut state, candidate).await
    }

    pub async fn clear_api_config(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.api = None;
        self.save_locked(&mut state, candidate).await
    }

    pub async fn set_security_config(&self, security: SecurityConfig) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.security = Some(security);
        self.save_locked(&mut state, candidate).await
    }

    pub async fn clear_security_config(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.security = None;
        self.save_locked(&mut state, candidate).await
    }

    pub async fn set_vpn_mode(&self, mode: VpnPolicyMode) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.vpn_mode = Some(mode);
        self.save_locked(&mut state, candidate).await
    }

    pub async fn clear_vpn_mode(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.vpn_mode = None;
        self.save_locked(&mut state, candidate).await
    }

    pub async fn set_interface(
        &self,
        interface: String,
        config: InterfaceConfig,
        allow_management_change: bool,
    ) -> Result<()> {
        config.validate(&interface)?;
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.interfaces.insert(
            interface,
            InterfaceOverride {
                config,
                allow_management_change,
            },
        );
        self.save_locked(&mut state, candidate).await
    }

    pub async fn check_interface(
        &self,
        interface: &str,
        config: &InterfaceConfig,
        allow_management_change: bool,
    ) -> Result<()> {
        config.validate(interface)?;
        let state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.interfaces.insert(
            interface.to_owned(),
            InterfaceOverride {
                config: config.clone(),
                allow_management_change,
            },
        );
        let candidate = candidate.normalized(self.base.dhcp.default_lease_seconds)?;
        validate_candidate(&candidate, &self.base)
    }

    pub fn path(&self) -> &Path {
        self.store.path()
    }
}

fn validate_candidate(candidate: &RuntimeOverrides, base: &AppConfig) -> Result<()> {
    let effective = candidate.effective_config(base)?;
    RouterDesired::from_effective_config(&effective)?;
    if candidate.vpn_mode == Some(VpnPolicyMode::Vpn) {
        if !effective.vpn.enabled {
            bail!("persisted vpn traffic policy mode \"vpn\" requires vpn.enabled = true");
        }
        if !effective.router.enabled {
            bail!("persisted vpn traffic policy mode \"vpn\" requires router.enabled = true");
        }
    }
    Ok(())
}

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

async fn create_temporary_file(path: &Path) -> Result<(PathBuf, File)> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("runtime-overrides.json");
    for _ in 0..100 {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = path.with_file_name(format!(
            ".{file_name}.tmp-{}-{sequence}",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        match options.open(&temporary).await {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to create temporary state file {}",
                        temporary.display()
                    )
                });
            }
        }
    }
    bail!("failed to allocate a unique temporary runtime override file")
}

#[cfg(unix)]
async fn sync_parent_directory(parent: &Path) -> Result<()> {
    File::open(parent)
        .await
        .with_context(|| format!("failed to open state directory {}", parent.display()))?
        .sync_all()
        .await
        .with_context(|| format!("failed to sync state directory {}", parent.display()))
}

#[cfg(not(unix))]
async fn sync_parent_directory(_parent: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tempfile::tempdir;

    use crate::config::{
        DhcpClientInterfaceConfig, DhcpInterfaceConfig, InterfaceRole, UplinkConfig, UplinkMode,
        WifiApConfig, WifiBand, WifiChannelWidth, WifiClientConfig, WifiClientSecurity,
        WifiSecurity,
    };

    use super::*;

    fn base_config() -> AppConfig {
        AppConfig::default()
    }

    fn interface_config(address: &str) -> InterfaceConfig {
        InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some(address.parse().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }
    }

    fn dhcp_interface_config(address: &str) -> InterfaceConfig {
        let mut config = interface_config(address);
        config.dhcp = Some(DhcpInterfaceConfig {
            pool_start: Ipv4Addr::new(192, 168, 10, 100),
            pool_end: Ipv4Addr::new(192, 168, 10, 200),
            router: Ipv4Addr::new(192, 168, 10, 1),
            dns_servers: Vec::new(),
            lease_seconds: Some(3600),
        });
        config
    }

    fn spec() -> DhcpServiceSpec {
        DhcpServiceSpec {
            interface: "wlan0".to_string(),
            server_ip: Ipv4Addr::new(192, 168, 10, 1),
            prefix_len: 24,
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            pool_start: Ipv4Addr::new(192, 168, 10, 100),
            pool_end: Ipv4Addr::new(192, 168, 10, 200),
            router: Ipv4Addr::new(192, 168, 10, 1),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
            lease_seconds: 3600,
        }
    }

    #[tokio::test]
    async fn loads_unversioned_legacy_document_as_revision_zero() {
        let directory = tempdir().expect("tempdir");
        let store = RuntimeOverrideStore::in_state_dir(directory.path());
        tokio::fs::write(
            store.path(),
            serde_json::to_vec(&serde_json::json!({
                "dhcp": {"wlan0": {"state": "configured", "spec": spec()}},
                "interfaces": {}
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        let manager = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .expect("legacy load");
        let state = manager.snapshot().await;
        assert_eq!(state.schema_version, CURRENT_RUNTIME_OVERRIDES_SCHEMA);
        assert_eq!(state.revision, 0);
        assert!(state.dhcp.contains_key("wlan0"));
    }

    #[tokio::test]
    async fn legacy_interface_override_without_dhcp_client_loads_unchanged() {
        let directory = tempdir().expect("tempdir");
        let store = RuntimeOverrideStore::in_state_dir(directory.path());
        tokio::fs::write(
            store.path(),
            br#"{
                "schema_version": 1,
                "dhcp": {"wan0": {"state": "disabled"}},
                "interfaces": {
                    "wan0": {
                        "config": {
                            "role": "input",
                            "managed": false,
                            "ipv4": null,
                            "dhcp": null,
                            "wifi": null,
                            "wifi_client": null
                        }
                    }
                }
            }"#,
        )
        .await
        .unwrap();

        let restored = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .expect("legacy override")
            .snapshot()
            .await;
        assert!(restored.interfaces["wan0"].config.dhcp_client.is_none());
    }

    #[tokio::test]
    async fn dhcp_client_interface_override_normalizes_saves_and_round_trips() {
        let directory = tempdir().expect("tempdir");
        let base = base_config();
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();
        let mut interface = InterfaceConfig {
            role: InterfaceRole::Input,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: Some(DhcpClientInterfaceConfig {
                route_metric: 250,
                install_default_route: false,
                request_dns: false,
                send_release_on_shutdown: true,
                ..DhcpClientInterfaceConfig::default()
            }),
            wifi: None,
            wifi_client: None,
        };
        manager
            .set_interface("wan0".into(), interface.clone(), false)
            .await
            .unwrap();

        let restored = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap()
            .snapshot()
            .await;
        assert_eq!(restored.interfaces["wan0"].config, interface);

        interface.dhcp_client.as_mut().unwrap().enabled = false;
        let normalized = RuntimeOverrides {
            interfaces: BTreeMap::from([(
                "wan0".into(),
                InterfaceOverride {
                    config: interface.clone(),
                    allow_management_change: false,
                },
            )]),
            ..RuntimeOverrides::default()
        }
        .normalized(base.dhcp.default_lease_seconds)
        .unwrap();
        assert_eq!(normalized.interfaces["wan0"].config, interface);
    }

    #[tokio::test]
    async fn current_document_saves_and_reloads() {
        let directory = tempdir().expect("tempdir");
        let base = base_config();
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();
        manager
            .set_dhcp("wlan0".into(), DhcpOverride::Configured { spec: spec() })
            .await
            .unwrap();

        let restored = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap()
            .snapshot()
            .await;
        assert_eq!(restored.schema_version, CURRENT_RUNTIME_OVERRIDES_SCHEMA);
        assert_eq!(restored.revision, 1);
        assert!(restored.dhcp.contains_key("wlan0"));
    }

    #[tokio::test]
    async fn api_override_saves_and_reloads() {
        let directory = tempdir().expect("tempdir");
        let base = base_config();
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();
        manager
            .set_api_config(ApiConfig {
                tcp: Some(crate::config::TcpApiConfig {
                    enabled: true,
                    listen: "0.0.0.0:9443".parse().expect("socket address"),
                    certificate_path: Some("/etc/traffic-masq/server.pem".into()),
                    private_key_path: Some("/etc/traffic-masq/server-key.pem".into()),
                }),
            })
            .await
            .unwrap();

        let restored = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap()
            .snapshot()
            .await;
        assert_eq!(restored.revision, 1);
        assert_eq!(
            restored.api,
            Some(ApiConfig {
                tcp: Some(crate::config::TcpApiConfig {
                    enabled: true,
                    listen: "0.0.0.0:9443".parse().expect("socket address"),
                    certificate_path: Some("/etc/traffic-masq/server.pem".into()),
                    private_key_path: Some("/etc/traffic-masq/server-key.pem".into()),
                }),
            })
        );
    }

    #[tokio::test]
    async fn security_override_saves_reloads_and_can_be_cleared() {
        let directory = tempdir().expect("tempdir");
        let base = base_config();
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();

        assert_eq!(
            manager.effective_security_config().await.unwrap(),
            base.security
        );

        manager
            .set_security_config(crate::config::SecurityConfig {
                rollback_timeout_seconds: 120,
            })
            .await
            .unwrap();
        assert_eq!(
            manager
                .effective_security_config()
                .await
                .unwrap()
                .rollback_timeout_seconds,
            120
        );

        let restored = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();
        assert_eq!(
            restored
                .effective_security_config()
                .await
                .unwrap()
                .rollback_timeout_seconds,
            120
        );

        restored.clear_security_config().await.unwrap();
        assert_eq!(
            restored.effective_security_config().await.unwrap(),
            base.security
        );
    }

    #[tokio::test]
    async fn security_override_rejects_zero_rollback_timeout() {
        let directory = tempdir().expect("tempdir");
        let base = base_config();
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();

        let error = manager
            .set_security_config(crate::config::SecurityConfig {
                rollback_timeout_seconds: 0,
            })
            .await
            .expect_err("zero rollback timeout must be rejected");
        assert!(error.to_string().contains("rollback_timeout_seconds"));
        assert_eq!(
            manager.effective_security_config().await.unwrap(),
            base.security
        );
    }

    #[tokio::test]
    async fn vpn_mode_defaults_to_base_config_and_can_be_overridden_and_cleared() {
        let directory = tempdir().expect("tempdir");
        let mut base = base_config();
        base.network.interfaces.insert(
            "wan0".into(),
            InterfaceConfig {
                role: InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
        base.network
            .interfaces
            .insert("lan0".into(), interface_config("192.168.10.1/24"));
        base.vpn.enabled = true;
        base.router = RouterConfig {
            enabled: true,
            uplink: Some(UplinkConfig {
                interface: "wan0".into(),
                mode: UplinkMode::External,
            }),
            ..RouterConfig::default()
        };
        base.validate().expect("base config");
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();

        assert_eq!(
            manager.effective_vpn_mode().await,
            crate::config::VpnPolicyMode::Direct
        );

        manager
            .set_vpn_mode(crate::config::VpnPolicyMode::Vpn)
            .await
            .unwrap();
        assert_eq!(
            manager.effective_vpn_mode().await,
            crate::config::VpnPolicyMode::Vpn
        );

        let restored = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();
        assert_eq!(
            restored.effective_vpn_mode().await,
            crate::config::VpnPolicyMode::Vpn
        );

        manager.clear_vpn_mode().await.unwrap();
        assert_eq!(
            manager.effective_vpn_mode().await,
            crate::config::VpnPolicyMode::Direct
        );
    }

    #[tokio::test]
    async fn set_vpn_mode_vpn_is_rejected_without_vpn_enabled_or_router_enabled() {
        let directory = tempdir().expect("tempdir");
        let base = base_config();
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();

        let error = manager
            .set_vpn_mode(crate::config::VpnPolicyMode::Vpn)
            .await
            .expect_err("vpn disabled and router disabled");
        assert!(error.to_string().contains("vpn.enabled = true"));
        assert_eq!(
            manager.effective_vpn_mode().await,
            crate::config::VpnPolicyMode::Direct
        );
    }

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

    #[tokio::test]
    async fn rejects_future_schema_version() {
        let directory = tempdir().expect("tempdir");
        let store = RuntimeOverrideStore::in_state_dir(directory.path());
        tokio::fs::write(store.path(), br#"{"schema_version":2,"revision":0}"#)
            .await
            .unwrap();

        let error = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .expect_err("future schema");
        assert!(error.to_string().contains("future schema version 2"));
    }

    #[tokio::test]
    async fn router_and_interface_conflict_is_rejected_without_state_change() {
        let directory = tempdir().expect("tempdir");
        let mut base = base_config();
        base.network.interfaces.insert(
            "wan0".into(),
            InterfaceConfig {
                role: InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
        base.network
            .interfaces
            .insert("lan0".into(), interface_config("192.168.10.1/24"));
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();
        let mut candidate = manager.snapshot().await;
        candidate.router = Some(RouterConfig {
            enabled: true,
            uplink: Some(UplinkConfig {
                interface: "wan0".into(),
                mode: UplinkMode::External,
            }),
            ..RouterConfig::default()
        });
        candidate.interfaces.insert(
            "wan0".into(),
            InterfaceOverride {
                config: InterfaceConfig {
                    role: InterfaceRole::Management,
                    managed: false,
                    ipv4: None,
                    dhcp: None,
                    dhcp_client: None,
                    wifi: None,
                    wifi_client: None,
                },
                allow_management_change: true,
            },
        );

        manager
            .save_committed(candidate)
            .await
            .expect_err("router conflict");
        assert_eq!(manager.snapshot().await.revision, 0);
        assert!(!manager.path().exists());
    }

    #[tokio::test]
    async fn rejects_stale_persisted_derived_dhcp() {
        let directory = tempdir().expect("tempdir");
        let store = RuntimeOverrideStore::in_state_dir(directory.path());
        let mut state = RuntimeOverrides::default();
        state.interfaces.insert(
            "wlan0".into(),
            InterfaceOverride {
                config: dhcp_interface_config("192.168.10.1/24"),
                allow_management_change: false,
            },
        );
        state.dhcp.insert("wlan0".into(), DhcpOverride::Disabled);
        store.save(&state).await.unwrap();

        let error = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .expect_err("stale DHCP");
        assert!(format!("{error:#}").contains("stale relative"));
    }

    #[tokio::test]
    async fn save_rebuilds_derived_dhcp_deterministically() {
        let directory = tempdir().expect("tempdir");
        let base = base_config();
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();
        let mut candidate = manager.snapshot().await;
        candidate.interfaces.insert(
            "wlan0".into(),
            InterfaceOverride {
                config: dhcp_interface_config("192.168.10.1/24"),
                allow_management_change: false,
            },
        );
        candidate
            .dhcp
            .insert("wlan0".into(), DhcpOverride::Disabled);
        manager.save_committed(candidate).await.unwrap();

        let state = manager.snapshot().await;
        let DhcpOverride::Configured { spec } = state.dhcp.get("wlan0").unwrap() else {
            panic!("derived DHCP must be rebuilt");
        };
        assert_eq!(spec.server_ip, Ipv4Addr::new(192, 168, 10, 1));
    }

    #[tokio::test]
    async fn invalid_candidate_leaves_file_state_and_revision_unchanged() {
        let directory = tempdir().expect("tempdir");
        let mut base = base_config();
        base.network
            .interfaces
            .insert("wlan0".into(), interface_config("192.168.10.1/24"));
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();
        manager
            .set_dhcp("wlan0".into(), DhcpOverride::Configured { spec: spec() })
            .await
            .unwrap();
        let before_state = manager.snapshot().await;
        let before_file = tokio::fs::read(manager.path()).await.unwrap();

        let error = manager
            .set_interface("usb0".into(), interface_config("192.168.10.2/25"), false)
            .await
            .expect_err("overlap");
        assert!(error.to_string().contains("overlap"));
        assert_eq!(manager.snapshot().await, before_state);
        assert_eq!(tokio::fs::read(manager.path()).await.unwrap(), before_file);
    }

    #[tokio::test]
    async fn failed_file_save_does_not_publish_state_or_revision() {
        let directory = tempdir().expect("tempdir");
        let base = base_config();
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .expect("manager");
        tokio::fs::create_dir(manager.path())
            .await
            .expect("conflicting target directory");
        let before = manager.snapshot().await;

        manager
            .set_dhcp("wlan0".into(), DhcpOverride::Configured { spec: spec() })
            .await
            .expect_err("rename over directory must fail");

        assert_eq!(manager.snapshot().await, before);
        assert_eq!(manager.snapshot().await.revision, 0);
        assert!(manager.path().is_dir());
    }

    #[tokio::test]
    async fn revision_increments_only_for_successful_saves() {
        let directory = tempdir().expect("tempdir");
        let mut base = base_config();
        base.network
            .interfaces
            .insert("wlan0".into(), interface_config("192.168.10.1/24"));
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();

        manager
            .set_dhcp("wlan0".into(), DhcpOverride::Configured { spec: spec() })
            .await
            .unwrap();
        assert_eq!(manager.snapshot().await.revision, 1);
        manager
            .set_interface("usb0".into(), interface_config("192.168.10.2/25"), false)
            .await
            .expect_err("invalid save");
        assert_eq!(manager.snapshot().await.revision, 1);
        manager
            .set_dhcp("usb0".into(), DhcpOverride::Disabled)
            .await
            .unwrap();
        assert_eq!(manager.snapshot().await.revision, 2);
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
                    role: InterfaceRole::Management,
                    managed: false,
                    ipv4: None,
                    dhcp: None,
                    dhcp_client: None,
                    wifi: None,
                    wifi_client: None,
                },
                allow_management_change: true,
            },
        );

        assert!(overrides.effective_network(&base.network).is_ok());
        assert!(overrides.effective_config(&base).is_err());
    }

    #[tokio::test]
    async fn candidate_commit_advances_revision_and_rejects_a_stale_candidate() {
        let directory = tempdir().expect("tempdir");
        let mut base = base_config();
        base.network.interfaces.insert(
            "wan0".into(),
            InterfaceConfig {
                role: InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
        base.network
            .interfaces
            .insert("lan0".into(), dhcp_interface_config("192.168.10.1/24"));
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();

        let router = RouterConfig {
            enabled: true,
            uplink: Some(UplinkConfig {
                interface: "wan0".into(),
                mode: UplinkMode::External,
            }),
            ..RouterConfig::default()
        };
        let candidate = manager
            .build_candidate(&RouterIntentProposal::new().set_router(router.clone()))
            .await
            .expect("candidate");
        assert_eq!(candidate.base_revision(), 0);

        assert_eq!(manager.commit_candidate(&candidate).await.unwrap(), 1);
        assert_eq!(manager.committed_revision().await, 1);
        assert!(manager.snapshot().await.router.is_some());

        let committed_state = manager.snapshot().await;
        let committed_file = tokio::fs::read(manager.path()).await.unwrap();
        let error = manager
            .commit_candidate(&candidate)
            .await
            .expect_err("stale candidate must not be saved");
        assert!(format!("{error:#}").contains("stale"));
        assert_eq!(manager.snapshot().await, committed_state);
        assert_eq!(
            tokio::fs::read(manager.path()).await.unwrap(),
            committed_file
        );
    }

    #[tokio::test]
    async fn candidate_rebuilt_on_current_state_commits_again() {
        let directory = tempdir().expect("tempdir");
        let base = base_config();
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();

        for expected_revision in 1..=2 {
            let candidate = manager
                .build_candidate(&RouterIntentProposal::new().set_interface(
                    format!("lan{expected_revision}"),
                    interface_config(&format!("192.168.{expected_revision}.1/24")),
                    false,
                ))
                .await
                .expect("candidate");
            assert_eq!(candidate.base_revision(), expected_revision - 1);
            assert_eq!(
                manager.commit_candidate(&candidate).await.unwrap(),
                expected_revision
            );
        }
        assert_eq!(manager.snapshot().await.interfaces.len(), 2);
    }

    #[tokio::test]
    async fn concurrent_updates_do_not_lose_overrides() {
        let directory = tempdir().expect("tempdir");
        let manager = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .unwrap();
        let first = manager.clone();
        let second = manager.clone();
        let mut second_spec = spec();
        second_spec.interface = "usb0".into();

        let (first_result, second_result) = tokio::join!(
            first.set_dhcp("wlan0".into(), DhcpOverride::Configured { spec: spec() }),
            second.set_dhcp(
                "usb0".into(),
                DhcpOverride::Configured { spec: second_spec }
            )
        );
        first_result.unwrap();
        second_result.unwrap();
        let state = manager.snapshot().await;
        assert_eq!(state.revision, 2);
        assert_eq!(state.dhcp.len(), 2);
    }

    #[tokio::test]
    async fn malformed_override_file_reports_its_path() {
        let directory = tempdir().expect("tempdir");
        let store = RuntimeOverrideStore::in_state_dir(directory.path());
        tokio::fs::write(store.path(), b"not valid json")
            .await
            .expect("write malformed state");

        let error = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .expect_err("malformed state must fail");
        let message = format!("{error:#}");
        assert!(message.contains("failed to parse runtime overrides"));
        assert!(message.contains("runtime-overrides.json"));
    }

    fn wifi_interface_config(address: &str) -> InterfaceConfig {
        let mut config = interface_config(address);
        config.wifi = Some(WifiApConfig {
            ssid: "traffic-masq".to_string(),
            country_code: Some("PL".to_string()),
            band: WifiBand::Ghz2,
            channel: 6,
            channel_width: WifiChannelWidth::Ht20,
            security: WifiSecurity::Wpa2,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
            passphrase_file: None,
        });
        config
    }

    #[tokio::test]
    async fn saving_an_interface_override_derives_its_wifi_section() {
        let directory = tempdir().expect("tempdir");
        let manager = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .expect("load");

        manager
            .set_interface(
                "wlan0".into(),
                wifi_interface_config("192.168.10.1/24"),
                false,
            )
            .await
            .expect("save");

        let state = manager.snapshot().await;
        let WifiOverride::Configured { spec } = state.wifi.get("wlan0").expect("derived wifi")
        else {
            panic!("an interface with a wifi block must derive a configured AP");
        };
        assert_eq!(spec.interface, "wlan0");
        assert_eq!(spec.ssid, "traffic-masq");

        manager
            .set_interface("lan0".into(), interface_config("192.168.20.1/24"), false)
            .await
            .expect("save");
        assert_eq!(
            manager.snapshot().await.wifi.get("lan0"),
            Some(&WifiOverride::Disabled)
        );
    }

    #[tokio::test]
    async fn a_document_predating_the_wifi_section_still_loads() {
        let directory = tempdir().expect("tempdir");
        let store = RuntimeOverrideStore::in_state_dir(directory.path());

        tokio::fs::write(
            store.path(),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": CURRENT_RUNTIME_OVERRIDES_SCHEMA,
                "revision": 7,
                "dhcp": {"wlan0": {"state": "configured", "spec": spec()}},
                "interfaces": {}
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        let manager = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .expect("pre-wifi document loads");
        let state = manager.snapshot().await;
        assert_eq!(state.revision, 7);
        assert!(state.wifi.is_empty());
    }

    #[tokio::test]
    async fn a_wifi_section_contradicting_its_interface_is_rejected_at_load() {
        let directory = tempdir().expect("tempdir");
        let store = RuntimeOverrideStore::in_state_dir(directory.path());
        let mut document = RuntimeOverrides::default();
        document.interfaces.insert(
            "wlan0".into(),
            InterfaceOverride {
                config: wifi_interface_config("192.168.10.1/24"),
                allow_management_change: false,
            },
        );
        document.dhcp.insert("wlan0".into(), DhcpOverride::Disabled);

        document.wifi.insert("wlan0".into(), WifiOverride::Disabled);
        tokio::fs::write(store.path(), serde_json::to_vec(&document).unwrap())
            .await
            .unwrap();

        let error = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .expect_err("inconsistent derived wifi must fail");
        let message = format!("{error:#}");
        assert!(
            message.contains("inconsistent derived Wi-Fi state"),
            "{message}"
        );
    }

    fn wifi_client_interface_config(ssid: &str) -> InterfaceConfig {
        InterfaceConfig {
            role: InterfaceRole::Input,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: Some(WifiClientConfig {
                ssid: ssid.to_string(),
                country_code: Some("PL".to_string()),
                security: WifiClientSecurity::Wpa2,
                passphrase_file: None,
            }),
        }
    }

    #[tokio::test]
    async fn saving_an_interface_override_derives_its_wifi_client_section() {
        let directory = tempdir().expect("tempdir");
        let manager = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .expect("load");

        manager
            .set_interface(
                "wlan1".into(),
                wifi_client_interface_config("upstream-network"),
                false,
            )
            .await
            .expect("save");

        let state = manager.snapshot().await;
        let WifiClientOverride::Configured { spec } =
            state.wifi_client.get("wlan1").expect("derived wifi client")
        else {
            panic!("an interface with a wifi_client block must derive a configured association");
        };
        assert_eq!(spec.interface, "wlan1");
        assert_eq!(spec.ssid, "upstream-network");

        assert_eq!(state.wifi.get("wlan1"), Some(&WifiOverride::Disabled));

        manager
            .set_interface("lan0".into(), interface_config("192.168.20.1/24"), false)
            .await
            .expect("save");
        assert_eq!(
            manager.snapshot().await.wifi_client.get("lan0"),
            Some(&WifiClientOverride::Disabled)
        );
    }

    #[tokio::test]
    async fn a_document_predating_the_derived_wifi_sections_still_loads() {
        let directory = tempdir().expect("tempdir");
        let store = RuntimeOverrideStore::in_state_dir(directory.path());

        let document = RuntimeOverrides {
            interfaces: BTreeMap::from([(
                "wlan0".to_string(),
                InterfaceOverride {
                    config: wifi_interface_config("192.168.10.1/24"),
                    allow_management_change: false,
                },
            )]),
            ..RuntimeOverrides::default()
        }
        .normalized(base_config().dhcp.default_lease_seconds)
        .expect("normalize");
        let mut value = serde_json::to_value(&document).expect("serialize");
        let object = value.as_object_mut().expect("object");
        for key in ["wifi", "wifi_client"] {
            object.remove(key).expect("the key is there to be stripped");
        }
        assert!(object.contains_key("dhcp"), "the DHCP half must survive");
        tokio::fs::write(store.path(), serde_json::to_vec(&value).unwrap())
            .await
            .unwrap();

        let manager = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .expect("a document predating both Wi-Fi maps loads");
        let state = manager.snapshot().await;
        assert!(state.interfaces.contains_key("wlan0"));
        assert!(state.wifi.is_empty());
        assert!(state.wifi_client.is_empty());
    }

    #[tokio::test]
    async fn a_wifi_client_section_contradicting_its_interface_is_rejected_at_load() {
        let directory = tempdir().expect("tempdir");
        let store = RuntimeOverrideStore::in_state_dir(directory.path());
        let mut document = RuntimeOverrides::default();
        document.interfaces.insert(
            "wlan1".into(),
            InterfaceOverride {
                config: wifi_client_interface_config("upstream-network"),
                allow_management_change: false,
            },
        );
        document.dhcp.insert("wlan1".into(), DhcpOverride::Disabled);
        document.wifi.insert("wlan1".into(), WifiOverride::Disabled);

        document
            .wifi_client
            .insert("wlan1".into(), WifiClientOverride::Disabled);
        tokio::fs::write(store.path(), serde_json::to_vec(&document).unwrap())
            .await
            .unwrap();

        let error = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .expect_err("inconsistent derived wifi client must fail");
        let message = format!("{error:#}");
        assert!(
            message.contains("inconsistent derived Wi-Fi client state"),
            "{message}"
        );
    }
}
