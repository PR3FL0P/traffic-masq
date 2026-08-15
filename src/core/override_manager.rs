//! The runtime override manager: the single writer of persisted intent.
//!
//! Lives in `core` rather than beside the document it writes, because every
//! write path here is gated on a domain question — "can this configuration
//! actually be realised as a router intent?" — answered by
//! [`RouterDesired::from_effective_config`]. Keeping the manager in `state`
//! meant the storage module had to import the domain to validate, and the
//! domain had to import storage to use it: a cycle at the bottom of the stack.
//!
//! `state` now holds only the document and its store; deciding what may be
//! written is this module's job.

use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::sync::{Mutex, Notify};

use crate::config::{ApiConfig, AppConfig, InterfaceConfig, SecurityConfig, VpnPolicyMode};
use crate::core::router::RouterDesired;
use crate::core::router_candidate::{RouterCandidate, RouterIntentProposal};
use crate::state::overrides::{InterfaceOverride, RuntimeOverrideStore, RuntimeOverrides};

#[derive(Debug, Clone)]
pub struct RuntimeOverrideManager {
    store: RuntimeOverrideStore,
    base: AppConfig,
    state: Arc<Mutex<RuntimeOverrides>>,
    /// Fires whenever the overrides change.
    ///
    /// The desired state just moved, so whoever converges the machine towards
    /// it has to look again. Without this the only way to notice would be to
    /// ask on a timer, which is the latency this daemon is trying not to have.
    changed: Arc<Notify>,
}

impl RuntimeOverrideManager {
    pub async fn load(state_dir: impl AsRef<Path>, base: &AppConfig) -> Result<Self> {
        let store = RuntimeOverrideStore::in_state_dir(state_dir);
        let state = store.load().await?;
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
            changed: Arc::new(Notify::new()),
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
        let mut candidate = candidate.normalized()?;
        validate_candidate(&candidate, &self.base)?;
        candidate.revision = state
            .revision
            .checked_add(1)
            .context("runtime override revision overflow")?;
        self.store.save(&candidate).await?;
        *state = candidate;
        // Every mutation funnels through here, so this is the one place that
        // has to announce that the desired state moved.
        self.changed.notify_waiters();
        Ok(())
    }

    /// Wait until the overrides change.
    ///
    /// Uses `notify_waiters`, so a change that happens while nobody is waiting
    /// is not buffered. That is the correct semantics for a converger: it reads
    /// the current state when it runs, so it only needs to know that *something*
    /// moved since it last looked, and it looks once before it starts waiting.
    pub async fn changed(&self) {
        self.changed.notified().await;
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
        let candidate = candidate.normalized()?;
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tempfile::tempdir;

    use std::collections::BTreeMap;

    use crate::config::{
        DhcpClientInterfaceConfig, DhcpInterfaceConfig, InterfaceRole, RouterConfig, UplinkConfig,
        UplinkMode,
    };
    use crate::state::overrides::CURRENT_RUNTIME_OVERRIDES_SCHEMA;

    use super::*;

    fn base_config() -> AppConfig {
        AppConfig::default()
    }

    /// The converger has no timer any more, so a change that does not announce
    /// itself is a change that never gets applied.

    #[tokio::test]
    async fn writing_an_override_wakes_whoever_is_waiting_for_a_change() {
        let directory = tempdir().expect("tempdir");
        let base = base_config();
        let manager = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .expect("overrides");

        let waiter = {
            let manager = manager.clone();
            tokio::spawn(async move { manager.changed().await })
        };
        // Let the waiter reach the wait before the change happens: `changed`
        // deliberately does not buffer, because the converger reads current
        // state and only needs to know that something moved.
        tokio::task::yield_now().await;

        manager
            .set_interface(
                "lan0".to_string(),
                interface_config("192.168.30.1/24"),
                false,
            )
            .await
            .expect("set interface");

        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("an override write must wake the converger")
            .expect("waiter task");
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

    /// A successful, self-contained mutation, for tests that need the store to
    /// change but do not care what changed. `set_dhcp` used to serve this role.

    fn api_override(port: u16) -> ApiConfig {
        ApiConfig {
            tcp: Some(crate::config::TcpApiConfig {
                enabled: true,
                listen: format!("0.0.0.0:{port}").parse().expect("socket address"),
                certificate_path: Some("/etc/traffic-masq/server.pem".into()),
                private_key_path: Some("/etc/traffic-masq/server-key.pem".into()),
            }),
        }
    }

    #[tokio::test]
    async fn loads_unversioned_legacy_document_as_revision_zero() {
        let directory = tempdir().expect("tempdir");
        let store = RuntimeOverrideStore::in_state_dir(directory.path());
        tokio::fs::write(
            store.path(),
            serde_json::to_vec(&serde_json::json!({
                "api": {"tcp": null},
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
        assert_eq!(state.api, Some(ApiConfig { tcp: None }));
    }

    #[tokio::test]
    async fn legacy_interface_override_without_dhcp_client_loads_unchanged() {
        let directory = tempdir().expect("tempdir");
        let store = RuntimeOverrideStore::in_state_dir(directory.path());
        tokio::fs::write(
            store.path(),
            br#"{
                "schema_version": 2,
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
        .normalized()
        .unwrap();
        assert_eq!(normalized.interfaces["wan0"].config, interface);
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

    #[tokio::test]
    async fn rejects_future_schema_version() {
        let directory = tempdir().expect("tempdir");
        let store = RuntimeOverrideStore::in_state_dir(directory.path());
        tokio::fs::write(store.path(), br#"{"schema_version":3,"revision":0}"#)
            .await
            .unwrap();

        let error = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .expect_err("future schema");
        assert!(error.to_string().contains("future schema version 3"));
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
            .set_api_config(api_override(9443))
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
            .set_api_config(api_override(9443))
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
            .set_api_config(api_override(9443))
            .await
            .unwrap();
        assert_eq!(manager.snapshot().await.revision, 1);
        manager
            .set_interface("usb0".into(), interface_config("192.168.10.2/25"), false)
            .await
            .expect_err("invalid save");
        assert_eq!(manager.snapshot().await.revision, 1);
        manager
            .set_api_config(api_override(9444))
            .await
            .unwrap();
        assert_eq!(manager.snapshot().await.revision, 2);
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
        let (first_result, second_result) = tokio::join!(
            first.set_interface("wlan0".into(), interface_config("192.168.10.1/24"), false),
            second.set_interface("usb0".into(), interface_config("192.168.20.1/24"), false)
        );
        first_result.unwrap();
        second_result.unwrap();
        let state = manager.snapshot().await;
        assert_eq!(state.revision, 2);
        assert_eq!(state.interfaces.len(), 2);
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
}
