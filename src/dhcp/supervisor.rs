use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use nix::net::if_::if_nametoindex;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::config::{AppConfig, DhcpInterfaceConfig, InterfaceConfig, InterfaceRole};
use crate::dhcp::lease::{DhcpLease, LeaseManager, LeasePoolConfig};
use crate::dhcp::runtime::{
    DhcpRuntimeConfig, SharedDhcpRuntime, SharedDhcpService, SharedDhcpServices,
};
use crate::dhcp::server::{DhcpHandler, DhcpServerConfig};
use crate::dhcp::store::LeaseStore;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpServiceSpec {
    pub interface: String,
    pub server_ip: Ipv4Addr,
    pub prefix_len: u8,
    pub subnet_mask: Ipv4Addr,
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub router: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_seconds: u32,
}

impl DhcpServiceSpec {
    pub fn from_interface_config(
        interface: &str,
        config: &InterfaceConfig,
        default_lease_seconds: u32,
    ) -> Result<Option<Self>> {
        config.validate(interface)?;
        if default_lease_seconds == 0 {
            anyhow::bail!("DHCP default lease duration must be greater than zero");
        }

        if !config.managed || config.role != InterfaceRole::Output {
            return Ok(None);
        }
        let (Some(network), Some(dhcp)) = (config.ipv4, config.dhcp.as_ref()) else {
            return Ok(None);
        };

        let spec = Self {
            interface: interface.to_string(),
            server_ip: network.addr(),
            prefix_len: network.prefix_len(),
            subnet_mask: network.netmask(),
            pool_start: dhcp.pool_start,
            pool_end: dhcp.pool_end,
            router: dhcp.router,
            dns_servers: dhcp.dns_servers.clone(),
            lease_seconds: dhcp.lease_seconds.unwrap_or(default_lease_seconds),
        };
        spec.validate()?;
        Ok(Some(spec))
    }

    pub fn validate(&self) -> Result<()> {
        let network = ipnet::Ipv4Net::new(self.server_ip, self.prefix_len)?;
        if network.netmask() != self.subnet_mask {
            anyhow::bail!("DHCP subnet mask does not match prefix length");
        }
        let config = InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some(network),
            dhcp: Some(DhcpInterfaceConfig {
                pool_start: self.pool_start,
                pool_end: self.pool_end,
                router: self.router,
                dns_servers: self.dns_servers.clone(),
                lease_seconds: Some(self.lease_seconds),
            }),
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
            nat: true,
        };
        config.validate(&self.interface)
    }
}

#[derive(Clone)]
struct DhcpTask {
    spec: DhcpServiceSpec,
    ifindex: u32,
}

struct RuntimeTask {
    services: SharedDhcpServices,
    task: JoinHandle<()>,
}

#[derive(Clone)]
pub struct DhcpSupervisor {
    inner: Arc<Inner>,
}

struct Inner {
    leases_dir: PathBuf,
    tasks: Mutex<HashMap<String, DhcpTask>>,
    runtime: Mutex<Option<RuntimeTask>>,
    operation_lock: Mutex<()>,
}

impl DhcpSupervisor {
    pub fn service_specs(config: &AppConfig) -> Result<Vec<DhcpServiceSpec>> {
        config.validate()?;

        let mut specs = Vec::new();
        for (name, interface) in &config.network.interfaces {
            if let Some(spec) = DhcpServiceSpec::from_interface_config(
                name,
                interface,
                config.dhcp.default_lease_seconds,
            )? {
                specs.push(spec);
            }
        }
        Ok(specs)
    }

    /// One DHCP service per interface the configuration asks for.
    ///
    /// Derived purely from the configuration. This used to also take the
    /// persisted overrides and refuse to proceed when they disagreed — but the
    /// result was always this, and the map it checked against was itself
    /// derived from the same configuration.
    pub fn effective_specs(config: &AppConfig) -> Result<Vec<DhcpServiceSpec>> {
        let specs: BTreeMap<String, DhcpServiceSpec> = Self::service_specs(config)?
            .into_iter()
            .map(|spec| (spec.interface.clone(), spec))
            .collect();

        Ok(specs.into_values().collect())
    }

    pub async fn start(config: &AppConfig) -> Result<Self> {
        let supervisor = Self {
            inner: Arc::new(Inner {
                leases_dir: config.dhcp.leases_dir.clone(),
                tasks: Mutex::new(HashMap::new()),
                runtime: Mutex::new(None),
                operation_lock: Mutex::new(()),
            }),
        };

        for spec in Self::effective_specs(config)? {
            if resolve_interface_index(&spec.interface).is_err() {
                tracing::warn!(
                    interface = %spec.interface,
                    "configured DHCP interface is absent at startup; skipping it — \
                     the runtime reconcile loop will configure it if it reappears"
                );
                continue;
            }
            if let Err(error) = supervisor.configure(spec).await {
                supervisor.shutdown().await;
                return Err(error);
            }
        }

        Ok(supervisor)
    }

    pub async fn configure(&self, spec: DhcpServiceSpec) -> Result<()> {
        spec.validate()?;
        let _operation = self.inner.operation_lock.lock().await;
        let interface = spec.interface.clone();
        let service = service_from_spec(&spec, &self.inner.leases_dir).await?;
        let services = self.ensure_runtime_locked().await?;
        let ifindex = services
            .replace(&interface, service)
            .await
            .with_context(|| format!("failed to configure DHCP on {interface}"))?;

        // Do not publish the new intent if the shared runtime died while the
        // service was being registered.  The service map belongs to that dead
        // runtime and will be discarded by the next recovery attempt.
        self.require_runtime_alive(&interface).await?;

        let previous = self
            .inner
            .tasks
            .lock()
            .await
            .insert(interface.clone(), DhcpTask { spec, ifindex });

        // Close the small window between registration and publishing the task.
        // If the runtime died there, restore the previous intent so rollback or
        // liveness recovery can rebuild the exact pre-operation state.
        if let Err(error) = self.require_runtime_alive(&interface).await {
            let mut tasks = self.inner.tasks.lock().await;
            tasks.remove(&interface);
            if let Some(previous) = previous {
                tasks.insert(interface.clone(), previous);
            }
            return Err(error);
        }

        if let Some(previous) = previous.filter(|previous| previous.ifindex != ifindex) {
            services.remove(previous.ifindex).await;
        }
        tracing::info!(%interface, ifindex, "DHCP service configured");
        Ok(())
    }

    pub async fn disable(&self, interface: &str) -> Result<Option<DhcpServiceSpec>> {
        let _operation = self.inner.operation_lock.lock().await;
        let Some(task) = self.inner.tasks.lock().await.get(interface).cloned() else {
            return Ok(None);
        };
        if let Some(runtime) = self.inner.runtime.lock().await.as_ref() {
            runtime.services.remove(task.ifindex).await;
        }
        self.inner.tasks.lock().await.remove(interface);
        tracing::info!(%interface, "DHCP service disabled");
        Ok(Some(task.spec))
    }

    pub async fn binding_stale(&self, interface: &str) -> Result<bool> {
        let Some((_, task_ifindex)) = self
            .inner
            .tasks
            .lock()
            .await
            .get(interface)
            .map(|task| (task.spec.clone(), task.ifindex))
        else {
            return Ok(false);
        };
        Ok(resolve_interface_index(interface)? != task_ifindex)
    }

    pub async fn reconcile(&self, spec: DhcpServiceSpec) -> Result<()> {
        spec.validate()?;
        let current_ifindex = resolve_interface_index(&spec.interface)?;
        let current = self
            .inner
            .tasks
            .lock()
            .await
            .get(&spec.interface)
            .map(|task| (task.spec.clone(), task.ifindex));
        if current == Some((spec.clone(), current_ifindex)) {
            return Ok(());
        }
        self.configure(spec).await
    }

    pub async fn running_interfaces(&self) -> Vec<String> {
        let runtime_healthy = self
            .inner
            .runtime
            .lock()
            .await
            .as_ref()
            .is_some_and(|runtime| !runtime.task.is_finished());
        let mut interfaces: Vec<String> = if runtime_healthy {
            self.inner.tasks.lock().await.keys().cloned().collect()
        } else {
            Vec::new()
        };
        interfaces.sort();
        interfaces
    }

    pub async fn unhealthy_interfaces(&self) -> Vec<String> {
        let runtime_failed = self
            .inner
            .runtime
            .lock()
            .await
            .as_ref()
            .is_some_and(|runtime| runtime.task.is_finished());
        let mut interfaces: Vec<String> = if runtime_failed {
            self.inner.tasks.lock().await.keys().cloned().collect()
        } else {
            Vec::new()
        };
        interfaces.sort();
        interfaces
    }

    pub async fn spec(&self, interface: &str) -> Option<DhcpServiceSpec> {
        self.inner
            .tasks
            .lock()
            .await
            .get(interface)
            .map(|task| task.spec.clone())
    }

    pub async fn ensure_runtime_alive(&self) -> Result<bool> {
        let _operation = self.inner.operation_lock.lock().await;
        let has_tasks = !self.inner.tasks.lock().await.is_empty();
        let runtime_state = {
            let runtime = self.inner.runtime.lock().await;
            runtime.as_ref().map(|runtime| runtime.task.is_finished())
        };

        match (runtime_state, has_tasks) {
            (Some(false), _) | (None, false) => return Ok(false),
            (Some(true), false) => {
                if let Some(runtime) = self.inner.runtime.lock().await.take() {
                    let _ = runtime.task.await;
                }
                return Ok(false);
            }
            (Some(true), true) => {
                tracing::warn!("shared DHCP runtime task has stopped; restarting it");
            }
            (None, true) => {
                tracing::warn!("shared DHCP runtime is absent; rebuilding configured services");
            }
        }

        self.ensure_runtime_locked().await?;
        let restored = self.inner.tasks.lock().await.len();
        tracing::info!(restored, "shared DHCP runtime restarted");
        Ok(true)
    }

    pub async fn shutdown(&self) {
        let _operation = self.inner.operation_lock.lock().await;
        let tasks = std::mem::take(&mut *self.inner.tasks.lock().await);
        if let Some(runtime) = self.inner.runtime.lock().await.take() {
            runtime.task.abort();
            let _ = runtime.task.await;
        }
        for interface in tasks.keys() {
            tracing::info!(%interface, "DHCP service stopped");
        }
    }

    async fn ensure_runtime_locked(&self) -> Result<SharedDhcpServices> {
        let stale = {
            let mut slot = self.inner.runtime.lock().await;
            match slot.as_ref() {
                Some(runtime) if !runtime.task.is_finished() => {
                    return Ok(runtime.services.clone());
                }
                Some(_) => slot.take(),
                None => None,
            }
        };
        if let Some(runtime) = stale {
            let _ = runtime.task.await;
        }

        let previous_tasks = self.inner.tasks.lock().await.clone();
        let services = SharedDhcpServices::new();
        let mut rebound = HashMap::with_capacity(previous_tasks.len());

        // Rebuild the complete service map before exposing a replacement UDP
        // runtime. Starting the socket first would create a window where only
        // a subset of the pre-crash/pre-failure DHCP services can answer.
        for task in previous_tasks.values() {
            let spec = task.spec.clone();
            let interface = spec.interface.clone();
            let service = service_from_spec(&spec, &self.inner.leases_dir)
                .await
                .with_context(|| {
                    format!("failed to rebuild DHCP service on {interface}")
                })?;
            let ifindex = services
                .replace(&interface, service)
                .await
                .with_context(|| format!("failed to re-register DHCP service on {interface}"))?;
            rebound.insert(interface, DhcpTask { spec, ifindex });
        }

        let runtime = Self::spawn_runtime_with_services(services.clone())?;
        if runtime.task.is_finished() {
            let _ = runtime.task.await;
            anyhow::bail!(
                "shared DHCP runtime stopped while configured services were being restored"
            );
        }

        *self.inner.runtime.lock().await = Some(runtime);
        if !previous_tasks.is_empty() {
            *self.inner.tasks.lock().await = rebound;
        }
        Ok(services)
    }

    fn spawn_runtime_with_services(services: SharedDhcpServices) -> Result<RuntimeTask> {
        let runtime = SharedDhcpRuntime::bind(runtime_config(), services.clone())?;
        let task = tokio::spawn(async move {
            if let Err(error) = runtime.run().await {
                tracing::error!(%error, "shared DHCP runtime stopped with an error");
            }
        });
        Ok(RuntimeTask { services, task })
    }

    async fn require_runtime_alive(&self, interface: &str) -> Result<()> {
        let alive = self
            .inner
            .runtime
            .lock()
            .await
            .as_ref()
            .is_some_and(|runtime| !runtime.task.is_finished());
        if alive {
            Ok(())
        } else {
            anyhow::bail!("shared DHCP runtime stopped while configuring {interface}")
        }
    }
}

async fn service_from_spec(spec: &DhcpServiceSpec, leases_dir: &Path) -> Result<SharedDhcpService> {
    let interface = spec.interface.clone();
    let store = LeaseStore::for_interface(leases_dir, &interface);
    let stored_leases: Vec<DhcpLease> = store
        .load()
        .await
        .with_context(|| format!("failed to restore DHCP leases for {interface}"))?;
    let pool = LeasePoolConfig {
        start: spec.pool_start,
        end: spec.pool_end,
        lease_time: Duration::from_secs(u64::from(spec.lease_seconds)),
    };
    let leases = LeaseManager::restore(pool, stored_leases, current_unix_time())?;
    let restored_leases = leases.snapshot();
    let handler = DhcpHandler::new(
        DhcpServerConfig {
            server_ip: spec.server_ip,
            router: spec.router,
            subnet_mask: spec.subnet_mask,
            dns_servers: spec.dns_servers.clone(),
        },
        leases,
    );

    Ok(SharedDhcpService {
        handler,
        lease_store: store,
        server_ip: spec.server_ip,

        persisted_leases: restored_leases,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn resolve_interface_index(interface: &str) -> Result<u32> {
    if_nametoindex(interface)
        .with_context(|| format!("failed to resolve interface index for {interface}"))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn resolve_interface_index(interface: &str) -> Result<u32> {
    anyhow::bail!("resolving interface index is unsupported on this platform for {interface}")
}

fn runtime_config() -> DhcpRuntimeConfig {
    DhcpRuntimeConfig {
        interface: None,
        bind_address: Ipv4Addr::UNSPECIFIED,
        response_address: Ipv4Addr::BROADCAST,
        server_port: 67,
        client_port: 68,
        max_packet_size: 1500,
    }
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_starts_no_dhcp_services() {
        let specs = DhcpSupervisor::service_specs(&AppConfig::default()).expect("specs");
        assert!(specs.is_empty());
    }

    #[test]
    fn example_config_creates_wlan0_service() {
        let config: AppConfig = toml::from_str(include_str!("../../examples/config.toml"))
            .expect("example config should parse");
        let specs = DhcpSupervisor::service_specs(&config).expect("specs");

        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].interface, "wlan0");
        assert_eq!(specs[0].server_ip, Ipv4Addr::new(192, 168, 50, 1));
        assert_eq!(specs[0].prefix_len, 24);
        assert_eq!(specs[0].pool_start, Ipv4Addr::new(192, 168, 50, 100));
        assert_eq!(specs[0].pool_end, Ipv4Addr::new(192, 168, 50, 200));
        assert_eq!(specs[0].lease_seconds, 86_400);
    }

    #[test]
    fn service_spec_is_derived_from_the_complete_interface_config() {
        let config: AppConfig = toml::from_str(include_str!("../../examples/config.toml"))
            .expect("example config should parse");
        let interface = config
            .network
            .interfaces
            .get("wlan0")
            .expect("wlan0 config");

        let spec = DhcpServiceSpec::from_interface_config(
            "wlan0",
            interface,
            config.dhcp.default_lease_seconds,
        )
        .expect("valid service")
        .expect("DHCP should be enabled");

        assert_eq!(spec.server_ip, interface.ipv4.expect("IPv4").addr());
        assert_eq!(spec.router, spec.server_ip);
    }

    #[test]
    fn service_spec_is_absent_for_an_output_without_dhcp() {
        let interface = InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.44.1/24".parse().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
            nat: true,
        };

        assert!(
            DhcpServiceSpec::from_interface_config("lan0", &interface, 3600)
                .expect("valid interface")
                .is_none()
        );
    }

    #[tokio::test]
    async fn start_skips_absent_configured_dhcp_interface_instead_of_failing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = AppConfig::default();
        config.dhcp.leases_dir = temp.path().join("leases");
        config.network.interfaces.insert(
            "tm-test-absent0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some("192.168.77.1/24".parse().expect("network")),
                dhcp: Some(DhcpInterfaceConfig {
                    pool_start: Ipv4Addr::new(192, 168, 77, 10),
                    pool_end: Ipv4Addr::new(192, 168, 77, 100),
                    router: Ipv4Addr::new(192, 168, 77, 1),
                    dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
                    lease_seconds: Some(3_600),
                }),
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
                nat: true,
            },
        );

        let supervisor = DhcpSupervisor::start(&config)
            .await
            .expect("startup must tolerate a configured-but-absent DHCP interface");

        assert!(supervisor.spec("tm-test-absent0").await.is_none());
    }
}
