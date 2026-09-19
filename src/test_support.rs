use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::netlink::{
    AddressOwnership, Ipv4AddressInfo, Ipv4RouteInfo, Ipv4RouteSpec, Ipv4RuleInfo, Ipv4RuleSpec,
    NetworkInterface, NetworkProvider,
};
use crate::vpn::wireguard::{WireGuardKey, WireGuardPeerConfig};
use crate::vpn::{ProviderError, VpnProvider};
use crate::wifi::process::{ProcessError, SupervisedProcess};


#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FakeProcessCall {
    Spawn(PathBuf),
    Terminate(u32),
    Kill(u32),
}

type ResponderFactory<R> = dyn Fn(&str, &Path, &str) -> R + Send + Sync;

/// Process fake shared by Wi-Fi AP/client supervisor tests. The responder
/// factory is the only daemon-specific piece: hostapd and wpa_supplicant use
/// the same process ownership, failure, termination, and call-recording model.
pub(crate) struct FakeSupervisedProcess<R: Send + 'static> {
    configs: StdMutex<HashMap<u32, PathBuf>>,
    responders: StdMutex<HashMap<u32, R>>,
    calls: StdMutex<Vec<FakeProcessCall>>,
    next_pid: AtomicU32,
    binary_name: &'static str,
    spawn_profile: StdMutex<String>,
    responder_factory: Box<ResponderFactory<R>>,
    pub(crate) fail_spawn: AtomicBool,
    pub(crate) suppress_spawn_responder: AtomicBool,
    pub(crate) persistent_responder: AtomicBool,
}

impl<R: Send + 'static> FakeSupervisedProcess<R> {
    pub(crate) fn new(
        binary_name: &'static str,
        first_pid: u32,
        spawn_profile: &str,
        responder_factory: impl Fn(&str, &Path, &str) -> R + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            configs: StdMutex::new(HashMap::new()),
            responders: StdMutex::new(HashMap::new()),
            calls: StdMutex::new(Vec::new()),
            next_pid: AtomicU32::new(first_pid),
            binary_name,
            spawn_profile: StdMutex::new(spawn_profile.to_string()),
            responder_factory: Box::new(responder_factory),
            fail_spawn: AtomicBool::new(false),
            suppress_spawn_responder: AtomicBool::new(false),
            persistent_responder: AtomicBool::new(false),
        })
    }

    pub(crate) fn calls(&self) -> Vec<FakeProcessCall> {
        self.calls.lock().unwrap().clone()
    }

    pub(crate) fn spawn_count(&self) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| matches!(call, FakeProcessCall::Spawn(_)))
            .count()
    }

    pub(crate) fn set_spawn_profile(&self, profile: &str) {
        *self.spawn_profile.lock().unwrap() = profile.to_string();
    }

    pub(crate) fn seed(&self, pid: u32, config_path: PathBuf, responder: R) {
        self.configs.lock().unwrap().insert(pid, config_path);
        self.responders.lock().unwrap().insert(pid, responder);
    }

    pub(crate) fn kill_externally(&self, pid: u32) {
        self.responders.lock().unwrap().remove(&pid);
        self.configs.lock().unwrap().remove(&pid);
    }

    async fn spawn_inner(&self, interface: &str, config_path: &Path) -> Result<u32, ProcessError> {
        self.calls
            .lock()
            .unwrap()
            .push(FakeProcessCall::Spawn(config_path.to_path_buf()));
        if self.fail_spawn.load(Ordering::Relaxed) {
            return Err(ProcessError::Spawn {
                binary: PathBuf::from(self.binary_name),
                source: std::io::Error::other("fake spawn failure"),
            });
        }

        let pid = self.next_pid.fetch_add(1, Ordering::Relaxed);
        if !self.suppress_spawn_responder.load(Ordering::Relaxed) {
            let profile = self.spawn_profile.lock().unwrap().clone();
            let responder = (self.responder_factory)(interface, config_path, &profile);
            self.responders.lock().unwrap().insert(pid, responder);
        }
        self.configs
            .lock()
            .unwrap()
            .insert(pid, config_path.to_path_buf());
        Ok(pid)
    }
}

#[async_trait]
impl<R: Send + 'static> SupervisedProcess for FakeSupervisedProcess<R> {
    async fn spawn(&self, _binary: &Path, config_path: &Path) -> Result<u32, ProcessError> {
        let interface = config_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("wlan0");
        self.spawn_inner(interface, config_path).await
    }

    async fn spawn_wifi_client(
        &self,
        _binary: &Path,
        interface: &str,
        config_path: &Path,
    ) -> Result<u32, ProcessError> {
        self.spawn_inner(interface, config_path).await
    }

    async fn is_alive(&self, pid: u32) -> Result<bool, ProcessError> {
        // Process liveness is independent from control-socket readiness. A
        // daemon can be alive before its responder exists (startup timeout),
        // while `persistent_responder` deliberately models the inverse: the
        // recorded PID is gone but a stale/foreign control socket still answers.
        Ok(!self.persistent_responder.load(Ordering::Relaxed)
            && self.configs.lock().unwrap().contains_key(&pid))
    }

    async fn cmdline_contains(&self, pid: u32, config_path: &Path) -> Result<bool, ProcessError> {
        Ok(self
            .configs
            .lock()
            .unwrap()
            .get(&pid)
            .is_some_and(|recorded| recorded == config_path))
    }

    async fn pids_with_config_path(
        &self,
        _kind: crate::wifi::record::WifiProcessKind,
        config_path: &Path,
    ) -> Result<Vec<u32>, ProcessError> {
        let mut pids: Vec<u32> = self
            .configs
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(pid, recorded)| (recorded == config_path).then_some(*pid))
            .collect();
        pids.sort_unstable();
        Ok(pids)
    }

    async fn terminate(&self, pid: u32) -> Result<(), ProcessError> {
        self.calls
            .lock()
            .unwrap()
            .push(FakeProcessCall::Terminate(pid));
        if !self.persistent_responder.load(Ordering::Relaxed) {
            self.responders.lock().unwrap().remove(&pid);
            self.configs.lock().unwrap().remove(&pid);
        }
        Ok(())
    }

    async fn kill(&self, pid: u32) -> Result<(), ProcessError> {
        self.calls.lock().unwrap().push(FakeProcessCall::Kill(pid));
        self.responders.lock().unwrap().remove(&pid);
        self.configs.lock().unwrap().remove(&pid);
        Ok(())
    }
}

/// Stateful network fake shared by unit tests that exercise interface, route,
/// and policy reconciliation together.
#[derive(Debug)]
pub(crate) struct FakeNetworkProvider {
    pub(crate) interfaces: Mutex<HashMap<String, NetworkInterface>>,
    pub(crate) addresses: Mutex<HashMap<String, Vec<Ipv4AddressInfo>>>,
    pub(crate) routes: Mutex<Vec<Ipv4RouteInfo>>,
    pub(crate) rules: Mutex<Vec<Ipv4RuleInfo>>,
    pub(crate) fail_next_add_route: Mutex<bool>,
    allow_missing_address_interface: bool,
    deduplicate_addresses: bool,
}

impl Default for FakeNetworkProvider {
    fn default() -> Self {
        Self {
            interfaces: Mutex::new(HashMap::new()),
            addresses: Mutex::new(HashMap::new()),
            routes: Mutex::new(Vec::new()),
            rules: Mutex::new(Vec::new()),
            fail_next_add_route: Mutex::new(false),
            allow_missing_address_interface: false,
            deduplicate_addresses: true,
        }
    }
}

impl FakeNetworkProvider {
    pub(crate) fn permissive_addresses() -> Self {
        Self {
            allow_missing_address_interface: true,
            deduplicate_addresses: false,
            ..Self::default()
        }
    }

    pub(crate) async fn add_interface(&self, name: &str, index: u32) {
        self.add_interface_with_state(name, index, true, Vec::new())
            .await;
    }

    pub(crate) async fn add_interface_with_state(
        &self,
        name: &str,
        index: u32,
        is_up: bool,
        addresses: Vec<Ipv4AddressInfo>,
    ) {
        self.interfaces.lock().await.insert(
            name.to_string(),
            NetworkInterface {
                is_wireless: false,
                index,
                name: name.to_string(),
                is_up,
                rx_bytes: 0,
                tx_bytes: 0,
            },
        );
        self.addresses
            .lock()
            .await
            .insert(name.to_string(), addresses);
    }
}

#[async_trait]
impl NetworkProvider for FakeNetworkProvider {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Ok(self.interfaces.lock().await.values().cloned().collect())
    }

    async fn list_ipv4_addresses(&self, interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
        Ok(self
            .addresses
            .lock()
            .await
            .get(interface)
            .cloned()
            .unwrap_or_default())
    }

    async fn set_link_up(&self, name: &str) -> Result<()> {
        let mut interfaces = self.interfaces.lock().await;
        interfaces
            .get_mut(name)
            .ok_or_else(|| anyhow!("interface not found: {name}"))?
            .is_up = true;
        Ok(())
    }

    async fn set_link_down(&self, name: &str) -> Result<()> {
        let mut interfaces = self.interfaces.lock().await;
        interfaces
            .get_mut(name)
            .ok_or_else(|| anyhow!("interface not found: {name}"))?
            .is_up = false;
        Ok(())
    }

    async fn add_ipv4_address(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
        ownership: AddressOwnership,
    ) -> Result<()> {
        let interface_index = match self.interfaces.lock().await.get(interface) {
            Some(value) => value.index,
            None if self.allow_missing_address_interface => 0,
            None => return Err(anyhow!("interface not found: {interface}")),
        };
        let mut addresses = self.addresses.lock().await;
        let entry = addresses.entry(interface.to_string()).or_default();
        let already_present = entry
            .iter()
            .any(|current| current.address == address && current.prefix_len == prefix_len);
        if !self.deduplicate_addresses || !already_present {
            entry.push(Ipv4AddressInfo {
                interface_index,
                address,
                prefix_len,
                protocol: ownership.protocol(),
            });
        }
        Ok(())
    }

    async fn delete_ipv4_address(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<()> {
        let mut addresses = self.addresses.lock().await;
        if self.allow_missing_address_interface {
            addresses
                .entry(interface.to_string())
                .or_default()
                .retain(|current| current.address != address || current.prefix_len != prefix_len);
        } else if let Some(addresses) = addresses.get_mut(interface) {
            addresses.retain(|current| {
                !(current.address == address && current.prefix_len == prefix_len)
            });
        }
        Ok(())
    }

    async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
        Ok(self.routes.lock().await.clone())
    }

    async fn add_ipv4_route(&self, route: &Ipv4RouteSpec) -> Result<()> {
        let mut fail = self.fail_next_add_route.lock().await;
        if *fail {
            *fail = false;
            anyhow::bail!("injected route add failure");
        }
        drop(fail);
        self.routes.lock().await.push(Ipv4RouteInfo {
            destination: route.destination,
            gateway: route.gateway,
            output_interface_index: route.output_interface_index,
            table: route.table,
            metric: route.metric,
            protocol: route.protocol,
            scope: if route.gateway.is_some() { 0 } else { 253 },
        });
        Ok(())
    }

    async fn delete_ipv4_route(&self, route: &Ipv4RouteInfo) -> Result<()> {
        self.routes.lock().await.retain(|current| current != route);
        Ok(())
    }

    async fn list_ipv4_rules(&self) -> Result<Vec<Ipv4RuleInfo>> {
        Ok(self.rules.lock().await.clone())
    }

    async fn add_ipv4_rule(&self, rule: &Ipv4RuleSpec) -> Result<()> {
        self.rules.lock().await.push(Ipv4RuleInfo {
            source: rule.source,
            destination: rule.destination,
            table: rule.table,
            priority: rule.priority,
            fw_mark: rule.fw_mark,
            fw_mask: rule.fw_mask,
            input_interface: rule.input_interface.clone(),
            output_interface: rule.output_interface.clone(),
        });
        Ok(())
    }

    async fn delete_ipv4_rule(&self, rule: &Ipv4RuleInfo) -> Result<()> {
        self.rules.lock().await.retain(|current| current != rule);
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct FakeVpnLink {
    private_key: WireGuardKey,
    launch_marker: String,
    up: bool,
}

/// In-memory WireGuard provider for tests that need ownership-proof semantics.
#[derive(Default)]
pub(crate) struct FakeVpnProvider {
    links: StdMutex<HashMap<String, FakeVpnLink>>,
}

impl FakeVpnProvider {
    pub(crate) fn seed_foreign_link(&self, name: &str, private_key: &str) {
        let key = WireGuardKey::parse(private_key, "test").unwrap();
        self.links.lock().unwrap().insert(
            name.to_string(),
            FakeVpnLink {
                private_key: key,
                launch_marker: "foreign".to_string(),
                up: true,
            },
        );
    }

    pub(crate) fn launch_marker_for(&self, name: &str) -> Option<String> {
        self.links
            .lock()
            .unwrap()
            .get(name)
            .map(|link| link.launch_marker.clone())
    }

    fn require_link(&self, name: &str) -> Result<(), ProviderError> {
        if self.links.lock().unwrap().contains_key(name) {
            Ok(())
        } else {
            Err(ProviderError::NotFound(name.to_string()))
        }
    }
}

pub(crate) fn fake_vpn_public_key(private_key: &WireGuardKey) -> WireGuardKey {
    let digest = Sha256::digest(private_key.0);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest[..32]);
    WireGuardKey(bytes)
}

#[async_trait]
impl VpnProvider for FakeVpnProvider {
    async fn link_exists(&self, name: &str) -> Result<bool, ProviderError> {
        Ok(self.links.lock().unwrap().contains_key(name))
    }

    async fn create_link(
        &self,
        name: &str,
        private_key: &WireGuardKey,
        _listen_port: Option<u16>,
        launch_marker: &str,
    ) -> Result<(), ProviderError> {
        let mut links = self.links.lock().unwrap();
        if links.contains_key(name) {
            return Err(ProviderError::CommandFailed {
                command: "ip",
                status: "exit code: 1".to_string(),
                stderr: "link already exists".to_string(),
            });
        }
        links.insert(
            name.to_string(),
            FakeVpnLink {
                private_key: private_key.clone(),
                launch_marker: launch_marker.to_string(),
                up: false,
            },
        );
        Ok(())
    }

    async fn delete_link_if_launch_marker(
        &self,
        name: &str,
        launch_marker: &str,
    ) -> Result<bool, ProviderError> {
        let matches = self
            .links
            .lock()
            .unwrap()
            .get(name)
            .is_some_and(|link| link.launch_marker == launch_marker);
        if !matches {
            return Ok(false);
        }
        self.delete_link(name).await?;
        Ok(true)
    }

    async fn set_addresses(
        &self,
        name: &str,
        _addresses: &[ipnet::IpNet],
    ) -> Result<(), ProviderError> {
        self.require_link(name)
    }

    async fn set_peers(
        &self,
        name: &str,
        _peers: &[WireGuardPeerConfig],
    ) -> Result<(), ProviderError> {
        self.require_link(name)
    }

    async fn set_link_up(&self, name: &str) -> Result<(), ProviderError> {
        let mut links = self.links.lock().unwrap();
        let link = links
            .get_mut(name)
            .ok_or_else(|| ProviderError::NotFound(name.to_string()))?;
        link.up = true;
        Ok(())
    }

    async fn set_link_down(&self, name: &str) -> Result<(), ProviderError> {
        let mut links = self.links.lock().unwrap();
        let link = links
            .get_mut(name)
            .ok_or_else(|| ProviderError::NotFound(name.to_string()))?;
        link.up = false;
        Ok(())
    }

    async fn delete_link(&self, name: &str) -> Result<(), ProviderError> {
        self.links
            .lock()
            .unwrap()
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| ProviderError::NotFound(name.to_string()))
    }

    async fn public_key(&self, name: &str) -> Result<Option<WireGuardKey>, ProviderError> {
        Ok(self
            .links
            .lock()
            .unwrap()
            .get(name)
            .map(|link| fake_vpn_public_key(&link.private_key)))
    }

    async fn is_up(&self, name: &str) -> Result<bool, ProviderError> {
        Ok(self
            .links
            .lock()
            .unwrap()
            .get(name)
            .map(|link| link.up)
            .unwrap_or(false))
    }
}

const STATIC_TEST_VPN_PUBLIC_KEY: &str =
    "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

/// Minimal WireGuard provider for tests that only care about link lifecycle.
pub(crate) struct StaticKeyVpnProvider {
    links: StdMutex<HashMap<String, bool>>,
    launch_markers: StdMutex<HashMap<String, String>>,
    public_key: WireGuardKey,
}

impl Default for StaticKeyVpnProvider {
    fn default() -> Self {
        Self {
            links: StdMutex::new(HashMap::new()),
            launch_markers: StdMutex::new(HashMap::new()),
            public_key: WireGuardKey::parse(STATIC_TEST_VPN_PUBLIC_KEY, "test").unwrap(),
        }
    }
}

impl StaticKeyVpnProvider {
    fn require_link(&self, name: &str) -> Result<(), ProviderError> {
        if self.links.lock().unwrap().contains_key(name) {
            Ok(())
        } else {
            Err(ProviderError::NotFound(name.to_string()))
        }
    }
}

#[async_trait]
impl VpnProvider for StaticKeyVpnProvider {
    async fn link_exists(&self, name: &str) -> Result<bool, ProviderError> {
        Ok(self.links.lock().unwrap().contains_key(name))
    }

    async fn create_link(
        &self,
        name: &str,
        _private_key: &WireGuardKey,
        _listen_port: Option<u16>,
        launch_marker: &str,
    ) -> Result<(), ProviderError> {
        self.links.lock().unwrap().insert(name.to_string(), false);
        self.launch_markers
            .lock()
            .unwrap()
            .insert(name.to_string(), launch_marker.to_string());
        Ok(())
    }

    async fn delete_link_if_launch_marker(
        &self,
        name: &str,
        launch_marker: &str,
    ) -> Result<bool, ProviderError> {
        let matches = self
            .launch_markers
            .lock()
            .unwrap()
            .get(name)
            .is_some_and(|marker| marker == launch_marker);
        if !matches {
            return Ok(false);
        }
        self.delete_link(name).await?;
        Ok(true)
    }

    async fn set_addresses(
        &self,
        name: &str,
        _addresses: &[ipnet::IpNet],
    ) -> Result<(), ProviderError> {
        self.require_link(name)
    }

    async fn set_peers(
        &self,
        name: &str,
        _peers: &[WireGuardPeerConfig],
    ) -> Result<(), ProviderError> {
        self.require_link(name)
    }

    async fn set_link_up(&self, name: &str) -> Result<(), ProviderError> {
        let mut links = self.links.lock().unwrap();
        let up = links
            .get_mut(name)
            .ok_or_else(|| ProviderError::NotFound(name.to_string()))?;
        *up = true;
        Ok(())
    }

    async fn set_link_down(&self, name: &str) -> Result<(), ProviderError> {
        let mut links = self.links.lock().unwrap();
        let up = links
            .get_mut(name)
            .ok_or_else(|| ProviderError::NotFound(name.to_string()))?;
        *up = false;
        Ok(())
    }

    async fn delete_link(&self, name: &str) -> Result<(), ProviderError> {
        let removed = self.links.lock().unwrap().remove(name);
        self.launch_markers.lock().unwrap().remove(name);
        removed
            .map(|_| ())
            .ok_or_else(|| ProviderError::NotFound(name.to_string()))
    }

    async fn public_key(&self, name: &str) -> Result<Option<WireGuardKey>, ProviderError> {
        Ok(self
            .links
            .lock()
            .unwrap()
            .contains_key(name)
            .then(|| self.public_key.clone()))
    }

    async fn is_up(&self, name: &str) -> Result<bool, ProviderError> {
        Ok(self.links.lock().unwrap().get(name).copied().unwrap_or(false))
    }
}
