//! Saved-profile selection runs in the daemon, independently of API clients.
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use super::*;
use crate::config::WifiClientSecurity;
use crate::wifi::{
    WifiClientProfileSummary, WpaState, WpaSupplicantScanResult, WpaSupplicantScanSecurity,
};

const ASSOCIATION_GRACE: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_secs(120);

#[derive(Default)]
pub(super) struct AutoconnectState {
    pub(super) suspended: HashSet<String>,
    pub(super) connecting_since: HashMap<String, Instant>,
    pub(super) attempts: HashMap<String, HashMap<String, Instant>>,
}

impl AutoconnectState {
    pub(super) fn suspend(&mut self, interface: &str) {
        self.suspended.insert(interface.to_string());
    }

    pub(super) fn resume(&mut self, interface: &str) {
        self.suspended.remove(interface);
        self.connecting_since
            .insert(interface.to_string(), Instant::now());
        self.attempts.remove(interface);
    }
}

fn matching_network(profile: &WifiClientProfileSummary, network: &WpaSupplicantScanResult) -> bool {
    use WpaSupplicantScanSecurity as Scan;
    profile.ssid == network.ssid
        && match profile.security {
            WifiClientSecurity::Open => network.security == Scan::Open,
            WifiClientSecurity::Wpa2 => {
                matches!(network.security, Scan::Wpa2Psk | Scan::Wpa2Wpa3Transition)
            }
            WifiClientSecurity::Wpa3 => {
                matches!(network.security, Scan::Wpa3Sae | Scan::Wpa2Wpa3Transition)
            }
        }
}

fn choose_profile<'a>(
    profiles: &'a [WifiClientProfileSummary],
    networks: &[WpaSupplicantScanResult],
    interface: &str,
    state: &AutoconnectState,
    now: Instant,
) -> Option<&'a WifiClientProfileSummary> {
    profiles
        .iter()
        .filter(|profile| {
            profile.autoconnect
                && (profile.security == WifiClientSecurity::Open || profile.has_passphrase)
                && networks
                    .iter()
                    .any(|network| matching_network(profile, network))
                && state
                    .attempts
                    .get(interface)
                    .and_then(|interface_attempts| interface_attempts.get(&profile.id))
                    .is_none_or(|at| now.saturating_duration_since(*at) >= RETRY_DELAY)
        })
        .min_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)))
}

impl ControlService {
    pub(crate) async fn autoconnect_wifi_once(&self) -> anyhow::Result<()> {
        let Some(wifi) = &self.wifi_client else {
            return Ok(());
        };
        // Avoid scanning at all when no profiles opted in.
        if !self
            .wifi_client_profiles
            .list()?
            .iter()
            .any(|profile| profile.autoconnect)
        {
            return Ok(());
        }
        let interfaces = self.network.list_interfaces().await?;
        for interface in interfaces
            .into_iter()
            .filter(|interface| interface.is_wireless)
        {
            let name = &interface.name;
            {
                let state = self.wifi_autoconnect.lock().await;
                if state.suspended.contains(name) {
                    continue;
                }
            }
            if self
                .transactions
                .pending()
                .await
                .iter()
                .any(|change| &change.interface == name)
            {
                continue;
            }
            if let Some(router) = &self.router {
                if router.status().await != crate::core::router_transaction::CoordinatorStatus::Idle
                {
                    continue;
                }
            }
            let effective = self.effective_config().await.map_err(anyhow::Error::msg)?;
            let Some(config) = effective.network.interfaces.get(name) else {
                continue;
            };
            if !config.managed || config.role != InterfaceRole::Input {
                continue;
            }
            let now = Instant::now();
            if let Some(status) = wifi.status(name).await {
                if status.wpa_state == WpaState::Completed {
                    self.wifi_autoconnect.lock().await.connecting_since.remove(name);
                    continue;
                }
                let mut state = self.wifi_autoconnect.lock().await;
                if let Some(since) = state.connecting_since.get(name) {
                    if now.saturating_duration_since(*since) < ASSOCIATION_GRACE {
                        continue;
                    }
                    state.connecting_since.remove(name);
                    drop(state);
                    tracing::warn!(interface = %name, "Wi-Fi autoconnect association timed out; clearing stalled profile");
                    let _network_mutation = self.network_mutations.write().await;
                    let secrets = crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore::in_state_dir(
                        &self.config.runtime.state_dir,
                    );
                    let committed_token = self
                        .overrides
                        .snapshot()
                        .await
                        .committed_router_transaction;
                    if secrets
                        .unresolved_after_committed_cleanup(committed_token.as_deref())
                        .await?
                    {
                        continue;
                    }
                    if self
                        .transactions
                        .pending()
                        .await
                        .iter()
                        .any(|change| &change.interface == name)
                    {
                        continue;
                    }
                    if let Some(router) = &self.router {
                        if router.status().await
                            != crate::core::router_transaction::CoordinatorStatus::Idle
                        {
                            continue;
                        }
                    }
                    let _mutation = self.wifi_client_mutations.lock().await;
                    let response = self.disable_wifi_client_locked(name.clone()).await;
                    if !matches!(response, Response::WifiClientDisabled { .. }) {
                        tracing::warn!(interface = %name, ?response, "failed to clear stalled Wi-Fi autoconnect profile");
                    }
                    continue;
                } else if matches!(
                    status.wpa_state,
                    WpaState::Authenticating
                        | WpaState::Associating
                        | WpaState::Associated
                        | WpaState::FourWayHandshake
                        | WpaState::GroupHandshake
                ) {
                    continue;
                }
            } else {
                self.wifi_autoconnect.lock().await.connecting_since.remove(name);
            }
            {
                let mut state = self.wifi_autoconnect.lock().await;
                state.attempts.retain(|_, attempts| {
                    attempts.retain(|_, at| now.saturating_duration_since(*at) < RETRY_DELAY);
                    !attempts.is_empty()
                });
            }
            let networks = match wifi.scan(name).await {
                Ok(networks) => networks,
                Err(error) => {
                    tracing::debug!(interface = %name, %error, "Wi-Fi autoconnect scan failed");
                    continue;
                }
            };
            let profiles = self.wifi_client_profiles.list()?;
            let id = {
                let state = self.wifi_autoconnect.lock().await;
                let Some(profile) = choose_profile(&profiles, &networks, name, &state, Instant::now())
                else {
                    continue;
                };
                profile.id.clone()
            };

            // Serialize the actual mutation with router/interface transaction starts.
            // The earlier checks can go stale while scanning, so repeat them
            // after acquiring the global network mutation gate.
            let _network_mutation = self.network_mutations.write().await;
            let secrets = crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore::in_state_dir(
                &self.config.runtime.state_dir,
            );
            let committed_token = self
                .overrides
                .snapshot()
                .await
                .committed_router_transaction;
            if secrets
                .unresolved_after_committed_cleanup(committed_token.as_deref())
                .await?
            {
                continue;
            }
            if self
                .transactions
                .pending()
                .await
                .iter()
                .any(|change| &change.interface == name)
            {
                continue;
            }
            if let Some(router) = &self.router {
                if router.status().await
                    != crate::core::router_transaction::CoordinatorStatus::Idle
                {
                    continue;
                }
            }
            let _mutation = self.wifi_client_mutations.lock().await;
            {
                let mut state = self.wifi_autoconnect.lock().await;
                if state.suspended.contains(name) {
                    continue;
                }
                // Verify interface didn't finish connecting while scanning
                if let Some(status) = wifi.status(name).await {
                    if status.wpa_state == WpaState::Completed {
                        state.connecting_since.remove(name);
                        continue;
                    }
                }
                state
                    .attempts
                    .entry(name.clone())
                    .or_default()
                    .insert(id.clone(), Instant::now());
                state.connecting_since.insert(name.clone(), Instant::now());
            }

            match self
                .activate_wifi_client_profile_locked(name.clone(), id.clone())
                .await
            {
                Response::WifiClientProfileActivated { .. } => {
                    tracing::info!(interface = %name, profile = %id, "Wi-Fi autoconnect profile activated");
                }
                response => {
                    tracing::warn!(interface = %name, profile = %id, ?response, "Wi-Fi autoconnect activation failed");
                    self.wifi_autoconnect.lock().await.connecting_since.remove(name);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::MacAddr;

    fn sample_profile(
        id: &str,
        ssid: &str,
        security: WifiClientSecurity,
        priority: i32,
        autoconnect: bool,
        has_passphrase: bool,
    ) -> WifiClientProfileSummary {
        WifiClientProfileSummary {
            id: id.to_string(),
            ssid: ssid.to_string(),
            country_code: None,
            security,
            priority,
            autoconnect,
            created_at: 0,
            modified_at: 0,
            has_passphrase,
        }
    }

    fn sample_network(ssid: &str, security: WpaSupplicantScanSecurity) -> WpaSupplicantScanResult {
        WpaSupplicantScanResult {
            bssid: MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            frequency_mhz: 2412,
            signal_dbm: -50,
            ssid: ssid.to_string(),
            raw_flags: String::new(),
            security,
        }
    }

    #[test]
    fn test_matching_network_security() {
        use WpaSupplicantScanSecurity as Scan;

        let p_open = sample_profile("p1", "Net", WifiClientSecurity::Open, 0, true, false);
        assert!(matching_network(
            &p_open,
            &sample_network("Net", Scan::Open)
        ));
        assert!(!matching_network(
            &p_open,
            &sample_network("Net", Scan::Wpa2Psk)
        ));
        assert!(!matching_network(
            &p_open,
            &sample_network("Net", Scan::Wpa3Sae)
        ));

        let p_wpa2 = sample_profile("p2", "Net", WifiClientSecurity::Wpa2, 0, true, true);
        assert!(matching_network(
            &p_wpa2,
            &sample_network("Net", Scan::Wpa2Psk)
        ));
        assert!(matching_network(
            &p_wpa2,
            &sample_network("Net", Scan::Wpa2Wpa3Transition)
        ));
        assert!(!matching_network(
            &p_wpa2,
            &sample_network("Net", Scan::Open)
        ));
        assert!(!matching_network(
            &p_wpa2,
            &sample_network("Net", Scan::Wpa3Sae)
        ));

        let p_wpa3 = sample_profile("p3", "Net", WifiClientSecurity::Wpa3, 0, true, true);
        assert!(matching_network(
            &p_wpa3,
            &sample_network("Net", Scan::Wpa3Sae)
        ));
        assert!(matching_network(
            &p_wpa3,
            &sample_network("Net", Scan::Wpa2Wpa3Transition)
        ));
        assert!(!matching_network(
            &p_wpa3,
            &sample_network("Net", Scan::Open)
        ));
        assert!(!matching_network(
            &p_wpa3,
            &sample_network("Net", Scan::Wpa2Psk)
        ));

        // SSID mismatch
        assert!(!matching_network(
            &p_open,
            &sample_network("Other", Scan::Open)
        ));
    }

    #[test]
    fn test_choose_profile_priority_and_filtering() {
        let now = Instant::now();
        let state = AutoconnectState::default();
        let networks = vec![
            sample_network("NetA", WpaSupplicantScanSecurity::Wpa2Psk),
            sample_network("NetB", WpaSupplicantScanSecurity::Wpa2Psk),
        ];

        let profiles = vec![
            // autoconnect is false -> skip
            sample_profile("p1", "NetA", WifiClientSecurity::Wpa2, 10, false, true),
            // no passphrase -> skip
            sample_profile("p2", "NetA", WifiClientSecurity::Wpa2, 10, true, false),
            // valid match
            sample_profile("p3", "NetA", WifiClientSecurity::Wpa2, 5, true, true),
            // valid match with higher priority
            sample_profile("p4", "NetB", WifiClientSecurity::Wpa2, 10, true, true),
        ];

        let chosen = choose_profile(&profiles, &networks, "wlan0", &state, now).unwrap();
        assert_eq!(chosen.id, "p4");
    }

    #[test]
    fn test_choose_profile_tie_breaking() {
        let now = Instant::now();
        let state = AutoconnectState::default();
        let networks = vec![sample_network("Net", WpaSupplicantScanSecurity::Wpa2Psk)];

        let profiles = vec![
            sample_profile("beta", "Net", WifiClientSecurity::Wpa2, 10, true, true),
            sample_profile("alpha", "Net", WifiClientSecurity::Wpa2, 10, true, true),
        ];

        let chosen = choose_profile(&profiles, &networks, "wlan0", &state, now).unwrap();
        assert_eq!(chosen.id, "alpha");
    }

    #[test]
    fn test_choose_profile_retry_delay_backoff() {
        let now = Instant::now();
        let mut state = AutoconnectState::default();
        let networks = vec![sample_network("Net", WpaSupplicantScanSecurity::Open)];
        let profiles = vec![sample_profile(
            "p1",
            "Net",
            WifiClientSecurity::Open,
            10,
            true,
            false,
        )];

        // Recent attempt (30 seconds ago) -> skipped
        state
            .attempts
            .entry("wlan0".to_string())
            .or_default()
            .insert("p1".to_string(), now - Duration::from_secs(30));
        assert!(choose_profile(&profiles, &networks, "wlan0", &state, now).is_none());

        // Old attempt (121 seconds ago) -> chosen
        state
            .attempts
            .get_mut("wlan0")
            .unwrap()
            .insert("p1".to_string(), now - Duration::from_secs(121));
        assert!(choose_profile(&profiles, &networks, "wlan0", &state, now).is_some());
    }

    #[test]
    fn test_autoconnect_state_suspend_and_resume() {
        let mut state = AutoconnectState::default();
        state
            .attempts
            .entry("wlan0".to_string())
            .or_default()
            .insert("p1".to_string(), Instant::now());
        state.suspend("wlan0");
        assert!(state.suspended.contains("wlan0"));

        state.resume("wlan0");
        assert!(!state.suspended.contains("wlan0"));
        assert!(state.connecting_since.contains_key("wlan0"));
        assert!(!state.attempts.contains_key("wlan0"));
    }
}
