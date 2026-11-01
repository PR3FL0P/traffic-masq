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
    (network.ssid_bytes.is_empty() || network.ssid_bytes == profile.ssid.as_bytes())
        && profile.ssid == network.ssid
        && match profile.security {
            WifiClientSecurity::Open => network.security == Scan::Open,
            WifiClientSecurity::Wpa2 => {
                matches!(network.security, Scan::Wpa2Psk | Scan::Wpa2Wpa3Transition)
            }
            WifiClientSecurity::Wpa2Wpa3 => matches!(
                network.security,
                Scan::Wpa2Psk | Scan::Wpa3Sae | Scan::Wpa2Wpa3Transition
            ),
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
    async fn has_pending_interface_transaction(&self) -> bool {
        !self.transactions.pending().await.is_empty()
    }

    pub(crate) async fn autoconnect_wifi_once(&self) -> anyhow::Result<()> {
        let Some(wifi) = &self.wifi_client else {
            return Ok(());
        };
        // Avoid scanning at all when no profiles opted in.
        if !self
            .wifi_client_profiles
            .list_async()
            .await?
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
            // Scanning can launch a temporary supplicant, so it belongs to the
            // same mutation boundary as activation and timeout cleanup. Read
            // eligibility only after admission: a queued pass must not act on
            // an association timeout superseded by a newer control operation.
            let _network_mutation = self.network_mutations.write().await;
            if self
                .overrides
                .recovery()
                .check_scope(&self.config.runtime.state_dir, Some(name))
                .is_err()
            {
                continue;
            }
            let secrets = crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore::in_state_dir(
                &self.config.runtime.state_dir, self.overrides.recovery().clone());
            let committed_token = self.overrides.snapshot().await.committed_router_transaction;
            if secrets
                .unresolved_after_committed_cleanup(committed_token.as_deref())
                .await?
            {
                continue;
            }
            {
                let state = self.wifi_autoconnect.lock().await;
                if state.suspended.contains(name) {
                    continue;
                }
            }
            if self.has_pending_interface_transaction().await {
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
            if crate::wifi::policy::WifiRadioPolicy::validate_scan(
                &effective.network,
                name,
                |name| self.network.wireless_phy(name),
            )
            .is_err()
            {
                continue;
            }
            let now = Instant::now();
            if let Some(status) = wifi.status(name).await {
                if status.wpa_state == WpaState::Completed {
                    self.wifi_autoconnect
                        .lock()
                        .await
                        .connecting_since
                        .remove(name);
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
                self.wifi_autoconnect
                    .lock()
                    .await
                    .connecting_since
                    .remove(name);
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
            let profiles = self.wifi_client_profiles.list_async().await?;
            let id = {
                let state = self.wifi_autoconnect.lock().await;
                let Some(profile) =
                    choose_profile(&profiles, &networks, name, &state, Instant::now())
                else {
                    continue;
                };
                profile.id.clone()
            };

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
                .activate_wifi_client_profile_internal(name.clone(), id.clone())
                .await
            {
                Response::WifiClientProfileActivated { .. } => {
                    tracing::info!(interface = %name, profile = %id, "Wi-Fi autoconnect profile activated");
                }
                response => {
                    tracing::warn!(interface = %name, profile = %id, ?response, "Wi-Fi autoconnect activation failed");
                    self.wifi_autoconnect
                        .lock()
                        .await
                        .connecting_since
                        .remove(name);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
