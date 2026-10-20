//! VPN control plane and legacy policy initialization at daemon startup.

use std::sync::Arc;

use anyhow::{Context, Result};

use crate::config::{AppConfig, VpnPolicyMode};
use crate::core::override_manager::RuntimeOverrideManager;
use crate::core::vpn_policy_manager::{
    vpn_policy_desired, vpn_policy_teardown_target, VpnPolicyManager,
};
use crate::firewall::{vpn::VpnPolicyFirewallBackend, NftExecutor};
use crate::netlink::NetworkProvider;
use crate::vpn::{
    ActiveProfileStore, LazyNetlinkVpnProvider, ProductionVpnManager, VpnManager, VpnProvider,
    WireGuardProfileStore, WireGuardVpnDriver,
};

pub(super) async fn build_vpn_manager(
    config: &AppConfig,
) -> Result<Option<Arc<ProductionVpnManager>>> {
    let store = WireGuardProfileStore::new(config.vpn.wireguard_config_dir.clone());
    let active_profile_store =
        ActiveProfileStore::new(config.runtime.state_dir.join("vpn-active-profile.json"));
    let provider: Arc<dyn VpnProvider> = Arc::new(LazyNetlinkVpnProvider::new());
    let driver = WireGuardVpnDriver::new(provider, store);
    let manager = Arc::new(VpnManager::new(driver, active_profile_store));

    // Build the control plane even when disabled; only enabled VPNs reconcile.
    if config.vpn.enabled {
        match manager.reconcile().await {
            Ok(outcome) => {
                tracing::info!(?outcome, "VPN startup reconcile complete");
            }
            Err(error) => {
                return Err(error).context("VPN startup reconcile failed");
            }
        }
    }
    Ok(Some(manager))
}

pub(crate) fn build_vpn_policy_manager<E: NftExecutor>(
    network: Arc<dyn NetworkProvider>,
    firewall_executor: E,
    tunnel: Arc<ProductionVpnManager>,
) -> VpnPolicyManager<WireGuardVpnDriver, E> {
    let firewall = VpnPolicyFirewallBackend::new(firewall_executor);
    VpnPolicyManager::new(network, firewall, tunnel)
}

pub(super) async fn apply_vpn_policy_startup<E: NftExecutor>(
    effective_config: &AppConfig,
    overrides: &RuntimeOverrideManager,
    network_provider: Arc<dyn NetworkProvider>,
    firewall_executor: E,
    vpn_manager: &Option<Arc<ProductionVpnManager>>,
) {
    // The router VPN chain owns the same hop-0 reserved routing namespace
    // as the legacy single-hop policy (the kernel interfaces themselves are
    // deliberately distinct). Router recovery/repair runs
    // before this startup hook, so touching legacy policy here would mutate a
    // just-recovered chain outside the router transaction coordinator. The
    // periodic integrity path has the same coexistence guard.
    if crate::core::recovery_control::preservation_required(&effective_config.runtime.state_dir)
        || !effective_config.vpn.enabled
        || !effective_config.router.vpn_chain.is_empty()
    {
        return;
    }

    let Some(tunnel) = vpn_manager else {
        return;
    };

    let mode = overrides.effective_vpn_mode().await;
    let policy = build_vpn_policy_manager(network_provider, firewall_executor, tunnel.clone());

    match mode {
        VpnPolicyMode::Vpn => {
            let Some(desired) = vpn_policy_desired(effective_config) else {
                tracing::error!(
                    "persisted VPN traffic policy mode is \"vpn\" but the effective config has \
                     no router uplink or managed output subnets to protect — fail closed, VPN \
                     policy not activated"
                );
                return;
            };
            match policy.activate(&desired).await {
                Ok(_) => tracing::info!(
                    interface = %desired.vpn_interface,
                    "VPN traffic policy activated at startup"
                ),
                Err(error) => tracing::error!(
                    %error,
                    "failed to activate VPN traffic policy at startup — fail closed, protected \
                     traffic is not routed through VPN; router mode continues unaffected"
                ),
            }
        }
        VpnPolicyMode::Direct => {
            let desired =
                vpn_policy_desired(effective_config).unwrap_or_else(vpn_policy_teardown_target);
            if let Err(error) = policy.deactivate(&desired).await {
                tracing::warn!(
                    %error,
                    "failed to fully clean up VPN traffic policy state while starting in direct \
                     mode"
                );
            }
        }
    }
}
