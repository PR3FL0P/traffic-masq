use std::net::Ipv4Addr;

use crate::config::{
    DhcpClientInterfaceConfig, DhcpInterfaceConfig, ForwardingConfig, InterfaceRole,
    OwnedIpv4RouteConfig, UplinkConfig, UplinkMode,
};
use crate::firewall::RouterDataplaneTarget;

use super::*;

fn input_interface() -> InterfaceConfig {
    InterfaceConfig {
        nat: true,
        role: InterfaceRole::Input,
        managed: false,
        ipv4: None,
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    }
}

fn output_interface(address: &str, pool_start: u8, pool_end: u8) -> InterfaceConfig {
    let ipv4: ipnet::Ipv4Net = address.parse().expect("IPv4 network");
    let octet = ipv4.addr().octets()[2];
    InterfaceConfig {
        nat: true,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some(ipv4),
        dhcp: Some(DhcpInterfaceConfig {
            pool_start: Ipv4Addr::new(192, 168, octet, pool_start),
            pool_end: Ipv4Addr::new(192, 168, octet, pool_end),
            router: ipv4.addr(),
            dns_servers: Vec::new(),
            lease_seconds: None,
        }),
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    }
}

fn base_config() -> AppConfig {
    let mut config = AppConfig::default();
    config
        .network
        .interfaces
        .insert("wan0".to_string(), input_interface());
    config.network.interfaces.insert(
        "lan0".to_string(),
        output_interface("192.168.10.1/24", 100, 150),
    );
    config
}

fn enabled_router() -> RouterConfig {
    RouterConfig {
        forwarding: None,
        vpn_chain: Vec::new(),
        uplink: Some(UplinkConfig {
            interface: "wan0".to_string(),
            mode: UplinkMode::External,
        }),
        owned_routes: Vec::new(),
        allow_default_route_change: false,
        route_host_traffic: false,
    }
}

fn dhcp_router() -> RouterConfig {
    let mut router = enabled_router();
    router.uplink.as_mut().expect("uplink").mode = UplinkMode::Dhcp;
    router
}

fn committed() -> RuntimeOverrides {
    RuntimeOverrides::default()
}

fn management_interface() -> InterfaceConfig {
    InterfaceConfig {
        nat: true,
        role: InterfaceRole::None,
        managed: false,
        ipv4: Some("192.168.1.20/24".parse().expect("IPv4 network")),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    }
}

fn base_config_with_management() -> AppConfig {
    let mut config = base_config();
    config
        .network
        .interfaces
        .insert("mgmt0".to_string(), management_interface());
    config
}

#[test]
fn rejects_relabelling_a_management_interface_without_confirmation() {
    let base = base_config_with_management();
    let relabelled = InterfaceConfig {
        nat: true,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("10.9.0.1/24".parse().expect("IPv4 network")),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };

    let error = RouterCandidate::build(
        &base,
        &committed(),
        &RouterIntentProposal::new().set_interface("mgmt0", relabelled.clone(), false),
    )
    .expect_err("relabelling an outside-router interface should be rejected");
    assert!(error.to_string().contains("outside-router interface mgmt0"));

    RouterCandidate::build(
        &base,
        &committed(),
        &RouterIntentProposal::new().set_interface("mgmt0", relabelled, true),
    )
    .expect("explicit confirmation should allow the change");
}

#[test]
fn rejects_removing_a_management_override_without_confirmation() {
    let error = RouterCandidate::build(
        &base_config_with_management(),
        &committed(),
        &RouterIntentProposal::new().remove_interface("mgmt0"),
    )
    .expect_err("dropping a management override should be rejected");
    assert!(error.to_string().contains("outside-router interface mgmt0"));
}

#[test]
fn allows_non_management_interface_changes_without_confirmation() {
    RouterCandidate::build(
        &base_config_with_management(),
        &committed(),
        &RouterIntentProposal::new().set_interface(
            "lan1",
            output_interface("192.168.20.1/24", 100, 150),
            false,
        ),
    )
    .expect("non-management change needs no confirmation");
}

#[test]
fn builds_validated_candidate_bound_to_committed_revision() {
    let mut committed = committed();
    committed.revision = 4;

    let candidate = RouterCandidate::build(
        &base_config(),
        &committed,
        &RouterIntentProposal::new()
            .set_router(enabled_router())
            .set_interface("lan1", output_interface("192.168.20.1/24", 100, 150), false),
    )
    .expect("valid candidate");

    assert_eq!(candidate.base_revision(), 4);
    assert!(candidate.desired().enabled);
    assert_eq!(candidate.desired().dhcp.len(), 2);
    assert!(candidate.effective_config().router.is_active());
    assert_eq!(candidate.document().revision, 4);
}

#[test]
fn rejects_activating_a_vpn_chain_without_router_intent() {
    let mut router = enabled_router();
    router.uplink = None;
    router.vpn_chain = vec![crate::config::VpnHopConfig {
        profile_name: "hop1".to_string(),
    }];

    let error = RouterCandidate::build(
        &base_config(),
        &committed(),
        &RouterIntentProposal::new().set_router(router),
    )
    .expect_err("a VPN chain must require a complete router intent");

    assert!(error.to_string().contains("router.uplink is required"));
}

#[test]
fn explicit_forwarding_does_not_require_a_global_uplink() {
    let mut router = enabled_router();
    router.uplink = None;
    router.forwarding = Some(vec![ForwardingConfig {
        source_subnet: None,
        from: "lan0".to_string(),
        to: "wan0".to_string(),
        masquerade: true,
    }]);

    RouterCandidate::build(
        &base_config(),
        &committed(),
        &RouterIntentProposal::new().set_router(router),
    )
    .expect("explicit forwarding should not require a global uplink");
}

#[test]
fn explicit_empty_forwarding_does_not_restore_the_legacy_uplink_requirement() {
    let mut router = enabled_router();
    router.uplink = None;
    router.forwarding = Some(Vec::new());

    RouterCandidate::build(
        &base_config(),
        &committed(),
        &RouterIntentProposal::new().set_router(router),
    )
    .expect("an explicit empty forwarding list should be a valid disabled dataplane");
}

#[test]
fn activates_enabled_router_candidate_without_uplink_when_routes_present() {
    let mut router = enabled_router();
    router.uplink = None;
    router.owned_routes = vec![OwnedIpv4RouteConfig {
        destination: "10.0.0.0/24".parse().expect("route"),
        gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
        output_interface: None,
        table: 254,
        metric: Some(100),
    }];

    let candidate = RouterCandidate::build(
        &base_config(),
        &committed(),
        &RouterIntentProposal::new().set_router(router),
    )
    .expect("candidate without uplink but with routes must build");

    assert!(candidate.desired().enabled);
    assert_eq!(candidate.desired().routes.len(), 1);
    assert_eq!(
        candidate.desired().dataplane,
        RouterDataplaneTarget::Disabled
    );
}

#[test]
fn rejects_candidate_that_is_invalid_across_sections() {
    let error = RouterCandidate::build(
        &base_config(),
        &committed(),
        &RouterIntentProposal::new()
            .set_router(enabled_router())
            .set_interface("wan0", output_interface("192.168.30.1/24", 100, 150), false),
    )
    .expect_err("uplink turned into an output must be rejected");

    assert!(format!("{error:#}").contains("router uplink interface must have the input role"));
}

#[test]
fn rejects_candidate_whose_owned_route_leaves_the_router_contract() {
    let mut router = enabled_router();
    router.owned_routes = vec![OwnedIpv4RouteConfig {
        destination: "0.0.0.0/0".parse().expect("route"),
        gateway: None,
        output_interface: Some("wan0".to_string()),
        table: 254,
        metric: None,
    }];

    let error = RouterCandidate::build(
        &base_config(),
        &committed(),
        &RouterIntentProposal::new().set_router(router),
    )
    .expect_err("default route without permission must be rejected");

    assert!(format!("{error:#}").contains("allow_default_route_change"));
}

#[test]
fn dhcp_uplink_materializes_dhcp_client_from_the_same_candidate_snapshot() {
    let mut base = base_config();
    base.network.interfaces.get_mut("wan0").unwrap().managed = true;

    let candidate = RouterCandidate::build(
        &base,
        &committed(),
        &RouterIntentProposal::new().set_router(dhcp_router()),
    )
    .expect("DHCP uplink candidate");

    let wan = candidate
        .document()
        .interfaces
        .get("wan0")
        .expect("derived wan0 override");
    assert!(wan.config.dhcp_client.as_ref().unwrap().enabled);
    assert!(!wan.allow_management_change);
    assert!(wan.dhcp_client_only);
}

#[test]
fn derived_dhcp_client_follows_later_base_interface_changes() {
    let mut base = base_config();
    base.network.interfaces.get_mut("wan0").unwrap().managed = true;
    let candidate = RouterCandidate::build(
        &base,
        &committed(),
        &RouterIntentProposal::new().set_router(dhcp_router()),
    )
    .expect("DHCP uplink candidate");

    let mut updated_base = base.clone();
    let wan = updated_base.network.interfaces.get_mut("wan0").unwrap();
    wan.nat = false;
    wan.dhcp_client = Some(DhcpClientInterfaceConfig {
        enabled: false,
        route_metric: 777,
        ..Default::default()
    });

    let persisted = serde_json::to_vec(candidate.document()).unwrap();
    let committed: RuntimeOverrides = serde_json::from_slice(&persisted).unwrap();
    let effective = committed.effective_config(&updated_base).unwrap();
    let wan = &effective.network.interfaces["wan0"];
    assert!(!wan.nat);
    assert_eq!(wan.dhcp_client.as_ref().unwrap().route_metric, 777);
    assert!(wan.dhcp_client.as_ref().unwrap().enabled);
}

#[test]
fn dhcp_uplink_preserves_existing_override_metadata_and_policy_options() {
    let mut base = base_config();
    base.network.interfaces.get_mut("wan0").unwrap().managed = true;

    let mut committed = committed();
    let mut wan = base.network.interfaces["wan0"].clone();
    wan.dhcp_client = Some(DhcpClientInterfaceConfig {
        wifi_owned: true,
        enabled: false,
        route_metric: 777,
        install_default_route: false,
        request_dns: false,
        send_release_on_shutdown: true,
    });
    committed.interfaces.insert(
        "wan0".to_owned(),
        InterfaceOverride {
            config: wan,
            allow_management_change: true,
            dhcp_client_only: false,
        },
    );

    let candidate = RouterCandidate::build(
        &base,
        &committed,
        &RouterIntentProposal::new().set_router(dhcp_router()),
    )
    .expect("DHCP uplink candidate");

    let wan = candidate.document().interfaces.get("wan0").unwrap();
    let policy = wan.config.dhcp_client.as_ref().unwrap();
    assert!(wan.allow_management_change);
    assert!(policy.enabled);
    assert!(policy.wifi_owned);
    assert_eq!(policy.route_metric, 777);
    assert!(!policy.install_default_route);
    assert!(!policy.request_dns);
    assert!(policy.send_release_on_shutdown);
}

#[test]
fn dhcp_uplink_rejects_removing_the_same_interface_in_one_proposal() {
    let mut base = base_config();
    base.network.interfaces.get_mut("wan0").unwrap().managed = true;

    let error = RouterCandidate::build(
        &base,
        &committed(),
        &RouterIntentProposal::new()
            .set_router(dhcp_router())
            .remove_interface("wan0"),
    )
    .expect_err("conflicting intent must be rejected");

    assert!(error
        .to_string()
        .contains("cannot remove router uplink interface wan0"));
}

#[test]
fn equal_intent_has_the_same_digest_regardless_of_declaration_order() {
    let base = base_config();
    let first = RouterCandidate::build(
        &base,
        &committed(),
        &RouterIntentProposal::new()
            .set_router(enabled_router())
            .set_interface("lan1", output_interface("192.168.20.1/24", 100, 150), false)
            .set_interface("lan2", output_interface("192.168.30.1/24", 100, 150), false),
    )
    .expect("first candidate");
    let second = RouterCandidate::build(
        &base,
        &committed(),
        &RouterIntentProposal::new()
            .set_interface("lan2", output_interface("192.168.30.1/24", 100, 150), false)
            .set_interface("lan1", output_interface("192.168.20.1/24", 100, 150), false)
            .set_router(enabled_router()),
    )
    .expect("second candidate");

    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.digest().to_string(), second.digest().to_string());
    assert_eq!(first.digest().to_string().len(), 64);
}

#[test]
fn digest_ignores_the_committed_revision() {
    let base = base_config();
    let proposal = RouterIntentProposal::new().set_router(enabled_router());
    let mut later = committed();
    later.revision = 97;

    let first = RouterCandidate::build(&base, &committed(), &proposal).expect("first");
    let second = RouterCandidate::build(&base, &later, &proposal).expect("second");

    assert_ne!(first.base_revision(), second.base_revision());
    assert_eq!(first.digest(), second.digest());
}

#[test]
fn semantic_intent_changes_change_the_digest() {
    let base = base_config();
    let router = RouterIntentProposal::new().set_router(enabled_router());
    let baseline = RouterCandidate::build(&base, &committed(), &router).expect("baseline");

    let mut allowed_default_route = enabled_router();
    allowed_default_route.allow_default_route_change = true;
    let changed_router = RouterCandidate::build(
        &base,
        &committed(),
        &RouterIntentProposal::new().set_router(allowed_default_route),
    )
    .expect("changed router");
    assert_ne!(baseline.digest(), changed_router.digest());

    let changed_interface = RouterCandidate::build(
        &base,
        &committed(),
        &router
            .clone()
            .set_interface("lan1", output_interface("192.168.20.1/24", 100, 150), false),
    )
    .expect("changed interface");
    assert_ne!(baseline.digest(), changed_interface.digest());

    let changed_dhcp = RouterCandidate::build(
        &base,
        &committed(),
        &router
            .clone()
            .set_interface("lan1", output_interface("192.168.20.1/24", 100, 149), false),
    )
    .expect("changed DHCP pool");
    assert_ne!(changed_interface.digest(), changed_dhcp.digest());
}

#[test]
fn stale_candidate_is_detected_by_the_revision_guard() {
    let mut committed = committed();
    committed.revision = 7;
    let candidate = RouterCandidate::build(
        &base_config(),
        &committed,
        &RouterIntentProposal::new().set_router(enabled_router()),
    )
    .expect("candidate");

    candidate
        .ensure_base_revision(7)
        .expect("current candidate");
    let error = candidate
        .ensure_base_revision(8)
        .expect_err("stale candidate");
    assert_eq!(
        error,
        StaleCandidateError {
            candidate: 7,
            current: 8,
        }
    );
    assert!(error.to_string().contains("stale"));
}

#[test]
fn validated_candidate_is_not_mutable_through_its_accessors() {
    let candidate = RouterCandidate::build(
        &base_config(),
        &committed(),
        &RouterIntentProposal::new()
            .set_router(enabled_router())
            .set_interface("lan1", output_interface("192.168.20.1/24", 100, 150), false),
    )
    .expect("candidate");
    let digest = candidate.digest();

    let mut document = candidate.document().clone();
    document.interfaces.clear();
    document.router = None;
    let mut desired = candidate.desired().clone();
    desired.dhcp.clear();

    assert_eq!(candidate.document().interfaces.len(), 1);
    assert!(candidate.document().router.is_some());
    assert_eq!(candidate.desired().dhcp.len(), 2);
    assert_eq!(candidate.digest(), digest);
}

#[test]
fn forget_and_reset_have_distinct_digests_and_setting_restores_intent() {
    let base = base_config();
    let committed = RuntimeOverrides::default();
    let forgotten = RouterCandidate::build(
        &base,
        &committed,
        &RouterIntentProposal::new().forget_interface("lan0"),
    )
    .unwrap();
    assert!(!forgotten
        .effective_config()
        .network
        .interfaces
        .contains_key("lan0"));
    let reset = RouterCandidate::build(
        &base,
        forgotten.document(),
        &RouterIntentProposal::new().remove_interface("lan0"),
    )
    .unwrap();
    assert!(reset
        .effective_config()
        .network
        .interfaces
        .contains_key("lan0"));
    assert_ne!(forgotten.digest(), reset.digest());
    let restored = RouterCandidate::build(
        &base,
        forgotten.document(),
        &RouterIntentProposal::new().set_interface(
            "lan0",
            base.network.interfaces["lan0"].clone(),
            false,
        ),
    )
    .unwrap();
    assert!(!restored.document().suppressed_interfaces.contains("lan0"));
}
