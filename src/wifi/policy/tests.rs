use super::*;

fn interface(role: WifiRadioRole) -> InterfaceConfig {
    serde_json::from_value(match role {
        WifiRadioRole::Ap => serde_json::json!({"managed": true, "role": "output", "wifi": {"ssid": "ap", "channel": 6, "security": "open"}}),
        WifiRadioRole::Client => serde_json::json!({"managed": true, "role": "input", "wifi_client": {"ssid": "sta", "security": "open"}}),
    }).unwrap()
}

#[test]
fn phy_admission_matrix_is_independent_of_netdev_names_and_order() {
    for first in [WifiRadioRole::Ap, WifiRadioRole::Client] {
        for second in [WifiRadioRole::Ap, WifiRadioRole::Client] {
            let roles = [("vif0", first), ("vif1", second)];
            assert_eq!(
                WifiRadioPolicy::validate_roles(roles, |_| Some("phy0".into())).is_ok(),
                first == second
            );
            assert!(WifiRadioPolicy::validate_roles(roles, |name| Some(name.into())).is_ok());
        }
    }
}

#[test]
fn transition_replaces_the_old_allocation_and_checks_other_interfaces() {
    let mut network = NetworkConfig::default();
    network
        .interfaces
        .insert("vif0".into(), interface(WifiRadioRole::Ap));
    assert!(WifiRadioPolicy::validate_transition(
        &network,
        "vif0",
        &interface(WifiRadioRole::Client),
        |_| Some("phy0".into())
    )
    .is_ok());
    network
        .interfaces
        .insert("vif1".into(), interface(WifiRadioRole::Ap));
    assert!(WifiRadioPolicy::validate_transition(
        &network,
        "vif0",
        &interface(WifiRadioRole::Client),
        |_| Some("phy0".into())
    )
    .is_err());
    // An ephemeral station scanner is an allocation too.
    assert!(WifiRadioPolicy::validate_scan(&network, "vif2", |_| Some("phy0".into())).is_err());
}

#[test]
fn hotplug_revalidation_rejects_newly_observable_conflicts() {
    let mut network = NetworkConfig::default();
    network
        .interfaces
        .insert("vif0".into(), interface(WifiRadioRole::Ap));
    network
        .interfaces
        .insert("vif1".into(), interface(WifiRadioRole::Client));
    assert!(WifiRadioPolicy::validate(&network, |_| None).is_ok());
    assert!(WifiRadioPolicy::validate(&network, |_| Some("phy0".into())).is_err());
    network.interfaces.get_mut("vif0").unwrap().managed = false;
    assert!(WifiRadioPolicy::validate(&network, |_| Some("phy0".into())).is_ok());
}

#[test]
fn explicit_pair_is_allowed_but_third_interface_is_not() {
    let mut network = NetworkConfig::default();
    let mut client = interface(WifiRadioRole::Client);
    client.wifi_concurrent = true;
    network.interfaces.insert("wlan0".into(), client);
    let ap = traffic_masq_protocol::concurrent_ap_name("wlan0");
    network.interfaces.insert(ap, interface(WifiRadioRole::Ap));
    assert!(WifiRadioPolicy::validate(&network, |_| Some("phy0".into())).is_ok());
    assert!(WifiRadioPolicy::validate_scan(&network, "wlan0", |_| Some("phy0".into())).is_ok());
    assert!(WifiRadioPolicy::validate_scan(&network, "other0", |_| Some("phy0".into())).is_err());
    network
        .interfaces
        .insert("extra-ap".into(), interface(WifiRadioRole::Ap));
    assert!(WifiRadioPolicy::validate(&network, |_| Some("phy0".into())).is_err());
}
