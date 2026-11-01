use super::*;

#[tokio::test]
async fn offline_router_save_cannot_change_host_vpn_routing() {
    let fixture = vpn_policy_fixture_with_router_chain(false, true).await;
    let current = fixture.service.effective_config().await.unwrap();
    let mut proposed = current.router.clone();
    proposed.route_host_traffic = true;
    let revision = fixture.overrides.committed_revision().await;
    let response = fixture
        .service
        .dispatch(Request::SaveRouterIntent {
            config: proposed.into(),
            expected_revision: revision,
        })
        .await;
    assert!(
        matches!(response, Response::RouterError { .. }),
        "{response:?}"
    );
    assert_eq!(fixture.overrides.committed_revision().await, revision);
    assert_eq!(
        fixture.service.effective_config().await.unwrap().router,
        current.router
    );
}

#[tokio::test]
async fn missing_interface_inventory_save_forget_reset_and_stale_editor() {
    use traffic_masq_protocol::InterfacePresence;
    let directory = tempdir().unwrap();
    let mut base = router_base_config();
    base.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new_detached(
        base.clone(),
        Arc::new(FakeNetwork {
            addresses: Vec::new(),
        }),
        dhcp,
        overrides.clone(),
    )
    .with_base_config_file(Some("/custom/router.toml".into()));
    let revision = match service.dispatch(Request::ListInterfaceInventory).await {
        Response::InterfaceInventory {
            base_config,
            interfaces,
            revision,
            ..
        } => {
            let base_config = base_config.unwrap();
            assert_eq!(base_config.file.as_deref(), Some("/custom/router.toml"));
            assert!(base_config.interfaces.contains(&"lan0".to_owned()));
            let lan = interfaces
                .iter()
                .find(|entry| entry.name == "lan0")
                .unwrap();
            assert_eq!(lan.presence, InterfacePresence::Missing);
            assert!(lan.observed.is_none());
            assert!(lan.configured.is_some());
            revision
        }
        response => panic!("{response:?}"),
    };
    let response = service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "lan0".into(),
            expected_revision: revision,
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    assert!(overrides
        .effective_interface("lan0")
        .await
        .unwrap()
        .is_none());
    let response = service
        .dispatch(Request::SaveInterfaceConfig {
            interface: "lan0".into(),
            config: base.network.interfaces["lan0"].clone().into(),
            allow_management_change: false,
            expected_revision: revision,
        })
        .await;
    assert!(matches!(response, Response::Error { .. }));
    assert!(overrides
        .effective_interface("lan0")
        .await
        .unwrap()
        .is_none());
    let restarted = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    assert!(restarted
        .effective_interface("lan0")
        .await
        .unwrap()
        .is_none());
    let response = service
        .dispatch(Request::ResetInterfaceOverride {
            interface: "lan0".into(),
            expected_revision: overrides.committed_revision().await,
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    assert_eq!(
        overrides.effective_interface("lan0").await.unwrap(),
        Some(base.network.interfaces["lan0"].clone())
    );
}

#[tokio::test]
async fn inventory_observation_failure_retains_cache_and_blocks_offline_writes() {
    use traffic_masq_protocol::InterfacePresence;
    let directory = tempdir().unwrap();
    let mut base = router_base_config();
    base.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("lan0", 7).await;
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new_detached(base, network.clone(), dhcp, overrides.clone());
    assert!(matches!(
        service.dispatch(Request::ListInterfaceInventory).await,
        Response::InterfaceInventory { .. }
    ));
    *network.fail_interface_observation.lock().await = true;
    match service.dispatch(Request::ListInterfaceInventory).await {
        Response::InterfaceInventory {
            interfaces,
            observation_error,
            ..
        } => {
            assert!(observation_error.is_some());
            let lan = interfaces
                .iter()
                .find(|entry| entry.name == "lan0")
                .unwrap();
            assert_eq!(lan.presence, InterfacePresence::Unknown);
            assert!(lan.observation_stale);
            assert_eq!(lan.observed.as_ref().unwrap().interface.index, 7);
            assert!(interfaces
                .iter()
                .all(|entry| entry.presence == InterfacePresence::Unknown));
        }
        response => panic!("{response:?}"),
    }
    let revision = overrides.committed_revision().await;
    assert!(matches!(
        service
            .dispatch(Request::ForgetInterfaceConfig {
                interface: "lan0".into(),
                expected_revision: revision,
            })
            .await,
        Response::Error { .. }
    ));
    assert_eq!(overrides.committed_revision().await, revision);
    assert!(overrides
        .effective_interface("lan0")
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn saved_dhcp_pool_is_readable_without_device_or_runtime_spec() {
    let directory = tempdir().unwrap();
    let mut base = router_base_config();
    base.runtime.state_dir = directory.path().into();
    let lan = base.network.interfaces.get_mut("lan0").unwrap();
    lan.ipv4 = Some("192.168.50.1/24".parse().unwrap());
    lan.dhcp = Some(dhcp_config());
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let runtime_base = router_base_config();
    let dhcp = DhcpSupervisor::start(&runtime_base).await.unwrap();
    assert!(dhcp.spec("lan0").await.is_none());
    let service = ControlService::new_detached(
        base,
        Arc::new(FakeNetwork {
            addresses: Vec::new(),
        }),
        dhcp,
        overrides,
    );
    match service
        .dispatch(Request::GetDhcpConfig {
            interface: "lan0".into(),
        })
        .await
    {
        Response::DhcpConfig {
            spec: Some(spec), ..
        } => {
            assert_eq!(spec.pool_start, dhcp_config().pool_start);
            assert_eq!(spec.pool_end, dhcp_config().pool_end);
        }
        response => panic!("{response:?}"),
    }
}

#[tokio::test]
async fn offline_intent_writers_reject_live_targets_and_serialize_stale_revisions() {
    let directory = tempdir().unwrap();
    let mut base = router_base_config();
    base.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("lan0", 7).await;
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service =
        ControlService::new_detached(base.clone(), network.clone(), dhcp, overrides.clone());
    let response = service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "lan0".into(),
            expected_revision: 0,
        })
        .await;
    assert!(matches!(response, Response::Error { .. }));
    assert_eq!(overrides.committed_revision().await, 0);
    network.interfaces.lock().await.clear();
    let forget = Request::ForgetInterfaceConfig {
        interface: "lan0".into(),
        expected_revision: 0,
    };
    let save = Request::SaveInterfaceConfig {
        interface: "lan0".into(),
        config: base.network.interfaces["lan0"].clone().into(),
        expected_revision: 0,
        allow_management_change: false,
    };
    let (first, second) = tokio::join!(service.dispatch(forget), service.dispatch(save));
    assert_eq!(
        [first, second]
            .iter()
            .filter(|response| matches!(response, Response::InterfaceIntentSaved { .. }))
            .count(),
        1
    );
    assert_eq!(overrides.committed_revision().await, 1);
}

#[tokio::test]
async fn offline_intent_respects_interface_recovery_fence() {
    let directory = tempdir().unwrap();
    let mut base = router_base_config();
    base.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new_detached(
        base,
        Arc::new(FakeNetwork {
            addresses: Vec::new(),
        }),
        dhcp,
        overrides.clone(),
    );
    service.overrides.recovery().block_interface(
        directory.path(),
        "lan0",
        "retained transaction proof".into(),
    );
    let response = service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "lan0".into(),
            expected_revision: 0,
        })
        .await;
    service
        .overrides
        .recovery()
        .unblock_interface(directory.path(), "lan0");
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert_eq!(overrides.committed_revision().await, 0);
    assert!(overrides
        .effective_interface("lan0")
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn offline_save_cleans_retained_missing_dhcp_client_runtime() {
    let fixture = dhcp_client_control_fixture(true).await;
    let config = fixture
        .overrides
        .effective_interface("wan0")
        .await
        .unwrap()
        .unwrap();
    let revision = fixture.overrides.committed_revision().await;
    let response = fixture
        .service
        .dispatch(Request::SaveInterfaceConfig {
            interface: "wan0".into(),
            config: config.clone().into(),
            allow_management_change: false,
            expected_revision: revision,
        })
        .await;
    assert!(
        matches!(
            response,
            Response::InterfaceIntentSaved { deferred: true, .. }
        ),
        "{response:?}"
    );
    assert_eq!(fixture.overrides.committed_revision().await, revision + 1);
    assert_eq!(
        fixture.overrides.effective_interface("wan0").await.unwrap(),
        Some(config)
    );
    assert!(fixture.supervisor.spec("wan0").await.is_none());
}

#[tokio::test]
async fn saved_missing_client_password_and_disable_preserve_independent_dhcp_policy() {
    let directory = tempdir().unwrap();
    let mut base = wifi_base_config(directory.path());
    let cfg = base.network.interfaces.get_mut("wlan0").unwrap();
    cfg.role = InterfaceRole::Input;
    cfg.ipv4 = None;
    cfg.wifi = None;
    cfg.dhcp_client = Some(DhcpClientInterfaceConfig {
        enabled: true,
        wifi_owned: false,
        ..Default::default()
    });
    cfg.wifi_client = Some(WifiClientConfig {
        ssid: "saved-uplink".into(),
        country_code: None,
        security: WifiClientSecurity::Wpa2,
        passphrase_file: None,
    });
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new_detached(
        base.clone(),
        Arc::new(crate::test_support::FakeNetworkProvider::default()),
        dhcp,
        overrides,
    );
    assert!(matches!(
        service
            .dispatch(Request::GetWifiClientConfig {
                interface: "wlan0".into()
            })
            .await,
        Response::WifiClientConfig { spec: Some(_), .. }
    ));
    let response = service
        .dispatch(Request::WifiClientSetPassphrase {
            interface: "wlan0".into(),
            passphrase: "client-password".into(),
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    let saved = service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    let file = saved.wifi_client.unwrap().passphrase_file.unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "client-password");
    let response = service
        .dispatch(Request::DisableWifiClient {
            interface: "wlan0".into(),
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    let saved = service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    assert!(saved.wifi_client.is_none());
    assert!(saved.dhcp_client.unwrap().enabled);
    assert!(file.exists());
    let restarted = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    assert!(restarted
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap()
        .wifi_client
        .is_none());
}

#[tokio::test]
async fn stale_or_unknown_offline_edit_does_not_stop_retained_ap() {
    for unknown in [false, true] {
        let fixture = wifi_enabled_fixture().await;
        let runtime = fixture.service.wifi.as_ref().unwrap();
        let pid = runtime.status("wlan0").await.unwrap().pid;
        let mut config = fixture
            .service
            .overrides
            .effective_interface("wlan0")
            .await
            .unwrap()
            .unwrap();
        config.wifi = None;
        fixture.network.interfaces.lock().await.remove("wlan0");
        *fixture.network.fail_interface_observation.lock().await = unknown;
        let response = fixture
            .service
            .dispatch(Request::SaveWifiInterface {
                interface: "wlan0".into(),
                config: config.into(),
                expected_revision: if unknown { 0 } else { 7 },
                passphrase: None,
            })
            .await;
        assert!(matches!(response, Response::Error { .. }), "{response:?}");
        assert!(fixture.process.is_alive(pid).await.unwrap());
        assert!(runtime.status("wlan0").await.is_some());
        assert_eq!(fixture.service.overrides.committed_revision().await, 0);
    }
}

#[tokio::test]
async fn offline_profile_reference_is_immutable_and_stale_selection_cannot_replace_it() {
    use traffic_masq_protocol::{ProvisionWifiClientRequest, WifiClientIpPolicy};
    let (service, _directory) = offline_client_profile_fixture().await;
    let settings = ProvisionWifiClientRequest {
        profile_id: "saved-uplink".into(),
        ip_policy: WifiClientIpPolicy::Preserve,
    };
    assert!(matches!(
        service
            .dispatch(Request::SaveWifiClientProfile {
                interface: "wlan1".into(),
                settings: settings.clone(),
                expected_revision: 0,
            })
            .await,
        Response::InterfaceIntentSaved { .. }
    ));
    let previous = service
        .overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .unwrap();
    let profile = WifiClientProfileWriteRequest {
        id: "saved-uplink".into(),
        ssid: "Updated profile".into(),
        country_code: Some("UA".into()),
        security: WifiClientSecurity::Wpa2,
        priority: 0,
        autoconnect: false,
        passphrase: Some("profile-updated-password".into()),
        clear_passphrase: false,
    };
    let response = service
        .dispatch(Request::UpdateWifiClientProfile {
            id: "saved-uplink".into(),
            profile: profile.clone(),
        })
        .await;
    assert!(
        matches!(response, Response::WifiClientProfile { .. }),
        "{response:?}"
    );
    assert_eq!(
        std::fs::read_to_string(
            previous
                .wifi_client
                .as_ref()
                .unwrap()
                .passphrase_file
                .as_ref()
                .unwrap()
        )
        .unwrap(),
        "profile-original-password"
    );
    let response = service
        .dispatch(Request::SaveWifiClientProfile {
            interface: "wlan1".into(),
            settings: settings.clone(),
            expected_revision: 0,
        })
        .await;
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert_eq!(
        service
            .overrides
            .effective_interface("wlan1")
            .await
            .unwrap(),
        Some(previous)
    );
    let response = service
        .dispatch(Request::DeleteWifiClientProfile {
            id: "saved-uplink".into(),
        })
        .await;
    assert!(
        matches!(response, Response::WifiClientProfileDeleted { .. }),
        "{response:?}"
    );
    let retained = service
        .overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(retained.wifi_client.unwrap().passphrase_file.unwrap()).unwrap(),
        "profile-original-password"
    );
    assert!(matches!(
        service
            .dispatch(Request::ForgetInterfaceConfig {
                interface: "wlan1".into(),
                expected_revision: 1
            })
            .await,
        Response::InterfaceIntentSaved { .. }
    ));
    let response = service
        .dispatch(Request::SaveWifiClientProfile {
            interface: "wlan1".into(),
            settings,
            expected_revision: 2,
        })
        .await;
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert!(service
        .overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn offline_client_disable_suspends_autoconnect_until_explicit_profile_save() {
    let (service, _directory) = offline_client_profile_fixture().await;
    let response = service
        .dispatch(Request::DisableWifiClient {
            interface: "wlan1".into(),
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    assert!(service
        .wifi_autoconnect
        .lock()
        .await
        .suspended
        .contains("wlan1"));
    let response = service
        .dispatch(Request::SaveWifiClientProfile {
            interface: "wlan1".into(),
            expected_revision: 1,
            settings: traffic_masq_protocol::ProvisionWifiClientRequest {
                profile_id: "saved-uplink".into(),
                ip_policy: traffic_masq_protocol::WifiClientIpPolicy::Dhcp,
            },
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    assert!(!service
        .wifi_autoconnect
        .lock()
        .await
        .suspended
        .contains("wlan1"));
}
