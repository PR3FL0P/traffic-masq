use super::*;

#[tokio::test]
async fn vpn_policy_requests_are_rejected_when_vpn_is_disabled() {
    let directory = tempdir().expect("tempdir");
    let config = router_base_config();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let service = ControlService::new_detached(config, network, dhcp, overrides);

    for request in [
        Request::VpnPolicyStatus,
        Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        },
        Request::VpnPolicyClearMode,
    ] {
        match service.dispatch(request).await {
            Response::VpnPolicyError {
                detail: VpnPolicyErrorDetail::VpnDisabled,
            } => {}
            other => panic!("unexpected response: {other:?}"),
        }
    }
}

#[tokio::test]
async fn legacy_vpn_policy_mutations_are_blocked_when_router_chain_is_configured() {
    let fixture = vpn_policy_fixture_with_router_chain(true, true).await;

    for request in [
        Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        },
        Request::VpnPolicyClearMode,
    ] {
        match fixture.service.dispatch(request).await {
            Response::Error { message } => assert!(message.contains("router VPN chain")),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    assert!(fixture.network.rules.lock().unwrap().is_empty());
    assert!(fixture.network.routes.lock().unwrap().is_empty());
    assert!(fixture.overrides.snapshot().await.vpn_mode.is_none());
}

#[tokio::test]
async fn vpn_policy_set_mode_vpn_activates_when_tunnel_is_healthy_and_persists() {
    let fixture = vpn_policy_fixture(true).await;

    match commit_policy_request(
        &fixture.service,
        Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        },
    )
    .await
    {
        Response::VpnPolicyStatus { status } => {
            assert_eq!(status.mode, VpnPolicyMode::Vpn);
            assert!(status.mode_override_active);
            assert!(status.policy_active);
            assert!(status.kill_switch_active);
            assert!(status.tunnel_healthy);
            assert_eq!(status.physical_uplink.as_deref(), Some("wan0"));
            assert_eq!(
                status.protected_subnets,
                vec!["192.168.10.0/24".parse().unwrap()]
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    assert_eq!(
        fixture.overrides.effective_vpn_mode().await,
        VpnPolicyMode::Vpn
    );

    match fixture.service.dispatch(Request::VpnPolicyStatus).await {
        Response::VpnPolicyStatus { status } => assert!(status.policy_active),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_policy_set_mode_restores_runtime_snapshot_when_persistence_fails() {
    let fixture = vpn_policy_fixture(true).await;

    let committed = fixture.overrides.snapshot().await;
    let path = fixture._directory.path().join("runtime-overrides.json");
    if path.exists() {
        std::fs::remove_file(&path).unwrap();
    }
    std::fs::create_dir(&path).unwrap();
    let response = fixture
        .service
        .dispatch(Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        })
        .await;
    let token = match response {
        Response::RouterTransactionPending { token, .. } => token,
        other => panic!("expected pending: {other:?}"),
    };
    let response = fixture
        .service
        .dispatch(Request::RouterCommit {
            token: token.clone(),
        })
        .await;
    assert!(
        matches!(response, Response::RouterError { .. }),
        "{response:?}"
    );
    assert_eq!(fixture.overrides.snapshot().await, committed);
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RouterRollback { token })
            .await,
        Response::RouterRolledBack
    ));
    match fixture.service.dispatch(Request::VpnPolicyStatus).await {
        Response::VpnPolicyStatus { status } => assert!(!status.policy_active),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_policy_set_mode_vpn_fails_closed_without_active_tunnel() {
    let fixture = vpn_policy_fixture(false).await;

    match fixture
        .service
        .dispatch(Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        })
        .await
    {
        Response::Error { message } => {
            assert!(message.contains("connected profile"));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    assert_eq!(
        fixture.overrides.effective_vpn_mode().await,
        VpnPolicyMode::Direct
    );

    match fixture.service.dispatch(Request::VpnPolicyStatus).await {
        Response::VpnPolicyStatus { status } => {
            assert!(!status.policy_active);
            assert!(!status.mode_override_active);
            assert_eq!(status.mode, VpnPolicyMode::Direct);
            assert!(!status.tunnel_healthy);
            assert!(status.tunnel.is_none());
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_policy_set_mode_direct_after_vpn_deactivates_and_persists() {
    let fixture = vpn_policy_fixture(true).await;
    commit_policy_request(
        &fixture.service,
        Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        },
    )
    .await;

    match commit_policy_request(
        &fixture.service,
        Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Direct,
        },
    )
    .await
    {
        Response::VpnPolicyStatus { status } => {
            assert_eq!(status.mode, VpnPolicyMode::Direct);
            assert!(status.mode_override_active);
            assert!(!status.policy_active);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    assert_eq!(
        fixture.overrides.effective_vpn_mode().await,
        VpnPolicyMode::Direct
    );
}

#[tokio::test]
async fn vpn_policy_clear_mode_restores_runtime_snapshot_when_persistence_fails() {
    let fixture = vpn_policy_fixture(true).await;
    commit_policy_request(
        &fixture.service,
        Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        },
    )
    .await;
    let committed = fixture.overrides.snapshot().await;
    let path = fixture._directory.path().join("runtime-overrides.json");
    if path.exists() {
        std::fs::remove_file(&path).unwrap();
    }
    std::fs::create_dir(&path).unwrap();
    let response = fixture.service.dispatch(Request::VpnPolicyClearMode).await;
    let token = match response {
        Response::RouterTransactionPending { token, .. } => token,
        other => panic!("expected pending: {other:?}"),
    };
    let response = fixture
        .service
        .dispatch(Request::RouterCommit {
            token: token.clone(),
        })
        .await;
    assert!(
        matches!(response, Response::RouterError { .. }),
        "{response:?}"
    );
    assert_eq!(fixture.overrides.snapshot().await, committed);
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RouterRollback { token })
            .await,
        Response::RouterRolledBack
    ));
    match fixture.service.dispatch(Request::VpnPolicyStatus).await {
        Response::VpnPolicyStatus { status } => assert!(status.policy_active),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_policy_clear_mode_falls_back_to_base_default() {
    let fixture = vpn_policy_fixture(true).await;
    commit_policy_request(
        &fixture.service,
        Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        },
    )
    .await;
    assert!(fixture.overrides.snapshot().await.vpn_mode.is_some());

    match commit_policy_request(&fixture.service, Request::VpnPolicyClearMode).await {
        Response::VpnPolicyStatus { status } => {
            assert_eq!(status.mode, VpnPolicyMode::Direct);
            assert!(!status.mode_override_active);
            assert!(!status.policy_active);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    assert!(fixture.overrides.snapshot().await.vpn_mode.is_none());
}

#[tokio::test]
async fn wifi_client_provision_keeps_ip_policy_tentative_and_restores_on_rollback() {
    let directory = tempdir().unwrap();
    let mut config = wifi_client_base_config(directory.path());
    config.wifi_client.wpa_supplicant_binary = PathBuf::from("/bin/true");
    let original = config.network.interfaces["wlan1"].clone();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wlan1", 1).await;
    let wifi = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
        .await
        .unwrap();
    let service = ControlService::new_detached(config, network, dhcp, overrides.clone())
        .with_wifi_client_supervisor(wifi);
    assert!(matches!(
        service
            .dispatch(Request::CreateWifiClientProfile {
                profile: WifiClientProfileWriteRequest {
                    id: "candidate".into(),
                    ssid: "candidate".into(),
                    country_code: None,
                    security: WifiClientSecurity::Open,
                    priority: 0,
                    autoconnect: false,
                    passphrase: None,
                    clear_passphrase: false,
                }
            })
            .await,
        Response::WifiClientProfile { .. }
    ));
    let response = service
        .dispatch(Request::ProvisionWifiClient {
            interface: "wlan1".into(),
            settings: crate::api::model::ProvisionWifiClientRequest {
                profile_id: "candidate".into(),
                ip_policy: crate::api::model::WifiClientIpPolicy::Static {
                    cidr: "192.168.77.2/24".parse().unwrap(),
                },
            },
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("{response:?}")
    };
    assert_eq!(
        overrides
            .effective_interface("wlan1")
            .await
            .unwrap()
            .unwrap(),
        original
    );
    assert!(matches!(
        service
            .dispatch(Request::RollbackNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeRolledBack { .. }
    ));
    assert_eq!(
        overrides
            .effective_interface("wlan1")
            .await
            .unwrap()
            .unwrap(),
        original
    );
}

#[tokio::test]
async fn standalone_vpn_restart_recovers_protected_policy_before_new_commit() {
    let fixture = vpn_policy_fixture(true).await;
    commit_policy_request(
        &fixture.service,
        Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        },
    )
    .await;
    let committed = fixture.overrides.snapshot().await;
    let response = fixture
        .service
        .dispatch(Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Direct,
        })
        .await;
    assert!(
        matches!(response, Response::RouterTransactionPending { .. }),
        "{response:?}"
    );
    assert!(fixture.network.rules.lock().unwrap().is_empty());
    assert_eq!(fixture.overrides.snapshot().await, committed);
    let config = fixture.service.base_config.clone();
    let overrides = RuntimeOverrideManager::load(fixture._directory.path(), &config)
        .await
        .unwrap();
    let tunnel = Arc::new(crate::vpn::VpnManager::new(
        crate::vpn::WireGuardVpnDriver::new(
            fixture.provider.clone(),
            crate::vpn::WireGuardProfileStore::new(config.vpn.wireguard_config_dir.clone()),
        ),
        crate::vpn::ActiveProfileStore::new(fixture._directory.path().join("active-profile.json")),
    ));
    let coordinator = crate::core::router_subsystems::tests::standalone_coordinator(
        &config,
        overrides.clone(),
        tunnel.clone(),
        fixture.provider.clone(),
        fixture.network.clone(),
        fixture.executor.clone(),
    )
    .await;
    coordinator.recover().await.unwrap();
    assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
    assert_eq!(
        tunnel.status().await.unwrap().unwrap().profile_name,
        "home.conf"
    );
    assert!(!fixture.network.rules.lock().unwrap().is_empty());
    assert_eq!(overrides.snapshot().await, committed);
    let policy = Arc::new(VpnPolicyManager::new(
        fixture.network.clone(),
        VpnPolicyFirewallBackend::new(fixture.executor.clone()),
        tunnel.clone(),
    ));
    let service = ControlService::new_detached(
        config.clone(),
        fixture.network.clone(),
        DhcpSupervisor::start(&config).await.unwrap(),
        overrides,
    )
    .with_vpn_manager(tunnel)
    .with_vpn_policy_manager(policy)
    .with_router_coordinator(coordinator);
    commit_policy_request(
        &service,
        Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Direct,
        },
    )
    .await;
    let reloaded =
        crate::state::overrides::RuntimeOverrideStore::in_state_dir(fixture._directory.path())
            .load()
            .await
            .unwrap();
    assert_eq!(reloaded.vpn_mode, Some(VpnPolicyMode::Direct));
    assert_eq!(reloaded.revision, committed.revision + 1);
}
