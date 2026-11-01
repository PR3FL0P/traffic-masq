use super::*;

#[test]
fn unmanaging_an_interface_with_a_running_ap_requires_explicit_confirmation() {
    let current = InterfaceConfig {
        wifi_concurrent: false,
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
        dhcp: None,
        dhcp_client: None,
        wifi: Some(wifi_ap_config_fixture("home-net")),
        wifi_client: None,
    };
    let mut new_config = current.clone();
    new_config.managed = false;
    new_config.wifi = None;

    let error = ControlService::validate_router_service_management(
        "wlan0",
        Some(&current),
        &new_config,
        false,
    )
    .unwrap_err();
    assert!(error.to_string().contains("access point 'home-net'"));

    assert!(ControlService::validate_router_service_management(
        "wlan0",
        Some(&current),
        &new_config,
        true,
    )
    .is_ok());
}

#[test]
fn an_empty_cidr_removes_the_configured_address() {
    let existing = InterfaceConfig {
        wifi_concurrent: false,
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };
    let edit = InterfaceEditRequest {
        wifi_concurrent: false,
        mac_address: None,
        cidr: String::new(),
        role: InterfaceRole::Output,
        managed: true,
        allow_management_change: false,
    };

    let (config, _) =
        interface_edit_request_to_config(edit, Some(&existing)).expect("edit must convert");

    assert_eq!(config.ipv4, None);
    assert!(
        config.managed,
        "removing the address must not stop managing the interface"
    );
}

/// Removing a runtime override has to fall back to the file configuration.
/// It only does so if overrides are merged onto the file config: merging
/// onto the already-merged startup config leaves the removed value baked in,
/// and makes the service disagree with the runtime reconcile loop, which
/// merges onto the file config.
#[tokio::test]
async fn removing_an_interface_override_falls_back_to_the_file_configuration() {
    let directory = tempdir().expect("tempdir");
    let base = router_base_config();
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .expect("overrides");

    let overridden = InterfaceConfig {
        wifi_concurrent: false,
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("10.9.9.1/24".parse().unwrap()),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };
    overrides
        .set_interface("lan0".to_string(), overridden, false)
        .await
        .expect("set override");

    // Constructed the way the daemon does it: the effective configuration
    // for what is running, the file configuration as the merge base.
    let effective = overrides
        .snapshot()
        .await
        .effective_config(&base)
        .expect("effective");
    let dhcp = DhcpSupervisor::start(&effective)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let service = ControlService::from_runtime(
        ControlRuntime {
            active_config: effective,
            base_config: base.clone(),
            network,
            dhcp,
            overrides: overrides.clone(),
            baselines: Vec::new(),
            ownership_journal: AddressOwnershipJournal::in_memory(),
            desired_state: DesiredNetworkState::new(base.clone(), overrides.clone()),
            mutation_gate: Arc::new(NetworkMutationGate::default()),
        },
        ControlSubsystems::default(),
    );

    let candidate = overrides
        .build_candidate(&RouterIntentProposal::new().remove_interface("lan0"))
        .await
        .expect("candidate");
    overrides
        .commit_candidate(&candidate)
        .await
        .expect("commit removal");

    match service
        .dispatch(Request::GetInterfaceConfig {
            interface: "lan0".to_string(),
        })
        .await
    {
        Response::InterfaceConfig { config, .. } => {
            let config = config.expect("lan0 is still in the file configuration");
            assert_eq!(
                config.ipv4, base.network.interfaces["lan0"].ipv4,
                "after the override is removed the file value must be reported"
            );
        }
        response => panic!("unexpected response: {response:?}"),
    }
}

#[tokio::test]
async fn configuring_an_unknown_interface_reports_it_as_not_found() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureWifiClient {
            interface: "nope0".to_string(),
            settings: WifiClientEditRequest {
                ssid: "upstream".to_string(),
                country_code: None,
                security: WifiClientSecurity::Open,
            },
        })
        .await;
    assert!(
        matches!(
            response,
            Response::WifiClientError {
                detail: WifiClientErrorDetail::InterfaceNotFound
            }
        ),
        "got {response:?}"
    );
}

#[tokio::test]
async fn reconnect_reports_the_network_it_reconnected_to() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::WifiClientReconnect {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::WifiClientConfigured { spec } = response else {
        panic!("expected the running spec back, got {response:?}");
    };
    assert_eq!(spec.ssid, "upstream");
}

#[tokio::test]
async fn reconnecting_an_unmanaged_interface_reports_it_as_not_found() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::WifiClientReconnect {
            interface: "wlan9".to_string(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::WifiClientError {
                detail: WifiClientErrorDetail::InterfaceNotFound
            }
        ),
        "got {response:?}"
    );
}

#[tokio::test]
async fn unrelated_recovery_does_not_block_interface_commit_or_rollback() {
    let directory = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.path().to_path_buf();
    config.dhcp.leases_dir = directory.path().join("leases");
    let interface = InterfaceConfig {
        wifi_concurrent: false,
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.77.1/24".parse().unwrap()),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };
    config
        .network
        .interfaces
        .insert("eth0".into(), interface.clone());
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("eth0", 1).await;
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let service = ControlService::new_detached(config, network, dhcp, overrides.clone());
    service.overrides.recovery().block_interface(
        directory.path(),
        "wlan0",
        "invalid snapshot".into(),
    );

    for commit in [true, false] {
        let token = match service
            .dispatch(Request::ApplyInterface {
                interface: "eth0".into(),
                config: interface.clone().into(),
                allow_management_change: false,
            })
            .await
        {
            Response::NetworkChangePending { change } => change.token,
            other => panic!("apply rejected: {other:?}"),
        };
        // A block on this transaction's own interface must still be enforced.
        service.overrides.recovery().block_interface(
            directory.path(),
            "eth0",
            "recovery required".into(),
        );
        let request = if commit {
            Request::CommitNetworkChange {
                token: token.clone(),
            }
        } else {
            Request::RollbackNetworkChange {
                token: token.clone(),
            }
        };
        assert!(matches!(
            service.dispatch(request).await,
            Response::Error { .. }
        ));
        service
            .overrides
            .recovery()
            .unblock_interface(directory.path(), "eth0");
        let response = service
            .dispatch(if commit {
                Request::CommitNetworkChange { token }
            } else {
                Request::RollbackNetworkChange { token }
            })
            .await;
        if commit {
            assert!(
                matches!(response, Response::NetworkChangeCommitted { .. }),
                "{response:?}"
            );
            assert!(overrides.snapshot().await.interfaces.contains_key("eth0"));
        } else {
            assert!(
                matches!(response, Response::NetworkChangeRolledBack { .. }),
                "{response:?}"
            );
        }
        assert!(service.transactions.pending().await.is_empty());
    }
}

#[tokio::test]
async fn operator_profile_activation_is_tentative_and_rollback_restores_committed_config() {
    let fixture = wifi_client_enabled_fixture().await;
    let original = fixture
        .service
        .effective_config()
        .await
        .unwrap()
        .network
        .interfaces["wlan1"]
        .clone();
    fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "tentative".into(),
                ssid: "tentative-network".into(),
                country_code: Some("PL".into()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: false,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    let response = fixture
        .service
        .dispatch(Request::ActivateWifiClientProfile {
            interface: "wlan1".into(),
            profile_id: "tentative".into(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("{response:?}")
    };
    assert_eq!(
        fixture
            .service
            .effective_config()
            .await
            .unwrap()
            .network
            .interfaces["wlan1"],
        original
    );
    assert!(fixture
        .service
        .overrides
        .snapshot()
        .await
        .interfaces
        .is_empty());
    let response = fixture
        .service
        .dispatch(Request::RollbackNetworkChange {
            token: change.token,
        })
        .await;
    assert!(
        matches!(response, Response::NetworkChangeRolledBack { .. }),
        "{response:?}"
    );
    assert_eq!(
        fixture
            .service
            .effective_config()
            .await
            .unwrap()
            .network
            .interfaces["wlan1"],
        original
    );
    assert!(fixture.service.transactions.pending().await.is_empty());
}

#[tokio::test]
async fn partially_stopped_ap_cleanup_preserves_intent_until_storage_is_repaired() {
    let fixture = wifi_enabled_fixture().await;
    let runtime = fixture.service.wifi.as_ref().unwrap();
    let pid = runtime.status("wlan0").await.unwrap().pid;
    fixture.network.interfaces.lock().await.remove("wlan0");
    let config_path = fixture.process.configs.lock().unwrap()[&pid].clone();
    let bad_path = config_path.clone();
    *fixture.process.after_stop.lock().unwrap() = Some(Box::new(move || {
        std::fs::remove_file(&bad_path).unwrap();
        std::fs::create_dir(&bad_path).unwrap();
    }));
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert!(!fixture.process.is_alive(pid).await.unwrap());
    assert_eq!(fixture.service.overrides.committed_revision().await, 0);
    assert!(fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap()
        .wifi
        .is_some());
    std::fs::remove_dir(config_path).unwrap();
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    assert!(runtime.status("wlan0").await.is_none());
    assert!(fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap()
        .wifi
        .is_none());
}

#[tokio::test]
async fn internal_profile_activation_restores_runtime_and_secret_on_persistence_failure() {
    let fixture = wifi_client_fixture_with_security(WifiClientSecurity::Wpa2).await;
    let wifi = fixture.service.wifi_client.as_ref().unwrap();
    let previous = wifi.status("wlan1").await.unwrap().spec;
    let previous_secret = wifi.stored_passphrase("wlan1").await.unwrap().unwrap();
    let created = fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "rollback-test".into(),
                ssid: "replacement-network".into(),
                country_code: Some("PL".into()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: false,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    assert!(
        matches!(created, Response::WifiClientProfile { .. }),
        "{created:?}"
    );
    std::fs::create_dir(fixture.service.overrides.path()).unwrap();
    let response = fixture
        .service
        .activate_wifi_client_profile_internal("wlan1".into(), "rollback-test".into())
        .await;
    assert!(
        matches!(
            response,
            Response::WifiClientProfileError {
                detail: WifiClientProfileErrorDetail::PersistenceFailed { .. }
            }
        ),
        "{response:?}"
    );
    assert_eq!(wifi.status("wlan1").await.unwrap().spec, previous);
    assert_eq!(
        wifi.stored_passphrase("wlan1")
            .await
            .unwrap()
            .unwrap()
            .expose(),
        previous_secret.expose()
    );
    assert_eq!(fixture.service.overrides.committed_revision().await, 0);
}
