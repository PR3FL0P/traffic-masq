use super::*;

#[test]
fn interface_edit_preserves_client_and_nat_settings() {
    let existing = InterfaceConfig {
        wifi_concurrent: false,
        randomize_mac: false,
        mac_address: None,
        role: InterfaceRole::Input,
        managed: true,
        ipv4: None,
        dhcp: None,
        dhcp_client: Some(crate::config::DhcpClientInterfaceConfig::default()),
        wifi: None,
        wifi_client: Some(crate::config::WifiClientConfig {
            ssid: "uplink".into(),
            country_code: None,
            security: crate::config::WifiClientSecurity::Open,
            passphrase_file: None,
        }),
    };
    let (config, _) = interface_edit_request_to_config(
        InterfaceEditRequest {
            wifi_concurrent: false,
            randomize_mac: false,
            mac_address: None,
            cidr: String::new(),
            role: InterfaceRole::Input,
            managed: true,
            allow_management_change: false,
        },
        Some(&existing),
    )
    .unwrap();
    assert_eq!(config.dhcp_client, existing.dhcp_client);
    assert_eq!(config.wifi_client, existing.wifi_client);
    config.validate("wlan0").unwrap();
}

#[test]
fn open_ap_passphrase_update_clears_stale_secret_for_legacy_clients() {
    let update = crate::api::control::wifi::ap_passphrase_update(WifiSecurity::Open, None, false)
        .expect("open AP update");
    assert!(matches!(update, crate::wifi::WifiPassphraseUpdate::Clear));
}

#[tokio::test]
async fn wifi_client_disable_commit_failure_keeps_the_candidate_pending() {
    let fixture = wifi_client_enabled_fixture().await;
    std::fs::create_dir(fixture.service.overrides.path()).unwrap();
    let response = fixture
        .service
        .dispatch(Request::DisableWifiClient {
            interface: "wlan1".into(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending client deactivation, got {response:?}");
    };

    let committed = fixture
        .service
        .dispatch(Request::CommitNetworkChange {
            token: change.token.clone(),
        })
        .await;
    assert!(matches!(committed, Response::Error { .. }), "{committed:?}");
    assert!(fixture
        .service
        .transactions
        .pending()
        .await
        .iter()
        .any(|pending| pending.token == change.token));

    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RollbackNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeRolledBack { .. }
    ));
}

#[tokio::test]
async fn wifi_client_requests_are_rejected_when_client_mode_is_disabled() {
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

    assert!(matches!(
        service
            .dispatch(Request::GetWifiClientConfig {
                interface: "wlan1".to_string(),
            })
            .await,
        Response::WifiClientConfig { spec: None, .. }
    ));

    for request in [
        Request::WifiClientStatus,
        Request::DisableWifiClient {
            interface: "wlan1".to_string(),
        },
        Request::WifiClientReconnect {
            interface: "wlan1".to_string(),
        },
        Request::WifiClientScan {
            interface: "wlan1".to_string(),
        },
        Request::WifiClientSetPassphrase {
            interface: "wlan1".to_string(),
            passphrase: "a-secret-value".to_string(),
        },
    ] {
        assert!(
            matches!(
                service.dispatch(request).await,
                Response::WifiClientError {
                    detail: WifiClientErrorDetail::WifiClientDisabled
                }
            ),
            "every client request must report the subsystem as disabled"
        );
    }
}

#[tokio::test]
async fn wifi_client_deactivate_preserves_managed_and_allows_subsequent_reactivation() {
    let fixture = wifi_client_enabled_fixture().await;
    let deactivated = fixture
        .service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = deactivated else {
        panic!("expected pending client deactivation, got {deactivated:?}");
    };
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));

    let effective = fixture.service.effective_config().await.unwrap();
    let iface = effective.network.interfaces.get("wlan1").unwrap();
    assert!(
        iface.managed,
        "interface must remain managed after deactivation"
    );
    assert!(iface.wifi_client.is_none());

    let created = fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "home".to_string(),
                ssid: "home-wifi".to_string(),
                country_code: Some("US".to_string()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: false,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    assert!(matches!(created, Response::WifiClientProfile { .. }));

    let activated = fixture
        .service
        .activate_wifi_client_profile_internal("wlan1".to_string(), "home".to_string())
        .await;
    assert!(matches!(
        activated,
        Response::WifiClientProfileActivated { .. }
    ));
}

#[tokio::test]
async fn manual_client_deactivation_suspends_autoconnect_only_after_commit() {
    let fixture = wifi_client_enabled_fixture().await;

    let first = fixture
        .service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = first else {
        panic!("expected pending client deactivation, got {first:?}");
    };
    assert!(!fixture
        .service
        .wifi_autoconnect
        .lock()
        .await
        .suspended
        .contains("wlan1"));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RollbackNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeRolledBack { .. }
    ));
    assert!(!fixture
        .service
        .wifi_autoconnect
        .lock()
        .await
        .suspended
        .contains("wlan1"));

    let second = fixture
        .service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = second else {
        panic!("expected pending client deactivation, got {second:?}");
    };
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    assert!(fixture
        .service
        .wifi_autoconnect
        .lock()
        .await
        .suspended
        .contains("wlan1"));
}

#[tokio::test]
async fn autoconnect_is_blocked_by_pending_transaction_on_another_interface() {
    let fixture = wifi_client_enabled_fixture().await;
    let created = fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "saved".to_string(),
                ssid: "upstream".to_string(),
                country_code: Some("PL".to_string()),
                security: WifiClientSecurity::Wpa2,
                priority: 10,
                autoconnect: true,
                passphrase: Some("password123".to_string()),
                clear_passphrase: false,
            },
        })
        .await;
    assert!(matches!(created, Response::WifiClientProfile { .. }));

    let target = InterfaceConfig {
        wifi_concurrent: false,
        randomize_mac: false,
        mac_address: None,
        role: InterfaceRole::Input,
        managed: true,
        ipv4: None,
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };
    let pending = fixture
        .service
        .transactions
        .apply(
            "wlan2",
            InterfaceChange {
                config: &target,
                previous: None,
                current_role: None,
                allow_management_change: true,
                passphrase: crate::wifi::WifiPassphraseUpdate::Keep,
            },
        )
        .await
        .expect("create pending transaction on wlan2");

    fixture.process.set_wpa_state("DISCONNECTED");
    fixture
        .service
        .autoconnect_wifi_once()
        .await
        .expect("autoconnect pass");

    let state = fixture.service.wifi_autoconnect.lock().await;
    assert!(
        !state.attempts.contains_key("wlan1"),
        "pending transaction on wlan2 must block autoconnect mutation on wlan1"
    );
    assert!(
        !state.connecting_since.contains_key("wlan1"),
        "blocked autoconnect must not enter the association grace period"
    );
    drop(state);

    let effective = fixture.service.effective_config().await.unwrap();
    assert_eq!(
        effective
            .network
            .interfaces
            .get("wlan1")
            .and_then(|interface| interface.wifi_client.as_ref())
            .map(|wifi| wifi.security),
        Some(WifiClientSecurity::Open),
        "blocked autoconnect must not replace the active Wi-Fi client configuration"
    );

    fixture
        .service
        .transactions
        .rollback(&pending.token)
        .await
        .expect("clean up pending wlan2 transaction");
}

#[tokio::test]
async fn autoconnect_does_not_launch_a_scan_during_secret_recovery() {
    let fixture = wifi_client_enabled_fixture().await;
    let created = fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "saved".into(),
                ssid: "saved-wifi".into(),
                country_code: Some("US".into()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: true,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    assert!(matches!(created, Response::WifiClientProfile { .. }));
    // Leave committed intent eligible for autoconnect, but require a temporary
    // supplicant for any scan. Recovery must prevent even this preliminary write.
    fixture
        .service
        .wifi_client
        .as_ref()
        .unwrap()
        .disable("wlan1")
        .await
        .unwrap();
    let next_pid = fixture.process.next_pid.load(WifiOrdering::Relaxed);
    let secrets = crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore::in_state_dir(
        &fixture.service.config.runtime.state_dir, fixture.service.overrides.recovery().clone());
    secrets
        .stage(std::collections::BTreeMap::from([(
            "wlan1".into(),
            (crate::wifi::store::WifiCredentialRole::Client, None),
        )]))
        .await
        .unwrap();

    fixture.service.autoconnect_wifi_once().await.unwrap();

    assert_eq!(
        fixture.process.next_pid.load(WifiOrdering::Relaxed),
        next_pid,
        "unresolved recovery must block temporary scan processes"
    );
}

#[tokio::test]
async fn queued_autoconnect_timeout_does_not_disable_a_new_association() {
    let fixture = wifi_client_enabled_fixture().await;
    let created = fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "saved".into(),
                ssid: "saved-wifi".into(),
                country_code: Some("US".into()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: true,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    assert!(matches!(created, Response::WifiClientProfile { .. }));
    fixture.process.set_wpa_state("ASSOCIATING");
    fixture
        .service
        .wifi_autoconnect
        .lock()
        .await
        .connecting_since
        .insert(
            "wlan1".into(),
            std::time::Instant::now() - std::time::Duration::from_secs(45),
        );

    // Hold the same gate as an admitted configuration request. Poll the
    // background pass until it is waiting for that request to finish.
    let mutation = fixture.service.network_mutations.write().await;
    let pass = fixture.service.autoconnect_wifi_once();
    tokio::pin!(pass);
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut pass)
        .await
        .is_err());
    // The admitted request starts a new association before releasing admission.
    fixture
        .service
        .wifi_autoconnect
        .lock()
        .await
        .resume("wlan1");
    drop(mutation);
    tokio::time::timeout(Duration::from_secs(5), pass)
        .await
        .unwrap()
        .unwrap();

    let effective = fixture.service.effective_config().await.unwrap();
    assert!(
        effective.network.interfaces["wlan1"].wifi_client.is_some(),
        "an expired timeout must not disable a newer association"
    );
    assert!(fixture
        .service
        .wifi_autoconnect
        .lock()
        .await
        .connecting_since
        .contains_key("wlan1"));
}

#[tokio::test]
async fn autoconnect_timeout_clears_stalled_profile_without_deadlock() {
    let fixture = wifi_client_enabled_fixture().await;
    let created = fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "saved".to_string(),
                ssid: "saved-wifi".to_string(),
                country_code: Some("US".to_string()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: true,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    assert!(matches!(created, Response::WifiClientProfile { .. }));

    let activated = fixture
        .service
        .activate_wifi_client_profile_internal("wlan1".to_string(), "saved".to_string())
        .await;
    assert!(matches!(
        activated,
        Response::WifiClientProfileActivated { .. }
    ));

    // Simulate connecting_since exceeded ASSOCIATION_GRACE and wpa_state is not Completed
    fixture.process.set_wpa_state("ASSOCIATING");
    {
        let mut state = fixture.service.wifi_autoconnect.lock().await;
        state.connecting_since.insert(
            "wlan1".to_string(),
            std::time::Instant::now() - std::time::Duration::from_secs(45),
        );
    }

    // Must complete within 5 seconds without deadlocking
    let run = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.service.autoconnect_wifi_once(),
    )
    .await;
    assert!(run.is_ok(), "autoconnect_wifi_once deadlocked!");
    assert!(run.unwrap().is_ok());

    // Interface must remain managed and stalled wifi_client cleared
    let effective = fixture.service.effective_config().await.unwrap();
    let iface = effective.network.interfaces.get("wlan1").unwrap();
    assert!(iface.managed, "interface must remain managed");
    assert!(
        iface.wifi_client.is_none(),
        "stalled wifi_client must be cleared"
    );

    let state = fixture.service.wifi_autoconnect.lock().await;
    assert!(
        !state.suspended.contains("wlan1"),
        "autoconnect must not be suspended"
    );
    assert!(
        !state.connecting_since.contains_key("wlan1"),
        "connecting_since must be cleared"
    );
}

#[tokio::test]
async fn wifi_client_status_reports_the_live_association() {
    let fixture = wifi_client_enabled_fixture().await;
    let Response::WifiClientStatus { interfaces } =
        fixture.service.dispatch(Request::WifiClientStatus).await
    else {
        panic!("expected a client status response");
    };
    assert_eq!(interfaces.len(), 1);
    assert_eq!(interfaces[0].interface, "wlan1");
    assert_eq!(interfaces[0].spec.ssid, "upstream");
    assert!(interfaces[0].wpa_state.is_connected());
}

#[tokio::test]
async fn configure_wifi_client_keeps_the_new_network_tentative_until_commit() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureWifiClient {
            interface: "wlan1".to_string(),
            settings: WifiClientEditRequest {
                ssid: "somewhere-else".to_string(),
                country_code: Some("PL".to_string()),
                security: WifiClientSecurity::Open,
            },
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
            .interfaces["wlan1"]
            .wifi_client
            .as_ref()
            .unwrap()
            .ssid,
        "upstream"
    );
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));

    let Response::WifiClientConfig { spec, .. } = fixture
        .service
        .dispatch(Request::GetWifiClientConfig {
            interface: "wlan1".to_string(),
        })
        .await
    else {
        panic!("expected a config response");
    };
    assert_eq!(spec.expect("spec persisted").ssid, "somewhere-else");
}

#[tokio::test]
async fn configuring_a_client_on_an_output_interface_is_an_invalid_spec() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_client_base_config(directory.path());
    config.network.interfaces.insert(
        "wlan2".to_string(),
        InterfaceConfig {
            wifi_concurrent: false,
            randomize_mac: false,
            mac_address: None,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.9.1/24".parse().unwrap()),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
        .await
        .expect("wifi client supervisor");
    let service = ControlService::new_detached(config, network, dhcp, overrides)
        .with_wifi_client_supervisor(wifi_client);

    let response = service
        .dispatch(Request::ConfigureWifiClient {
            interface: "wlan2".to_string(),
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
                detail: WifiClientErrorDetail::InvalidSpec { .. }
            }
        ),
        "got {response:?}"
    );
}

#[tokio::test]
async fn disable_wifi_client_is_tentative_until_explicit_commit() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::DisableWifiClient {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending client deactivation, got {response:?}");
    };

    let before = fixture.service.effective_config().await.unwrap();
    assert!(before.network.interfaces["wlan1"].wifi_client.is_some());

    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    let after = fixture.service.effective_config().await.unwrap();
    assert!(after.network.interfaces["wlan1"].wifi_client.is_none());
}

#[tokio::test]
async fn wifi_client_scan_rejects_configured_ap_without_hostapd_task() {
    let directory = tempdir().unwrap();
    let mut config = wifi_client_base_config(directory.path());
    let mut ap = config.network.interfaces["wlan1"].clone();
    ap.role = InterfaceRole::Output;
    ap.wifi_client = None;
    ap.dhcp_client = None;
    ap.wifi = Some(wifi_ap_config("hotspot", WifiSecurity::Open));
    config.network.interfaces.insert("wlan0".into(), ap);
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let process = FakeSupplicantProcess::new();
    let wifi_client = ClientSupervisor::start_with_process(&config, process.clone())
        .await
        .unwrap();
    let before = process.configs.lock().unwrap().len();
    let network: Arc<dyn NetworkProvider> =
        Arc::new(ProvisioningNetwork::with_wireless(&["wlan0", "wlan1"]));
    // No AP supervisor: configured APs must still never spawn a scan supplicant.
    let service = ControlService::new_detached(config, network, dhcp, overrides)
        .with_wifi_client_supervisor(wifi_client);
    let response = service
        .dispatch(Request::WifiClientScan {
            interface: "wlan0".into(),
        })
        .await;
    assert!(
        matches!(response, Response::WifiClientError {
        detail: WifiClientErrorDetail::InvalidSpec { ref message }
    } if message.contains("access point")),
        "{response:?}"
    );
    assert_eq!(process.configs.lock().unwrap().len(), before);
}

#[tokio::test]
async fn wifi_client_scan_on_configured_interface_returns_scan_results() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::WifiClientScan {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::WifiClientScanResults { interface, results } = response else {
        panic!("expected scan results, got {response:?}");
    };
    assert_eq!(interface, "wlan1");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ssid, "upstream");
}

#[tokio::test]
async fn wifi_client_scan_on_unconfigured_interface_performs_ephemeral_scan() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::WifiClientScan {
            interface: "wlan2".to_string(),
        })
        .await;
    let Response::WifiClientScanResults { interface, results } = response else {
        panic!("expected scan results, got {response:?}");
    };
    assert_eq!(interface, "wlan2");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ssid, "upstream");
}

#[tokio::test]
async fn wifi_client_scan_rejects_non_wireless_interface() {
    let directory = tempdir().expect("tempdir");
    let config = wifi_client_base_config(directory.path());
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(
        ProvisioningNetwork::with_wireless(&["wlan1"]).with_address("eth0", [192, 168, 1, 1], 24),
    );
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
        .await
        .expect("wifi client supervisor");
    let service = ControlService::new_detached(config, network, dhcp, overrides)
        .with_wifi_client_supervisor(wifi_client);

    let response = service
        .dispatch(Request::WifiClientScan {
            interface: "eth0".to_string(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::WifiClientError {
                detail: WifiClientErrorDetail::NotWireless
            }
        ),
        "expected NotWireless for non-wireless NIC, got {response:?}"
    );
}

#[tokio::test]
async fn wifi_client_scan_rejects_missing_interface_when_network_known() {
    let directory = tempdir().expect("tempdir");
    let config = wifi_client_base_config(directory.path());
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> =
        Arc::new(ProvisioningNetwork::with_wireless(&["wlan1"]));
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
        .await
        .expect("wifi client supervisor");
    let service = ControlService::new_detached(config, network, dhcp, overrides)
        .with_wifi_client_supervisor(wifi_client);

    let response = service
        .dispatch(Request::WifiClientScan {
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
        "expected InterfaceNotFound, got {response:?}"
    );
}

#[tokio::test]
async fn wifi_client_deactivation_disables_only_wifi_owned_dhcp_on_commit() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_client_base_config(directory.path());
    let mut wlan1_cfg = config.network.interfaces["wlan1"].clone();
    wlan1_cfg.dhcp_client = Some(DhcpClientInterfaceConfig {
        wifi_owned: true,
        ..Default::default()
    });
    config
        .network
        .interfaces
        .insert("wlan1".to_string(), wlan1_cfg);
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeWirelessNetwork {
        missing: Default::default(),
        interfaces: vec![NetworkInterface {
            name: "wlan1".into(),
            index: 1,
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            is_wireless: true,
        }],
    });
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
        .await
        .expect("wifi client supervisor");
    let service = ControlService::new_detached(config, network, dhcp, overrides.clone())
        .with_wifi_client_supervisor(wifi_client);

    let response = service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending client deactivation, got {response:?}");
    };
    let committed_before = overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .unwrap();
    assert!(committed_before.wifi_client.is_some());
    assert!(committed_before.dhcp_client.unwrap().enabled);

    assert!(matches!(
        service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    let committed = overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .unwrap();
    assert!(committed.wifi_client.is_none());
    let policy = committed.dhcp_client.expect("dhcp client policy");
    assert!(!policy.enabled);
    assert!(!policy.wifi_owned);
}

#[tokio::test]
async fn wifi_client_deactivation_commit_failure_can_be_rolled_back_cleanly() {
    let fixture = wifi_client_enabled_fixture().await;
    std::fs::create_dir(fixture.service.overrides.path()).unwrap();
    let original = fixture
        .service
        .effective_config()
        .await
        .unwrap()
        .network
        .interfaces["wlan1"]
        .clone();

    let response = fixture
        .service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending client deactivation, got {response:?}");
    };
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token.clone()
            })
            .await,
        Response::Error { .. }
    ));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RollbackNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeRolledBack { .. }
    ));
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
}

#[tokio::test]
async fn wifi_client_deactivation_rollback_preserves_wifi_owned_dhcp_intent() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_client_base_config(directory.path());
    let mut wlan1_cfg = config.network.interfaces["wlan1"].clone();
    wlan1_cfg.dhcp_client = Some(DhcpClientInterfaceConfig {
        wifi_owned: true,
        ..Default::default()
    });
    config
        .network
        .interfaces
        .insert("wlan1".to_string(), wlan1_cfg.clone());
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeWirelessNetwork {
        missing: Default::default(),
        interfaces: vec![NetworkInterface {
            name: "wlan1".into(),
            index: 1,
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            is_wireless: true,
        }],
    });
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
        .await
        .expect("wifi client supervisor");
    let service = ControlService::new_detached(config, network, dhcp, overrides.clone())
        .with_wifi_client_supervisor(wifi_client);

    let response = service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending client deactivation, got {response:?}");
    };
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
        wlan1_cfg
    );
}

#[tokio::test]
async fn internal_wifi_client_disable_cleans_up_wifi_owned_dhcp() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_client_base_config(directory.path());
    let mut wlan1_cfg = config
        .network
        .interfaces
        .get("wlan1")
        .expect("wlan1 declared")
        .clone();
    wlan1_cfg.managed = true;
    wlan1_cfg.dhcp_client = Some(DhcpClientInterfaceConfig {
        wifi_owned: true,
        ..Default::default()
    });
    config
        .network
        .interfaces
        .insert("wlan1".to_string(), wlan1_cfg.clone());

    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
        .await
        .expect("wifi client supervisor");
    let wifi_spec = WifiClientSpec::from_interface_config("wlan1", &wlan1_cfg)
        .expect("valid")
        .expect("wifi_client declared on wlan1");
    wifi_client
        .configure(wifi_spec)
        .await
        .expect("configure wlan1 wifi");

    let dhcp_client = DhcpClientSupervisor::start(&config, network.clone())
        .await
        .expect("client supervisor");
    let dhcp_spec = DhcpClientSpec::from_interface_config("wlan1", &wlan1_cfg)
        .expect("valid")
        .expect("dhcp_client declared on wlan1");
    dhcp_client.configure(dhcp_spec).await;
    assert!(dhcp_client.spec("wlan1").await.is_some());

    let service = ControlService::new_detached(config, network, dhcp, overrides.clone())
        .with_wifi_client_supervisor(wifi_client)
        .with_dhcp_client_supervisor(dhcp_client.clone());

    let response = service
        .disable_wifi_client_locked("wlan1".to_string())
        .await;
    assert!(
        matches!(response, Response::WifiClientDisabled { .. }),
        "got {response:?}"
    );

    // DHCP client supervisor must be stopped and purged
    assert!(dhcp_client.spec("wlan1").await.is_none());

    // Interface config in overrides must have wifi_client cleared and dhcp_client disabled
    let persisted = overrides
        .effective_interface("wlan1")
        .await
        .expect("overrides")
        .expect("interface wlan1 exists");
    assert!(persisted.wifi_client.is_none());
    assert!(persisted.managed);
    assert!(!persisted.dhcp_client.expect("dhcp_client block").enabled);

    // Reactivating a profile re-configures DHCP client in supervisor
    let created = service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "reactivate".to_string(),
                ssid: "reactivate-wifi".to_string(),
                country_code: Some("US".to_string()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: false,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    assert!(matches!(created, Response::WifiClientProfile { .. }));

    let activated = service
        .activate_wifi_client_profile_internal("wlan1".to_string(), "reactivate".to_string())
        .await;
    assert!(matches!(
        activated,
        Response::WifiClientProfileActivated { .. }
    ));

    // DHCP client supervisor must now be re-configured
    assert!(dhcp_client.spec("wlan1").await.is_some());
    let persisted_again = overrides
        .effective_interface("wlan1")
        .await
        .expect("overrides")
        .expect("interface wlan1 exists");
    assert!(
        persisted_again
            .dhcp_client
            .expect("dhcp_client block")
            .enabled
    );
}

#[tokio::test]
async fn internal_wifi_client_disable_restores_state_if_persistence_fails() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_client_base_config(directory.path());
    let mut wlan1_cfg = config
        .network
        .interfaces
        .get("wlan1")
        .expect("wlan1 declared")
        .clone();
    wlan1_cfg.managed = true;
    wlan1_cfg.dhcp_client = Some(DhcpClientInterfaceConfig {
        wifi_owned: true,
        ..Default::default()
    });
    config
        .network
        .interfaces
        .insert("wlan1".to_string(), wlan1_cfg.clone());

    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
        .await
        .expect("wifi client supervisor");
    let wifi_spec = WifiClientSpec::from_interface_config("wlan1", &wlan1_cfg)
        .expect("valid")
        .expect("wifi_client declared on wlan1");
    wifi_client
        .configure(wifi_spec)
        .await
        .expect("configure wlan1 wifi");

    let dhcp_client = DhcpClientSupervisor::start(&config, network.clone())
        .await
        .expect("client supervisor");
    let dhcp_spec = DhcpClientSpec::from_interface_config("wlan1", &wlan1_cfg)
        .expect("valid")
        .expect("dhcp_client declared on wlan1");
    dhcp_client.configure(dhcp_spec).await;
    assert!(dhcp_client.spec("wlan1").await.is_some());

    let original = overrides.effective_interface("wlan1").await.unwrap();
    // A directory at the document path prevents replacement even for root.
    std::fs::create_dir(overrides.path()).expect("block override persistence");

    let service = ControlService::new_detached(config, network, dhcp, overrides.clone())
        .with_wifi_client_supervisor(wifi_client.clone())
        .with_dhcp_client_supervisor(dhcp_client.clone());

    let response = service
        .disable_wifi_client_locked("wlan1".to_string())
        .await;
    assert!(
        matches!(&response, Response::WifiClientError {
            detail: WifiClientErrorDetail::Other { message },
        } if message.contains("failed to persist Wi-Fi client disable")
            && message.contains("prior runtime state was restored")),
        "got {response:?}"
    );

    // Both Wi-Fi and DHCP client supervisors must be restored
    assert!(wifi_client.status("wlan1").await.is_some());
    assert!(dhcp_client.spec("wlan1").await.is_some());
    assert_eq!(
        overrides.effective_interface("wlan1").await.unwrap(),
        original
    );
}

#[tokio::test]
async fn internal_wifi_client_disable_restores_state_if_dhcp_disable_fails() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().expect("tempdir");
    let mut config = wifi_client_base_config(directory.path());
    let mut wlan1_cfg = config
        .network
        .interfaces
        .get("wlan1")
        .expect("wlan1 declared")
        .clone();
    wlan1_cfg.managed = true;
    wlan1_cfg.dhcp_client = Some(DhcpClientInterfaceConfig {
        wifi_owned: true,
        ..Default::default()
    });
    config
        .network
        .interfaces
        .insert("wlan1".to_string(), wlan1_cfg.clone());

    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
        .await
        .expect("wifi client supervisor");
    let wifi_spec = WifiClientSpec::from_interface_config("wlan1", &wlan1_cfg)
        .expect("valid")
        .expect("wifi_client declared on wlan1");
    wifi_client
        .configure(wifi_spec)
        .await
        .expect("configure wlan1 wifi");

    let dhcp_client = DhcpClientSupervisor::start(&config, network.clone())
        .await
        .expect("client supervisor");
    let dhcp_spec = DhcpClientSpec::from_interface_config("wlan1", &wlan1_cfg)
        .expect("valid")
        .expect("dhcp_client declared on wlan1");
    dhcp_client.configure(dhcp_spec).await;
    assert!(dhcp_client.spec("wlan1").await.is_some());

    let store = crate::dhcp::client::store::DhcpClientLeaseStore::new(&config.runtime.state_dir)
        .expect("store");
    let lease = crate::dhcp::client::lease::DhcpClientLease {
        schema_version: crate::dhcp::client::lease::DHCP_CLIENT_LEASE_SCHEMA_VERSION,
        state: crate::dhcp::client::lease::DhcpClientLeaseState::Bound,
        interface: "wlan1".into(),
        interface_index: 2,
        hardware_address: vec![2, 0, 0, 0, 0, 1],
        client_identifier: vec![1, 2, 0, 0, 0, 0, 1],
        policy: None,
        server_identifier: std::net::Ipv4Addr::new(192, 0, 2, 1),
        address: std::net::Ipv4Addr::new(192, 0, 2, 20),
        prefix_len: 24,
        routers: vec![std::net::Ipv4Addr::new(192, 0, 2, 1)],
        dns_servers: vec![std::net::Ipv4Addr::new(192, 0, 2, 53)],
        lease_seconds: 3600,
        renewal_seconds: 1800,
        rebinding_seconds: 3150,
        expires_at_unix: 10_000,
        owned_routes: Vec::new(),
    };
    store.save(&lease).expect("save initial lease");

    // Make dhcp-client directory read-only so cleanup save fails during dhcp disable
    let dhcp_client_dir = store.directory();
    std::fs::set_permissions(dhcp_client_dir, std::fs::Permissions::from_mode(0o500))
        .expect("read-only permissions");

    let service = ControlService::new_detached(config, network, dhcp, overrides.clone())
        .with_wifi_client_supervisor(wifi_client.clone())
        .with_dhcp_client_supervisor(dhcp_client.clone());

    let response = service
        .disable_wifi_client_locked("wlan1".to_string())
        .await;
    assert!(
        matches!(response, Response::WifiClientError { .. }),
        "got {response:?}"
    );

    // Restore permissions
    std::fs::set_permissions(dhcp_client_dir, std::fs::Permissions::from_mode(0o700))
        .expect("restore permissions");

    // Both Wi-Fi and DHCP client supervisors must remain configured
    assert!(wifi_client.status("wlan1").await.is_some());
    assert!(dhcp_client.spec("wlan1").await.is_some());

    // Overrides must not have been modified
    let current = overrides
        .effective_interface("wlan1")
        .await
        .expect("overrides")
        .expect("interface exists");
    assert!(current.wifi_client.is_some());
    assert!(current.managed);
}

#[tokio::test]
async fn configure_client_open_erases_obsolete_stored_credentials() {
    let fixture = wifi_client_enabled_fixture().await;
    let wifi = fixture.service.wifi_client.as_ref().unwrap();
    wifi.set_passphrase("wlan1", &WifiPassphrase::new("obsolete-password").unwrap())
        .await
        .unwrap();
    let response = fixture
        .service
        .dispatch(Request::ConfigureWifiClient {
            interface: "wlan1".into(),
            settings: WifiClientEditRequest {
                ssid: "open-network".into(),
                country_code: Some("PL".into()),
                security: WifiClientSecurity::Open,
            },
        })
        .await;
    assert!(
        matches!(response, Response::NetworkChangePending { .. }),
        "{response:?}"
    );
    assert!(wifi.stored_passphrase("wlan1").await.unwrap().is_none());
}

#[tokio::test]
async fn queued_autoconnect_observes_commit_fence_after_admission() {
    let fixture = wifi_client_enabled_fixture().await;
    let created = fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "saved".into(),
                ssid: "saved-wifi".into(),
                country_code: Some("US".into()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: true,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    assert!(matches!(created, Response::WifiClientProfile { .. }));
    fixture
        .service
        .wifi_client
        .as_ref()
        .unwrap()
        .disable("wlan1")
        .await
        .unwrap();
    let next_pid = fixture.process.next_pid.load(WifiOrdering::Relaxed);
    let mutation = fixture.service.network_mutations.write().await;
    let pass = fixture.service.autoconnect_wifi_once();
    tokio::pin!(pass);
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut pass)
        .await
        .is_err());
    fixture.service.overrides.recovery().fence_commit(
        &fixture.service.config.runtime.state_dir,
        "commit failed while autoconnect waited for admission".into(),
    );
    drop(mutation);
    tokio::time::timeout(Duration::from_secs(5), pass)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        fixture.process.next_pid.load(WifiOrdering::Relaxed),
        next_pid,
        "a queued scan must not launch a supplicant after an uncertain commit"
    );
}

#[tokio::test]
async fn client_configuration_converges_before_reply_and_rollback_restores_runtime_without_deadlock(
) {
    let fixture = wifi_client_enabled_fixture().await;
    let (service, worker) = client_convergence_service(&fixture).await;
    let runtime = service.wifi_client.as_ref().unwrap().clone();
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        service.dispatch(Request::ConfigureWifiClient {
            interface: "wlan1".into(),
            settings: WifiClientEditRequest {
                ssid: "tentative-runtime".into(),
                country_code: Some("PL".into()),
                security: WifiClientSecurity::Open,
            },
        }),
    )
    .await
    .expect("dispatch must not hold convergence's execution lock");
    let Response::NetworkChangePending { change } = response else {
        worker.abort();
        panic!("{response:?}")
    };
    assert_eq!(
        runtime.status("wlan1").await.unwrap().spec.ssid,
        "tentative-runtime"
    );
    assert_eq!(
        service.effective_config().await.unwrap().network.interfaces["wlan1"]
            .wifi_client
            .as_ref()
            .unwrap()
            .ssid,
        "upstream"
    );
    let rollback = tokio::time::timeout(
        Duration::from_secs(5),
        service.dispatch(Request::RollbackNetworkChange {
            token: change.token,
        }),
    )
    .await
    .unwrap();
    assert!(
        matches!(rollback, Response::NetworkChangeRolledBack { .. }),
        "{rollback:?}"
    );
    assert_eq!(runtime.status("wlan1").await.unwrap().spec.ssid, "upstream");
    worker.abort();
}

#[tokio::test]
async fn client_password_change_converges_and_rollback_restores_secret_before_consumers() {
    let fixture = wifi_client_fixture_with_security(WifiClientSecurity::Wpa2).await;
    let (service, worker) = client_convergence_service(&fixture).await;
    let store = crate::wifi::PassphraseStore::for_role(
        fixture._directory.path(),
        crate::wifi::store::WifiCredentialRole::Client,
    );
    let committed = service.overrides.snapshot().await;
    let token = network_pending_token(
        service
            .dispatch(Request::WifiClientSetPassphrase {
                interface: "wlan1".into(),
                passphrase: "second client secret".into(),
            })
            .await,
    );
    assert_eq!(
        store.get("wlan1").unwrap().unwrap().expose(),
        "second client secret"
    );
    assert_eq!(service.overrides.snapshot().await, committed);
    let response = service
        .dispatch(Request::RollbackNetworkChange { token })
        .await;
    assert!(
        matches!(response, Response::NetworkChangeRolledBack { .. }),
        "{response:?}"
    );
    assert_eq!(
        store.get("wlan1").unwrap().unwrap().expose(),
        "first client secret"
    );
    assert!(service
        .wifi_client
        .as_ref()
        .unwrap()
        .status("wlan1")
        .await
        .is_some());
    let token = network_pending_token(
        service
            .dispatch(Request::WifiClientSetPassphrase {
                interface: "wlan1".into(),
                passphrase: "confirmed client secret".into(),
            })
            .await,
    );
    assert!(matches!(
        service
            .dispatch(Request::CommitNetworkChange { token })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    assert_eq!(
        store.get("wlan1").unwrap().unwrap().expose(),
        "confirmed client secret"
    );
    let reloaded =
        crate::state::overrides::RuntimeOverrideStore::in_state_dir(fixture._directory.path())
            .load()
            .await
            .unwrap();
    assert_eq!(reloaded.revision, committed.revision + 1);
    worker.abort();
}
