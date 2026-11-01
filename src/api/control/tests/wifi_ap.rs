use super::*;

#[test]
fn interface_edit_request_preserves_existing_wifi_settings_while_managed() {
    let existing_wifi = wifi_ap_config_fixture("home-net");
    let existing = InterfaceConfig {
        wifi_concurrent: false,
        randomize_mac: false,
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
        dhcp: None,
        dhcp_client: None,
        wifi: Some(existing_wifi.clone()),
        wifi_client: None,
    };
    let edit = InterfaceEditRequest {
        wifi_concurrent: false,
        randomize_mac: false,
        mac_address: None,
        cidr: "192.168.60.1/24".to_string(),
        role: InterfaceRole::Output,
        managed: true,
        allow_management_change: false,
    };

    let (config, _) =
        interface_edit_request_to_config(edit, Some(&existing)).expect("edit must convert");

    assert_eq!(
        config.wifi,
        Some(existing_wifi),
        "an edit that never touches Managed must not silently wipe the AP config"
    );
}

#[test]
fn interface_edit_request_drops_wifi_settings_when_unmanaged() {
    let existing = InterfaceConfig {
        wifi_concurrent: false,
        randomize_mac: false,
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
        dhcp: None,
        dhcp_client: None,
        wifi: Some(wifi_ap_config_fixture("home-net")),
        wifi_client: None,
    };
    let edit = InterfaceEditRequest {
        wifi_concurrent: false,
        randomize_mac: false,
        mac_address: None,
        cidr: String::new(),
        role: InterfaceRole::Output,
        managed: false,
        allow_management_change: true,
    };

    let (config, _) =
        interface_edit_request_to_config(edit, Some(&existing)).expect("edit must convert");

    assert_eq!(config.wifi, None);
}

#[tokio::test]
async fn wifi_disable_commit_failure_keeps_the_candidate_pending_until_rollback() {
    let fixture = wifi_enabled_fixture().await;
    // Turn the override file path into a directory. The tentative apply should
    // still succeed; persistence is deliberately deferred until commit.
    std::fs::create_dir(fixture.service.overrides.path()).unwrap();
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending AP deactivation, got {response:?}");
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
async fn wifi_requests_are_rejected_when_wifi_is_disabled() {
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
            .dispatch(Request::GetWifiConfig {
                interface: "wlan0".to_string(),
            })
            .await,
        Response::WifiConfig { spec: None, .. }
    ));

    for request in [
        Request::WifiStatus,
        Request::ConfigureWifi {
            interface: "wlan0".to_string(),
            settings: WifiEditRequest {
                ssid: "net-a".to_string(),
                country_code: Some("PL".to_string()),
                band: WifiBand::Ghz2,
                channel: 6,
                channel_width: WifiChannelWidth::Ht20,
                security: WifiSecurity::Open,
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
        },
        Request::DisableWifi {
            interface: "wlan0".to_string(),
        },
        Request::WifiSetPassphrase {
            interface: "wlan0".to_string(),
            passphrase: "correct horse battery".to_string(),
        },
        Request::ListWifiStations {
            interface: "wlan0".to_string(),
        },
        Request::WifiDeauthStation {
            interface: "wlan0".to_string(),
            mac: "02:00:00:00:00:01".to_string(),
        },
        Request::WifiReload {
            interface: "wlan0".to_string(),
        },
    ] {
        let response = service.dispatch(request).await;
        assert!(
            matches!(
                response,
                Response::WifiError {
                    detail: WifiErrorDetail::WifiDisabled
                }
            ),
            "{response:?}"
        );
    }
}

#[tokio::test]
async fn wifi_status_reports_a_configured_access_point_because_start_up_brought_it_up() {
    let fixture = wifi_enabled_fixture().await;

    assert_eq!(fixture.process.configs.lock().unwrap().len(), 1);

    match fixture.service.dispatch(Request::WifiStatus).await {
        Response::WifiStatus { interfaces } => {
            assert_eq!(interfaces.len(), 1);
            assert_eq!(interfaces[0].interface, "wlan0");
            assert_eq!(interfaces[0].spec.ssid, "net-a");
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn get_wifi_config_reports_none_for_an_interface_without_a_wifi_block() {
    let mut fixture_directory = tempdir().expect("tempdir");
    let mut config = wifi_base_config(fixture_directory.path());
    config.network.interfaces.insert(
        "wan0".to_string(),
        InterfaceConfig {
            wifi_concurrent: false,
            randomize_mac: false,
            mac_address: None,
            role: InterfaceRole::Input,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    let overrides = RuntimeOverrideManager::load(fixture_directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let process = FakeWifiProcess::new();
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        process,
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .expect("wifi supervisor");
    let service =
        ControlService::new_detached(config, network, dhcp, overrides).with_wifi_supervisor(wifi);
    let _ = &mut fixture_directory;

    match service
        .dispatch(Request::GetWifiConfig {
            interface: "wan0".to_string(),
        })
        .await
    {
        Response::WifiConfig { interface, spec } => {
            assert_eq!(interface, "wan0");
            assert!(spec.is_none());
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn get_wifi_config_reports_unknown_interface_as_none_too() {
    let fixture = wifi_enabled_fixture().await;
    match fixture
        .service
        .dispatch(Request::GetWifiConfig {
            interface: "does-not-exist".to_string(),
        })
        .await
    {
        Response::WifiConfig { spec, .. } => assert!(spec.is_none()),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn configure_wifi_keeps_the_new_ssid_tentative_until_commit() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureWifi {
            interface: "wlan0".to_string(),
            settings: WifiEditRequest {
                ssid: "net-b".to_string(),
                country_code: Some("PL".to_string()),
                band: WifiBand::Ghz2,
                channel: 6,
                channel_width: WifiChannelWidth::Ht20,
                security: WifiSecurity::Open,
                hidden: false,
                client_isolation: false,
                max_stations: 32,
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
            .interfaces["wlan0"]
            .wifi
            .as_ref()
            .unwrap()
            .ssid,
        "net-a"
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

    match fixture
        .service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".to_string(),
        })
        .await
    {
        Response::WifiConfig {
            spec: Some(spec), ..
        } => assert_eq!(spec.ssid, "net-b"),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn provision_wifi_access_point_stays_pending_until_explicit_commit() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_base_config(directory.path());
    config.wifi.hostapd_binary = PathBuf::from("/bin/true");
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wlan0", 1).await;
    network
        .interfaces
        .lock()
        .await
        .get_mut("wlan0")
        .expect("wlan0")
        .is_wireless = true;
    let process = FakeWifiProcess::new();
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        process,
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .expect("wifi supervisor");
    configure_wlan0(&wifi, &config).await;
    let service = ControlService::new_detached(config, network, dhcp, overrides.clone())
        .with_wifi_supervisor(wifi);

    let response = service
        .dispatch(Request::ProvisionWifiAccessPoint {
            interface: "wlan0".into(),
            settings: WifiEditRequest {
                ssid: "net-b".into(),
                country_code: Some("PL".into()),
                band: WifiBand::Ghz2,
                channel: 11,
                channel_width: WifiChannelWidth::Ht20,
                security: WifiSecurity::Open,
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
            passphrase: None,
            clear_passphrase: true,
            configure_dhcp: false,
            subnet: None,
            disable_dhcp: false,
        })
        .await;
    let token = match response {
        Response::NetworkChangePending { change } => change.token,
        other => panic!("unexpected response: {other:?}"),
    };

    assert!(!overrides.snapshot().await.interfaces.contains_key("wlan0"));
    match service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".into(),
        })
        .await
    {
        Response::WifiConfig {
            spec: Some(spec), ..
        } => assert_eq!(spec.ssid, "net-a"),
        other => panic!("unexpected response: {other:?}"),
    }

    assert!(matches!(
        service
            .dispatch(Request::CommitNetworkChange { token })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    assert!(overrides.snapshot().await.interfaces.contains_key("wlan0"));
    match service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".into(),
        })
        .await
    {
        Response::WifiConfig {
            spec: Some(spec), ..
        } => {
            assert_eq!(spec.ssid, "net-b");
            assert_eq!(spec.channel, 11);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn configure_wifi_on_an_unknown_interface_is_interface_not_found() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureWifi {
            interface: "does-not-exist".to_string(),
            settings: WifiEditRequest {
                ssid: "net-a".to_string(),
                country_code: None,
                band: WifiBand::Ghz2,
                channel: 6,
                channel_width: WifiChannelWidth::Ht20,
                security: WifiSecurity::Open,
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
        })
        .await;
    assert!(matches!(
        response,
        Response::WifiError {
            detail: WifiErrorDetail::InterfaceNotFound
        }
    ));
}

#[tokio::test]
async fn disable_wifi_is_tentative_until_explicit_commit() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending AP deactivation, got {response:?}");
    };

    // Committed intent is unchanged while the candidate is awaiting approval.
    match fixture
        .service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".to_string(),
        })
        .await
    {
        Response::WifiConfig { spec, .. } => assert!(spec.is_some()),
        other => panic!("unexpected response: {other:?}"),
    }

    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    match fixture
        .service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".to_string(),
        })
        .await
    {
        Response::WifiConfig { spec, .. } => assert!(spec.is_none()),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn list_wifi_stations_on_an_unconfigured_interface_is_interface_not_found() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::ListWifiStations {
            interface: "does-not-exist".to_string(),
        })
        .await;
    assert!(matches!(
        response,
        Response::WifiError {
            detail: WifiErrorDetail::InterfaceNotFound
        }
    ));
}

#[tokio::test]
async fn wifi_deauth_station_rejects_a_malformed_mac() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::WifiDeauthStation {
            interface: "wlan0".to_string(),
            mac: "not-a-mac".to_string(),
        })
        .await;
    assert!(matches!(
        response,
        Response::WifiError {
            detail: WifiErrorDetail::InvalidSpec { .. }
        }
    ));
}

#[tokio::test]
async fn wifi_reload_sends_reload_and_returns_the_current_spec() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::WifiReload {
            interface: "wlan0".to_string(),
        })
        .await;
    match response {
        Response::WifiConfigured { spec } => assert_eq!(spec.ssid, "net-a"),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn replacing_or_clearing_ap_secret_removes_legacy_passphrase_file_fallback() {
    let previous = std::path::PathBuf::from("/run/legacy.psk");
    assert_eq!(
        crate::api::control::wifi::ap_passphrase_file_update(
            Some(&previous),
            &crate::wifi::WifiPassphraseUpdate::Keep,
        ),
        Some(previous.clone())
    );
    assert!(crate::api::control::wifi::ap_passphrase_file_update(
        Some(&previous),
        &crate::wifi::WifiPassphraseUpdate::Clear,
    )
    .is_none());
    assert!(crate::api::control::wifi::ap_passphrase_file_update(
        Some(&previous),
        &crate::wifi::WifiPassphraseUpdate::Set(
            crate::wifi::WifiPassphrase::new("replacement password").unwrap(),
        ),
    )
    .is_none());
}

#[test]
fn ap_passphrase_update_rejects_set_and_clear_together() {
    let error = crate::api::control::wifi::ap_passphrase_update(
        WifiSecurity::Wpa2,
        Some("correct horse battery".into()),
        true,
    )
    .expect_err("set and clear must conflict");
    assert!(matches!(error, WifiErrorDetail::InvalidSpec { .. }));
}

#[test]
fn secured_ap_passphrase_update_rejects_clear_without_replacement() {
    let error = crate::api::control::wifi::ap_passphrase_update(WifiSecurity::Wpa2, None, true)
        .expect_err("secured AP cannot clear its only credential");
    assert!(matches!(error, WifiErrorDetail::InvalidSpec { .. }));
}

#[tokio::test]
async fn configure_wifi_wpa2_to_open_clears_the_stored_passphrase() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_base_config(directory.path());
    config.network.interfaces.get_mut("wlan0").unwrap().wifi =
        Some(wifi_ap_config("net-a", WifiSecurity::Wpa2));
    let store = crate::wifi::PassphraseStore::new(directory.path().join("wifi/psk-ap"));
    store
        .set(
            "wlan0",
            &crate::wifi::WifiPassphrase::new("original password").unwrap(),
        )
        .unwrap();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wlan0", 1).await;
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        FakeWifiProcess::new(),
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .expect("wifi supervisor");
    configure_wlan0(&wifi, &config).await;
    let service =
        ControlService::new_detached(config, network, dhcp, overrides).with_wifi_supervisor(wifi);

    let response = service
        .dispatch(Request::ConfigureWifi {
            interface: "wlan0".to_string(),
            settings: WifiEditRequest {
                ssid: "net-a".to_string(),
                country_code: Some("PL".to_string()),
                band: WifiBand::Ghz2,
                channel: 6,
                channel_width: WifiChannelWidth::Ht20,
                security: WifiSecurity::Open,
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
        })
        .await;
    assert!(
        matches!(response, Response::NetworkChangePending { .. }),
        "{response:?}"
    );
    assert!(store.get("wlan0").unwrap().is_none());
}

#[tokio::test]
async fn disable_wifi_secret_clear_rolls_back_and_commits_with_the_network_change() {
    let fixture = wifi_enabled_fixture().await;
    let store = crate::wifi::PassphraseStore::new(fixture._directory.path().join("wifi/psk-ap"));
    store
        .set(
            "wlan0",
            &crate::wifi::WifiPassphrase::new("stale password").unwrap(),
        )
        .unwrap();

    let first = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = first else {
        panic!("expected pending AP deactivation, got {first:?}");
    };
    assert!(store.get("wlan0").unwrap().is_none());
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
        store.get("wlan0").unwrap().unwrap().expose(),
        "stale password"
    );

    let second = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = second else {
        panic!("expected pending AP deactivation, got {second:?}");
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
    assert!(store.get("wlan0").unwrap().is_none());
}

#[tokio::test]
async fn configure_wifi_to_wpa2_without_a_passphrase_is_refused_and_changes_nothing() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureWifi {
            interface: "wlan0".to_string(),
            settings: WifiEditRequest {
                ssid: "net-a".to_string(),
                country_code: Some("PL".to_string()),
                band: WifiBand::Ghz2,
                channel: 6,
                channel_width: WifiChannelWidth::Ht20,
                security: WifiSecurity::Wpa2,
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
        })
        .await;
    assert!(
        matches!(
            response,
            Response::WifiError {
                detail: WifiErrorDetail::PassphraseMissing
            }
        ),
        "{response:?}"
    );

    match fixture
        .service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".to_string(),
        })
        .await
    {
        Response::WifiConfig {
            spec: Some(spec), ..
        } => assert_eq!(spec.security, WifiSecurity::Open),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn wifi_passphrase_is_tentative_and_restored_or_committed() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_base_config(directory.path());
    config.network.interfaces.insert(
        "wlan0".to_string(),
        InterfaceConfig {
            wifi_concurrent: false,
            randomize_mac: false,
            mac_address: None,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.101.1/24".parse().unwrap()),
            dhcp: None,
            dhcp_client: None,
            wifi: Some(wifi_ap_config("net-a", WifiSecurity::Wpa2)),
            wifi_client: None,
        },
    );
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wlan0", 1).await;
    let process = FakeWifiProcess::new();
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        process,
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .expect("wifi supervisor");

    let passphrase_store = crate::wifi::PassphraseStore::new(directory.path().join("wifi/psk-ap"));
    passphrase_store
        .set(
            "wlan0",
            &crate::wifi::WifiPassphrase::new("first passphrase").unwrap(),
        )
        .unwrap();
    configure_wlan0(&wifi, &config).await;
    let service =
        ControlService::new_detached(config, network, dhcp, overrides).with_wifi_supervisor(wifi);

    let response = service
        .dispatch(Request::WifiSetPassphrase {
            interface: "wlan0".to_string(),
            passphrase: "second passphrase".to_string(),
        })
        .await;
    let token = network_pending_token(response);
    assert_eq!(
        passphrase_store.get("wlan0").unwrap().unwrap().expose(),
        "second passphrase"
    );
    let response = service
        .dispatch(Request::RollbackNetworkChange { token })
        .await;
    assert!(
        matches!(response, Response::NetworkChangeRolledBack { .. }),
        "{response:?}"
    );
    assert_eq!(
        passphrase_store.get("wlan0").unwrap().unwrap().expose(),
        "first passphrase"
    );
    let token = network_pending_token(
        service
            .dispatch(Request::WifiSetPassphrase {
                interface: "wlan0".into(),
                passphrase: "third passphrase".into(),
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
        passphrase_store.get("wlan0").unwrap().unwrap().expose(),
        "third passphrase"
    );
}

#[test]
fn no_wifi_response_variant_can_hold_a_passphrase() {
    fn assert_no_passphrase_field(spec: &crate::api::model::WifiApSpecView) {
        let crate::api::model::WifiApSpecView {
            interface: _,
            ssid: _,
            country_code: _,
            band: _,
            channel: _,
            channel_width: _,
            security: _,
            hidden: _,
            client_isolation: _,
            max_stations: _,
            passphrase_file: _,
        } = spec;
    }
    let _ = assert_no_passphrase_field;
}

#[tokio::test]
async fn wifi_configured_response_never_serializes_the_passphrase_that_was_just_set() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_base_config(directory.path());
    config.network.interfaces.insert(
        "wlan0".to_string(),
        InterfaceConfig {
            wifi_concurrent: false,
            randomize_mac: false,
            mac_address: None,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.101.1/24".parse().unwrap()),
            dhcp: None,
            dhcp_client: None,
            wifi: Some(wifi_ap_config("net-a", WifiSecurity::Wpa2)),
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
    let process = FakeWifiProcess::new();

    let passphrase_store = crate::wifi::PassphraseStore::new(directory.path().join("wifi/psk-ap"));
    passphrase_store
        .set(
            "wlan0",
            &crate::wifi::WifiPassphrase::new("seed passphrase").unwrap(),
        )
        .unwrap();
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        process,
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .expect("wifi supervisor");
    configure_wlan0(&wifi, &config).await;
    let service =
        ControlService::new_detached(config, network, dhcp, overrides).with_wifi_supervisor(wifi);

    let secret = "super secret passphrase, must never leak";
    let response = service
        .dispatch(Request::WifiSetPassphrase {
            interface: "wlan0".to_string(),
            passphrase: secret.to_string(),
        })
        .await;
    let encoded = serde_json::to_string(&response).expect("serialize");
    assert!(
        !encoded.contains(secret),
        "a Wi-Fi response must never echo back a passphrase: {encoded}"
    );

    for other in [
        service.dispatch(Request::WifiStatus).await,
        service
            .dispatch(Request::GetWifiConfig {
                interface: "wlan0".to_string(),
            })
            .await,
        service
            .dispatch(Request::ListWifiStations {
                interface: "wlan0".to_string(),
            })
            .await,
    ] {
        let encoded = serde_json::to_string(&other).expect("serialize");
        assert!(!encoded.contains(secret), "{encoded}");
    }
}

#[tokio::test]
async fn a_passphrase_is_never_echoed_back_in_any_response() {
    const SECRET: &str = "a-very-secret-passphrase";
    let fixture = wifi_client_enabled_fixture().await;

    fixture
        .service
        .dispatch(Request::ConfigureWifiClient {
            interface: "wlan1".to_string(),
            settings: WifiClientEditRequest {
                ssid: "upstream".to_string(),
                country_code: Some("PL".to_string()),
                security: WifiClientSecurity::Wpa2,
            },
        })
        .await;
    let set = fixture
        .service
        .dispatch(Request::WifiClientSetPassphrase {
            interface: "wlan1".to_string(),
            passphrase: SECRET.to_string(),
        })
        .await;
    let status = fixture.service.dispatch(Request::WifiClientStatus).await;
    let config = fixture
        .service
        .dispatch(Request::GetWifiClientConfig {
            interface: "wlan1".to_string(),
        })
        .await;

    for response in [set, status, config] {
        let encoded = serde_json::to_string(&response).expect("serialize");
        assert!(
            !encoded.contains(SECRET),
            "a passphrase leaked into {encoded}"
        );
    }
}

#[tokio::test]
async fn saved_ap_profile_activation_stays_pending_until_explicit_commit() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_base_config(directory.path());
    config.wifi.hostapd_binary = PathBuf::from("/bin/true");
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wlan0", 1).await;
    network
        .interfaces
        .lock()
        .await
        .get_mut("wlan0")
        .expect("wlan0")
        .is_wireless = true;
    let process = FakeWifiProcess::new();
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        process,
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .expect("wifi supervisor");
    configure_wlan0(&wifi, &config).await;
    let service = ControlService::new_detached(config, network, dhcp, overrides.clone())
        .with_wifi_supervisor(wifi);

    let saved = service
        .dispatch(Request::SaveWifiApProfile {
            profile: crate::api::model::WifiApProfileWriteRequest {
                id: "guest".into(),
                configuration: crate::api::model::ProvisionWifiAccessPointRequest {
                    settings: WifiEditRequest {
                        ssid: "net-b".into(),
                        country_code: Some("PL".into()),
                        band: WifiBand::Ghz2,
                        channel: 11,
                        channel_width: WifiChannelWidth::Ht20,
                        security: WifiSecurity::Open,
                        hidden: false,
                        client_isolation: true,
                        max_stations: 32,
                    },
                    passphrase: None,
                    clear_passphrase: true,
                    configure_dhcp: false,
                    subnet: None,
                    disable_dhcp: false,
                },
            },
        })
        .await;
    assert!(
        matches!(saved, Response::WifiApProfileSaved { .. }),
        "{saved:?}"
    );
    let response = service
        .dispatch(Request::ActivateWifiApProfile {
            interface: "wlan0".into(),
            profile_id: "guest".into(),
        })
        .await;
    let token = match response {
        Response::NetworkChangePending { change } => change.token,
        other => panic!("unexpected response: {other:?}"),
    };

    assert!(!overrides.snapshot().await.interfaces.contains_key("wlan0"));
    match service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".into(),
        })
        .await
    {
        Response::WifiConfig {
            spec: Some(spec), ..
        } => assert_eq!(spec.ssid, "net-a"),
        other => panic!("unexpected response: {other:?}"),
    }

    assert!(matches!(
        service
            .dispatch(Request::CommitNetworkChange { token })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    assert!(overrides.snapshot().await.interfaces.contains_key("wlan0"));
    match service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".into(),
        })
        .await
    {
        Response::WifiConfig {
            spec: Some(spec), ..
        } => {
            assert_eq!(spec.ssid, "net-b");
            assert_eq!(spec.channel, 11);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn hotspot_provision_uses_preassigned_output_role_and_subnet_atomically() {
    let directory = tempdir().unwrap();
    let mut config = wifi_base_config(directory.path());
    config.wifi.hostapd_binary = PathBuf::from("/bin/true");
    config.network.interfaces.get_mut("wlan0").unwrap().wifi = None;
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wlan0", 1).await;
    network
        .interfaces
        .lock()
        .await
        .get_mut("wlan0")
        .unwrap()
        .is_wireless = true;
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        FakeWifiProcess::new(),
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .unwrap();
    let service = ControlService::new_detached(config, network, dhcp, overrides.clone())
        .with_wifi_supervisor(wifi);
    let response = service
        .dispatch(Request::ProvisionWifiAccessPoint {
            interface: "wlan0".into(),
            settings: WifiEditRequest {
                ssid: "hotspot".into(),
                country_code: Some("PL".into()),
                band: WifiBand::Ghz2,
                channel: 6,
                channel_width: WifiChannelWidth::Ht20,
                security: WifiSecurity::Open,
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
            passphrase: None,
            clear_passphrase: true,
            configure_dhcp: true,
            subnet: Some("192.168.50.1/24".parse().unwrap()),
            disable_dhcp: false,
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("{response:?}")
    };
    assert!(overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap()
        .wifi
        .is_none());
    assert!(matches!(
        service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    let committed = overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    assert!(committed.managed);
    assert_eq!(committed.role, InterfaceRole::Output);
    assert_eq!(committed.ipv4, Some("192.168.50.1/24".parse().unwrap()));
    assert_eq!(committed.wifi.unwrap().ssid, "hotspot");
    assert_eq!(
        committed.dhcp.unwrap().router,
        "192.168.50.1".parse::<Ipv4Addr>().unwrap()
    );
}

#[tokio::test]
async fn every_wifi_admission_path_rejects_mixed_roles_on_one_phy_before_mutation() {
    let (service, _directory) = shared_phy_wifi_service().await;
    let ap = WifiEditRequest {
        ssid: "changed-ap".into(),
        country_code: Some("PL".into()),
        band: WifiBand::Ghz2,
        channel: 6,
        channel_width: WifiChannelWidth::Ht20,
        security: WifiSecurity::Open,
        hidden: false,
        client_isolation: false,
        max_stations: 32,
    };
    for request in [
        Request::ConfigureWifi {
            interface: "wlan0".into(),
            settings: ap.clone(),
        },
        Request::ProvisionWifiAccessPoint {
            interface: "wlan0".into(),
            settings: ap,
            passphrase: None,
            clear_passphrase: true,
            configure_dhcp: false,
            subnet: None,
            disable_dhcp: false,
        },
        Request::ConfigureWifiClient {
            interface: "wlan1".into(),
            settings: WifiClientEditRequest {
                ssid: "changed-sta".into(),
                country_code: Some("PL".into()),
                security: WifiClientSecurity::Open,
            },
        },
        Request::ProvisionWifiClient {
            interface: "wlan1".into(),
            settings: crate::api::model::ProvisionWifiClientRequest {
                profile_id: "radio-test".into(),
                ip_policy: crate::api::model::WifiClientIpPolicy::Preserve,
            },
        },
        Request::ActivateWifiClientProfile {
            interface: "wlan1".into(),
            profile_id: "radio-test".into(),
        },
        Request::WifiClientScan {
            interface: "wlan1".into(),
        },
    ] {
        let response = service.dispatch(request).await;
        assert!(
            serde_json::to_string(&response)
                .unwrap()
                .contains("shared-radio"),
            "{response:?}"
        );
        assert!(service.transactions.pending().await.is_empty());
        assert!(service.overrides.snapshot().await.interfaces.is_empty());
    }
    let response = service
        .activate_wifi_client_profile_internal("wlan1".into(), "radio-test".into())
        .await;
    assert!(
        serde_json::to_string(&response)
            .unwrap()
            .contains("shared-radio"),
        "{response:?}"
    );
    service.autoconnect_wifi_once().await.unwrap();
    assert!(service.overrides.snapshot().await.interfaces.is_empty());
    assert!(service
        .wifi
        .as_ref()
        .unwrap()
        .status("wlan0")
        .await
        .is_none());
    assert!(service
        .wifi_client
        .as_ref()
        .unwrap()
        .status("wlan1")
        .await
        .is_none());
}

#[tokio::test]
async fn wifi_liveness_cannot_restart_a_task_removed_or_changed_by_newer_intent() {
    let ap = wifi_enabled_fixture().await;
    let client = wifi_client_enabled_fixture().await;
    ap.process.responders.lock().unwrap().clear();
    ap.process.configs.lock().unwrap().clear();
    client.process.responders.lock().unwrap().clear();
    client.process.configs.lock().unwrap().clear();
    for removed in [false, true] {
        let mut config = ap.service.base_config.clone();
        if removed {
            config.network.interfaces.get_mut("wlan0").unwrap().wifi = None;
        } else {
            config
                .network
                .interfaces
                .get_mut("wlan0")
                .unwrap()
                .wifi
                .as_mut()
                .unwrap()
                .ssid = "newer-ap".into();
        }
        assert!(!ap
            .service
            .wifi
            .as_ref()
            .unwrap()
            .ensure_alive_for_config(&config)
            .await
            .unwrap());
        assert!(ap.process.configs.lock().unwrap().is_empty());
        let mut config = client.service.base_config.clone();
        if removed {
            config
                .network
                .interfaces
                .get_mut("wlan1")
                .unwrap()
                .wifi_client = None;
        } else {
            config
                .network
                .interfaces
                .get_mut("wlan1")
                .unwrap()
                .wifi_client
                .as_mut()
                .unwrap()
                .ssid = "newer-client".into();
        }
        assert!(!client
            .service
            .wifi_client
            .as_ref()
            .unwrap()
            .ensure_alive_for_config(&config)
            .await
            .unwrap());
        assert!(client.process.configs.lock().unwrap().is_empty());
    }
}
