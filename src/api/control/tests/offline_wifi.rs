use super::*;

#[tokio::test]
async fn saved_wifi_client_profile_crud_activation_and_active_delete_guard() {
    let fixture = wifi_client_enabled_fixture().await;
    let create = fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "office".to_string(),
                ssid: "profile-network".to_string(),
                country_code: Some("PL".to_string()),
                security: WifiClientSecurity::Open,
                priority: 10,
                autoconnect: false,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    let Response::WifiClientProfile { profile } = create else {
        panic!("expected profile response, got {create:?}");
    };
    assert_eq!(profile.id, "office");
    assert!(!profile.has_passphrase);
    let serialized = serde_json::to_string(&profile).unwrap();
    assert!(serialized.contains("has_passphrase"));
    assert!(!serialized.contains("a-secret-value"));

    let Response::WifiClientProfiles { profiles } = fixture
        .service
        .dispatch(Request::ListWifiClientProfiles)
        .await
    else {
        panic!("expected profile list");
    };
    assert_eq!(profiles.len(), 1);

    let activated = fixture
        .service
        .activate_wifi_client_profile_internal("wlan1".to_string(), "office".to_string())
        .await;
    assert!(matches!(
        activated,
        Response::WifiClientProfileActivated { .. }
    ));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::DeleteWifiClientProfile {
                id: "office".to_string(),
            })
            .await,
        Response::WifiClientProfileError {
            detail: WifiClientProfileErrorDetail::ProfileActive { .. }
        }
    ));

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
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));

    // This fixture has no convergence worker. Realize the committed removal
    // before checking the runtime-based active-profile deletion guard.
    fixture
        .service
        .wifi_client
        .as_ref()
        .unwrap()
        .disable("wlan1")
        .await
        .unwrap();

    assert!(matches!(
        fixture
            .service
            .dispatch(Request::DeleteWifiClientProfile {
                id: "office".to_string(),
            })
            .await,
        Response::WifiClientProfileDeleted { .. }
    ));
}

#[tokio::test]
async fn wifi_inventory_and_config_include_saved_missing_ap_without_runtime() {
    let (service, _directory) = saved_wifi_without_runtime().await;
    match service.dispatch(Request::ListWifiInventory).await {
        Response::WifiInventory { interfaces, .. } => {
            assert_eq!(interfaces.len(), 1);
            let row = &interfaces[0];
            assert_eq!(
                row.interface.presence,
                traffic_masq_protocol::InterfacePresence::Missing
            );
            assert!(row.interface.observed.is_none());
            assert!(row.ap_runtime.is_none());
            assert!(row.client_runtime.is_none());
            assert_eq!(
                row.interface
                    .configured
                    .as_ref()
                    .unwrap()
                    .wifi
                    .as_ref()
                    .unwrap()
                    .ssid,
                "net-a"
            );
        }
        response => panic!("{response:?}"),
    }
    assert!(matches!(
        service
            .dispatch(Request::GetWifiConfig {
                interface: "wlan0".into()
            })
            .await,
        Response::WifiConfig { spec: Some(_), .. }
    ));
}

#[tokio::test]
async fn missing_wifi_password_creates_new_durable_reference_and_preserves_old_secret() {
    let (service, directory) = saved_wifi_without_runtime().await;
    let old_config = service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    let old_file = old_config
        .wifi
        .as_ref()
        .unwrap()
        .passphrase_file
        .clone()
        .unwrap();
    let response = service
        .dispatch(Request::WifiSetPassphrase {
            interface: "wlan0".into(),
            passphrase: "replacement-password".into(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::InterfaceIntentSaved { deferred: true, .. }
        ),
        "{response:?}"
    );
    let saved = service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    let new_file = saved.wifi.unwrap().passphrase_file.unwrap();
    assert_ne!(old_file, new_file);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&new_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(new_file.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let wire = serde_json::to_string(&response).unwrap();
    assert!(!wire.contains("replacement-password"));
    assert!(!wire.contains("previous-password"));
    assert_eq!(
        std::fs::read_to_string(&old_file).unwrap(),
        "previous-password"
    );
    assert_eq!(
        std::fs::read_to_string(&new_file).unwrap(),
        "replacement-password"
    );
    let restarted = RuntimeOverrideManager::load(directory.path(), &service.base_config)
        .await
        .unwrap();
    assert_eq!(
        restarted
            .effective_interface("wlan0")
            .await
            .unwrap()
            .unwrap()
            .wifi
            .unwrap()
            .passphrase_file,
        Some(new_file)
    );
    let response = service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    assert!(service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap()
        .wifi
        .is_none());
    assert!(old_file.exists());
}

#[tokio::test]
async fn offline_wifi_secret_commit_failure_keeps_previous_intent_and_credential() {
    let (service, _directory) = saved_wifi_without_runtime().await;
    let previous = service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    let previous_file = previous
        .wifi
        .as_ref()
        .unwrap()
        .passphrase_file
        .as_ref()
        .unwrap();
    std::fs::create_dir(service.overrides.path()).unwrap();
    let response = service
        .dispatch(Request::SaveWifiInterface {
            interface: "wlan0".into(),
            config: previous.clone().into(),
            expected_revision: 0,
            passphrase: Some("replacement-password".into()),
        })
        .await;
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert_eq!(service.overrides.committed_revision().await, 0);
    assert_eq!(
        service
            .overrides
            .effective_interface("wlan0")
            .await
            .unwrap(),
        Some(previous.clone())
    );
    assert_eq!(
        std::fs::read_to_string(previous_file).unwrap(),
        "previous-password"
    );
}

#[tokio::test]
async fn stale_wifi_editor_cannot_restore_forgotten_configuration_or_change_its_secret() {
    let (service, _directory) = saved_wifi_without_runtime().await;
    let previous = service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    let old_file = previous
        .wifi
        .as_ref()
        .unwrap()
        .passphrase_file
        .as_ref()
        .unwrap();
    let response = service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "wlan0".into(),
            expected_revision: 0,
        })
        .await;
    assert!(matches!(response, Response::InterfaceIntentSaved { .. }));
    let response = service
        .dispatch(Request::SaveWifiInterface {
            interface: "wlan0".into(),
            config: previous.clone().into(),
            expected_revision: 0,
            passphrase: Some("replacement-password".into()),
        })
        .await;
    assert!(matches!(response, Response::Error { .. }));
    assert!(service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        std::fs::read_to_string(old_file).unwrap(),
        "previous-password"
    );
}

#[tokio::test]
async fn unplugged_ap_disable_stops_owned_process_before_committing_intent() {
    let fixture = wifi_enabled_fixture().await;
    let runtime = fixture.service.wifi.as_ref().unwrap();
    let pid = runtime.status("wlan0").await.unwrap().pid;
    fixture.network.interfaces.lock().await.remove("wlan0");
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::InterfaceIntentSaved { deferred: true, .. }
        ),
        "{response:?}"
    );
    assert!(!fixture.process.is_alive(pid).await.unwrap());
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
    let restarted =
        RuntimeOverrideManager::load(fixture._directory.path(), &fixture.service.base_config)
            .await
            .unwrap();
    assert!(restarted
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap()
        .wifi
        .is_none());
    runtime.ensure_alive().await.unwrap();
    assert!(fixture.process.configs.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unplugged_ap_persistence_failure_keeps_previous_durable_intent_and_wakes_reconcile() {
    let fixture = wifi_enabled_fixture().await;
    let runtime = fixture.service.wifi.as_ref().unwrap();
    let pid = runtime.status("wlan0").await.unwrap().pid;
    let previous = fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    fixture.network.interfaces.lock().await.remove("wlan0");
    std::fs::create_dir(fixture.service.overrides.path()).unwrap();
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert!(!fixture.process.is_alive(pid).await.unwrap());
    assert!(runtime.status("wlan0").await.is_none());
    assert_eq!(fixture.service.overrides.committed_revision().await, 0);
    assert_eq!(
        fixture
            .service
            .overrides
            .effective_interface("wlan0")
            .await
            .unwrap(),
        Some(previous.clone())
    );
    tokio::time::timeout(
        Duration::from_millis(100),
        fixture.service.overrides.changed(),
    )
    .await
    .unwrap();
    std::fs::remove_dir(fixture.service.overrides.path()).unwrap();
    let restarted =
        RuntimeOverrideManager::load(fixture._directory.path(), &fixture.service.base_config)
            .await
            .unwrap();
    assert_eq!(
        restarted.effective_interface("wlan0").await.unwrap(),
        Some(previous)
    );
}

#[tokio::test]
async fn unplugged_ap_changed_process_proof_blocks_cleanup_and_preserves_intent() {
    let fixture = wifi_enabled_fixture().await;
    let runtime = fixture.service.wifi.as_ref().unwrap();
    let pid = runtime.status("wlan0").await.unwrap().pid;
    fixture.network.interfaces.lock().await.remove("wlan0");
    // Model PID reuse / external replacement of the recorded process identity.
    fixture
        .process
        .configs
        .lock()
        .unwrap()
        .insert(pid, fixture._directory.path().join("foreign.conf"));
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert!(fixture.process.is_alive(pid).await.unwrap());
    assert!(runtime.status("wlan0").await.is_some());
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
}

#[tokio::test]
async fn unplugged_client_with_exited_unadopted_record_can_save_offline_intent() {
    for placeholder in [false, true] {
        for operation in ["unmanage", "edit", "forget"] {
            let mut fixture = wifi_client_enabled_fixture().await;
            let status = fixture
                .service
                .wifi_client
                .as_ref()
                .unwrap()
                .status("wlan1")
                .await
                .unwrap();
            let store = crate::wifi::record::WifiRecordStore::for_client(
                fixture._directory.path().join("wifi"),
                &fixture.service.config.wifi_client.runtime_dir,
                "wlan1",
            );
            fixture.network.missing.store(true, WifiOrdering::SeqCst);
            // Unplug/restart: the process and socket are gone, but the durable
            // record survives and startup skips adoption of the absent NIC.
            fixture.process.terminate(status.pid).await.unwrap();
            let runtime = ClientSupervisor::open_with_process_for_recovery(
                fixture.service.overrides.recovery().clone(),
                &fixture.service.config,
                fixture.process.clone(),
            );
            if placeholder {
                runtime
                    .record_failed_startup(&status.spec, "device disappeared")
                    .await;
            }
            fixture.service.wifi_client = Some(runtime);
            assert!(store.load().await.unwrap().is_some());
            let mut config = fixture
                .service
                .overrides
                .effective_interface("wlan1")
                .await
                .unwrap()
                .unwrap();
            let request = match operation {
                "unmanage" => {
                    config.managed = false;
                    config.wifi_client = None;
                    config.dhcp_client = None;
                    Request::SaveInterfaceConfig {
                        interface: "wlan1".into(),
                        config: config.clone().into(),
                        allow_management_change: true,
                        expected_revision: 0,
                    }
                }
                "edit" => {
                    config.wifi_client.as_mut().unwrap().ssid = "offline-upstream".into();
                    Request::SaveWifiInterface {
                        interface: "wlan1".into(),
                        config: config.clone().into(),
                        expected_revision: 0,
                        passphrase: None,
                    }
                }
                "forget" => Request::ForgetInterfaceConfig {
                    interface: "wlan1".into(),
                    expected_revision: 0,
                },
                _ => unreachable!(),
            };
            let response = fixture.service.dispatch(request).await;
            assert!(
                matches!(response, Response::InterfaceIntentSaved { .. }),
                "{operation}, placeholder={placeholder}: {response:?}"
            );
            assert!(store.load().await.unwrap().is_none());
            assert!(!fixture
                .service
                .config
                .wifi_client
                .runtime_dir
                .join("wlan1.conf")
                .exists());
            assert!(fixture
                .service
                .wifi_client
                .as_ref()
                .unwrap()
                .status("wlan1")
                .await
                .is_none());
            assert_eq!(fixture.service.overrides.committed_revision().await, 1);
            let restarted = RuntimeOverrideManager::load(
                fixture._directory.path(),
                &fixture.service.base_config,
            )
            .await
            .unwrap();
            assert_eq!(
                restarted.effective_interface("wlan1").await.unwrap(),
                (operation != "forget").then_some(config)
            );
            assert!(fixture.process.configs.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn unplugged_ap_with_exited_unadopted_record_can_be_forgotten() {
    let mut fixture = wifi_enabled_fixture().await;
    let pid = fixture
        .service
        .wifi
        .as_ref()
        .unwrap()
        .status("wlan0")
        .await
        .unwrap()
        .pid;
    fixture.network.interfaces.lock().await.remove("wlan0");
    fixture.process.terminate(pid).await.unwrap();
    fixture.service.wifi = Some(WifiSupervisor::open_with_process_for_recovery(
        fixture.service.overrides.recovery().clone(),
        &fixture.service.config,
        fixture.process.clone(),
    ));
    let response = fixture
        .service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "wlan0".into(),
            expected_revision: 0,
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    let store = crate::wifi::record::WifiRecordStore::for_access_point(
        fixture._directory.path().join("wifi"),
        &fixture.service.config.wifi.runtime_dir,
        "wlan0",
    );
    assert!(store.load().await.unwrap().is_none());
    assert!(fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn unplugged_client_unadopted_record_retains_intent_for_live_process_or_foreign_socket() {
    for live_process in [false, true] {
        let mut fixture = wifi_client_enabled_fixture().await;
        let pid = fixture
            .service
            .wifi_client
            .as_ref()
            .unwrap()
            .status("wlan1")
            .await
            .unwrap()
            .pid;
        fixture.network.missing.store(true, WifiOrdering::SeqCst);
        let _foreign = if live_process {
            None
        } else {
            fixture.process.terminate(pid).await.unwrap();
            Some(
                std::os::unix::net::UnixDatagram::bind(
                    fixture.service.config.wifi_client.runtime_dir.join("wlan1"),
                )
                .unwrap(),
            )
        };
        fixture.service.wifi_client = Some(ClientSupervisor::open_with_process_for_recovery(
            fixture.service.overrides.recovery().clone(),
            &fixture.service.config,
            fixture.process.clone(),
        ));
        let response = fixture
            .service
            .dispatch(Request::ForgetInterfaceConfig {
                interface: "wlan1".into(),
                expected_revision: 0,
            })
            .await;
        assert!(matches!(response, Response::Error { .. }), "{response:?}");
        assert_eq!(fixture.process.is_alive(pid).await.unwrap(), live_process);
        assert_eq!(fixture.service.overrides.committed_revision().await, 0);
        let store = crate::wifi::record::WifiRecordStore::for_client(
            fixture._directory.path().join("wifi"),
            &fixture.service.config.wifi_client.runtime_dir,
            "wlan1",
        );
        assert!(store.load().await.unwrap().is_some());
        assert!(fixture
            .service
            .config
            .wifi_client
            .runtime_dir
            .join("wlan1")
            .exists());
    }
}

#[tokio::test]
async fn unplugged_client_disable_stops_supplicant_and_dhcp_before_commit() {
    let fixture = wifi_client_enabled_fixture().await;
    let runtime = fixture.service.wifi_client.as_ref().unwrap();
    let dhcp = fixture.service.dhcp_client.as_ref().unwrap();
    let pid = runtime.status("wlan1").await.unwrap().pid;
    fixture.network.missing.store(true, WifiOrdering::SeqCst);
    let response = fixture
        .service
        .dispatch(Request::DisableWifiClient {
            interface: "wlan1".into(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::InterfaceIntentSaved { deferred: true, .. }
        ),
        "{response:?}"
    );
    assert!(!fixture.process.is_alive(pid).await.unwrap());
    assert!(runtime.status("wlan1").await.is_none());
    assert!(dhcp.spec("wlan1").await.is_none());
    let config = fixture
        .service
        .overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .unwrap();
    assert!(config.wifi_client.is_none());
    // The fixture's DHCP policy was configured independently of Wi-Fi.
    assert!(config.dhcp_client.unwrap().enabled);
    runtime.ensure_alive().await.unwrap();
    assert!(fixture.process.configs.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unplugged_ap_provisioning_commits_new_secret_after_runtime_cleanup() {
    let fixture = wifi_enabled_fixture().await;
    let runtime = fixture.service.wifi.as_ref().unwrap();
    let pid = runtime.status("wlan0").await.unwrap().pid;
    fixture.network.interfaces.lock().await.remove("wlan0");
    let mut config = fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    let ap = config.wifi.as_mut().unwrap();
    ap.ssid = "new-offline-ap".into();
    ap.security = WifiSecurity::Wpa2;
    let response = fixture
        .service
        .dispatch(Request::SaveWifiInterface {
            interface: "wlan0".into(),
            config: config.into(),
            expected_revision: 0,
            passphrase: Some("offline-new-password".into()),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::InterfaceIntentSaved { deferred: true, .. }
        ),
        "{response:?}"
    );
    assert!(!fixture.process.is_alive(pid).await.unwrap());
    assert!(runtime.status("wlan0").await.is_none());
    let config = fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    let ap = config.wifi.unwrap();
    assert_eq!(ap.ssid, "new-offline-ap");
    assert_eq!(
        std::fs::read_to_string(ap.passphrase_file.unwrap()).unwrap(),
        "offline-new-password"
    );
}

#[tokio::test]
async fn unplugged_ap_orphaned_or_interrupted_ownership_cannot_be_forgotten() {
    for interrupted in [false, true] {
        let mut fixture = wifi_enabled_fixture().await;
        let pid = fixture
            .service
            .wifi
            .as_ref()
            .unwrap()
            .status("wlan0")
            .await
            .unwrap()
            .pid;
        fixture.network.interfaces.lock().await.remove("wlan0");
        if interrupted {
            let store = crate::wifi::record::WifiRecordStore::for_access_point(
                fixture._directory.path().join("wifi"),
                &fixture.service.config.wifi.runtime_dir,
                "wlan0",
            );
            store.mark_transition().await.unwrap();
        } else {
            // Reopen without task adoption: the durable process record remains.
            fixture.service.wifi = Some(WifiSupervisor::open_with_process_for_recovery(
                fixture.service.overrides.recovery().clone(),
                &fixture.service.config,
                fixture.process.clone(),
            ));
        }
        let response = fixture
            .service
            .dispatch(Request::ForgetInterfaceConfig {
                interface: "wlan0".into(),
                expected_revision: 0,
            })
            .await;
        assert!(matches!(response, Response::Error { .. }), "{response:?}");
        assert!(fixture.process.is_alive(pid).await.unwrap());
        assert_eq!(fixture.service.overrides.committed_revision().await, 0);
        assert!(fixture
            .service
            .overrides
            .effective_interface("wlan0")
            .await
            .unwrap()
            .is_some());
    }
}

#[tokio::test]
async fn unplugged_ap_cleanup_failure_retains_process_record_and_allows_verified_retry() {
    let fixture = wifi_enabled_fixture().await;
    let runtime = fixture.service.wifi.as_ref().unwrap();
    let pid = runtime.status("wlan0").await.unwrap().pid;
    fixture.network.interfaces.lock().await.remove("wlan0");
    fixture.process.fail_stop.store(true, WifiOrdering::SeqCst);
    let store = crate::wifi::record::WifiRecordStore::for_access_point(
        fixture._directory.path().join("wifi"),
        &fixture.service.config.wifi.runtime_dir,
        "wlan0",
    );
    let previous = store.load().await.unwrap().unwrap();
    let response = fixture
        .service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "wlan0".into(),
            expected_revision: 0,
        })
        .await;
    assert!(
        matches!(response, Response::Error { ref message } if message.contains("previous saved intent retained")),
        "{response:?}"
    );
    assert!(fixture.process.is_alive(pid).await.unwrap());
    assert_eq!(store.load().await.unwrap(), Some(previous));
    assert_eq!(fixture.service.overrides.committed_revision().await, 0);
    fixture.process.fail_stop.store(false, WifiOrdering::SeqCst);
    let response = fixture
        .service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "wlan0".into(),
            expected_revision: 0,
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    assert!(!fixture.process.is_alive(pid).await.unwrap());
    assert!(store.load().await.unwrap().is_none());
    assert!(fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn replug_during_cleanup_does_not_commit_offline_intent_or_touch_replacement() {
    let fixture = wifi_enabled_fixture().await;
    let network = fixture.network.clone();
    fixture.network.interfaces.lock().await.remove("wlan0");
    let mut replacement = fixture.service.network.list_interfaces().await.unwrap();
    assert!(replacement.is_empty());
    replacement.push(NetworkInterface {
        name: "wlan0".into(),
        index: 99,
        is_up: true,
        rx_bytes: 0,
        tx_bytes: 0,
        is_wireless: true,
    });
    *fixture.process.after_stop.lock().unwrap() = Some(Box::new(move || {
        network
            .interfaces
            .try_lock()
            .unwrap()
            .insert("wlan0".into(), replacement[0].clone());
    }));
    let response = fixture
        .service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "wlan0".into(),
            expected_revision: 0,
        })
        .await;
    assert!(
        matches!(response, Response::Error { ref message } if message.contains("observation changed")),
        "{response:?}"
    );
    assert_eq!(fixture.service.overrides.committed_revision().await, 0);
    assert!(fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .is_some());
    assert_eq!(fixture.network.interfaces.lock().await["wlan0"].index, 99);
    assert!(fixture.process.configs.lock().unwrap().is_empty());
}

#[tokio::test]
async fn offline_client_profile_preserves_or_updates_ip_policy_without_execution() {
    use traffic_masq_protocol::{ProvisionWifiClientRequest, WifiClientIpPolicy};
    for policy in [
        WifiClientIpPolicy::Preserve,
        WifiClientIpPolicy::Dhcp,
        WifiClientIpPolicy::Static {
            cidr: "198.51.100.10/24".parse().unwrap(),
        },
    ] {
        let (service, directory) = offline_client_profile_fixture().await;
        let response = service
            .dispatch(Request::SaveWifiClientProfile {
                interface: "wlan1".into(),
                settings: ProvisionWifiClientRequest {
                    profile_id: "saved-uplink".into(),
                    ip_policy: policy.clone(),
                },
                expected_revision: 0,
            })
            .await;
        assert!(
            matches!(
                response,
                Response::InterfaceIntentSaved {
                    deferred: true,
                    revision: 1,
                    ..
                }
            ),
            "{response:?}"
        );
        let config = service
            .overrides
            .effective_interface("wlan1")
            .await
            .unwrap()
            .unwrap();
        match policy {
            WifiClientIpPolicy::Preserve => {
                assert_eq!(config.ipv4, Some("192.0.2.10/24".parse().unwrap()))
            }
            WifiClientIpPolicy::Dhcp => {
                assert!(config.ipv4.is_none());
                assert!(config.dhcp_client.as_ref().unwrap().enabled);
            }
            WifiClientIpPolicy::Static { cidr } => {
                assert_eq!(config.ipv4, Some(cidr));
                assert!(!config.dhcp_client.as_ref().unwrap().enabled);
            }
        }
        assert!(!config.dhcp_client.as_ref().unwrap().wifi_owned);
        let client = config.wifi_client.as_ref().unwrap();
        assert_eq!(client.ssid, "Offline uplink");
        assert_eq!(
            std::fs::read_to_string(client.passphrase_file.as_ref().unwrap()).unwrap(),
            "profile-original-password"
        );
        assert!(!serde_json::to_string(&response)
            .unwrap()
            .contains("profile-original-password"));
        let restarted = RuntimeOverrideManager::load(directory.path(), &service.base_config)
            .await
            .unwrap();
        assert_eq!(
            restarted.effective_interface("wlan1").await.unwrap(),
            Some(config)
        );
        match service.dispatch(Request::ListWifiInventory).await {
            Response::WifiInventory {
                ap_execution_available,
                client_execution_available,
                interfaces,
                ..
            } => {
                assert!(!ap_execution_available && !client_execution_available);
                assert!(
                    interfaces
                        .iter()
                        .any(|entry| entry.interface.name == "wlan1"
                            && entry.client_runtime.is_none())
                );
            }
            response => panic!("{response:?}"),
        }
    }
}

#[tokio::test]
async fn offline_profile_save_rejects_present_target_before_stopping_supplicant() {
    let fixture = wifi_client_enabled_fixture().await;
    let runtime = fixture.service.wifi_client.as_ref().unwrap();
    let pid = runtime.status("wlan1").await.unwrap().pid;
    let response = fixture
        .service
        .dispatch(Request::SaveWifiClientProfile {
            interface: "wlan1".into(),
            settings: traffic_masq_protocol::ProvisionWifiClientRequest {
                profile_id: "nonexistent".into(),
                ip_policy: traffic_masq_protocol::WifiClientIpPolicy::Dhcp,
            },
            expected_revision: 0,
        })
        .await;
    assert!(
        matches!(response, Response::Error { ref message } if message.contains("present")),
        "{response:?}"
    );
    assert!(fixture.process.is_alive(pid).await.unwrap());
    assert_eq!(fixture.service.overrides.committed_revision().await, 0);
}
