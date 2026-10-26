use std::net::Ipv4Addr;

use tempfile::tempdir;

use std::collections::BTreeMap;

use crate::config::{
    DhcpClientInterfaceConfig, DhcpInterfaceConfig, InterfaceRole, RouterConfig, UplinkConfig,
    UplinkMode,
};
use crate::state::overrides::CURRENT_RUNTIME_OVERRIDES_SCHEMA;

use super::*;

fn base_config() -> AppConfig {
    AppConfig::default()
}

#[tokio::test]
async fn settings_write_with_changed_commit_proof_still_fences_network_recovery() {
    let directory = tempdir().unwrap();
    let base = base_config();
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    manager
        .save_committed(RuntimeOverrides::default())
        .await
        .unwrap();
    let before = manager.snapshot().await;
    let mut candidate = before.clone();
    candidate.security = Some(base.security);
    candidate
        .committed_interface_transactions
        .insert("lan0".into(), "new-proof".into());
    crate::atomic_file::fail_replacement_and_compensation(manager.path());
    let error = manager.save_committed(candidate).await.unwrap_err();
    assert!(crate::atomic_file::is_indeterminate_write(&error));
    assert!(crate::core::recovery::check_commit(directory.path()).is_err());
    assert!(crate::core::recovery::check_persistence(directory.path()).is_err());
    assert_eq!(manager.snapshot().await, before);
}

/// The converger has no timer any more, so a change that does not announce
/// itself is a change that never gets applied.

#[tokio::test]
async fn writing_an_override_wakes_whoever_is_waiting_for_a_change() {
    let directory = tempdir().expect("tempdir");
    let base = base_config();
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .expect("overrides");

    let waiter = {
        let manager = manager.clone();
        tokio::spawn(async move { manager.changed().await })
    };
    // Let the waiter reach the wait before the change happens: `changed`
    // also retains a notification if convergence is still running.
    tokio::task::yield_now().await;

    manager
        .set_interface(
            "lan0".to_string(),
            interface_config("192.168.30.1/24"),
            false,
        )
        .await
        .expect("set interface");

    tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
        .await
        .expect("an override write must wake the converger")
        .expect("waiter task");
}

fn interface_config(address: &str) -> InterfaceConfig {
    InterfaceConfig {
        wifi_concurrent: false,
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some(address.parse().expect("network")),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    }
}

fn dhcp_interface_config(address: &str) -> InterfaceConfig {
    let mut config = interface_config(address);
    config.dhcp = Some(DhcpInterfaceConfig {
        pool_start: Ipv4Addr::new(192, 168, 10, 100),
        pool_end: Ipv4Addr::new(192, 168, 10, 200),
        router: Ipv4Addr::new(192, 168, 10, 1),
        dns_servers: Vec::new(),
        lease_seconds: Some(3600),
    });
    config
}

/// A successful, self-contained mutation, for tests that need the store to
/// change but do not care what changed. `set_dhcp` used to serve this role.
fn api_override(port: u16) -> ApiConfig {
    ApiConfig {
        tcp: Some(crate::config::TcpApiConfig {
            enabled: true,
            listen: format!("0.0.0.0:{port}").parse().expect("socket address"),
            certificate_path: Some("/etc/traffic-masq/server.pem".into()),
            private_key_path: Some("/etc/traffic-masq/server-key.pem".into()),
        }),
    }
}

#[tokio::test]
async fn rejects_unversioned_document() {
    let directory = tempdir().expect("tempdir");
    let store = RuntimeOverrideStore::in_state_dir(directory.path());
    tokio::fs::write(
        store.path(),
        serde_json::to_vec(&serde_json::json!({
            "api": {"tcp": null},
            "interfaces": {}
        }))
        .unwrap(),
    )
    .await
    .unwrap();

    assert!(
        RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rejects_old_interface_override_schema() {
    let directory = tempdir().expect("tempdir");
    let store = RuntimeOverrideStore::in_state_dir(directory.path());
    tokio::fs::write(
        store.path(),
        br#"{
            "schema_version": 2,
            "interfaces": {
                "wan0": {
                    "config": {
                        "role": "input",
                        "managed": false,
                        "ipv4": null,
                        "dhcp": null,
                        "wifi": null,
                        "wifi_client": null
                    }
                }
            }
        }"#,
    )
    .await
    .unwrap();

    assert!(
        RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dhcp_client_interface_override_normalizes_saves_and_round_trips() {
    let directory = tempdir().expect("tempdir");
    let base = base_config();
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let mut interface = InterfaceConfig {
        wifi_concurrent: false,
        mac_address: None,
        role: InterfaceRole::Input,
        managed: true,
        ipv4: None,
        dhcp: None,
        dhcp_client: Some(DhcpClientInterfaceConfig {
            route_metric: 250,
            install_default_route: false,
            request_dns: false,
            send_release_on_shutdown: true,
            ..DhcpClientInterfaceConfig::default()
        }),
        wifi: None,
        wifi_client: None,
    };
    manager
        .set_interface("wan0".into(), interface.clone(), false)
        .await
        .unwrap();

    let restored = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap()
        .snapshot()
        .await;
    assert_eq!(restored.interfaces["wan0"].config, interface);

    interface.dhcp_client.as_mut().unwrap().enabled = false;
    let normalized = RuntimeOverrides {
        interfaces: BTreeMap::from([(
            "wan0".into(),
            InterfaceOverride {
                config: interface.clone(),
                allow_management_change: false,
                dhcp_client_only: false,
            },
        )]),
        ..RuntimeOverrides::default()
    }
    .normalized()
    .unwrap();
    assert_eq!(normalized.interfaces["wan0"].config, interface);
}

#[tokio::test]
async fn api_override_saves_and_reloads() {
    let directory = tempdir().expect("tempdir");
    let base = base_config();
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    manager
        .set_api_config(ApiConfig {
            tcp: Some(crate::config::TcpApiConfig {
                enabled: true,
                listen: "0.0.0.0:9443".parse().expect("socket address"),
                certificate_path: Some("/etc/traffic-masq/server.pem".into()),
                private_key_path: Some("/etc/traffic-masq/server-key.pem".into()),
            }),
        })
        .await
        .unwrap();

    let restored = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap()
        .snapshot()
        .await;
    assert_eq!(restored.revision, 1);
    assert_eq!(
        restored.api,
        Some(ApiConfig {
            tcp: Some(crate::config::TcpApiConfig {
                enabled: true,
                listen: "0.0.0.0:9443".parse().expect("socket address"),
                certificate_path: Some("/etc/traffic-masq/server.pem".into()),
                private_key_path: Some("/etc/traffic-masq/server-key.pem".into()),
            }),
        })
    );
}

#[tokio::test]
async fn security_override_saves_reloads_and_can_be_cleared() {
    let directory = tempdir().expect("tempdir");
    let base = base_config();
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();

    assert_eq!(
        manager.effective_security_config().await.unwrap(),
        base.security
    );

    manager
        .set_security_config(crate::config::SecurityConfig {
            rollback_timeout_seconds: 120,
        })
        .await
        .unwrap();
    assert_eq!(
        manager
            .effective_security_config()
            .await
            .unwrap()
            .rollback_timeout_seconds,
        120
    );

    let restored = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    assert_eq!(
        restored
            .effective_security_config()
            .await
            .unwrap()
            .rollback_timeout_seconds,
        120
    );

    restored.clear_security_config().await.unwrap();
    assert_eq!(
        restored.effective_security_config().await.unwrap(),
        base.security
    );
}

#[tokio::test]
async fn security_override_rejects_zero_rollback_timeout() {
    let directory = tempdir().expect("tempdir");
    let base = base_config();
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();

    let error = manager
        .set_security_config(crate::config::SecurityConfig {
            rollback_timeout_seconds: 0,
        })
        .await
        .expect_err("zero rollback timeout must be rejected");
    assert!(error.to_string().contains("rollback_timeout_seconds"));
    assert_eq!(
        manager.effective_security_config().await.unwrap(),
        base.security
    );
}

#[tokio::test]
async fn vpn_mode_defaults_to_base_config_and_can_be_overridden_and_cleared() {
    let directory = tempdir().expect("tempdir");
    let mut base = base_config();
    base.network.interfaces.insert(
        "wan0".into(),
        InterfaceConfig {
            wifi_concurrent: false,
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
    base.network
        .interfaces
        .insert("lan0".into(), interface_config("192.168.10.1/24"));
    base.vpn.enabled = true;
    base.router = RouterConfig {
        uplink: Some(UplinkConfig {
            interface: "wan0".into(),
            mode: UplinkMode::External,
        }),
        ..RouterConfig::default()
    };
    base.validate().expect("base config");
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();

    assert_eq!(
        manager.effective_vpn_mode().await,
        crate::config::VpnPolicyMode::Direct
    );

    manager
        .set_vpn_mode(crate::config::VpnPolicyMode::Vpn)
        .await
        .unwrap();
    assert_eq!(
        manager.effective_vpn_mode().await,
        crate::config::VpnPolicyMode::Vpn
    );

    let restored = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    assert_eq!(
        restored.effective_vpn_mode().await,
        crate::config::VpnPolicyMode::Vpn
    );

    manager.clear_vpn_mode().await.unwrap();
    assert_eq!(
        manager.effective_vpn_mode().await,
        crate::config::VpnPolicyMode::Direct
    );
}

#[tokio::test]
async fn set_vpn_mode_vpn_is_rejected_without_vpn_enabled_or_router_enabled() {
    let directory = tempdir().expect("tempdir");
    let base = base_config();
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();

    let error = manager
        .set_vpn_mode(crate::config::VpnPolicyMode::Vpn)
        .await
        .expect_err("vpn disabled and router disabled");
    assert!(error.to_string().contains("vpn.enabled = true"));
    assert_eq!(
        manager.effective_vpn_mode().await,
        crate::config::VpnPolicyMode::Direct
    );
}

#[tokio::test]
async fn rejects_future_schema_version() {
    let directory = tempdir().expect("tempdir");
    let store = RuntimeOverrideStore::in_state_dir(directory.path());
    let future = crate::state::overrides::CURRENT_RUNTIME_OVERRIDES_SCHEMA + 1;
    tokio::fs::write(
        store.path(),
        serde_json::to_vec(&serde_json::json!({"schema_version": future, "revision": 0})).unwrap(),
    )
    .await
    .unwrap();

    let error = RuntimeOverrideManager::load(directory.path(), &base_config())
        .await
        .expect_err("future schema");
    assert!(error
        .to_string()
        .contains(&format!("unsupported runtime override schema {future}")));
}

#[tokio::test]
async fn router_and_interface_conflict_is_rejected_without_state_change() {
    let directory = tempdir().expect("tempdir");
    let mut base = base_config();
    base.network.interfaces.insert(
        "wan0".into(),
        InterfaceConfig {
            wifi_concurrent: false,
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
    base.network
        .interfaces
        .insert("lan0".into(), interface_config("192.168.10.1/24"));
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let mut candidate = manager.snapshot().await;
    candidate.router = Some(RouterConfig {
        uplink: Some(UplinkConfig {
            interface: "wan0".into(),
            mode: UplinkMode::External,
        }),
        ..RouterConfig::default()
    });
    candidate.interfaces.insert(
        "wan0".into(),
        InterfaceOverride {
            config: InterfaceConfig {
                wifi_concurrent: false,
                mac_address: None,
                role: InterfaceRole::None,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
            allow_management_change: true,
            dhcp_client_only: false,
        },
    );

    manager
        .save_committed(candidate)
        .await
        .expect_err("router conflict");
    assert_eq!(manager.snapshot().await.revision, 0);
    assert!(!manager.path().exists());
}

#[tokio::test]
async fn invalid_candidate_leaves_file_state_and_revision_unchanged() {
    let directory = tempdir().expect("tempdir");
    let mut base = base_config();
    base.network
        .interfaces
        .insert("wlan0".into(), interface_config("192.168.10.1/24"));
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    manager.set_api_config(api_override(9443)).await.unwrap();
    let before_state = manager.snapshot().await;
    let before_file = tokio::fs::read(manager.path()).await.unwrap();

    let error = manager
        .set_interface("usb0".into(), interface_config("192.168.10.2/25"), false)
        .await
        .expect_err("overlap");
    assert!(error.to_string().contains("overlap"));
    assert_eq!(manager.snapshot().await, before_state);
    assert_eq!(tokio::fs::read(manager.path()).await.unwrap(), before_file);
}

#[tokio::test]
async fn restoring_an_absent_interface_override_removes_it_exactly() {
    let directory = tempdir().expect("tempdir");
    let base = base_config();
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .expect("manager");

    manager
        .set_interface("wlan0".into(), interface_config("192.168.30.1/24"), false)
        .await
        .expect("set interface override");
    assert!(manager.snapshot().await.interfaces.contains_key("wlan0"));

    manager
        .restore_interface_override("wlan0", None)
        .await
        .expect("restore absent override");

    let state = manager.snapshot().await;
    assert!(!state.interfaces.contains_key("wlan0"));
    let persisted = RuntimeOverrideStore::in_state_dir(directory.path())
        .load()
        .await
        .expect("load persisted overrides");
    assert!(!persisted.interfaces.contains_key("wlan0"));
}

#[tokio::test]
async fn failed_file_save_does_not_publish_state_or_revision() {
    let directory = tempdir().expect("tempdir");
    let base = base_config();
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .expect("manager");
    tokio::fs::create_dir(manager.path())
        .await
        .expect("conflicting target directory");
    let before = manager.snapshot().await;

    manager
        .set_api_config(api_override(9443))
        .await
        .expect_err("rename over directory must fail");

    assert_eq!(manager.snapshot().await, before);
    assert_eq!(manager.snapshot().await.revision, 0);
    assert!(manager.path().is_dir());
}

#[tokio::test]
async fn revision_increments_only_for_successful_saves() {
    let directory = tempdir().expect("tempdir");
    let mut base = base_config();
    base.network
        .interfaces
        .insert("wlan0".into(), interface_config("192.168.10.1/24"));
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();

    manager.set_api_config(api_override(9443)).await.unwrap();
    assert_eq!(manager.snapshot().await.revision, 1);
    manager
        .set_interface("usb0".into(), interface_config("192.168.10.2/25"), false)
        .await
        .expect_err("invalid save");
    assert_eq!(manager.snapshot().await.revision, 1);
    manager.set_api_config(api_override(9444)).await.unwrap();
    assert_eq!(manager.snapshot().await.revision, 2);
}

#[tokio::test]
async fn candidate_commit_advances_revision_and_rejects_a_stale_candidate() {
    let directory = tempdir().expect("tempdir");
    let mut base = base_config();
    base.network.interfaces.insert(
        "wan0".into(),
        InterfaceConfig {
            wifi_concurrent: false,
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
    base.network
        .interfaces
        .insert("lan0".into(), dhcp_interface_config("192.168.10.1/24"));
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();

    let router = RouterConfig {
        uplink: Some(UplinkConfig {
            interface: "wan0".into(),
            mode: UplinkMode::External,
        }),
        ..RouterConfig::default()
    };
    let candidate = manager
        .build_candidate(&RouterIntentProposal::new().set_router(router.clone()))
        .await
        .expect("candidate");
    assert_eq!(candidate.base_revision(), 0);

    assert_eq!(manager.commit_candidate(&candidate).await.unwrap(), 1);
    assert_eq!(manager.committed_revision().await, 1);
    assert!(manager.snapshot().await.router.is_some());

    let committed_state = manager.snapshot().await;
    let committed_file = tokio::fs::read(manager.path()).await.unwrap();
    let error = manager
        .commit_candidate(&candidate)
        .await
        .expect_err("stale candidate must not be saved");
    assert!(format!("{error:#}").contains("stale"));
    assert_eq!(manager.snapshot().await, committed_state);
    assert_eq!(
        tokio::fs::read(manager.path()).await.unwrap(),
        committed_file
    );
}

#[tokio::test]
async fn candidate_rebuilt_on_current_state_commits_again() {
    let directory = tempdir().expect("tempdir");
    let base = base_config();
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();

    for expected_revision in 1..=2 {
        let candidate = manager
            .build_candidate(&RouterIntentProposal::new().set_interface(
                format!("lan{expected_revision}"),
                interface_config(&format!("192.168.{expected_revision}.1/24")),
                false,
            ))
            .await
            .expect("candidate");
        assert_eq!(candidate.base_revision(), expected_revision - 1);
        assert_eq!(
            manager.commit_candidate(&candidate).await.unwrap(),
            expected_revision
        );
    }
    assert_eq!(manager.snapshot().await.interfaces.len(), 2);
}

#[tokio::test]
async fn concurrent_updates_do_not_lose_overrides() {
    let directory = tempdir().expect("tempdir");
    let manager = RuntimeOverrideManager::load(directory.path(), &base_config())
        .await
        .unwrap();
    let first = manager.clone();
    let second = manager.clone();
    let (first_result, second_result) = tokio::join!(
        first.set_interface("wlan0".into(), interface_config("192.168.10.1/24"), false),
        second.set_interface("usb0".into(), interface_config("192.168.20.1/24"), false)
    );
    first_result.unwrap();
    second_result.unwrap();
    let state = manager.snapshot().await;
    assert_eq!(state.revision, 2);
    assert_eq!(state.interfaces.len(), 2);
}

#[tokio::test]
async fn malformed_override_file_reports_its_path() {
    let directory = tempdir().expect("tempdir");
    let store = RuntimeOverrideStore::in_state_dir(directory.path());
    tokio::fs::write(store.path(), b"not valid json")
        .await
        .expect("write malformed state");

    let error = RuntimeOverrideManager::load(directory.path(), &base_config())
        .await
        .expect_err("malformed state must fail");
    let message = format!("{error:#}");
    assert!(message.contains("failed to parse runtime overrides"));
    assert!(message.contains("runtime-overrides.json"));
}

#[tokio::test]
async fn router_recovery_manager_ignores_unrelated_invalid_override_fields_until_hydration() {
    let directory = tempdir().expect("tempdir");
    let store = RuntimeOverrideStore::in_state_dir(directory.path());
    tokio::fs::write(
        store.path(),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": CURRENT_RUNTIME_OVERRIDES_SCHEMA,
            "revision": 11,
            "committed_router_transaction": "router-proof",
            "interfaces": {},
            "api": {"tcp": "invalid-for-normal-startup"},
            "unknown_future_field": true
        }))
        .unwrap(),
    )
    .await
    .expect("write recovery state");

    let manager =
        RuntimeOverrideManager::load_for_router_recovery(directory.path(), &base_config())
            .await
            .expect("router recovery state");
    let snapshot = manager.snapshot().await;
    assert_eq!(snapshot.revision, 11);
    assert_eq!(
        snapshot.committed_router_transaction.as_deref(),
        Some("router-proof")
    );
    assert!(snapshot.api.is_none());
    assert!(manager.hydrate_strict().await.is_err());
}

#[test]
fn cancelled_persistence_fences_mutations_until_commit_proof_is_reloaded() {
    use std::future::Future;
    use std::task::Poll;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let directory = tempdir().unwrap();
    runtime.block_on(async {
        let manager = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .unwrap();
        let (release, blocked) = std::sync::mpsc::channel();
        let (entered, ready) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            entered.send(()).unwrap();
            let _ = blocked.recv();
        });
        ready.recv().unwrap();
        {
            let mut saving = std::pin::pin!(manager.save_committed(RuntimeOverrides::default()));
            std::future::poll_fn(|cx| {
                assert!(
                    saving.as_mut().poll(cx).is_pending(),
                    "storage must be waiting for the blocking worker"
                );
                Poll::Ready(())
            })
            .await;
            // Drop the save future while its storage operation is outstanding.
        }
        assert!(crate::core::recovery::check_commit(directory.path()).is_err());
        assert!(manager
            .save_committed(RuntimeOverrides::default())
            .await
            .is_err());
        assert_eq!(manager.committed_revision().await, 0);
        release.send(()).unwrap();
        blocker.await.unwrap();
    });
}

#[tokio::test]
async fn dhcp_dns_defaults_persist_without_changing_existing_servers() {
    use traffic_masq_protocol::DhcpDnsDefaults;
    let directory = tempdir().unwrap();
    let mut base = base_config();
    let mut lan = InterfaceConfig {
        managed: true,
        role: InterfaceRole::Output,
        ipv4: Some("192.168.50.1/24".parse().unwrap()),
        dhcp: Some(DhcpInterfaceConfig {
            pool_start: "192.168.50.100".parse().unwrap(),
            pool_end: "192.168.50.200".parse().unwrap(),
            router: "192.168.50.1".parse().unwrap(),
            dns_servers: vec![],
            lease_seconds: None,
        }),
        wifi_concurrent: false,
        mac_address: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };
    base.network.interfaces.insert("lan0".into(), lan.clone());
    let manager = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    assert_eq!(
        manager.effective_dhcp_dns_defaults().await.unwrap(),
        DhcpDnsDefaults::default()
    );
    for servers in [vec![Ipv4Addr::new(9, 9, 9, 9)], vec![]] {
        let settings = DhcpDnsDefaults { servers };
        manager
            .set_dhcp_dns_defaults(settings.clone())
            .await
            .unwrap();
        let restored = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();
        assert_eq!(
            restored.effective_dhcp_dns_defaults().await.unwrap(),
            settings
        );
        assert_eq!(
            restored.effective_interface("lan0").await.unwrap(),
            Some(lan.clone())
        );
    }
    // A server with its own DNS also remains independent of the global setting.
    lan.dhcp.as_mut().unwrap().dns_servers = vec![Ipv4Addr::new(8, 8, 8, 8)];
    manager
        .set_interface("lan0".into(), lan.clone(), false)
        .await
        .unwrap();
    manager
        .set_dhcp_dns_defaults(DhcpDnsDefaults::default())
        .await
        .unwrap();
    assert_eq!(
        manager.effective_interface("lan0").await.unwrap(),
        Some(lan)
    );
    let before = manager.snapshot().await;
    assert!(manager
        .set_dhcp_dns_defaults(DhcpDnsDefaults {
            servers: vec![Ipv4Addr::UNSPECIFIED]
        })
        .await
        .is_err());
    assert_eq!(manager.snapshot().await, before);
}
