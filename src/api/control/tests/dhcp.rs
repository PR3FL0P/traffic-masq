use super::*;

#[test]
fn default_ap_dhcp_pool_uses_larger_side_of_router_in_24() {
    let settings = default_dhcp_settings(
        "192.168.50.128/24".parse().unwrap(),
        traffic_masq_protocol::DhcpDnsDefaults::default().servers,
    )
    .unwrap();
    assert_eq!(settings.router, Ipv4Addr::new(192, 168, 50, 128));
    assert_eq!(settings.pool_start, Ipv4Addr::new(192, 168, 50, 1));
    assert_eq!(settings.pool_end, Ipv4Addr::new(192, 168, 50, 127));
    assert_eq!(settings.dns_servers, vec![Ipv4Addr::new(1, 1, 1, 1)]);
    assert_eq!(settings.lease_seconds, None);
}

#[test]
fn default_ap_dhcp_pool_supports_30() {
    let settings = default_dhcp_settings(
        "192.168.50.1/30".parse().unwrap(),
        traffic_masq_protocol::DhcpDnsDefaults::default().servers,
    )
    .unwrap();
    assert_eq!(settings.pool_start, Ipv4Addr::new(192, 168, 50, 2));
    assert_eq!(settings.pool_end, Ipv4Addr::new(192, 168, 50, 2));
}

#[test]
fn default_ap_dhcp_pool_rejects_31() {
    let error = default_dhcp_settings(
        "192.168.50.0/31".parse().unwrap(),
        traffic_masq_protocol::DhcpDnsDefaults::default().servers,
    )
    .unwrap_err();
    assert!(error.contains("/31"));
}

#[test]
fn interface_edit_request_preserves_existing_dhcp_settings() {
    let existing_dhcp = dhcp_config();
    let existing = InterfaceConfig {
        wifi_concurrent: false,
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
        dhcp: Some(existing_dhcp.clone()),
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };
    let edit = InterfaceEditRequest {
        wifi_concurrent: false,
        mac_address: None,
        cidr: "192.168.60.1/24".to_string(),
        role: InterfaceRole::Output,
        managed: true,
        allow_management_change: false,
    };

    let (config, allow_management_change) =
        interface_edit_request_to_config(edit, Some(&existing)).expect("edit must convert");

    assert_eq!(
        config.ipv4,
        Some("192.168.60.1/24".parse().expect("valid cidr"))
    );
    assert_eq!(config.dhcp, Some(existing_dhcp));
    assert!(!allow_management_change);
}

#[test]
fn removing_the_address_under_a_dhcp_server_says_what_to_disable_first() {
    let existing = InterfaceConfig {
        wifi_concurrent: false,
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
        dhcp: Some(dhcp_config()),
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

    let error = interface_edit_request_to_config(edit, Some(&existing))
        .expect_err("a DHCP server cannot outlive the address it serves");
    assert_eq!(
        error.to_string(),
        "cannot remove the IPv4 address while a DHCP server is configured on this interface; disable DHCP first"
    );
}

#[tokio::test]
async fn selects_the_only_address_whose_subnet_validates_dhcp() {
    let network = FakeNetwork {
        addresses: vec![address([10, 0, 0, 1], 24), address([192, 168, 50, 1], 24)],
    };

    let spec = build_dhcp_spec("test0", dhcp_config(), &network, 3_600)
        .await
        .expect("one live subnet should match");

    assert_eq!(spec.server_ip, Ipv4Addr::new(192, 168, 50, 1));
    assert_eq!(spec.prefix_len, 24);
}

#[tokio::test]
async fn rejects_when_no_address_has_a_valid_dhcp_subnet() {
    let network = FakeNetwork {
        addresses: vec![address([10, 0, 0, 1], 24), address([172, 16, 0, 1], 16)],
    };

    let error = build_dhcp_spec("test0", dhcp_config(), &network, 3_600)
        .await
        .expect_err("no live subnet should match");

    assert!(error
        .to_string()
        .contains("no IPv4 address with a subnet valid"));
}

#[tokio::test]
async fn selects_the_live_address_that_matches_the_dhcp_router() {
    let network = FakeNetwork {
        addresses: vec![
            address([192, 168, 50, 1], 24),
            address([192, 168, 50, 2], 24),
        ],
    };

    let spec = build_dhcp_spec("test0", dhcp_config(), &network, 3_600)
        .await
        .expect("the DHCP router must identify the server address");

    assert_eq!(spec.server_ip, Ipv4Addr::new(192, 168, 50, 1));
    assert_eq!(spec.router, spec.server_ip);
}

#[tokio::test]
async fn dhcp_uplink_plan_auto_enables_interface_dhcp_client() {
    let mut config = router_base_config();
    let wan = config
        .network
        .interfaces
        .get_mut("wan0")
        .expect("wan0 interface");
    wan.managed = true;
    wan.dhcp_client = None;

    let (service, _directory) =
        router_service_with_config(Arc::new(FakeRouterSubsystems::default()), config).await;
    let mut proposal = router_proposal();
    proposal
        .set_router
        .as_mut()
        .unwrap()
        .uplink
        .as_mut()
        .unwrap()
        .mode = UplinkMode::Dhcp;

    match service
        .dispatch(Request::RouterPlan {
            proposal: proposal.into(),
        })
        .await
    {
        Response::RouterPlan { plan } => {
            let dhcp = plan
                .desired
                .uplink_dhcp
                .expect("DHCP uplink should be derived automatically");
            assert_eq!(dhcp.interface, "wan0");
        }
        other => panic!("expected DHCP router plan, got {other:?}"),
    }
}

#[tokio::test]
async fn dhcp_uplink_plan_preserves_explicit_interface_override_while_enabling_dhcp() {
    let mut config = router_base_config();
    let wan = config
        .network
        .interfaces
        .get_mut("wan0")
        .expect("wan0 interface");
    wan.managed = true;

    let (service, _directory) =
        router_service_with_config(Arc::new(FakeRouterSubsystems::default()), config).await;
    let mut proposal = router_proposal();
    proposal
        .set_router
        .as_mut()
        .unwrap()
        .uplink
        .as_mut()
        .unwrap()
        .mode = UplinkMode::Dhcp;

    let override_config = proposal
        .set_interfaces
        .get("wan0")
        .map(|request| request.config.clone())
        .unwrap_or_else(|| InterfaceConfig {
            wifi_concurrent: false,
            mac_address: None,
            role: InterfaceRole::Input,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: Some(DhcpClientInterfaceConfig {
                enabled: false,
                ..Default::default()
            }),
            wifi: None,
            wifi_client: None,
        });
    proposal.set_interfaces.insert(
        "wan0".to_string(),
        crate::api::model::InterfaceOverrideRequest {
            config: override_config,
            allow_management_change: false,
        },
    );

    match service
        .dispatch(Request::RouterPlan {
            proposal: proposal.into(),
        })
        .await
    {
        Response::RouterPlan { plan } => {
            let uplink = plan
                .desired
                .interfaces
                .iter()
                .find(|interface| interface.name == "wan0")
                .expect("wan0 desired interface");
            assert!(uplink
                .config
                .dhcp_client
                .as_ref()
                .is_some_and(|policy| policy.enabled));
        }
        other => panic!("expected DHCP router plan, got {other:?}"),
    }
}

#[tokio::test]
async fn dhcp_client_control_list_get_and_typed_missing_states() {
    let fixture = dhcp_client_control_fixture(true).await;
    assert!(matches!(
        fixture.service.dispatch(Request::DhcpClientStatus).await,
        Response::DhcpClientStatus { interfaces } if interfaces.len() == 1 && interfaces[0].interface == "wan0"
    ));
    assert!(matches!(
        fixture.service.dispatch(Request::GetDhcpClient { interface: "wan0".into() }).await,
        Response::DhcpClientInterface { status } if status.interface == "wan0"
    ));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::GetDhcpClient {
                interface: "missing0".into()
            })
            .await,
        Response::DhcpClientError {
            detail: DhcpClientErrorDetail::InterfaceNotFound
        }
    ));
    let disabled = dhcp_client_control_fixture(false).await;
    assert!(matches!(
        disabled
            .service
            .dispatch(Request::GetDhcpClient {
                interface: "wan0".into()
            })
            .await,
        Response::DhcpClientError {
            detail: DhcpClientErrorDetail::Disabled
        }
    ));
}

#[tokio::test]
async fn dhcp_client_control_rejects_interface_transitions_without_mutation() {
    for (role, managed, ipv4) in [
        (InterfaceRole::None, false, None),
        (InterfaceRole::None, true, None),
        (InterfaceRole::Output, true, Some("192.168.50.1/24")),
        (InterfaceRole::Input, false, None),
        (InterfaceRole::Input, true, Some("192.168.50.1/24")),
    ] {
        let fixture = dhcp_client_control_fixture(false).await;
        let mut original = fixture
            .overrides
            .effective_interface("wan0")
            .await
            .unwrap()
            .unwrap();
        original.role = role;
        original.managed = managed;
        original.ipv4 = ipv4.map(|value| value.parse().unwrap());
        original.wifi_client = None;
        if role == InterfaceRole::Output {
            original.dhcp = Some(dhcp_config());
        }
        fixture
            .overrides
            .set_interface("wan0".into(), original.clone(), false)
            .await
            .unwrap();
        let before = fixture.overrides.snapshot().await;
        let persisted_before = std::fs::read(fixture.overrides.path()).unwrap();

        let response = fixture
            .service
            .dispatch(Request::ConfigureDhcpClient {
                interface: "wan0".into(),
                config: DhcpClientConfigRequest::default(),
            })
            .await;
        assert!(
            matches!(response, Response::DhcpClientError {
                detail: DhcpClientErrorDetail::InvalidConfig { ref message }
            } if message.contains("apply and commit")),
            "{role:?}, managed={managed}, ipv4={ipv4:?}: {response:?}"
        );
        assert_eq!(fixture.overrides.snapshot().await, before);
        assert_eq!(
            std::fs::read(fixture.overrides.path()).unwrap(),
            persisted_before
        );
        assert!(fixture.supervisor.spec("wan0").await.is_none());
        assert!(fixture.service.transactions.pending().await.is_empty());
    }
}

#[tokio::test]
async fn dhcp_client_control_configure_preserves_wifi_client() {
    let (fixture, worker) = dhcp_confirm_fixture(false, 30).await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest {
                route_metric: 77,
                ..Default::default()
            },
        })
        .await;
    let token = network_pending_token(response);
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange { token })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    let persisted = fixture
        .overrides
        .effective_interface("wan0")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.dhcp_client.unwrap().route_metric, 77);
    assert_eq!(persisted.wifi_client.unwrap().ssid, "upstream");
    assert!(persisted.managed);
    assert_eq!(persisted.role, InterfaceRole::Input);
    worker.abort();
}

#[tokio::test]
async fn dhcp_route_policy_requires_commit_and_rollback_restores_runtime() {
    for install_default_route in [true, false] {
        let (fixture, worker) = dhcp_route_policy_fixture(30).await;
        let previous = fixture.overrides.snapshot().await;
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            fixture.service.dispatch(Request::ConfigureDhcpClient {
                interface: "wan0".into(),
                config: DhcpClientConfigRequest {
                    route_metric: 777,
                    install_default_route,
                    ..Default::default()
                },
            }),
        )
        .await
        .expect("DHCP transaction must release execution for convergence");
        let Response::NetworkChangePending { change } = response else {
            worker.abort();
            panic!("{response:?}");
        };
        assert_eq!(fixture.overrides.snapshot().await, previous);
        let runtime = fixture.supervisor.spec("wan0").await.unwrap();
        assert_eq!(runtime.route_metric, 777);
        assert_eq!(runtime.install_default_route, install_default_route);
        assert!(fixture
            .directory
            .path()
            .join("interface-transactions/wan0.json")
            .exists());
        let blocked = fixture
            .service
            .dispatch(Request::RenewDhcpClient {
                interface: "wan0".into(),
            })
            .await;
        assert!(matches!(blocked, Response::Error { message } if message.contains("pending")));
        let rollback = fixture
            .service
            .dispatch(Request::RollbackNetworkChange {
                token: change.token,
            })
            .await;
        assert!(
            matches!(rollback, Response::NetworkChangeRolledBack { .. }),
            "{rollback:?}"
        );
        assert_eq!(fixture.overrides.snapshot().await, previous);
        let runtime = fixture.supervisor.spec("wan0").await.unwrap();
        assert_eq!(
            runtime.route_metric,
            DhcpClientConfigRequest::default().route_metric
        );
        assert!(runtime.install_default_route);
        assert!(!fixture
            .directory
            .path()
            .join("interface-transactions/wan0.json")
            .exists());
        worker.abort();
    }
}

#[tokio::test]
async fn dhcp_default_route_policy_is_persisted_only_after_confirmation() {
    let (fixture, worker) = dhcp_route_policy_fixture(30).await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest {
                install_default_route: false,
                ..Default::default()
            },
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        worker.abort();
        panic!("{response:?}");
    };
    assert!(
        fixture
            .overrides
            .effective_interface("wan0")
            .await
            .unwrap()
            .unwrap()
            .dhcp_client
            .unwrap()
            .install_default_route
    );
    let response = fixture
        .service
        .dispatch(Request::CommitNetworkChange {
            token: change.token,
        })
        .await;
    assert!(
        matches!(response, Response::NetworkChangeCommitted { .. }),
        "{response:?}"
    );
    assert!(
        !fixture
            .overrides
            .effective_interface("wan0")
            .await
            .unwrap()
            .unwrap()
            .dhcp_client
            .unwrap()
            .install_default_route
    );
    assert!(
        !fixture
            .supervisor
            .spec("wan0")
            .await
            .unwrap()
            .install_default_route
    );
    assert!(fixture.service.transactions.pending().await.is_empty());
    worker.abort();
}

#[tokio::test]
async fn dhcp_route_policy_refuses_changes_without_a_running_converger() {
    let fixture = dhcp_client_control_fixture(true).await;
    fixture.service.transactions.require_converger(true);
    let before = fixture.overrides.snapshot().await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest {
                install_default_route: false,
                ..Default::default()
            },
        })
        .await;
    assert!(
        matches!(response, Response::Error { message } if message.contains("converger unavailable"))
    );
    assert_eq!(fixture.overrides.snapshot().await, before);
    assert!(
        fixture
            .supervisor
            .spec("wan0")
            .await
            .unwrap()
            .install_default_route
    );
    assert!(fixture.service.transactions.pending().await.is_empty());
}

#[tokio::test]
async fn dhcp_route_policy_timeout_restores_committed_policy() {
    let (fixture, worker) = dhcp_route_policy_fixture(1).await;
    let previous = fixture.overrides.snapshot().await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest {
                install_default_route: false,
                ..Default::default()
            },
        })
        .await;
    assert!(
        matches!(response, Response::NetworkChangePending { .. }),
        "{response:?}"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while !fixture.service.transactions.pending().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("confirmation timer must finish rollback");
    assert_eq!(fixture.overrides.snapshot().await, previous);
    assert!(
        fixture
            .supervisor
            .spec("wan0")
            .await
            .unwrap()
            .install_default_route
    );
    assert!(!fixture
        .directory
        .path()
        .join("interface-transactions/wan0.json")
        .exists());
    worker.abort();
}

#[tokio::test]
async fn interrupted_dhcp_route_policy_is_recovered_from_committed_intent() {
    let (fixture, worker) = dhcp_route_policy_fixture(30).await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest {
                install_default_route: false,
                ..Default::default()
            },
        })
        .await;
    assert!(
        matches!(response, Response::NetworkChangePending { .. }),
        "{response:?}"
    );
    worker.abort();
    let committed = fixture.overrides.snapshot().await;
    let manager = crate::core::interface::InterfaceManager::new(
        fixture.service.network.clone(),
        AddressOwnershipJournal::in_memory(),
    );
    // Startup restores the interface journal before DHCP ownership recovery
    // and reconfiguration from the last committed policy.
    crate::core::transaction::recover_interface_transactions(
        fixture.overrides.recovery(),
        fixture.directory.path(),
        &manager,
        &committed,
        &crate::wifi::WifiRuntimeDirs::new(
            fixture.directory.path().join("hostapd"),
            fixture.directory.path().join("wpa_supplicant"),
        ),
    )
    .await
    .unwrap();
    let restarted = DhcpClientSupervisor::start(
        &committed
            .effective_config(&fixture.service.base_config)
            .unwrap(),
        Arc::new(FakeNetwork {
            addresses: Vec::new(),
        }),
    )
    .await
    .unwrap();
    assert!(restarted.spec("wan0").await.unwrap().install_default_route);
    assert_eq!(fixture.overrides.snapshot().await, committed);
    assert!(!fixture
        .directory
        .path()
        .join("interface-transactions/wan0.json")
        .exists());
}

#[tokio::test]
async fn dhcp_client_control_configure_compensates_runtime_when_persistence_fails() {
    let (fixture, worker) = dhcp_confirm_fixture(false, 30).await;
    std::fs::create_dir(fixture.directory.path().join("runtime-overrides.json"))
        .expect("block override file rename");
    let response = fixture
        .service
        .dispatch(Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest::default(),
        })
        .await;
    let token = network_pending_token(response);
    let response = fixture
        .service
        .dispatch(Request::CommitNetworkChange {
            token: token.clone(),
        })
        .await;
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert!(fixture.supervisor.spec("wan0").await.is_some());
    assert!(fixture.overrides.snapshot().await.interfaces.is_empty());
    let response = fixture
        .service
        .dispatch(Request::RollbackNetworkChange { token })
        .await;
    assert!(
        matches!(response, Response::NetworkChangeRolledBack { .. }),
        "{response:?}"
    );
    assert!(fixture.supervisor.spec("wan0").await.is_none());
    worker.abort();
}

#[tokio::test]
async fn dhcp_client_control_delete_cleans_runtime_and_persists_disabled_intent() {
    let (fixture, worker) = dhcp_confirm_fixture(true, 30).await;
    let mut original = fixture
        .overrides
        .effective_interface("wan0")
        .await
        .unwrap()
        .unwrap();
    let policy = original.dhcp_client.as_mut().unwrap();
    policy.route_metric = 777;
    policy.install_default_route = false;
    policy.request_dns = false;
    policy.send_release_on_shutdown = false;
    let mut expected = policy.clone();
    expected.enabled = false;
    fixture
        .overrides
        .set_interface("wan0".into(), original, false)
        .await
        .unwrap();
    let response = fixture
        .service
        .dispatch(Request::DisableDhcpClient {
            interface: "wan0".into(),
        })
        .await;
    let token = network_pending_token(response);
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange { token })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    assert!(fixture.supervisor.spec("wan0").await.is_none());
    let persisted = fixture
        .overrides
        .effective_interface("wan0")
        .await
        .unwrap()
        .unwrap();
    assert!(
        persisted.managed,
        "managed interface remains managed when dhcp client is disabled"
    );
    assert_eq!(persisted.dhcp_client.unwrap(), expected);
    assert_eq!(persisted.wifi_client.unwrap().ssid, "upstream");
    worker.abort();
}

#[tokio::test]
async fn dhcp_client_control_delete_refuses_router_held_uplink_without_touching_runtime() {
    let fixture = dhcp_client_control_fixture_with_router(true, true).await;
    let response = fixture
        .service
        .dispatch(Request::DisableDhcpClient {
            interface: "wan0".into(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::DhcpClientError {
                detail: DhcpClientErrorDetail::InvalidConfig { .. }
            }
        ),
        "{response:?}"
    );

    assert!(fixture.supervisor.spec("wan0").await.is_some());
    let persisted = fixture
        .overrides
        .effective_interface("wan0")
        .await
        .unwrap()
        .unwrap();
    assert!(persisted.managed);
    assert!(persisted.dhcp_client.unwrap().enabled);
}

#[tokio::test]
async fn dhcp_client_control_renew_and_release_dispatch_keep_intent() {
    let fixture = dhcp_client_control_fixture(true).await;
    for request in [
        Request::RenewDhcpClient {
            interface: "wan0".into(),
        },
        Request::ReleaseDhcpClient {
            interface: "wan0".into(),
        },
    ] {
        let response = fixture.service.dispatch(request).await;
        assert!(
            matches!(response, Response::DhcpClientInterface { ref status } if status.interface == "wan0"),
            "{response:?}"
        );
        assert!(fixture.supervisor.spec("wan0").await.is_some());
    }
}

#[tokio::test]
async fn wifi_deactivate_preserves_independent_dhcp_intent() {
    let fixture = wifi_client_enabled_fixture().await;
    let before = fixture
        .service
        .overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .unwrap()
        .dhcp_client;
    let response = fixture
        .service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".into(),
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
    let after = fixture
        .service
        .overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .unwrap()
        .dhcp_client;
    assert_eq!(before, after);
    assert!(after.unwrap().enabled);
}

#[tokio::test]
async fn uncertain_dhcp_commit_preserves_candidate_and_blocks_subsequent_mutations() {
    let (fixture, worker) = dhcp_confirm_fixture(false, 30).await;
    fixture
        .overrides
        .save_committed(fixture.overrides.snapshot().await)
        .await
        .unwrap();
    crate::atomic_file::fail_replacement_and_compensation(fixture.overrides.path());
    let response = fixture
        .service
        .dispatch(Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest::default(),
        })
        .await;
    let token = network_pending_token(response);
    let response = fixture
        .service
        .dispatch(Request::CommitNetworkChange {
            token: token.clone(),
        })
        .await;
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert!(fixture.supervisor.spec("wan0").await.is_some());
    let response = fixture
        .service
        .dispatch(Request::DisableDhcpClient {
            interface: "wan0".into(),
        })
        .await;
    assert!(
        matches!(response, Response::Error { ref message } if message.contains("commit_indeterminate")),
        "{response:?}"
    );
    assert!(fixture.supervisor.spec("wan0").await.is_some());
    worker.abort();
}

#[tokio::test]
async fn dhcp_client_disable_persists_when_runtime_spec_is_absent() {
    let (fixture, worker) = dhcp_confirm_fixture(true, 30).await;
    fixture.supervisor.disable("wan0").await.unwrap();
    assert!(fixture.supervisor.spec("wan0").await.is_none());
    let response = fixture
        .service
        .dispatch(Request::DisableDhcpClient {
            interface: "wan0".into(),
        })
        .await;
    let token = network_pending_token(response);
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange { token })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    assert!(
        !fixture
            .overrides
            .effective_interface("wan0")
            .await
            .unwrap()
            .unwrap()
            .dhcp_client
            .unwrap()
            .enabled
    );
    let reloaded =
        crate::state::overrides::RuntimeOverrideStore::in_state_dir(fixture.directory.path())
            .load()
            .await
            .unwrap();
    assert!(
        !reloaded.interfaces["wan0"]
            .config
            .dhcp_client
            .as_ref()
            .unwrap()
            .enabled
    );
    worker.abort();
}

#[tokio::test]
async fn dhcp_dns_defaults_dispatch_uses_saved_settings_immediately() {
    use traffic_masq_protocol::DhcpDnsDefaults;
    let directory = tempdir().unwrap();
    let config = router_base_config();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let service = ControlService::new_detached(
        config,
        Arc::new(FakeNetwork {
            addresses: Vec::new(),
        }),
        dhcp,
        overrides.clone(),
    );
    assert!(
        matches!(service.dispatch(Request::GetDhcpDnsDefaults).await,
        Response::DhcpDnsDefaults { settings } if settings == DhcpDnsDefaults::default())
    );
    for servers in [vec![Ipv4Addr::new(9, 9, 9, 9)], vec![]] {
        let desired = DhcpDnsDefaults { servers };
        assert!(
            matches!(service.dispatch(Request::ConfigureDhcpDnsDefaults { settings: desired.clone() }).await,
            Response::DhcpDnsDefaults { settings } if settings == desired)
        );
        let effective = service.effective_config().await.unwrap();
        let dhcp = default_dhcp_settings(
            "192.168.50.1/24".parse().unwrap(),
            effective.dhcp.default_dns_servers,
        )
        .unwrap();
        assert_eq!(dhcp.dns_servers, desired.servers);
        assert!(
            matches!(service.dispatch(Request::GetDhcpDnsDefaults).await,
            Response::DhcpDnsDefaults { settings } if settings == desired)
        );
    }
}
