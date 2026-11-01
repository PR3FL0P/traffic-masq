use super::*;

#[tokio::test]
async fn router_without_intent_reports_inactive_provisioning_state() {
    let mut config = router_base_config_with_router_enabled();
    config.router.uplink = None;
    config.router.forwarding = None;
    let (service, _directory) =
        router_service_with_config(Arc::new(FakeRouterSubsystems::default()), config).await;

    match service.dispatch(Request::RouterProvisioningStatus).await {
        Response::RouterProvisioningStatus { status } => {
            assert_eq!(status.stage, ProvisioningStage::Inactive);
            assert!(!status.enabled);
            assert!(!status.ready);
            assert_eq!(status.coordinator, CoordinatorStatus::Idle);
        }
        other => panic!("expected unconfigured provisioning status, got {other:?}"),
    }
}

#[tokio::test]
async fn enabled_router_without_uplink_with_routes_reports_ready_provisioning_state() {
    let mut config = router_base_config_with_router_enabled();
    config.router.uplink = None;
    config.router.owned_routes = vec![crate::config::OwnedIpv4RouteConfig {
        destination: "10.0.0.0/24".parse().expect("destination"),
        gateway: Some(std::net::Ipv4Addr::new(192, 168, 1, 1)),
        output_interface: None,
        table: 254,
        metric: Some(100),
    }];
    let (service, _directory) =
        router_service_with_config(Arc::new(FakeRouterSubsystems::default()), config).await;

    match service.dispatch(Request::RouterProvisioningStatus).await {
        Response::RouterProvisioningStatus { status } => {
            assert_eq!(status.stage, ProvisioningStage::Ready);
            assert!(status.enabled);
            assert!(status.ready);
            assert_eq!(status.coordinator, CoordinatorStatus::Idle);
        }
        other => panic!("expected ready provisioning status, got {other:?}"),
    }
}

#[tokio::test]
async fn provisioning_preview_derives_complete_downstream_defaults() {
    let fixture = provisioning_fixture().await;

    let preview = preview_of(
        fixture
            .service
            .dispatch(preview_request(provisioning_request()))
            .await,
    );

    assert_eq!(
        preview.downstream.interface_ipv4,
        "10.77.0.1/24".parse().unwrap()
    );
    assert_eq!(preview.downstream.subnet, "10.77.0.0/24".parse().unwrap());
    assert_eq!(preview.downstream.router, Ipv4Addr::new(10, 77, 0, 1));
    assert_eq!(preview.downstream.pool_start, Ipv4Addr::new(10, 77, 0, 100));
    assert_eq!(preview.downstream.pool_end, Ipv4Addr::new(10, 77, 0, 200));
    assert_eq!(preview.downstream.lease_seconds, DEFAULT_DHCP_LEASE_SECONDS);
    assert!(preview.downstream.dns_servers.is_empty());
    assert_eq!(preview.uplink.mode, UplinkMode::Dhcp);
    assert!(preview
        .warnings
        .contains(&ProvisioningWarning::NoDownstreamDns));
    assert!(preview
        .warnings
        .contains(&ProvisioningWarning::PendingSecret {
            interface: "wlan-out".to_string()
        }));

    assert_eq!(fixture.overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn provisioning_preview_carries_no_secret_or_secret_path() {
    let fixture = provisioning_fixture().await;
    fixture
        .wifi
        .set_passphrase(
            "wlan-out",
            &WifiPassphrase::new("downstream-secret").expect("valid passphrase"),
        )
        .await
        .expect("stage AP secret");

    let response = fixture
        .service
        .dispatch(Request::RouterProvisioningPreview {
            request: RouterProvisioningPreviewRequest {
                provisioning: provisioning_request(),
                uplink_secret_pending: true,
                output_secret_pending: false,
            },
        })
        .await;
    let encoded = serde_json::to_string(&response).expect("serializable response");

    assert!(!encoded.contains("downstream-secret"), "{encoded}");
    assert!(!encoded.contains("passphrase_file"), "{encoded}");
    assert!(!encoded.contains("psk"), "{encoded}");
    let preview = preview_of(response);

    assert!(preview.output.secret_available);
    assert!(preview.uplink.secret_available);
}

#[tokio::test]
async fn provisioning_preview_relocates_a_conflicting_default_subnet() {
    let directory = tempdir().expect("tempdir");
    let fixture = provisioning_fixture_with(
        Arc::new(FakeProvisioningSubsystems::default()),
        provisioning_base_config(directory.path()),
        ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]).with_address(
            "eth0",
            [10, 77, 0, 5],
            24,
        ),
        Duration::from_millis(200),
    )
    .await;

    let preview = preview_of(
        fixture
            .service
            .dispatch(preview_request(provisioning_request()))
            .await,
    );

    assert_eq!(
        preview.downstream.interface_ipv4,
        "10.77.1.1/24".parse().unwrap()
    );
    assert!(preview
        .warnings
        .contains(&ProvisioningWarning::DownstreamSubnetRelocated {
            preferred: "10.77.0.0/24".parse().unwrap(),
            selected: "10.77.1.0/24".parse().unwrap(),
        }));
}

#[tokio::test]
async fn provisioning_rejects_a_management_interface_without_confirmation() {
    let directory = tempdir().expect("tempdir");
    let mut config = provisioning_base_config(directory.path());
    config.network.interfaces.insert(
        "wlan-up".to_string(),
        InterfaceConfig {
            wifi_concurrent: false,
            randomize_mac: false,
            mac_address: None,
            role: InterfaceRole::None,
            managed: false,
            ipv4: Some("192.168.1.20/24".parse().unwrap()),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    let fixture = provisioning_fixture_with(
        Arc::new(FakeProvisioningSubsystems::default()),
        config,
        ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]),
        Duration::from_millis(200),
    )
    .await;

    assert_eq!(
        provisioning_detail(
            fixture
                .service
                .dispatch(apply_request(provisioning_request()))
                .await
        ),
        RouterProvisioningErrorDetail::ManagementConfirmationRequired {
            interface: "wlan-up".to_string()
        }
    );
    assert_eq!(fixture.overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn provisioning_rejects_a_protected_network_with_no_available_secret() {
    let fixture = provisioning_fixture().await;

    let response = fixture
        .service
        .dispatch(Request::RouterProvisioningApply {
            request: RouterProvisioningApplyRequest {
                provisioning: provisioning_request(),
                uplink_passphrase: Some("upstream-secret".to_string()),
                output_passphrase: None,
            },
        })
        .await;

    assert_eq!(
        provisioning_detail(response),
        RouterProvisioningErrorDetail::OutputSecretMissing {
            interface: "wlan-out".to_string()
        }
    );

    assert!(fixture
        .wifi_client
        .stored_passphrase("wlan-up")
        .await
        .expect("store readable")
        .is_none());
    assert_eq!(fixture.overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn provisioning_apply_stages_secrets_and_opens_one_coordinator_transaction() {
    let fixture = provisioning_fixture().await;

    let (token, preview) = match fixture
        .service
        .dispatch(apply_request(provisioning_request()))
        .await
    {
        Response::RouterProvisioningApplied { token, preview } => (token, preview),
        other => panic!("expected an applied transaction, got {other:?}"),
    };
    assert!(!token.is_empty());
    assert!(preview.output.secret_available);
    assert!(preview.uplink.secret_available);
    assert!(!preview
        .warnings
        .iter()
        .any(|warning| matches!(warning, ProvisioningWarning::PendingSecret { .. })));

    assert!(fixture
        .wifi
        .stored_passphrase("wlan-out")
        .await
        .expect("store readable")
        .is_some());
    assert!(fixture
        .wifi_client
        .stored_passphrase("wlan-up")
        .await
        .expect("store readable")
        .is_some());
    assert_eq!(
        fixture.subsystems.applied_output_wifi.lock().unwrap().len(),
        1
    );
    assert_eq!(
        fixture.subsystems.applied_uplink_wifi.lock().unwrap().len(),
        1
    );

    match fixture
        .service
        .dispatch(Request::RouterProvisioningStatus)
        .await
    {
        Response::RouterProvisioningStatus { status } => {
            assert_eq!(status.stage, ProvisioningStage::AwaitingConfirmation);
            assert_eq!(status.coordinator, CoordinatorStatus::Pending);
        }
        other => panic!("expected provisioning status, got {other:?}"),
    }

    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RouterCommit {
                token: fixture
                    .service
                    .router
                    .as_ref()
                    .unwrap()
                    .pending_token()
                    .await
                    .unwrap_or_default()
            })
            .await,
        Response::RouterCommitted { revision: 1 }
    ));

    match fixture
        .service
        .dispatch(Request::RouterProvisioningStatus)
        .await
    {
        Response::RouterProvisioningStatus { status } => {
            assert_eq!(status.stage, ProvisioningStage::Ready);
            assert!(status.enabled);
            assert!(status.ready);
            assert!(status.failures.is_empty());
        }
        other => panic!("expected provisioning status, got {other:?}"),
    }

    let output = fixture
        .overrides
        .effective_interface("wlan-out")
        .await
        .expect("effective interface")
        .expect("provisioned output interface");
    let dhcp = output.dhcp.expect("derived downstream DHCP service");
    assert_eq!(output.ipv4, Some("10.77.0.1/24".parse().unwrap()));
    assert_eq!(dhcp.pool_start, Ipv4Addr::new(10, 77, 0, 100));
    assert_eq!(dhcp.pool_end, Ipv4Addr::new(10, 77, 0, 200));
    assert_eq!(dhcp.lease_seconds, Some(DEFAULT_DHCP_LEASE_SECONDS));
}

#[tokio::test]
async fn provisioning_apply_is_idempotent_about_the_derived_subnet() {
    let fixture = provisioning_fixture().await;
    assert!(matches!(
        fixture
            .service
            .dispatch(apply_request(provisioning_request()))
            .await,
        Response::RouterProvisioningApplied { .. }
    ));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RouterCommit {
                token: fixture
                    .service
                    .router
                    .as_ref()
                    .unwrap()
                    .pending_token()
                    .await
                    .unwrap_or_default()
            })
            .await,
        Response::RouterCommitted { .. }
    ));

    let preview = preview_of(
        fixture
            .service
            .dispatch(preview_request(provisioning_request()))
            .await,
    );
    assert_eq!(
        preview.downstream.interface_ipv4,
        "10.77.0.1/24".parse().unwrap()
    );
}

#[tokio::test]
async fn provisioning_apply_refuses_a_second_concurrent_transaction() {
    let fixture = provisioning_fixture().await;
    assert!(matches!(
        fixture
            .service
            .dispatch(apply_request(provisioning_request()))
            .await,
        Response::RouterProvisioningApplied { .. }
    ));

    assert_eq!(
        provisioning_detail(
            fixture
                .service
                .dispatch(apply_request(provisioning_request()))
                .await
        ),
        RouterProvisioningErrorDetail::TransactionPending
    );
}

#[tokio::test]
async fn provisioning_apply_reports_a_readiness_timeout_and_restores_prior_secrets() {
    let directory = tempdir().expect("tempdir");
    let subsystems = Arc::new(FakeProvisioningSubsystems::default());
    *subsystems.uplink_dhcp_unready.lock().unwrap() = true;
    let fixture = provisioning_fixture_with(
        subsystems,
        provisioning_base_config(directory.path()),
        ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]),
        Duration::from_millis(50),
    )
    .await;

    let detail = provisioning_detail(
        fixture
            .service
            .dispatch(apply_request(provisioning_request()))
            .await,
    );
    assert!(
        matches!(
            detail,
            RouterProvisioningErrorDetail::ReadinessTimeout { .. }
        ),
        "{detail:?}"
    );

    assert!(fixture
        .wifi
        .stored_passphrase("wlan-out")
        .await
        .expect("store readable")
        .is_none());
    assert!(fixture
        .wifi_client
        .stored_passphrase("wlan-up")
        .await
        .expect("store readable")
        .is_none());
    assert_eq!(fixture.overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn provisioning_status_reports_a_degraded_committed_topology() {
    let fixture = provisioning_fixture().await;
    assert!(matches!(
        fixture
            .service
            .dispatch(apply_request(provisioning_request()))
            .await,
        Response::RouterProvisioningApplied { .. }
    ));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RouterCommit {
                token: fixture
                    .service
                    .router
                    .as_ref()
                    .unwrap()
                    .pending_token()
                    .await
                    .unwrap_or_default()
            })
            .await,
        Response::RouterCommitted { .. }
    ));
    *fixture.subsystems.unhealthy_dataplane.lock().unwrap() = true;

    match fixture
        .service
        .dispatch(Request::RouterProvisioningStatus)
        .await
    {
        Response::RouterProvisioningStatus { status } => {
            assert_eq!(status.stage, ProvisioningStage::Degraded);
            assert!(status.enabled);
            assert!(!status.ready);
            assert!(status.readiness.dataplane.is_some());
            assert!(status.readiness.interfaces.is_none());
        }
        other => panic!("expected provisioning status, got {other:?}"),
    }
}

#[tokio::test]
async fn provisioning_requests_are_rejected_when_the_router_is_disabled() {
    let directory = tempdir().expect("tempdir");
    let config = provisioning_base_config(directory.path());
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let service = ControlService::new_detached(
        config,
        Arc::new(ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]))
            as Arc<dyn NetworkProvider>,
        dhcp,
        overrides,
    );

    for request in [
        preview_request(provisioning_request()),
        apply_request(provisioning_request()),
        Request::RouterProvisioningStatus,
    ] {
        assert_eq!(
            provisioning_detail(service.dispatch(request).await),
            RouterProvisioningErrorDetail::RouterDisabled
        );
    }
}

#[tokio::test]
async fn provisioning_rejects_one_interface_in_both_roles() {
    let fixture = provisioning_fixture().await;
    let mut request = provisioning_request();
    request.output.interface = request.uplink.interface.clone();

    assert_eq!(
        provisioning_detail(fixture.service.dispatch(preview_request(request)).await),
        RouterProvisioningErrorDetail::InterfaceReused {
            interface: "wlan-up".to_string()
        }
    );
}

#[tokio::test]
async fn provisioning_rejects_an_interface_that_does_not_exist() {
    let fixture = provisioning_fixture().await;
    let mut request = provisioning_request();
    request.output.interface = "wlan-absent".to_string();

    assert_eq!(
        provisioning_detail(fixture.service.dispatch(preview_request(request)).await),
        RouterProvisioningErrorDetail::InterfaceNotFound {
            interface: "wlan-absent".to_string()
        }
    );
}

#[tokio::test]
async fn provisioning_rejects_an_advanced_pool_override_without_its_network() {
    let fixture = provisioning_fixture().await;
    let mut request = provisioning_request();
    request.downstream.pool_start = Some(Ipv4Addr::new(10, 77, 0, 50));
    request.downstream.pool_end = Some(Ipv4Addr::new(10, 77, 0, 60));

    assert!(
        matches!(
            provisioning_detail(fixture.service.dispatch(preview_request(request)).await),
            RouterProvisioningErrorDetail::InvalidPool { .. }
        ),
        "an explicit pool without an explicit network must be typed, not accepted"
    );
}

#[tokio::test]
async fn provisioning_applies_advanced_downstream_overrides_verbatim() {
    let fixture = provisioning_fixture().await;
    let mut request = provisioning_request();
    request.downstream = ProvisioningDownstreamOverrides {
        interface_ipv4: Some("172.20.5.1/24".parse().unwrap()),
        pool_start: Some(Ipv4Addr::new(172, 20, 5, 20)),
        pool_end: Some(Ipv4Addr::new(172, 20, 5, 40)),
        dns_servers: vec![Ipv4Addr::new(9, 9, 9, 9)],
        lease_seconds: Some(600),
    };

    let preview = preview_of(
        fixture
            .service
            .dispatch(preview_request(request.clone()))
            .await,
    );
    assert_eq!(
        preview.downstream.interface_ipv4,
        "172.20.5.1/24".parse().unwrap()
    );
    assert_eq!(preview.downstream.pool_start, Ipv4Addr::new(172, 20, 5, 20));
    assert_eq!(preview.downstream.pool_end, Ipv4Addr::new(172, 20, 5, 40));
    assert_eq!(
        preview.downstream.dns_servers,
        vec![Ipv4Addr::new(9, 9, 9, 9)]
    );
    assert_eq!(preview.downstream.lease_seconds, 600);
    assert!(!preview
        .warnings
        .contains(&ProvisioningWarning::NoDownstreamDns));

    assert!(matches!(
        fixture.service.dispatch(apply_request(request)).await,
        Response::RouterProvisioningApplied { .. }
    ));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RouterCommit {
                token: fixture
                    .service
                    .router
                    .as_ref()
                    .unwrap()
                    .pending_token()
                    .await
                    .unwrap_or_default()
            })
            .await,
        Response::RouterCommitted { .. }
    ));
    let output = fixture
        .overrides
        .effective_interface("wlan-out")
        .await
        .expect("effective interface")
        .expect("provisioned output interface");
    let dhcp = output.dhcp.expect("derived downstream DHCP service");
    assert_eq!(dhcp.pool_start, Ipv4Addr::new(172, 20, 5, 20));
    assert_eq!(dhcp.dns_servers, vec![Ipv4Addr::new(9, 9, 9, 9)]);
    assert_eq!(dhcp.lease_seconds, Some(600));
}

#[tokio::test]
async fn provisioning_rejects_an_explicit_downstream_conflict() {
    let directory = tempdir().expect("tempdir");
    let fixture = provisioning_fixture_with(
        Arc::new(FakeProvisioningSubsystems::default()),
        provisioning_base_config(directory.path()),
        ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]).with_address(
            "eth0",
            [192, 168, 1, 20],
            24,
        ),
        Duration::from_millis(200),
    )
    .await;
    let mut request = provisioning_request();
    request.downstream.interface_ipv4 = Some("192.168.1.1/24".parse().unwrap());

    let detail = provisioning_detail(fixture.service.dispatch(preview_request(request)).await);
    match detail {
        RouterProvisioningErrorDetail::SubnetConflict {
            requested,
            conflicting,
            ..
        } => {
            assert_eq!(requested, "192.168.1.0/24".parse().unwrap());
            assert_eq!(conflicting, "192.168.1.0/24".parse().unwrap());
        }
        other => panic!("expected a typed subnet conflict, got {other:?}"),
    }
}

#[test]
fn provisioning_apply_request_debug_redacts_key_material() {
    let formatted = format!(
        "{:?}",
        Request::RouterProvisioningApply {
            request: RouterProvisioningApplyRequest {
                provisioning: provisioning_request(),
                uplink_passphrase: Some("upstream-secret".to_string()),
                output_passphrase: None,
            },
        }
    );

    assert!(!formatted.contains("upstream-secret"), "{formatted}");
    assert!(formatted.contains("<redacted>"), "{formatted}");
    assert!(formatted.contains("<absent>"), "{formatted}");
}

#[tokio::test]
async fn wifi_provisioning_rejects_interfaces_without_the_required_role() {
    let ap = wifi_enabled_fixture().await;
    let client = wifi_client_enabled_fixture().await;
    let mut input = client.service.base_config.network.interfaces["wlan1"].clone();
    input.wifi_client = None;
    ap.service
        .overrides
        .set_interface("input".into(), input, false)
        .await
        .unwrap();
    let mut output = ap.service.base_config.network.interfaces["wlan0"].clone();
    output.wifi = None;
    client
        .service
        .overrides
        .set_interface("output".into(), output, false)
        .await
        .unwrap();
    for interface in ["missing", "input"] {
        let response = ap
            .service
            .dispatch(Request::ProvisionWifiAccessPoint {
                interface: interface.into(),
                settings: WifiEditRequest {
                    ssid: "test".into(),
                    country_code: None,
                    band: WifiBand::Ghz2,
                    channel: 0,
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
        assert!(
            matches!(response, Response::WifiError {
            detail: WifiErrorDetail::InvalidSpec { ref message }
        } if message.contains("managed output")),
            "{response:?}"
        );
    }
    for interface in ["missing", "output"] {
        let response = client
            .service
            .dispatch(Request::ProvisionWifiClient {
                interface: interface.into(),
                settings: crate::api::model::ProvisionWifiClientRequest {
                    profile_id: "unused".into(),
                    ip_policy: crate::api::model::WifiClientIpPolicy::Dhcp,
                },
            })
            .await;
        assert!(
            matches!(response, Response::WifiClientError {
            detail: WifiClientErrorDetail::InvalidSpec { ref message }
        } if message.contains("managed input")),
            "{response:?}"
        );
    }
}

// Exercise both production timers through an accepted provisioning request.
// A transient router failure must not orphan the other half of the transaction.
#[tokio::test]
async fn regression_provisioning_secrets_follow_successful_automatic_router_retry() {
    let directory = tempdir().unwrap();
    let mut config = provisioning_base_config(directory.path());
    config.security.rollback_timeout_seconds = 1;
    let mut fixture = provisioning_fixture_with(
        Arc::new(FakeProvisioningSubsystems::default()),
        config,
        ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]),
        Duration::from_millis(200),
    )
    .await;
    fixture.service = fixture
        .service
        .with_router_coordinator(RouterTransactionCoordinator::new(
            RouterManager::new(fixture.subsystems.clone()),
            fixture.overrides.clone(),
            Duration::from_secs(1),
        ));
    *fixture.subsystems.rollback_unavailable.lock().unwrap() = true;
    let response = fixture
        .service
        .dispatch(apply_request(provisioning_request()))
        .await;
    assert!(
        matches!(response, Response::RouterProvisioningApplied { .. }),
        "{response:?}"
    );
    let router = fixture.service.router.as_ref().unwrap();
    // Wait for the failed attempt to complete; elapsed time alone does not
    // prove the timer's filesystem work has finished.
    tokio::time::timeout(Duration::from_secs(5), async {
        while router.status().await != CoordinatorStatus::RollbackFailed {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("automatic router rollback must encounter the injected failure");
    *fixture.subsystems.rollback_unavailable.lock().unwrap() = false;
    tokio::time::timeout(Duration::from_secs(5), async {
        while router.status().await != CoordinatorStatus::Idle {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("transient router failure must recover automatically");
    assert_eq!(fixture.overrides.committed_revision().await, 0);

    let restored = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let uplink = fixture
                .wifi_client
                .stored_passphrase("wlan-up")
                .await
                .unwrap();
            let output = fixture.wifi.stored_passphrase("wlan-out").await.unwrap();
            if uplink.is_none()
                && output.is_none()
                && !fixture
                    ._directory
                    .path()
                    .join("router-provisioning-secrets.json")
                    .exists()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(restored.is_ok(),
        "router recovered automatically, but uncommitted provisioning secrets/journal remain; ordinary network mutations stay blocked");
}

#[tokio::test]
async fn provisioning_plan_failure_restores_both_secrets_before_coordinator_apply() {
    let fixture = provisioning_fixture().await;
    let old = crate::wifi::WifiPassphrase::new("previous provisioning secret").unwrap();
    fixture.wifi.set_passphrase("wlan-out", &old).await.unwrap();
    fixture
        .wifi_client
        .set_passphrase("wlan-up", &old)
        .await
        .unwrap();
    *fixture.subsystems.plan_unavailable.lock().unwrap() = true;
    let response = fixture
        .service
        .dispatch(apply_request(provisioning_request()))
        .await;
    assert!(
        matches!(response, Response::RouterProvisioningError { .. }),
        "{response:?}"
    );
    assert_eq!(
        fixture
            .wifi
            .stored_passphrase("wlan-out")
            .await
            .unwrap()
            .unwrap()
            .expose(),
        old.expose()
    );
    assert_eq!(
        fixture
            .wifi_client
            .stored_passphrase("wlan-up")
            .await
            .unwrap()
            .unwrap()
            .expose(),
        old.expose()
    );
    assert_eq!(fixture.overrides.committed_revision().await, 0);
    assert_eq!(
        fixture.service.router.as_ref().unwrap().status().await,
        CoordinatorStatus::Idle
    );
    assert!(!fixture
        ._directory
        .path()
        .join("router-provisioning-secrets.json")
        .exists());
}
