use super::*;

#[test]
fn unmanaging_an_interface_with_no_router_services_needs_no_confirmation() {
    let current = InterfaceConfig {
        wifi_concurrent: false,
        randomize_mac: false,
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };
    let mut new_config = current.clone();
    new_config.managed = false;

    assert!(ControlService::validate_router_service_management(
        "wlan0",
        Some(&current),
        &new_config,
        false,
    )
    .is_ok());
}

#[tokio::test]
async fn router_requests_are_rejected_when_router_mode_is_disabled() {
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
        Request::RouterStatus,
        Request::RouterPlan {
            proposal: router_proposal().into(),
        },
        Request::RouterApply {
            proposal: router_proposal().into(),
        },
        Request::RouterCommit {
            token: String::new(),
        },
        Request::RouterRollback {
            token: String::new(),
        },
        Request::RouterPendingTransaction,
    ] {
        let response = service.dispatch(request).await;
        assert!(matches!(
            response,
            Response::RouterError {
                detail: RouterErrorDetail::RouterDisabled
            }
        ));
    }
}

#[tokio::test]
async fn explicit_forwarding_without_uplink_is_not_reported_as_unconfigured() {
    let mut config = router_base_config_with_router_enabled();
    config.router.uplink = None;
    config.router.forwarding = Some(vec![crate::config::ForwardingConfig {
        source_subnet: None,
        from: "lan0".to_string(),
        to: "wan0".to_string(),
        masquerade: true,
    }]);
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
async fn router_plan_apply_commit_workflow_dispatches_through_control_service() {
    let (service, _directory) = router_enabled_service().await;

    match service.dispatch(Request::RouterStatus).await {
        Response::RouterStatus { enabled, .. } => assert!(!enabled),
        other => panic!("unexpected response: {other:?}"),
    }

    match service
        .dispatch(Request::RouterPlan {
            proposal: router_proposal().into(),
        })
        .await
    {
        Response::RouterPlan { plan } => assert!(plan.desired.enabled),
        other => panic!("unexpected response: {other:?}"),
    }

    let token = match service
        .dispatch(Request::RouterApply {
            proposal: router_proposal().into(),
        })
        .await
    {
        Response::RouterTransactionPending { token, plan } => {
            assert!(plan.desired.enabled);
            token
        }
        other => panic!("unexpected response: {other:?}"),
    };
    assert!(!token.is_empty());

    match service.dispatch(Request::RouterPendingTransaction).await {
        Response::RouterPendingTransaction {
            status,
            expires_at_unix,
            ..
        } => {
            assert!(expires_at_unix.is_some());
            assert_eq!(
                status,
                crate::core::router_transaction::CoordinatorStatus::Pending
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    match service
        .dispatch(Request::RouterCommit {
            token: service
                .router
                .as_ref()
                .unwrap()
                .pending_token()
                .await
                .unwrap_or_default(),
        })
        .await
    {
        Response::RouterCommitted { revision } => assert_eq!(revision, 1),
        other => panic!("unexpected response: {other:?}"),
    }

    match service.dispatch(Request::RouterStatus).await {
        Response::RouterStatus { enabled, ready, .. } => {
            assert!(enabled);
            assert!(ready);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn router_plan_apply_rollback_workflow_dispatches_through_control_service() {
    let (service, _directory) = router_enabled_service().await;

    match service
        .dispatch(Request::RouterApply {
            proposal: router_proposal().into(),
        })
        .await
    {
        Response::RouterTransactionPending { .. } => {}
        other => panic!("unexpected response: {other:?}"),
    }

    match service
        .dispatch(Request::RouterRollback {
            token: service
                .router
                .as_ref()
                .unwrap()
                .pending_token()
                .await
                .unwrap_or_default(),
        })
        .await
    {
        Response::RouterRolledBack => {}
        other => panic!("unexpected response: {other:?}"),
    }

    match service.dispatch(Request::RouterPendingTransaction).await {
        Response::RouterPendingTransaction { status, .. } => {
            assert_eq!(
                status,
                crate::core::router_transaction::CoordinatorStatus::Idle
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    match service
        .dispatch(Request::RouterRollback {
            token: service
                .router
                .as_ref()
                .unwrap()
                .pending_token()
                .await
                .unwrap_or_default(),
        })
        .await
    {
        Response::RouterError {
            detail: RouterErrorDetail::NoPendingTransaction,
        } => {}
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn second_concurrent_router_apply_is_rejected_with_typed_conflict() {
    let (service, _directory) = router_enabled_service().await;

    service
        .dispatch(Request::RouterApply {
            proposal: router_proposal().into(),
        })
        .await;

    match service
        .dispatch(Request::RouterApply {
            proposal: router_proposal().into(),
        })
        .await
    {
        Response::RouterError {
            detail: RouterErrorDetail::TransactionPending,
        } => {}
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn router_status_reports_ready_false_only_for_the_unhealthy_subsystem() {
    for subsystem in ["interfaces", "routes", "dhcp", "dataplane"] {
        let fake = Arc::new(FakeRouterSubsystems::default());
        fake.fail_health(subsystem);
        let (service, _directory) =
            router_service_with_config(fake, router_base_config_with_router_enabled()).await;

        match service.dispatch(Request::RouterStatus).await {
            Response::RouterStatus {
                enabled,
                ready,
                health,
                ..
            } => {
                assert!(enabled, "subsystem {subsystem}");
                assert!(!ready, "subsystem {subsystem}");
                let statuses = [
                    ("interfaces", health.interfaces.is_some()),
                    ("routes", health.routes.is_some()),
                    ("dhcp", health.dhcp.is_some()),
                    ("dataplane", health.dataplane.is_some()),
                ];
                for (name, is_unhealthy) in statuses {
                    assert_eq!(
                        is_unhealthy,
                        name == subsystem,
                        "subsystem {subsystem}: unexpected health.{name} state"
                    );
                }
            }
            other => panic!("unexpected response for {subsystem}: {other:?}"),
        }
    }
}

#[tokio::test]
async fn router_status_is_ready_when_all_subsystems_are_healthy() {
    let fake = Arc::new(FakeRouterSubsystems::default());
    let (service, _directory) =
        router_service_with_config(fake, router_base_config_with_router_enabled()).await;

    match service.dispatch(Request::RouterStatus).await {
        Response::RouterStatus {
            enabled,
            ready,
            health,
            ..
        } => {
            assert!(enabled);
            assert!(ready);
            assert!(health.interfaces.is_none());
            assert!(health.routes.is_none());
            assert!(health.dhcp.is_none());
            assert!(health.dataplane.is_none());
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn default_route_guard_covers_managed_to_unmanaged_and_input_transitions() {
    let (service, _directory) = route_guard_service(None).await;
    let current = router_base_config().network.interfaces["lan0"].clone();

    let mut unmanaged = current.clone();
    unmanaged.managed = false;
    let error = service
        .validate_default_route_management("lan0", Some(&current), &unmanaged, false)
        .await
        .expect_err("unmanaging the default-route interface needs confirmation");
    assert!(error.to_string().contains("default route"));

    let mut input = current.clone();
    input.role = InterfaceRole::Input;
    let error = service
        .validate_default_route_management("lan0", Some(&current), &input, false)
        .await
        .expect_err("re-roling the default-route interface needs confirmation");
    assert!(error.to_string().contains("default route"));

    service
        .validate_default_route_management("lan0", Some(&current), &input, true)
        .await
        .expect("explicit confirmation permits the transition");
}

#[tokio::test]
async fn default_route_guard_fails_closed_when_routes_cannot_be_observed() {
    let (service, _directory) = route_guard_service(Some("injected route dump failure")).await;
    let current = router_base_config().network.interfaces["lan0"].clone();

    let error = service
        .validate_default_route_management("lan0", Some(&current), &current, false)
        .await
        .expect_err("route observation failure must not bypass the safety guard");
    let message = format!("{error:#}");
    assert!(
        message.contains("failed to inspect IPv4 routes"),
        "{message}"
    );
    assert!(message.contains("injected route dump failure"), "{message}");
}

#[tokio::test]
async fn list_routes_and_get_router_config_dispatch() {
    let directory = tempdir().expect("tempdir");
    let config = router_base_config();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(RouteFakeNetwork {
        interfaces: vec![
            NetworkInterface {
                index: 2,
                name: "eth0".to_string(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: false,
            },
            NetworkInterface {
                index: 3,
                name: "wlan0".to_string(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: true,
            },
        ],
        routes: vec![
            crate::netlink::Ipv4RouteInfo {
                destination: "0.0.0.0/0".parse().unwrap(),
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                output_interface_index: Some(2),
                table: 254,
                metric: Some(100),
                protocol: 3, // Boot
                scope: 0,
            },
            crate::netlink::Ipv4RouteInfo {
                destination: "10.0.0.0/24".parse().unwrap(),
                gateway: None,
                output_interface_index: Some(3),
                table: 254,
                metric: None,
                protocol: 201, // TrafficMasqStatic
                scope: 253,
            },
            crate::netlink::Ipv4RouteInfo {
                destination: "127.0.0.1/32".parse().unwrap(),
                gateway: None,
                output_interface_index: Some(1),
                table: 255, // Local table
                metric: None,
                protocol: 2, // Kernel
                scope: 254,
            },
        ],
        route_error: None,
    });
    let service = ControlService::new_detached(config.clone(), network, dhcp, overrides);

    let resp = service
        .dispatch(Request::ListRoutes {
            include_local_table: false,
        })
        .await;
    match resp {
        Response::Routes { routes } => {
            assert_eq!(routes.len(), 2);
            assert_eq!(routes[0].destination, "10.0.0.0/24".parse().unwrap());
            assert_eq!(routes[0].output_interface.as_deref(), Some("wlan0"));
            assert_eq!(
                routes[0].owner,
                traffic_masq_protocol::RouteOwnerView::TrafficMasqStatic
            );

            assert_eq!(routes[1].destination, "0.0.0.0/0".parse().unwrap());
            assert_eq!(routes[1].output_interface.as_deref(), Some("eth0"));
            assert_eq!(routes[1].owner, traffic_masq_protocol::RouteOwnerView::Boot);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let resp_all = service
        .dispatch(Request::ListRoutes {
            include_local_table: true,
        })
        .await;
    match resp_all {
        Response::Routes { routes } => {
            assert_eq!(routes.len(), 3);
            assert_eq!(routes[2].table, 255);
            assert_eq!(routes[2].destination, "127.0.0.1/32".parse().unwrap());
            assert_eq!(
                routes[2].owner,
                traffic_masq_protocol::RouteOwnerView::Kernel
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let cfg_resp = service.dispatch(Request::GetRouterConfig).await;
    match cfg_resp {
        Response::RouterConfig { config: router_cfg } => {
            assert_eq!(router_cfg.is_active(), config.router.is_active());
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn explicit_router_retry_bypasses_only_its_own_persisted_stop() {
    let (service, directory) = router_enabled_service().await;
    let token = match service
        .dispatch(Request::RouterApply {
            proposal: router_proposal().into(),
        })
        .await
    {
        Response::RouterTransactionPending { token, .. } => token,
        response => panic!("unexpected response: {response:?}"),
    };
    let journal = directory.path().join("router-transaction.json");
    service
        .overrides
        .recovery()
        .stop(
            &journal,
            crate::core::recovery_control::FailureKind::Conflict,
            "external conflict",
        )
        .await
        .unwrap();
    match service.dispatch(Request::RouterPendingTransaction).await {
        Response::RouterPendingTransaction {
            status,
            recovery: Some(notice),
            ..
        } => {
            assert_eq!(status, CoordinatorStatus::RecoveryRequired);
            let progress = notice.recovery_progress.unwrap();
            assert_eq!(
                progress.failure_kind,
                traffic_masq_protocol::RecoveryFailureKind::Conflict
            );
            assert!(!progress.automatic_recovery);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(!matches!(
        service
            .dispatch(Request::RouterCommit {
                token: token.clone()
            })
            .await,
        Response::RouterCommitted { .. }
    ));
    assert!(matches!(
        service.dispatch(Request::RouterRollback { token }).await,
        Response::RouterRolledBack
    ));
    assert!(!journal.exists());
}

#[tokio::test]
async fn router_intent_preview_with_missing_dependencies_is_observational() {
    use traffic_masq_protocol::{InterfaceReadiness, InterfaceReadinessBlocker};
    let (service, directory) = router_enabled_service().await;
    let revision = service.overrides.committed_revision().await;
    match service
        .dispatch(Request::RouterIntentPreview {
            proposal: router_proposal().into(),
        })
        .await
    {
        Response::RouterIntentPreview {
            revision: preview_revision,
            config,
            desired,
            device_readiness,
            blockers,
            execution_available,
        } => {
            assert_eq!(preview_revision, revision);
            assert!(config.is_active() && desired.enabled && execution_available);
            assert_eq!(device_readiness, InterfaceReadiness::WaitingDevice);
            assert_eq!(
                blockers,
                vec![
                    InterfaceReadinessBlocker::MissingInterface {
                        interface: "lan0".into()
                    },
                    InterfaceReadinessBlocker::MissingInterface {
                        interface: "wan0".into()
                    },
                ]
            );
            // Legacy sharing is derived without a device or a runtime plan.
            assert!(matches!(
                desired.dataplane,
                traffic_masq_protocol::RouterDataplaneTargetView::Enabled(_)
            ));
        }
        response => panic!("{response:?}"),
    }
    assert_eq!(service.overrides.committed_revision().await, revision);
    assert!(!service.effective_config().await.unwrap().router.is_active());
    assert!(matches!(
        service.dispatch(Request::RouterPendingTransaction).await,
        Response::RouterPendingTransaction { token: None, .. }
    ));
    assert!(!directory.path().join("router-transaction.json").exists());
}

#[tokio::test]
async fn router_intent_preview_without_execution_preserves_saved_routes() {
    let directory = tempdir().unwrap();
    let mut config = router_base_config();
    config.runtime.state_dir = directory.path().into();
    config
        .router
        .owned_routes
        .push(crate::config::OwnedIpv4RouteConfig {
            destination: "10.30.0.0/16".parse().unwrap(),
            gateway: None,
            output_interface: Some("lan0".into()),
            table: 254,
            metric: Some(50),
        });
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let service = ControlService::new_detached(
        config,
        Arc::new(FakeNetwork { addresses: vec![] }),
        dhcp,
        overrides,
    );
    match service
        .dispatch(Request::RouterIntentPreview {
            proposal: Default::default(),
        })
        .await
    {
        Response::RouterIntentPreview {
            config,
            desired,
            execution_available,
            ..
        } => {
            assert!(!execution_available);
            assert!(config.is_active());
            assert_eq!(config.owned_routes.len(), 1);
            assert_eq!(
                config.owned_routes[0].output_interface.as_deref(),
                Some("lan0")
            );
            assert_eq!(desired.routes.len(), 1);
        }
        response => panic!("{response:?}"),
    }
}

#[tokio::test]
async fn router_intent_preview_distinguishes_unknown_and_ready_and_rejects_invalid_intent() {
    use traffic_masq_protocol::{InterfaceReadiness, InterfaceReadinessBlocker};
    let directory = tempdir().unwrap();
    let mut config = router_base_config();
    config.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    let service = ControlService::new_detached(config, network.clone(), dhcp, overrides.clone());
    network.add_interface("lan0", 7).await;
    network.add_interface("wan0", 8).await;
    assert!(matches!(service.dispatch(Request::RouterIntentPreview {
        proposal: router_proposal().into(),
    }).await, Response::RouterIntentPreview {
        device_readiness: InterfaceReadiness::Ready, blockers, ..
    } if blockers.is_empty()));
    *network.fail_interface_observation.lock().await = true;
    assert!(matches!(service.dispatch(Request::RouterIntentPreview {
        proposal: router_proposal().into(),
    }).await, Response::RouterIntentPreview {
        device_readiness: InterfaceReadiness::Unknown, blockers, ..
    } if matches!(blockers.as_slice(), [InterfaceReadinessBlocker::ObservationFailed { .. }])));
    let mut invalid = router_proposal();
    invalid
        .set_router
        .as_mut()
        .unwrap()
        .uplink
        .as_mut()
        .unwrap()
        .interface = "not-configured".into();
    assert!(matches!(
        service
            .dispatch(Request::RouterIntentPreview {
                proposal: invalid.into()
            })
            .await,
        Response::RouterError { .. }
    ));
    assert_eq!(overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn saved_router_intent_removes_missing_rules_independently_and_survives_restart() {
    let fake = Arc::new(FakeRouterSubsystems::default());
    let base = router_with_two_saved_sharing_rules();
    let (service, directory) = router_service_with_config(fake.clone(), base.clone()).await;
    let original = service.current_router_desired().await.unwrap();
    let mut saved = base.router.clone();
    saved.owned_routes.clear();
    saved.forwarding.as_mut().unwrap().remove(0);
    let revision = match service
        .dispatch(Request::SaveRouterIntent {
            config: saved.clone().into(),
            expected_revision: 0,
        })
        .await
    {
        Response::RouterIntentSaved {
            revision,
            deferred,
            missing_dependencies,
            cleanup_blockers,
            ..
        } => {
            assert!(deferred);
            assert!(missing_dependencies.contains(&"absent_wan".into()));
            assert!(cleanup_blockers.is_empty());
            revision
        }
        response => panic!("{response:?}"),
    };
    assert_eq!(service.effective_config().await.unwrap().router, saved);
    assert!(service
        .router
        .as_ref()
        .unwrap()
        .cleanup_removed_dataplane(&original)
        .await
        .is_err());
    let restarted = RuntimeOverrideManager::load(directory.path(), &service.config)
        .await
        .unwrap();
    let snapshot = restarted.snapshot().await;
    assert_eq!(snapshot.router.as_ref(), Some(&saved));
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: base.router.into(),
                expected_revision: 0,
            })
            .await,
        Response::RouterError {
            detail: RouterErrorDetail::StaleCandidate { .. }
        }
    ));
    assert_eq!(fake.cleanup_targets.lock().unwrap().len(), 1);
    saved.forwarding = Some(vec![]);
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: saved.clone().into(),
                expected_revision: revision,
            })
            .await,
        Response::RouterIntentSaved { .. }
    ));
    assert_eq!(service.effective_config().await.unwrap().router, saved);
    assert_eq!(fake.cleanup_targets.lock().unwrap().len(), 2);
    assert!(!directory.path().join("router-transaction.json").exists());
}

#[tokio::test]
async fn saved_router_intent_reports_cleanup_failure_after_durable_commit() {
    let fake = Arc::new(FakeRouterSubsystems::default());
    *fake.cleanup_failure.lock().unwrap() = true;
    let base = router_with_two_saved_sharing_rules();
    let (service, _) = router_service_with_config(fake.clone(), base.clone()).await;
    let mut saved = base.router;
    saved.forwarding = Some(vec![]);
    assert!(matches!(service.dispatch(Request::SaveRouterIntent {
        config: saved.clone().into(), expected_revision: 0,
    }).await, Response::RouterIntentSaved { revision: 1, cleanup_blockers, .. }
        if cleanup_blockers.iter().any(|blocker| blocker.contains("injected cleanup failure"))));
    assert_eq!(service.effective_config().await.unwrap().router, saved);
    assert_eq!(
        service.router.as_ref().unwrap().status().await,
        CoordinatorStatus::Idle
    );
    *fake.cleanup_failure.lock().unwrap() = false;
    service
        .router
        .as_ref()
        .unwrap()
        .cleanup_removed_dataplane(&service.current_router_desired().await.unwrap())
        .await
        .unwrap();
    assert_eq!(service.overrides.committed_revision().await, 1);
}

#[tokio::test]
async fn saved_router_intent_blocks_unknown_live_and_non_router_changes() {
    let directory = tempdir().unwrap();
    let mut config = router_with_two_saved_sharing_rules();
    config.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    let fake = Arc::new(FakeRouterSubsystems::default());
    let coordinator = RouterTransactionCoordinator::new(
        crate::core::router::RouterManager::new(fake.clone()),
        overrides.clone(),
        Duration::from_secs(30),
    );
    let service =
        ControlService::new_detached(config.clone(), network.clone(), dhcp, overrides.clone())
            .with_router_coordinator(coordinator);
    let mut saved = config.router.clone();
    saved.forwarding.as_mut().unwrap().pop();
    *network.fail_interface_observation.lock().await = true;
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: saved.clone().into(),
                expected_revision: 0
            })
            .await,
        Response::RouterError { .. }
    ));
    *network.fail_interface_observation.lock().await = false;
    for (index, name) in ["lan0", "wan0", "absent_lan", "absent_wan"]
        .into_iter()
        .enumerate()
    {
        network.add_interface(name, index as u32 + 1).await;
    }
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: saved.clone().into(),
                expected_revision: 0
            })
            .await,
        Response::RouterError { .. }
    ));
    saved.uplink = None;
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: saved.into(),
                expected_revision: 0
            })
            .await,
        Response::RouterError { .. }
    ));
    assert_eq!(overrides.committed_revision().await, 0);
    assert!(fake.cleanup_targets.lock().unwrap().is_empty());
}

#[tokio::test]
async fn saved_router_intent_preserves_pending_transaction_and_supports_disabled_storage() {
    let fake = Arc::new(FakeRouterSubsystems::default());
    let base = router_with_two_saved_sharing_rules();
    let (service, _) = router_service_with_config(fake.clone(), base.clone()).await;
    let token = match service
        .dispatch(Request::RouterApply {
            proposal: Default::default(),
        })
        .await
    {
        Response::RouterTransactionPending { token, .. } => token,
        response => panic!("{response:?}"),
    };
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: base.router.into(),
                expected_revision: 0
            })
            .await,
        Response::Error { .. }
    ));
    assert_eq!(service.overrides.committed_revision().await, 0);
    assert!(fake.cleanup_targets.lock().unwrap().is_empty());
    assert!(matches!(
        service.dispatch(Request::RouterRollback { token }).await,
        Response::RouterRolledBack
    ));

    let directory = tempdir().unwrap();
    let mut base = router_base_config();
    base.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new_detached(
        base,
        Arc::new(FakeNetwork { addresses: vec![] }),
        dhcp,
        overrides,
    );
    let saved = crate::config::RouterConfig {
        forwarding: Some(vec![]),
        ..Default::default()
    };
    assert!(
        matches!(service.dispatch(Request::SaveRouterIntent { config: saved.into(), expected_revision: 0 }).await,
        Response::RouterIntentSaved { execution_available: false, cleanup_blockers, .. } if !cleanup_blockers.is_empty())
    );
}

#[tokio::test]
async fn cancelled_router_cleanup_keeps_coordination_until_writes_settle() {
    let fake = Arc::new(FakeRouterSubsystems::default());
    let hold = Arc::new(tokio::sync::Notify::new());
    *fake.cleanup_hold.lock().unwrap() = Some(hold.clone());
    let (service, _) =
        router_service_with_config(fake.clone(), router_with_two_saved_sharing_rules()).await;
    let router = service.router.clone().unwrap();
    let desired = service.current_router_desired().await.unwrap();
    let caller = tokio::spawn({
        let router = router.clone();
        async move { router.cleanup_removed_dataplane(&desired).await }
    });
    fake.cleanup_started.notified().await;
    caller.abort();
    let _ = caller.await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), router.wait_until_idle())
            .await
            .is_err()
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), router.status())
            .await
            .unwrap(),
        CoordinatorStatus::Idle,
        "status observation must remain available while cleanup retains coordination"
    );
    hold.notify_one();
    tokio::time::timeout(Duration::from_secs(2), router.wait_until_idle())
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), router.status())
            .await
            .unwrap(),
        CoordinatorStatus::Idle
    );
    assert_eq!(service.overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn uncertain_router_intent_commit_never_cleans_runtime_and_fences_later_saves() {
    let fake = Arc::new(FakeRouterSubsystems::default());
    let (service, _) =
        router_service_with_config(fake.clone(), router_with_two_saved_sharing_rules()).await;
    service
        .overrides
        .save_committed(service.overrides.snapshot().await)
        .await
        .unwrap();
    let revision = service.overrides.committed_revision().await;
    crate::atomic_file::fail_replacement_and_compensation(service.overrides.path());
    let mut saved = service.effective_config().await.unwrap().router;
    saved.forwarding = Some(vec![]);
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: saved.clone().into(),
                expected_revision: revision
            })
            .await,
        Response::RouterError { .. }
    ));
    assert!(fake.cleanup_targets.lock().unwrap().is_empty());
    assert!(
        matches!(service.dispatch(Request::SaveRouterIntent { config: saved.into(), expected_revision: revision }).await,
        Response::Error { message } if message.contains("commit_indeterminate"))
    );
    assert!(fake.cleanup_targets.lock().unwrap().is_empty());
}

#[tokio::test]
async fn route_inventory_keeps_missing_saved_routes_and_does_not_adopt_foreign_routes() {
    use traffic_masq_protocol::InterfacePresence;
    let directory = tempdir().unwrap();
    let mut config = router_base_config();
    config.runtime.state_dir = directory.path().into();
    let saved = crate::config::OwnedIpv4RouteConfig {
        destination: "203.0.113.0/24".parse().unwrap(),
        gateway: None,
        output_interface: Some("wan0".into()),
        table: 254,
        metric: Some(100),
    };
    config.router.owned_routes = vec![saved.clone()];
    let observed = crate::netlink::Ipv4RouteInfo {
        destination: saved.destination,
        gateway: None,
        output_interface_index: Some(7),
        table: 254,
        metric: Some(100),
        protocol: 4,
        scope: 253,
    };
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    *network.routes.lock().await = vec![observed.clone()];
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let service = ControlService::new_detached(config, network.clone(), dhcp, overrides);
    match service
        .dispatch(Request::ListRouteInventory {
            include_local_table: false,
        })
        .await
    {
        Response::RouteInventory {
            revision,
            config,
            routes,
            observation_error,
        } => {
            assert_eq!(revision, 0);
            assert!(config.is_active());
            assert_eq!(routes.len(), 2);
            assert!(routes[0].configured.is_some());
            assert!(routes[0].observed.is_none());
            assert_eq!(routes[0].output_presence, Some(InterfacePresence::Missing));
            assert!(routes[1].configured.is_none());
            assert_eq!(routes[1].observed.as_ref().unwrap().protocol, 4);
            assert!(observation_error.is_none());
        }
        response => panic!("{response:?}"),
    }
    network.add_interface("wan0", 7).await;
    *network.routes.lock().await = vec![crate::netlink::Ipv4RouteInfo {
        protocol: crate::netlink::TRAFFIC_MASQ_ROUTE_PROTOCOL,
        ..observed
    }];
    match service
        .dispatch(Request::ListRouteInventory {
            include_local_table: false,
        })
        .await
    {
        Response::RouteInventory { routes, .. } => {
            assert_eq!(routes.len(), 1);
            assert!(routes[0].configured.is_some() && routes[0].observed.is_some());
            assert_eq!(routes[0].output_presence, Some(InterfacePresence::Present));
        }
        response => panic!("{response:?}"),
    }
    *network.fail_interface_observation.lock().await = true;
    match service
        .dispatch(Request::ListRouteInventory {
            include_local_table: false,
        })
        .await
    {
        Response::RouteInventory {
            routes,
            observation_error,
            ..
        } => {
            assert_eq!(routes[0].output_presence, Some(InterfacePresence::Unknown));
            assert!(routes[0].observed.is_none());
            assert!(routes[1].configured.is_none());
            assert!(observation_error.is_some());
        }
        response => panic!("{response:?}"),
    }
}

#[tokio::test]
async fn route_inventory_reports_observation_failure_without_losing_saved_configuration() {
    let directory = tempdir().unwrap();
    let mut config = router_with_two_saved_sharing_rules();
    config.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let service = ControlService::new_detached(
        config.clone(),
        Arc::new(RouteFakeNetwork {
            interfaces: vec![],
            routes: vec![],
            route_error: Some("netlink unavailable"),
        }),
        dhcp,
        overrides,
    );
    match service
        .dispatch(Request::ListRouteInventory {
            include_local_table: false,
        })
        .await
    {
        Response::RouteInventory {
            config: saved,
            routes,
            observation_error,
            ..
        } => {
            assert_eq!(saved.owned_routes.len(), config.router.owned_routes.len());
            assert!(routes
                .iter()
                .all(|row| row.configured.is_some() && row.observed.is_none()));
            assert!(observation_error.unwrap().contains("netlink unavailable"));
        }
        response => panic!("{response:?}"),
    }
}

#[tokio::test]
async fn router_status_separates_saved_revision_from_historical_applied_revision() {
    let (service, _) = router_service_with_config(
        Arc::new(FakeRouterSubsystems::default()),
        router_with_two_saved_sharing_rules(),
    )
    .await;
    let router = service.router.as_ref().unwrap();
    assert!(router.last_applied_revision().is_none());
    router
        .repair(service.current_router_desired().await.unwrap())
        .await
        .unwrap();
    assert_eq!(router.last_applied_revision(), Some(0));
    let mut saved = service.effective_config().await.unwrap().router;
    saved.forwarding = Some(vec![]);
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: saved.into(),
                expected_revision: 0
            })
            .await,
        Response::RouterIntentSaved { revision: 1, .. }
    ));
    assert!(matches!(
        service.dispatch(Request::RouterStatus).await,
        Response::RouterStatus {
            desired_revision: Some(1),
            last_applied_revision: Some(0),
            ..
        }
    ));
    let restarted = RouterTransactionCoordinator::new(
        router.manager(),
        service.overrides.clone(),
        Duration::from_secs(30),
    );
    assert!(restarted.last_applied_revision().is_none());
    restarted
        .reconcile_dataplane(service.current_router_desired().await.unwrap())
        .await
        .unwrap();
    assert_eq!(restarted.last_applied_revision(), Some(1));
}

#[tokio::test]
async fn router_status_endpoints_bound_health_observation() {
    let fake = Arc::new(FakeRouterSubsystems::default());
    let (service, _) =
        router_service_with_config(fake.clone(), router_with_two_saved_sharing_rules()).await;
    fake.health_pending
        .store(true, std::sync::atomic::Ordering::SeqCst);
    tokio::time::pause();
    for request in [Request::RouterStatus, Request::RouterProvisioningStatus] {
        let response = tokio::time::timeout(Duration::from_secs(2), service.dispatch(request))
            .await
            .expect("a busy health probe must not hide transaction status");
        let (coordinator, ready, health) = match response {
            Response::RouterStatus {
                coordinator_status,
                ready,
                health,
                ..
            } => (coordinator_status, ready, health),
            Response::RouterProvisioningStatus { status } => {
                (status.coordinator, status.ready, status.readiness)
            }
            other => panic!("unexpected status response: {other:?}"),
        };
        assert_eq!(coordinator, CoordinatorStatus::Idle);
        assert!(!ready);
        assert!(health
            .interfaces
            .as_deref()
            .unwrap()
            .contains("observation timed out"));
    }
    fake.health_pending
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let Response::RouterStatus { health, .. } = service.dispatch(Request::RouterStatus).await
    else {
        panic!("expected router status after observation recovers");
    };
    assert!(health.ready(), "a later request must observe fresh health");
}

#[tokio::test]
async fn reviewed_sharing_plan_rejects_changed_revision_or_observation_before_apply() {
    let fake = Arc::new(FakeRouterSubsystems::default());
    let (service, _directory) = router_enabled_service_with(fake.clone()).await;
    let mut proposal = router_proposal();
    let plan = match service
        .dispatch(Request::RouterPlan {
            proposal: proposal.clone().into(),
        })
        .await
    {
        Response::RouterPlan { plan } => plan,
        other => panic!("{other:?}"),
    };
    proposal.expected_revision = plan.base_revision;
    proposal.expected_fingerprint = plan.observation_fingerprint;
    let committed = service.overrides.snapshot().await;
    let mut changed = proposal.clone();
    changed.expected_fingerprint = Some("changed-observation".into());
    let response = service
        .dispatch(Request::RouterApply {
            proposal: changed.into(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::RouterError {
                detail: RouterErrorDetail::StalePlan
            }
        ),
        "{response:?}"
    );
    assert_eq!(service.overrides.snapshot().await, committed);
    assert_eq!(
        service.router.as_ref().unwrap().status().await,
        CoordinatorStatus::Idle
    );
    service
        .overrides
        .save_committed(committed.clone())
        .await
        .unwrap();
    let response = service
        .dispatch(Request::RouterApply {
            proposal: proposal.into(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::RouterError {
                detail: RouterErrorDetail::StaleCandidate { .. }
            }
        ),
        "{response:?}"
    );
    assert_eq!(
        service.router.as_ref().unwrap().status().await,
        CoordinatorStatus::Idle
    );
    let plan = match service
        .dispatch(Request::RouterPlan {
            proposal: router_proposal().into(),
        })
        .await
    {
        Response::RouterPlan { plan } => plan,
        other => panic!("{other:?}"),
    };
    let mut fresh = router_proposal();
    fresh.expected_revision = plan.base_revision;
    fresh.expected_fingerprint = plan.observation_fingerprint;
    let response = service
        .dispatch(Request::RouterApply {
            proposal: fresh.into(),
        })
        .await;
    let token = match response {
        Response::RouterTransactionPending { token, .. } => token,
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        service.dispatch(Request::RouterCommit { token }).await,
        Response::RouterCommitted { .. }
    ));
}
