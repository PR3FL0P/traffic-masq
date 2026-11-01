use super::*;

#[tokio::test]
async fn api_https_settings_dispatch_persists_override_and_requires_restart() {
    let directory = tempdir().expect("tempdir");
    let mut config = router_base_config();
    config.api.tcp = Some(TcpApiConfig {
        enabled: false,
        listen: "127.0.0.1:8443".parse().expect("socket address"),
        certificate_path: None,
        private_key_path: None,
    });
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let service = ControlService::new_detached(config.clone(), network, dhcp, overrides.clone());

    let settings = ApiHttpsSettings {
        enabled: true,
        listen: "0.0.0.0:9443".to_string(),
        certificate_path: Some("/etc/traffic-masq/server.pem".to_string()),
        private_key_path: Some("/etc/traffic-masq/server-key.pem".to_string()),
    };

    match service
        .dispatch(Request::ConfigureApiHttpsSettings {
            settings: settings.clone(),
        })
        .await
    {
        Response::ApiHttpsConfig {
            active,
            desired,
            override_active,
            restart_required,
        } => {
            assert!(!active.enabled);
            assert_eq!(desired, settings);
            assert!(override_active);
            assert!(restart_required);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(overrides.snapshot().await.api.is_some());

    match service.dispatch(Request::ResetApiHttpsSettings).await {
        Response::ApiHttpsConfig {
            active,
            desired,
            override_active,
            restart_required,
        } => {
            assert_eq!(active, desired);
            assert!(!override_active);
            assert!(!restart_required);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(overrides.snapshot().await.api.is_none());
}

#[tokio::test]
async fn security_settings_dispatch_persists_override_and_requires_restart() {
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
    let service = ControlService::new_detached(config.clone(), network, dhcp, overrides.clone());

    let settings = SecuritySettings {
        rollback_timeout_seconds: 120,
    };

    match service
        .dispatch(Request::ConfigureSecuritySettings { settings })
        .await
    {
        Response::SecurityConfig {
            active,
            desired,
            override_active,
            restart_required,
        } => {
            assert_eq!(active.rollback_timeout_seconds, 60);
            assert_eq!(desired, settings);
            assert!(override_active);
            assert!(restart_required);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(overrides.snapshot().await.security.is_some());

    match service.dispatch(Request::ResetSecuritySettings).await {
        Response::SecurityConfig {
            active,
            desired,
            override_active,
            restart_required,
        } => {
            assert_eq!(active, desired);
            assert!(!override_active);
            assert!(!restart_required);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(overrides.snapshot().await.security.is_none());
}

#[tokio::test]
async fn settings_writes_wait_for_network_execution_and_observe_commit_fence() {
    for request in [
        Request::ResetApiHttpsSettings,
        Request::ResetSecuritySettings,
    ] {
        let fixture = dhcp_client_control_fixture(false).await;
        let revision = fixture.overrides.committed_revision().await;
        let execution = fixture.service.network_mutations.execute().await;
        let write = fixture.service.dispatch(request);
        tokio::pin!(write);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut write)
                .await
                .is_err(),
            "settings must not write shared intent during runtime execution"
        );
        fixture.service.overrides.recovery().fence_commit(
            &fixture.service.config.runtime.state_dir,
            "uncertain network commit".into(),
        );
        drop(execution);
        let response = write.await;
        assert!(
            matches!(response, Response::Error { ref message } if message.contains("commit_indeterminate")),
            "{response:?}"
        );
        assert_eq!(fixture.overrides.committed_revision().await, revision);
    }
}
