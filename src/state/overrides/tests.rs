use crate::config::{InterfaceRole, UplinkConfig, UplinkMode};

use super::*;

fn base_config() -> AppConfig {
    AppConfig::default()
}

/// The converger has no timer any more, so a change that does not announce
/// itself is a change that never gets applied.
fn interface_config(address: &str) -> InterfaceConfig {
    InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some(address.parse().expect("network")),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
        nat: true,
    }
}

/// A successful, self-contained mutation, for tests that need the store to
/// change but do not care what changed. `set_dhcp` used to serve this role.

#[test]
fn effective_config_applies_api_override() {
    let mut base = base_config();
    base.api.tcp = Some(crate::config::TcpApiConfig {
        enabled: false,
        listen: "127.0.0.1:8443".parse().expect("socket address"),
        certificate_path: None,
        private_key_path: None,
    });

    let overrides = RuntimeOverrides {
        api: Some(ApiConfig {
            tcp: Some(crate::config::TcpApiConfig {
                enabled: true,
                listen: "192.0.2.10:9443".parse().expect("socket address"),
                certificate_path: Some("/etc/traffic-masq/server.pem".into()),
                private_key_path: Some("/etc/traffic-masq/server-key.pem".into()),
            }),
        }),
        ..RuntimeOverrides::default()
    };

    let effective = overrides.effective_config(&base).expect("effective config");
    let tcp = effective.api.tcp.expect("api tcp");
    assert!(tcp.enabled);
    assert_eq!(
        tcp.listen,
        "192.0.2.10:9443".parse().expect("socket address")
    );
}

#[test]
fn effective_config_revalidates_router_against_interface_overrides() {
    let mut base = base_config();
    base.network.interfaces.insert(
        "wan0".to_string(),
        InterfaceConfig {
            role: InterfaceRole::Input,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
            nat: true,
        },
    );
    base.network
        .interfaces
        .insert("lan0".to_string(), interface_config("192.168.10.1/24"));
    base.router.enabled = true;
    base.router.uplink = Some(UplinkConfig {
        interface: "wan0".to_string(),
        mode: UplinkMode::External,
    });
    base.validate().expect("base router config");

    let mut overrides = RuntimeOverrides::default();
    overrides.interfaces.insert(
        "wan0".to_string(),
        InterfaceOverride {
            config: InterfaceConfig {
                role: InterfaceRole::None,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
                nat: true,
            },
            allow_management_change: true,
        },
    );

    assert!(overrides.effective_network(&base.network).is_ok());
    assert!(overrides.effective_config(&base).is_err());
}

#[tokio::test]
async fn recovery_commit_proof_ignores_unrelated_invalid_override_fields() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = RuntimeOverrideStore::in_state_dir(directory.path());
    tokio::fs::write(
        store.path(),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": CURRENT_RUNTIME_OVERRIDES_SCHEMA,
            "revision": 7,
            "committed_router_transaction": "router-token",
            "committed_interface_transactions": {"lan0": "interface-token"},
            "api": {"tcp": "invalid-for-full-loader"},
            "unknown_future_field": true
        }))
        .unwrap(),
    )
    .await
    .expect("write recovery proof");

    let proof = store
        .load_recovery_commit_proof()
        .await
        .expect("proof load must ignore unrelated fields");
    assert_eq!(
        proof.committed_router_transaction().unwrap().as_deref(),
        Some("router-token")
    );
    assert_eq!(
        proof
            .committed_interface_transactions()
            .unwrap()
            .get("lan0")
            .map(String::as_str),
        Some("interface-token")
    );
    assert!(store.load().await.is_err(), "full override load must stay strict");
}

#[tokio::test]
async fn recovery_commit_proof_fields_fail_independently() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = RuntimeOverrideStore::in_state_dir(directory.path());
    tokio::fs::write(
        store.path(),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": CURRENT_RUNTIME_OVERRIDES_SCHEMA,
            "committed_router_transaction": "router-token",
            "committed_interface_transactions": ["not-an-object"]
        }))
        .unwrap(),
    )
    .await
    .expect("write recovery proof");

    let proof = store.load_recovery_commit_proof().await.expect("proof envelope");
    assert_eq!(
        proof.committed_router_transaction().unwrap().as_deref(),
        Some("router-token")
    );
    assert!(proof.committed_interface_transactions().is_err());
    assert!(proof.router_recovery_overrides().is_ok());
}

#[tokio::test]
async fn recovery_commit_proof_rejects_invalid_schema_type() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = RuntimeOverrideStore::in_state_dir(directory.path());
    tokio::fs::write(
        store.path(),
        br#"{"schema_version":"3","committed_router_transaction":"token"}"#,
    )
    .await
    .expect("write recovery proof");

    assert!(store.load_recovery_commit_proof().await.is_err());
}

#[tokio::test]
async fn recovery_commit_proof_rejects_dangling_override_symlink() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = RuntimeOverrideStore::in_state_dir(directory.path());
    std::os::unix::fs::symlink(directory.path().join("missing-overrides"), store.path())
        .expect("dangling symlink");

    assert!(store.load_recovery_commit_proof().await.is_err());
    assert!(store.load().await.is_err());
}

#[test]
fn router_recovery_effective_config_ignores_unrelated_security_and_api_admission() {
    let mut base = AppConfig::default();
    base.auth.argon2_iterations = 0;
    let mut overrides = RuntimeOverrides::default();
    overrides.security = Some(crate::config::SecurityConfig {
        rollback_timeout_seconds: 0,
    });

    assert!(overrides.effective_config(&base).is_err());
    overrides
        .effective_router_recovery_config(&base)
        .expect("recovery-scoped merge must ignore unrelated auth/security admission");
}

#[tokio::test]
async fn router_recovery_state_can_use_a_separately_parsed_commit_token() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = RuntimeOverrideStore::in_state_dir(directory.path());
    tokio::fs::write(
        store.path(),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": CURRENT_RUNTIME_OVERRIDES_SCHEMA,
            "committed_router_transaction": 42,
            "revision": 7
        }))
        .unwrap(),
    )
    .await
    .expect("write recovery proof");

    let proof = store.load_recovery_commit_proof().await.expect("proof envelope");
    assert!(proof.committed_router_transaction().is_err());
    let state = proof
        .router_recovery_overrides_with_commit_token(None)
        .expect("router state should decode independently of the malformed token field");
    assert_eq!(state.revision, 7);
    assert!(state.committed_router_transaction.is_none());
}
