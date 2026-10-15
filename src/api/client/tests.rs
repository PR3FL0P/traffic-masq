use super::*;
use crate::api::model::Request;

#[tokio::test]
async fn silent_api_times_out_and_closes_connection() {
    use tokio::io::AsyncReadExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let client = ApiClient::new(path);
    let request = tokio::spawn(async move {
        client
            .send_with_timeout(
                Method::GET,
                "/api/v1/status",
                None,
                std::time::Duration::from_millis(50),
            )
            .await
    });
    let (mut peer, _) = listener.accept().await.unwrap();
    assert!(request
        .await
        .unwrap()
        .err()
        .expect("request timeout")
        .to_string()
        .contains("timed out"));
    tokio::task::yield_now().await;
    let mut bytes = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        peer.read_to_end(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
}

#[test]
fn control_deadlines_follow_commands_instead_of_the_shared_post_method() {
    for request in [
        Request::Ping,
        Request::ListInterfaces,
        Request::DaemonLogs { limit: 10 },
    ] {
        assert_eq!(control_request_timeout(&request), DEFAULT_REQUEST_TIMEOUT);
    }
    for request in [
        Request::WifiClientScan {
            interface: "wlan0".into(),
        },
        Request::RouterPlan {
            proposal: Default::default(),
        },
        Request::RollbackNetworkChange {
            token: "test".into(),
        },
        Request::ResetSecuritySettings,
    ] {
        assert_eq!(
            control_request_timeout(&request),
            CONTROL_MUTATION_REQUEST_TIMEOUT
        );
    }
    assert!(CONTROL_MUTATION_REQUEST_TIMEOUT > crate::api::HTTP_CONNECTION_TIMEOUT);
}

#[test]
fn maps_ping_to_status_and_synthesizes_pong() {
    let mapped = map_request(&Request::Ping).expect("ping should map");

    assert_eq!(mapped.method, Method::GET);
    assert_eq!(mapped.path, "/api/v1/status");
    assert!(mapped.body.is_none());
    assert!(mapped.synthesize_pong);
}

#[test]
fn control_transport_preserves_command_payloads_without_path_interpolation() {
    for request in [
        Request::GetDhcpClient {
            interface: "wan/0".into(),
        },
        Request::ConfigureDhcpClient {
            interface: "wan/0".into(),
            config: Default::default(),
        },
        Request::WifiClientScan {
            interface: "wlan/guest".into(),
        },
        Request::CommitNetworkChange {
            token: "pending/change".into(),
        },
        Request::ActivateWifiApProfile {
            interface: "wlan/0".into(),
            profile_id: "guest".into(),
        },
    ] {
        let mapped = map_request(&request).unwrap();
        assert_eq!(mapped.method, Method::POST);
        assert_eq!(mapped.path, "/api/v1/control");
        assert!(!mapped.synthesize_pong);
        let body: serde_json::Value = serde_json::from_slice(&mapped.body.unwrap()).unwrap();
        assert_eq!(body, serde_json::to_value(&request).unwrap());
    }
}
