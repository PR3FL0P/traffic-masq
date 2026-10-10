use super::*;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

struct Server {
    _dir: tempfile::TempDir,
    ca: PathBuf,
    port: u16,
    task: tokio::task::JoinHandle<Option<String>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn server(status: &str, body: &str) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, cert.pem()).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key.into())
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(tcp)
            .await
        else {
            return None;
        };
        let mut request = Vec::new();
        loop {
            let mut buffer = [0u8; 1024];
            let count = tls.read(&mut buffer).await.unwrap_or(0);
            if count == 0 {
                return None;
            }
            request.extend_from_slice(&buffer[..count]);
            if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                break;
            }
        }
        tls.write_all(response.as_bytes()).await.unwrap();
        tls.shutdown().await.unwrap();
        Some(String::from_utf8(request).unwrap())
    });
    Server {
        _dir: dir,
        ca,
        port,
        task,
    }
}
async fn authenticate(client: &ControlApiClient) {
    client
        .restore_authentication(ClientAuthentication {
            token: zeroize::Zeroizing::new("test-token".into()),
            authenticated_at: 1,
            absolute_expires_at: i64::MAX,
        })
        .await;
}

#[tokio::test]
async fn verified_https_sends_token_and_scopes_sessions_to_origin_and_ca() {
    let mut server = server("200 OK", "pong").await;
    let url = format!("https://localhost:{}", server.port);
    let client = ControlApiClient::https(&url, Some(&server.ca)).unwrap();
    authenticate(&client).await;
    let response = client
        .send_with_timeout(Method::GET, "/api/v1/test", None, Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(response.body, "pong");
    let request = (&mut server.task).await.unwrap().unwrap();
    assert!(request.contains("authorization: Bearer test-token"));
    assert!(request.contains(&format!("host: localhost:{}", server.port)));
    assert!(client.socket_path().is_none());
    let same = ControlApiClient::https(&format!("{url}/"), Some(&server.ca)).unwrap();
    assert_eq!(
        client.remote_session_identity(),
        same.remote_session_identity()
    );
    let another = ControlApiClient::https("https://localhost:444", Some(&server.ca)).unwrap();
    assert_ne!(
        client.remote_session_identity(),
        another.remote_session_identity()
    );
    let certificate = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let other_ca = server._dir.path().join("other-ca.pem");
    std::fs::write(&other_ca, certificate.cert.pem()).unwrap();
    let other = ControlApiClient::https(&url, Some(&other_ca)).unwrap();
    assert_ne!(
        client.remote_session_identity(),
        other.remote_session_identity()
    );
}

#[tokio::test]
async fn hostname_mismatch_and_untrusted_certificate_are_rejected_before_http() {
    for wrong_host in [true, false] {
        let mut server = server("200 OK", "pong").await;
        let other_ca = server._dir.path().join("wrong.pem");
        let certificate = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(&other_ca, certificate.cert.pem()).unwrap();
        let client = ControlApiClient::https(
            &format!(
                "https://{}:{}",
                if wrong_host { "127.0.0.1" } else { "localhost" },
                server.port
            ),
            Some(if wrong_host { &server.ca } else { &other_ca }),
        )
        .unwrap();
        authenticate(&client).await;
        assert!(client
            .send_with_timeout(Method::GET, "/api/v1/test", None, Duration::from_secs(3))
            .await
            .is_err());
        assert!((&mut server.task).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn unauthorized_https_discards_session_and_remote_initialization_is_local_only() {
    let server = server("401 Unauthorized", "{}").await;
    let client = ControlApiClient::https(
        &format!("https://localhost:{}", server.port),
        Some(&server.ca),
    )
    .unwrap();
    authenticate(&client).await;
    assert!(client.initialize("new-password").await.is_err());
    let response = client
        .send_with_timeout(Method::GET, "/api/v1/test", None, Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(!client.is_authenticated().await);
}

#[test]
fn rejects_cleartext_urls_credentials_and_non_origin_paths() {
    for url in [
        "http://localhost",
        "https://user:pass@localhost",
        "https://localhost/api",
        "https://localhost/?token=x",
        "https://localhost/#x",
        "https://localhost:0",
        "https://localhost:65536",
        "https://localhost:abc",
    ] {
        assert!(ControlApiClient::https(url, None).is_err(), "{url}");
    }
}
