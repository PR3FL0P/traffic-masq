//! Unix-socket HTTP transport shared by API clients.

mod control;
pub use control::{encode_path_segment, map_request, RestRequest};
mod session;
pub use session::{
    control_request_timeout, ApiClient, ClientAuthentication, LoginSession,
    CONTROL_MUTATION_REQUEST_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
};

pub type ControlApiClient = ApiClient<traffic_masq_protocol::ControlResponse>;

use std::path::Path;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::client::conn::http1;
use hyper::header::{AUTHORIZATION, CONNECTION, CONTENT_TYPE, HOST};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const HOST_VALUE: &str = "localhost";

pub struct RawResponse {
    pub status: StatusCode,
    pub body: Bytes,
}

struct AbortConnection(tokio::task::AbortHandle);

impl Drop for AbortConnection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn send(
    socket_path: &Path,
    method: Method,
    path: &str,
    body: Option<Vec<u8>>,
    token: Option<&str>,
) -> Result<RawResponse> {
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("failed to connect to API socket {}", socket_path.display()))?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .context("failed to establish HTTP/1 connection to the API")?;
    let mut connection_task = tokio::spawn(connection);
    let _abort_on_drop = AbortConnection(connection_task.abort_handle());

    let has_json_body = body.is_some();
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, HOST_VALUE)
        .header(CONNECTION, "close");
    if has_json_body {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    if let Some(token) = token {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }

    let request = builder
        .body(Full::new(Bytes::from(body.unwrap_or_default())))
        .context("failed to build API request")?;
    let response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(error) => {
            drop(sender);
            connection_task.abort();
            return Err(error).context("failed to send request to the API");
        }
    };
    drop(sender);

    let status = response.status();
    let body_result = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|error| {
            anyhow::anyhow!("failed to read API response body (maximum size is 1 MiB): {error}")
        });
    let connection_result = (&mut connection_task).await;

    let body = body_result?;
    connection_result
        .context("API HTTP connection task failed")?
        .context("API HTTP connection failed")?;

    Ok(RawResponse { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn sends_authenticated_json_over_unix_socket() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 1024];
            let size = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..size]);
            assert!(request.starts_with("POST /api/v1/ping HTTP/1.1"));
            assert!(request.contains("authorization: Bearer secret"));
            assert!(request.contains("content-type: application/json"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong")
                .await
                .unwrap();
        });

        let response = send(
            &socket,
            Method::POST,
            "/api/v1/ping",
            Some(b"{}".to_vec()),
            Some("secret"),
        )
        .await
        .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, "pong");
        server.await.unwrap();
    }
}
