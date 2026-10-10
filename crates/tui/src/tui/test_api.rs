//! Socket-level test harness for TUI workflows (no daemon or network privileges).
use super::api::{client::ApiClient, model::Response};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub(crate) struct Call {
    pub method: String,
    pub path: String,
    pub body: serde_json::Value,
}
pub(crate) struct Mock {
    pub client: ApiClient,
    pub calls: Arc<Mutex<Vec<Call>>>,
    server: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.server.abort();
    }
}

pub(crate) async fn mock(responses: Vec<Response>) -> Mock {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let captured = calls.clone();
    let server = tokio::spawn(async move {
        for response in responses {
            let (stream, _) = listener.accept().await.unwrap();
            let captured = captured.clone();
            let response = serde_json::to_vec(&response).unwrap();
            http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                        let captured = captured.clone();
                        let response = response.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let bytes = body.collect().await.unwrap().to_bytes();
                            captured.lock().unwrap().push(Call {
                                method: parts.method.to_string(),
                                path: parts.uri.path().to_string(),
                                body: if bytes.is_empty() {
                                    serde_json::Value::Null
                                } else {
                                    serde_json::from_slice(&bytes).unwrap()
                                },
                            });
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                Bytes::from(response),
                            )))
                        }
                    }),
                )
                .await
                .unwrap();
        }
    });
    Mock {
        client: ApiClient::new(socket),
        calls,
        server,
        _directory: directory,
    }
}
