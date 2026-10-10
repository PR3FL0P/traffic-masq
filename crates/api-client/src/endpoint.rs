//! API destination and verified TLS configuration. HTTP redirects are never followed.
use anyhow::{bail, Context, Result};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Debug)]
pub(crate) enum Endpoint {
    Unix(PathBuf),
    Https(Arc<HttpsEndpoint>),
}

#[derive(Debug)]
pub(crate) struct HttpsEndpoint {
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub server_name: ServerName<'static>,
    pub tls: Arc<ClientConfig>,
    pub identity: String,
}

impl HttpsEndpoint {
    pub fn new(url: &str, ca_file: Option<&Path>) -> Result<Self> {
        let uri: hyper::Uri = url.parse().context("invalid HTTPS server URL")?;
        if uri.scheme_str() != Some("https")
            || uri.query().is_some()
            || url.contains(['#', '@'])
            || !matches!(uri.path(), "" | "/")
        {
            bail!("server must be an HTTPS origin, e.g. https://router.example:8443 (no credentials, path, query or fragment)");
        }
        let host = uri
            .host()
            .context("HTTPS server requires a hostname")?
            .trim_matches(['[', ']'])
            .to_ascii_lowercase();
        let authority = uri
            .authority()
            .context("HTTPS server requires an authority")?
            .as_str();
        let suffix = authority
            .strip_prefix(uri.host().unwrap())
            .context("invalid HTTPS authority")?;
        let port = if suffix.is_empty() {
            443
        } else {
            suffix
                .strip_prefix(':')
                .context("invalid HTTPS authority")?
                .parse::<u16>()
                .context("invalid HTTPS port")?
        };
        if port == 0 {
            bail!("HTTPS server port must be nonzero");
        }
        let server_name = ServerName::try_from(host.clone()).context("invalid TLS server name")?;
        let ca_path = match ca_file {
            Some(path) => path.to_path_buf(),
            None => system_ca_file()?,
        };
        let pem = std::fs::read(&ca_path)
            .with_context(|| format!("could not read CA certificates {}", ca_path.display()))?;
        let certificates = rustls_pemfile::certs(&mut pem.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("invalid CA certificate PEM")?;
        let mut roots = RootCertStore::empty();
        for certificate in certificates {
            roots.add(certificate).context("invalid CA certificate")?;
        }
        if roots.is_empty() {
            bail!("CA file contains no certificates");
        }
        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let identity = format!("https://{authority}/|ca-sha256={:x}", Sha256::digest(&pem));
        Ok(Self {
            host,
            port,
            authority,
            server_name,
            tls: Arc::new(tls),
            identity,
        })
    }
}

fn system_ca_file() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("SSL_CERT_FILE") {
        return Ok(path.into());
    }
    [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
    .context("system CA bundle not found; specify --ca-cert")
}
