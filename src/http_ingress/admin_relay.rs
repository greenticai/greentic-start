use std::env;
use std::fmt::Display;
use std::io::{BufReader, Cursor};
use std::sync::Arc;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes};
use hyper::client::conn::http1;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::helpers::error_response;

pub(super) const ADMIN_RELAY_PREFIX: &str = "/admin-relay/v1";

#[derive(Clone)]
pub(super) struct AdminRelayConfig {
    pub(super) token: String,
    pub(super) admin_port: u16,
    pub(super) client_config: Arc<rustls::ClientConfig>,
}

pub(super) fn load_admin_relay_config_from_env() -> Result<Option<Arc<AdminRelayConfig>>> {
    let Some(token) = env_var_nonempty("GREENTIC_ADMIN_RELAY_TOKEN") else {
        return Ok(None);
    };

    let ca_pem = env_var_nonempty("GREENTIC_ADMIN_CA_PEM")
        .context("GREENTIC_ADMIN_RELAY_TOKEN is set but GREENTIC_ADMIN_CA_PEM is missing")?;
    let client_cert_pem = env_var_nonempty("GREENTIC_ADMIN_CLIENT_CERT_PEM").context(
        "GREENTIC_ADMIN_RELAY_TOKEN is set but GREENTIC_ADMIN_CLIENT_CERT_PEM is missing",
    )?;
    let client_key_pem = env_var_nonempty("GREENTIC_ADMIN_CLIENT_KEY_PEM").context(
        "GREENTIC_ADMIN_RELAY_TOKEN is set but GREENTIC_ADMIN_CLIENT_KEY_PEM is missing",
    )?;

    let admin_port = parse_admin_port_from_env().unwrap_or(8443);
    let client_config = build_client_config(&ca_pem, &client_cert_pem, &client_key_pem)?;

    Ok(Some(Arc::new(AdminRelayConfig {
        token,
        admin_port,
        client_config: Arc::new(client_config),
    })))
}

pub(super) fn relay_target_path(path: &str) -> Option<String> {
    let suffix = path.strip_prefix(ADMIN_RELAY_PREFIX)?;
    Some(format!("/admin/v1{suffix}"))
}

pub(super) async fn handle_admin_relay<B>(
    req: Request<B>,
    target_path: String,
    config: Arc<AdminRelayConfig>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Display,
{
    if !authorized(req.headers().get(AUTHORIZATION), &config.token) {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "missing or invalid bearer token for admin relay",
        ));
    }

    let method = req.method().clone();
    let content_type = req.headers().get(CONTENT_TYPE).cloned();
    let query = req.uri().query().map(str::to_string);
    let target_uri = match query {
        Some(query) if !query.is_empty() => format!("{target_path}?{query}"),
        _ => target_path,
    };
    let body = req
        .into_body()
        .collect()
        .await
        .map_err(|err| {
            error_response(
                StatusCode::BAD_REQUEST,
                format!("failed to read admin relay request body: {err}"),
            )
        })?
        .to_bytes();

    forward_admin_request(&config, method, target_uri, content_type, body)
        .await
        .map_err(|err| {
            error_response(
                StatusCode::BAD_GATEWAY,
                format!("admin relay failed: {err:#}"),
            )
        })
}

fn env_var_nonempty(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.trim().is_empty())
}

fn parse_admin_port_from_env() -> Option<u16> {
    let value = env::var("GREENTIC_ADMIN_LISTEN").ok()?;
    let port = value.rsplit(':').next()?;
    port.parse().ok()
}

fn authorized(header: Option<&hyper::header::HeaderValue>, expected_token: &str) -> bool {
    let Some(header) = header else {
        return false;
    };
    let Ok(header) = header.to_str() else {
        return false;
    };
    let Some(token) = header.strip_prefix("Bearer ") else {
        return false;
    };
    token == expected_token
}

async fn forward_admin_request(
    config: &AdminRelayConfig,
    method: Method,
    target_uri: String,
    content_type: Option<hyper::header::HeaderValue>,
    body: Bytes,
) -> Result<Response<Full<Bytes>>> {
    let tcp = TcpStream::connect(("127.0.0.1", config.admin_port))
        .await
        .with_context(|| {
            format!(
                "connect to local admin listener on 127.0.0.1:{}",
                config.admin_port
            )
        })?;

    let connector = TlsConnector::from(config.client_config.clone());
    let server_name = ServerName::try_from("localhost")
        .map_err(|_| anyhow::anyhow!("invalid admin relay server name"))?;
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .context("TLS connect to local admin listener")?;

    let (mut sender, connection) = http1::handshake(TokioIo::new(tls_stream))
        .await
        .context("handshake admin relay HTTP/1 client")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut builder = Request::builder().method(method).uri(target_uri);
    if let Some(content_type) = content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    }
    builder = builder.header(HOST, "localhost");
    let request = builder
        .body(Full::new(body))
        .map_err(|err| anyhow::anyhow!("build admin relay request: {err}"))?;

    let response = sender
        .send_request(request)
        .await
        .context("send admin relay request")?;
    let status = response.status();
    let content_type = response.headers().get(CONTENT_TYPE).cloned();
    let body = response
        .into_body()
        .collect()
        .await
        .context("read admin relay response body")?
        .to_bytes();

    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    }
    builder
        .body(Full::new(body))
        .map_err(|err| anyhow::anyhow!("build admin relay response: {err}"))
}

fn build_client_config(
    ca_pem: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
) -> Result<rustls::ClientConfig> {
    let ca_certs = parse_certs(ca_pem).context("parse admin relay CA certs")?;
    let client_certs = parse_certs(client_cert_pem).context("parse admin relay client certs")?;
    let client_key = parse_private_key(client_key_pem).context("parse admin relay client key")?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .context("add admin relay CA cert to root store")?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());

    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("set admin relay TLS protocol versions")?
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .context("build admin relay client config")
}

fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut BufReader::new(Cursor::new(pem.as_bytes())))
        .collect::<Result<Vec<_>, _>>()
        .context("parse PEM certificates")
}

fn parse_private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(Cursor::new(pem.as_bytes())))
        .context("parse PEM private key")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in PEM"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_target_path_maps_public_prefix_to_admin_api() {
        assert_eq!(
            relay_target_path("/admin-relay/v1/health").as_deref(),
            Some("/admin/v1/health")
        );
        assert_eq!(
            relay_target_path("/admin-relay/v1/qa/session/abc").as_deref(),
            Some("/admin/v1/qa/session/abc")
        );
        assert_eq!(relay_target_path("/not-admin"), None);
    }

    #[test]
    fn authorized_requires_matching_bearer_token() {
        let ok = hyper::header::HeaderValue::from_static("Bearer secret-token");
        let wrong = hyper::header::HeaderValue::from_static("Bearer nope");
        let malformed = hyper::header::HeaderValue::from_static("Basic abc");

        assert!(authorized(Some(&ok), "secret-token"));
        assert!(!authorized(Some(&wrong), "secret-token"));
        assert!(!authorized(Some(&malformed), "secret-token"));
        assert!(!authorized(None, "secret-token"));
    }
}
