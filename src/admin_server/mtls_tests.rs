//! End-to-end check of the admin server's mTLS allowlist, over a real TLS
//! handshake with real client certificates.
//!
//! The unit tests in `admin_server.rs` cover the CN parser and the allowlist
//! matcher in isolation. What they cannot show is the property that matters
//! operationally: a client removed through `/admin/v1/admins/remove` loses
//! access on the keep-alive connection it already has open, not only on its
//! next handshake.

use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use greentic_setup::admin::AdminTlsConfig;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::{AdminServer, AdminServerConfig};
use crate::runtime_state::RuntimePaths;

struct Pki {
    ca_der: CertificateDer<'static>,
    ca_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

struct Leaf {
    cert: CertificateDer<'static>,
    key_der: Vec<u8>,
    pem: String,
    key_pem: String,
}

impl Pki {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "greentic-test-ca");
        let ca_key = KeyPair::generate().expect("ca key");
        let ca = params.self_signed(&ca_key).expect("ca cert");
        Self {
            ca_der: ca.der().clone(),
            ca_pem: ca.pem(),
            issuer: Issuer::new(params, ca_key),
        }
    }

    fn leaf(&self, cn: &str, usage: ExtendedKeyUsagePurpose) -> Leaf {
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        params.distinguished_name.push(DnType::CommonName, cn);
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate().expect("leaf key");
        let cert = params.signed_by(&key, &self.issuer).expect("leaf cert");
        Leaf {
            cert: cert.der().clone(),
            key_der: key.serialize_der(),
            pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }
}

fn free_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind probe");
    listener.local_addr().expect("local addr").port()
}

fn client_config(pki: &Pki, client: &Leaf) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pki.ca_der.clone()).expect("add ca");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = PrivateKeyDer::try_from(client.key_der.clone()).expect("client key");
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![client.cert.clone()], key)
        .expect("client auth cert");
    Arc::new(config)
}

async fn connect(
    port: u16,
    config: Arc<rustls::ClientConfig>,
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    let name = ServerName::try_from("localhost").expect("server name");
    TlsConnector::from(config).connect(name, tcp).await
}

/// One request on an already-open connection. Returns the status code, or an
/// error when the server closed the connection before answering.
async fn request(
    stream: &mut TlsStream<TcpStream>,
    method: &str,
    path: &str,
    body: &str,
) -> std::io::Result<u16> {
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await?;

    // Read until the headers and the declared body are both in.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before a response",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        let Some(split) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&buf[..split]).to_ascii_lowercase();
        let declared = headers
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        if buf.len() >= split + 4 + declared {
            let status = headers
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "no status line")
                })?;
            return Ok(status);
        }
    }
}

fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write pem");
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn a_removed_client_loses_its_open_keep_alive_connection() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pki = Pki::new();
    let server = pki.leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth);
    let alice = pki.leaf("alice", ExtendedKeyUsagePurpose::ClientAuth);
    let bob = pki.leaf("bob", ExtendedKeyUsagePurpose::ClientAuth);

    let bundle_root = dir.path().join("bundle");
    std::fs::create_dir_all(&bundle_root).expect("bundle dir");
    let port = free_port();
    let admin = AdminServer::start(AdminServerConfig {
        tls_config: AdminTlsConfig {
            server_cert: write(dir.path(), "server.pem", &server.pem),
            server_key: write(dir.path(), "server.key", &server.key_pem),
            client_ca: write(dir.path(), "ca.pem", &pki.ca_pem),
            allowed_clients: vec!["alice".to_string(), "bob".to_string()],
            port,
        },
        bundle_root: bundle_root.clone(),
        runtime_paths: RuntimePaths::new(dir.path().join("state"), "demo", "default"),
    })
    .expect("admin server starts");

    let alice_cfg = client_config(&pki, &alice);
    let bob_cfg = client_config(&pki, &bob);

    let mut alice_conn = connect(port, alice_cfg.clone())
        .await
        .expect("alice connects");
    let mut bob_conn = connect(port, bob_cfg).await.expect("bob connects");

    assert_eq!(
        request(&mut alice_conn, "GET", "/admin/v1/status", "")
            .await
            .expect("alice status"),
        200,
        "an allowed client is served"
    );
    assert_eq!(
        request(&mut bob_conn, "GET", "/admin/v1/status", "")
            .await
            .expect("bob status"),
        200,
    );

    // Bob removes alice. Her connection is still open.
    let remove = serde_json::json!({
        "bundle_path": bundle_root,
        "client_cn": "alice",
    })
    .to_string();
    assert_eq!(
        request(&mut bob_conn, "POST", "/admin/v1/admins/remove", &remove)
            .await
            .expect("remove"),
        200,
    );

    // The very next request on alice's already-authenticated connection is
    // refused: the allowlist is re-read per request, not once per handshake.
    assert_eq!(
        request(&mut alice_conn, "GET", "/admin/v1/status", "")
            .await
            .expect("alice's open connection still answers"),
        403,
        "a removed client must lose its open connection"
    );

    // And a new connection from her is dropped at the door.
    let fresh = async {
        let mut conn = connect(port, alice_cfg).await?;
        request(&mut conn, "GET", "/admin/v1/status", "").await
    }
    .await;
    assert!(
        fresh.is_err(),
        "a removed client must not get a fresh session, got {fresh:?}"
    );

    // Bob is unaffected.
    assert_eq!(
        request(&mut bob_conn, "GET", "/admin/v1/status", "")
            .await
            .expect("bob again"),
        200,
    );

    drop(alice_conn);
    drop(bob_conn);
    admin.stop().expect("admin server stops");
}
