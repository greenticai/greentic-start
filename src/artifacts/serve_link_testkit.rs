//! Doubles for the signed-link route tests: a scripted door reader, a unit
//! fixture that mints its own links, and a comparable view of a response.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use greentic_aw_runtime::{ArtifactBytes, ArtifactError, ArtifactReader};
use greentic_deploy_spec::ids::DeploymentId;
use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper::{Method, Response, StatusCode};

use super::ingest_testkit::{FakeStore, pipeline};
use super::link::{LinkKey, LinkPath, mint};
use super::link_table::LinkUnit;
use super::recent_puts::RecentPuts;
use super::serve_link::{LinkRequest, serve_link};
use super::serve_link_limits::LinkLimits;
use super::unit::{UnitAttachments, UnitCell};
use crate::http_ingress::limits::ClientKey;

pub(crate) const TOKEN: &str = "gtm_route-token";
pub(crate) const TENANT: &str = "acme";
pub(crate) const BUNDLE: &str = "b1";
pub(crate) const ID: &str =
    "artifact://dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
pub(crate) const NOW: u64 = 1_800_000_000;
pub(crate) const TTL: u64 = 86_400;
pub(crate) const NOT_FOUND_BODY: &[u8] =
    b"This link is not valid or has expired. Ask the assistant to send the file again.";

/// A scripted door answer: (mime type, name, bytes) or an error.
pub(crate) type Scripted = Result<(String, Option<String>, Vec<u8>), ArtifactError>;

/// Answers from a script, in order; the last answer repeats.
pub(crate) struct StubReader {
    answers: Mutex<VecDeque<Scripted>>,
    calls: AtomicUsize,
}

impl StubReader {
    pub(crate) fn new(answers: Vec<Scripted>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.into()),
            calls: AtomicUsize::new(0),
        })
    }

    pub(crate) fn file(mime: &str, name: Option<&str>, bytes: &[u8]) -> Arc<Self> {
        Self::new(vec![Ok((
            mime.to_string(),
            name.map(str::to_string),
            bytes.to_vec(),
        ))])
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

pub(crate) fn copy(error: &ArtifactError) -> ArtifactError {
    match error {
        ArtifactError::NotFound => ArtifactError::NotFound,
        ArtifactError::Unauthorized => ArtifactError::Unauthorized,
        ArtifactError::PurposeNotGranted => ArtifactError::PurposeNotGranted,
        ArtifactError::TooLarge => ArtifactError::TooLarge,
        ArtifactError::Unavailable(why) => ArtifactError::Unavailable(why.clone()),
    }
}

impl ArtifactReader for StubReader {
    fn get<'a>(
        &'a self,
        _id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ArtifactBytes, ArtifactError>> + Send + 'a>,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = {
            let mut answers = self.answers.lock().unwrap();
            if answers.len() > 1 {
                answers.pop_front().unwrap()
            } else {
                match answers.front().unwrap() {
                    Ok(file) => Ok(file.clone()),
                    Err(error) => Err(copy(error)),
                }
            }
        };
        Box::pin(async move {
            answer.map(|(mime_type, name, bytes)| ArtifactBytes {
                mime_type,
                name,
                bytes,
            })
        })
    }
}

/// Never answers: the route must bound the wait.
pub(crate) struct HangingReader;

impl ArtifactReader for HangingReader {
    fn get<'a>(
        &'a self,
        _id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ArtifactBytes, ArtifactError>> + Send + 'a>,
    > {
        Box::pin(std::future::pending())
    }
}

pub(crate) fn enabled_cell() -> Arc<UnitCell> {
    Arc::new(UnitCell::new(UnitAttachments::Enabled {
        pipeline: Arc::new(pipeline(vec![], Arc::new(FakeStore::default()))),
    }))
}

pub(crate) struct Fixture {
    pub(crate) deployment: DeploymentId,
    pub(crate) unit: Arc<LinkUnit>,
    pub(crate) _cell: Arc<UnitCell>,
}

pub(crate) fn fixture(reader: Arc<dyn ArtifactReader>) -> Fixture {
    let cell = enabled_cell();
    let deployment = DeploymentId::new();
    let unit = Arc::new(LinkUnit {
        key: LinkKey::derive(TOKEN, TENANT, BUNDLE, &deployment.to_string()),
        reader,
        recent: Arc::new(RecentPuts::default()),
        cells: vec![Arc::downgrade(&cell)],
        deployment: deployment.to_string(),
    });
    Fixture {
        deployment,
        unit,
        _cell: cell,
    }
}

impl Fixture {
    pub(crate) fn link(&self) -> LinkPath {
        self.link_for(ID, NOW, TTL)
    }

    pub(crate) fn link_for(&self, id: &str, now: u64, ttl: u64) -> LinkPath {
        let key = LinkKey::derive(TOKEN, TENANT, BUNDLE, &self.deployment.to_string());
        mint(&key, &self.deployment.to_string(), id, now, ttl).expect("mint")
    }

    pub(crate) async fn request(&self, method: Method, path: &str, limits: &LinkLimits) -> Answer {
        self.request_with(method, path, limits, None, true, NOW)
            .await
    }

    pub(crate) async fn request_with(
        &self,
        method: Method,
        path: &str,
        limits: &LinkLimits,
        client: Option<ClientKey>,
        links_on: bool,
        now: u64,
    ) -> Answer {
        let unit = Arc::clone(&self.unit);
        let deployment = self.deployment;
        let lookup = move |id: &DeploymentId| (*id == deployment).then(|| Arc::clone(&unit));
        let response = serve_link(
            LinkRequest {
                method: &method,
                path,
                client,
                now,
                ttl_max: TTL,
                links_on,
            },
            lookup,
            limits,
        )
        .await;
        Answer::of(response).await
    }
}

pub(crate) fn limits() -> LinkLimits {
    LinkLimits::new(2, 1 << 30)
}

#[derive(Debug, PartialEq)]
pub(crate) struct Answer {
    pub(crate) status: StatusCode,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Bytes,
}

impl Answer {
    pub(crate) async fn of(response: Response<http_body_util::Full<Bytes>>) -> Self {
        let status = response.status();
        let mut headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap().to_string()))
            .collect();
        headers.sort();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        Self {
            status,
            headers,
            body,
        }
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

pub(crate) fn assert_security_headers(answer: &Answer) {
    assert_eq!(answer.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(answer.header("cache-control"), Some("private, no-store"));
    assert_eq!(
        answer.header("content-security-policy"),
        Some("sandbox; default-src 'none'")
    );
    assert_eq!(answer.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(answer.header("x-frame-options"), Some("DENY"));
    for absent in [
        "set-cookie",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "location",
        "etag",
        "last-modified",
    ] {
        assert!(answer.header(absent).is_none(), "{absent}: {answer:?}");
    }
}
