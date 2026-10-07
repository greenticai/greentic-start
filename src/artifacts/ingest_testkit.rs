//! In-memory doubles for the ingest tests: a store that records every put and
//! a fetcher that answers from a script and counts its calls.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use greentic_types::{Attachment, ChannelMessageEnvelope};
use serde_json::{Value, json};

use super::fetch::{FetchError, Fetched, Fetcher};
use super::fetch_ref::FetchRef;
use super::ingest::Pipeline;
use super::origin::Origin;
use super::store::{ArtifactStore, PutRequest, StoreError, Stored};

pub(crate) fn png(tag: u8) -> Vec<u8> {
    let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0];
    bytes.push(tag);
    bytes
}

#[derive(Debug, Clone)]
pub(crate) struct Recorded {
    pub name: String,
    pub mime: String,
    pub bytes: Vec<u8>,
    pub derived_from: Option<String>,
    pub conversation_id: Option<String>,
}

#[derive(Default)]
pub(crate) struct FakeStore {
    pub puts: Mutex<Vec<Recorded>>,
    /// Fail the put with this 0-based call number.
    pub fail_on: Mutex<Option<usize>>,
    /// Never answer the put with this 0-based call number.
    pub hang_on: Mutex<Option<usize>>,
}

impl FakeStore {
    pub(crate) fn puts(&self) -> Vec<Recorded> {
        self.puts.lock().unwrap().clone()
    }
}

#[async_trait]
impl ArtifactStore for FakeStore {
    async fn put(&self, req: PutRequest<'_>) -> Result<Stored, StoreError> {
        let n = {
            let mut puts = self.puts.lock().unwrap();
            puts.push(Recorded {
                name: req.name.into(),
                mime: req.mime.into(),
                bytes: req.bytes.to_vec(),
                derived_from: req.derived_from.map(str::to_string),
                conversation_id: req.conversation_id.map(str::to_string),
            });
            puts.len() - 1
        };
        if *self.hang_on.lock().unwrap() == Some(n) {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
        if *self.fail_on.lock().unwrap() == Some(n) {
            return Err(StoreError::Unavailable("down".into()));
        }
        let kind = if req.mime.starts_with("image/") {
            "image"
        } else {
            "document"
        };
        Ok(Stored {
            id: format!("artifact://id{}", n + 1),
            sha256: "aa".into(),
            size_bytes: req.bytes.len() as u64,
            kind: kind.into(),
            mime_type: req.mime.into(),
        })
    }

    async fn probe(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

/// One scripted answer.
#[derive(Clone)]
pub(crate) enum Answer {
    Bytes(Vec<u8>),
    Denied,
    /// Never answers.
    Hang,
}

/// Cycles through the answers and counts calls.
pub(crate) struct FakeFetcher {
    answers: Vec<Answer>,
    pub calls: AtomicUsize,
}

impl FakeFetcher {
    pub(crate) fn new(answers: Vec<Answer>) -> Arc<Self> {
        Arc::new(Self {
            answers,
            calls: AtomicUsize::new(0),
        })
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Fetcher for FakeFetcher {
    async fn fetch(&self, _: &Origin, _: &FetchRef) -> Result<Fetched, FetchError> {
        let i = self.calls.fetch_add(1, Ordering::SeqCst);
        match self.answers[i % self.answers.len()].clone() {
            Answer::Bytes(bytes) => Ok(Fetched { bytes }),
            Answer::Denied => Err(FetchError::Denied(401)),
            Answer::Hang => {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                Err(FetchError::Transport("never".into()))
            }
        }
    }
}

pub(crate) fn ok(bytes: Vec<u8>) -> Answer {
    Answer::Bytes(bytes)
}

/// An envelope with no attachments and no extensions.
pub(crate) fn bare_envelope() -> ChannelMessageEnvelope {
    serde_json::from_value(json!({
        "id": "msg-1",
        "tenant": {
            "env": "dev",
            "tenant": "demo",
            "tenant_id": "demo",
            "team": "default",
            "attempt": 0
        },
        "channel": "conv-1",
        "session_id": "conv-1",
        "text": "hello",
        "metadata": {}
    }))
    .expect("envelope")
}

/// `n` PNG attachments, each with a `public` fetch reference.
pub(crate) fn envelope(n: usize) -> ChannelMessageEnvelope {
    let mut env = bare_envelope();
    env.attachments = (0..n)
        .map(|i| Attachment {
            mime_type: "image/png".into(),
            url: None,
            content: None,
            name: Some(format!("f{i}.png")),
            size_bytes: None,
        })
        .collect();
    env.extensions = BTreeMap::from([(
        "attachment_fetch".to_string(),
        Value::Array(
            (0..n)
                .map(|i| json!({"kind":"public","url":format!("https://x/{i}")}))
                .collect(),
        ),
    )]);
    env
}

pub(crate) fn pipeline(answers: Vec<Answer>, store: Arc<FakeStore>) -> Pipeline {
    Pipeline::new(store, FakeFetcher::new(answers))
}

pub(crate) fn note(env: &ChannelMessageEnvelope, i: usize) -> &Value {
    &env.extensions["attachment_notes"][i]
}

/// The origin most ingest tests run under: a verified request received on
/// Slack.
pub(crate) fn slack() -> Origin {
    Origin::new(
        "messaging.slack.api",
        "messaging-provider-slack",
        "demo",
        None,
    )
    .verified_by_host(true)
}

/// The origin a reference of this kind legitimately arrives on.
pub(crate) fn origin_of(reference: &FetchRef) -> Origin {
    let provider_type = match reference {
        FetchRef::TelegramFile { .. } => "messaging.telegram.bot",
        FetchRef::WhatsappMedia { .. } => "messaging.whatsapp",
        FetchRef::Bearer { secret_key, .. } if secret_key == "WEBEX_BOT_TOKEN" => "messaging.webex",
        _ => "messaging.slack.api",
    };
    Origin::new(provider_type, "messaging-provider-under-test", "demo", None).verified_by_host(true)
}
