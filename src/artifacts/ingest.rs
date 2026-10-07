//! Per-envelope attachment ingest: fetch, sniff, store, extract, rewrite.
//!
//! One attachment failing never fails the envelope and never removes or
//! reorders anything: the slot keeps its place with `url = null` and a note
//! (master plan C1). `attachments`, `extensions["artifacts"]` and
//! `extensions["attachment_notes"]` stay parallel by index.
//!
//! Bounds, each enforced here:
//! - at most [`MAX_FILES`] referenced attachments are processed, the rest get a
//!   `quota_exceeded` note;
//! - at most [`MAX_MESSAGE_BYTES`] of new content per message;
//! - the whole message gets [`MESSAGE_DEADLINE`]: a fetch or a put past it is a
//!   note, text extraction past it only loses the derived text;
//! - text extraction runs in `spawn_blocking` (a PDF waits on a worker
//!   process) and the derived text is at most [`MAX_TEXT_CHARS`] characters.
//!
//! A note's `message` is `"\"<label>\": not read, <reason>"`: a cleaned file
//! label, quoted and at most 64 characters, and a fixed reason, never a URL, a token, a status body or a provider id.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use greentic_types::{Attachment, ChannelMessageEnvelope};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout_at};

use super::drops::append_drop_notes;
use super::extract::{extract_text, truncate_chars};
use super::fetch::{FetchError, Fetcher};
use super::fetch_ref::{EXTENSION_KEY as FETCH_KEY, FetchRef, parse_refs};
use super::label::display_label;
use super::limits::{MAX_FILE_BYTES, MAX_FILES, MAX_MESSAGE_BYTES, MAX_TEXT_CHARS};
use super::origin::Origin;
use super::pdf_limits::{SLOTS_ENV, worker_slots};
use super::provenance::strip_reserved;
use super::sniff::{Kind, detect};
use super::store::{ArtifactStore, PutRequest, StoreError, Stored};

pub(crate) const ARTIFACTS_KEY: &str = "artifacts";
pub(crate) const NOTES_KEY: &str = "attachment_notes";
/// Time one message's attachments may take in all, fetches and puts included.
pub(crate) const MESSAGE_DEADLINE: Duration = Duration::from_secs(120);
/// Longest label, in characters, quoted in a note the agent reads.
const NOTE_LABEL_CHARS: usize = 64;

/// Extracts document text; blocking. The production one is [`extract_text`].
pub(crate) type Extractor = Arc<dyn Fn(&[u8], &str) -> Option<String> + Send + Sync>;

/// A failure, in the closed vocabulary of master C1.
#[derive(Debug)]
pub(crate) struct Note {
    pub code: &'static str,
    pub reason: &'static str,
}

impl Note {
    const fn new(code: &'static str, reason: &'static str) -> Self {
        Self { code, reason }
    }

    /// The label is quoted and at most [`NOTE_LABEL_CHARS`] characters: a file
    /// name is the sender's text, and the agent reads it as data, not as part
    /// of the sentence.
    pub(crate) fn to_value(&self, label: &str) -> Value {
        let short: String = label
            .chars()
            .take(NOTE_LABEL_CHARS)
            .map(|c| if c == '"' { '\'' } else { c })
            .collect();
        json!({ "code": self.code, "message": format!("\"{short}\": not read, {}", self.reason) })
    }
}

const TOO_MANY: Note = Note::new("quota_exceeded", "only 5 files per message are accepted");
const MESSAGE_TOO_LARGE: Note = Note::new(
    "too_large",
    "the message's files together exceed the allowed size",
);
const FILE_TOO_LARGE: Note = Note::new("too_large", "the file is larger than the allowed size");
const BAD_INLINE: Note = Note::new("fetch_failed", "the attached data could not be read");
const OUT_OF_TIME: Note = Note::new("fetch_failed", "reading the message's files took too long");
const STORE_OUT_OF_TIME: Note = Note::new("door_unavailable", "it could not be stored in time");

type Done = (Stored, Option<String>);

pub(crate) struct Pipeline {
    store: Arc<dyn ArtifactStore>,
    fetcher: Arc<dyn Fetcher>,
    message_cap: u64,
    deadline: Duration,
    extractor: Extractor,
    /// One permit per extraction running on a blocking thread. Taken BEFORE
    /// `spawn_blocking` and moved into the closure, so the number of blocking
    /// threads doing (or queueing for) extraction never exceeds it, even when
    /// a message stops waiting at its deadline and the thread keeps running.
    extraction: Arc<Semaphore>,
}

/// Process-wide extraction permits, as many as the PDF worker gate has slots:
/// more blocking threads than that would only wait on the gate.
fn shared_extraction_permits() -> Arc<Semaphore> {
    static PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    PERMITS
        .get_or_init(|| {
            Arc::new(Semaphore::new(worker_slots(
                std::env::var(SLOTS_ENV).ok().as_deref(),
            )))
        })
        .clone()
}

impl Pipeline {
    pub(crate) fn new(store: Arc<dyn ArtifactStore>, fetcher: Arc<dyn Fetcher>) -> Self {
        Self {
            store,
            fetcher,
            message_cap: MAX_MESSAGE_BYTES,
            deadline: MESSAGE_DEADLINE,
            extractor: Arc::new(extract_text),
            extraction: shared_extraction_permits(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_extraction_permits(mut self, permits: usize) -> Self {
        self.extraction = Arc::new(Semaphore::new(permits));
        self
    }

    #[cfg(test)]
    pub(crate) fn with_shared_extraction_permits(mut self, permits: Arc<Semaphore>) -> Self {
        self.extraction = permits;
        self
    }

    #[cfg(test)]
    pub(crate) fn extraction_permits(&self) -> Arc<Semaphore> {
        self.extraction.clone()
    }

    #[cfg(test)]
    pub(crate) fn with_message_cap(mut self, cap: u64) -> Self {
        self.message_cap = cap;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_extractor(mut self, extractor: Extractor) -> Self {
        self.extractor = extractor;
        self
    }

    /// First removes every host field a provider wrote (see
    /// [`super::provenance`]), then rewrites `envelope` in place, then appends
    /// a note slot for every attachment or message the provider counted as
    /// dropped (see [`super::drops`]). Beyond that removal, nothing changes
    /// when no attachment carries a usable fetch reference and no counter is
    /// present.
    pub(crate) async fn process(
        &self,
        envelope: &mut ChannelMessageEnvelope,
        conversation_id: Option<&str>,
        origin: &Origin,
    ) {
        strip_reserved(envelope);
        self.ingest(envelope, conversation_id, origin).await;
        append_drop_notes(envelope);
    }

    async fn ingest(
        &self,
        envelope: &mut ChannelMessageEnvelope,
        conversation_id: Option<&str>,
        origin: &Origin,
    ) {
        if envelope.attachments.is_empty() {
            return;
        }
        let refs = parse_refs(&envelope.extensions);
        if refs.iter().all(Option::is_none) {
            return; // no provider asked for a fetch: leave the envelope alone
        }
        let deadline = Instant::now() + self.deadline;
        let turn = Turn {
            origin,
            conversation_id,
            deadline,
        };
        let count = envelope.attachments.len();
        let mut meta = vec![Value::Null; count];
        let mut notes = vec![Value::Null; count];
        let mut budget = Budget {
            total: 0,
            seen: HashMap::new(),
        };
        let mut attempted = 0usize;

        for (index, attachment) in envelope.attachments.iter_mut().enumerate() {
            let Some(reference) = refs.get(index).cloned().flatten() else {
                continue; // no usable reference for this slot: untouched
            };
            let label = display_label(attachment.name.as_deref(), index);
            let outcome = if attempted >= MAX_FILES {
                Err(TOO_MANY)
            } else if Instant::now() >= deadline {
                attempted += 1;
                Err(OUT_OF_TIME)
            } else {
                attempted += 1;
                self.one(turn, &reference, attachment, &label, &mut budget)
                    .await
            };
            // An inline payload must never stay in the envelope, stored or not.
            attachment.content = None;
            match outcome {
                Ok((stored, text_ref)) => {
                    attachment.url = Some(stored.id.clone());
                    attachment.mime_type = stored.mime_type.clone();
                    attachment.size_bytes = Some(stored.size_bytes);
                    meta[index] = json!({
                        "sha256": stored.sha256,
                        "kind": stored.kind,
                        "text_ref": text_ref,
                    });
                }
                Err(note) => {
                    attachment.url = None;
                    notes[index] = note.to_value(&label);
                }
            }
        }

        let failed = notes.iter().filter(|n| !n.is_null()).count();
        tracing::info!(
            attachments = count,
            processed = attempted,
            failed,
            "inbound attachments ingested"
        );
        envelope.extensions.remove(FETCH_KEY);
        envelope
            .extensions
            .insert(ARTIFACTS_KEY.into(), Value::Array(meta));
        if failed > 0 {
            envelope
                .extensions
                .insert(NOTES_KEY.into(), Value::Array(notes));
        }
    }

    async fn one(
        &self,
        turn: Turn<'_>,
        reference: &FetchRef,
        attachment: &Attachment,
        label: &str,
        budget: &mut Budget,
    ) -> Result<Done, Note> {
        let Turn {
            origin,
            conversation_id,
            deadline,
        } = turn;
        // The fetcher refuses this too; refusing here keeps the rule
        // independent of the fetcher.
        if !origin.channel().allows(reference) {
            return Err(fetch_note(FetchError::NotThisChannel));
        }
        let bytes = match reference {
            FetchRef::Inline => decode_inline(attachment.content.as_ref())?,
            other => {
                timeout_at(deadline, self.fetcher.fetch(origin, other))
                    .await
                    .map_err(|_| OUT_OF_TIME)?
                    .map_err(fetch_note)?
                    .bytes
            }
        };
        let key = Sha256::digest(&bytes).to_vec();
        if let Some(done) = budget.seen.get(&key) {
            return Ok(done.clone());
        }
        let size = bytes.len() as u64;
        if budget.total + size > self.message_cap {
            return Err(MESSAGE_TOO_LARGE);
        }
        let detected = detect(&bytes).map_err(|r| Note::new("unsupported_type", r.describe()))?;
        let put = PutRequest {
            name: label,
            mime: detected.mime,
            bytes: &bytes,
            derived_from: None,
            conversation_id,
        };
        let stored = timeout_at(deadline, self.store.put(put))
            .await
            .map_err(|_| STORE_OUT_OF_TIME)?
            .map_err(store_note)?;
        budget.total += size;
        let text_ref = match detected.kind {
            Kind::Document => {
                self.text_artifact(bytes, detected.mime, label, &stored.id, turn)
                    .await
            }
            Kind::Image => None,
        };
        let done = (stored, text_ref);
        budget.seen.insert(key, done.clone());
        Ok(done)
    }

    /// The derived text artifact's id, or `None` when there is no text, the
    /// time ran out, or the door did not take it. The original stays stored
    /// either way.
    async fn text_artifact(
        &self,
        bytes: Vec<u8>,
        mime: &'static str,
        label: &str,
        source_id: &str,
        turn: Turn<'_>,
    ) -> Option<String> {
        let Turn {
            conversation_id,
            deadline,
            ..
        } = turn;
        let extractor = self.extractor.clone();
        let Ok(Ok(permit)) = timeout_at(deadline, self.extraction.clone().acquire_owned()).await
        else {
            tracing::warn!("no extraction slot was free in time; the file is kept without text");
            return None;
        };
        // One closure, start to finish: a PDF worker's death signal is tied to
        // the thread that spawned it. The permit lives as long as the thread.
        let job = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            extractor(&bytes, mime)
        });
        let text = match timeout_at(deadline, job).await {
            Ok(Ok(Some(text))) if !text.is_empty() => truncate_chars(&text, MAX_TEXT_CHARS),
            Ok(Ok(_)) => return None,
            Ok(Err(_)) | Err(_) => {
                tracing::warn!(
                    "document text extraction did not finish; the file is kept without text"
                );
                return None;
            }
        };
        let name = format!("{label}.txt");
        let put = PutRequest {
            name: &name,
            mime: "text/plain",
            bytes: text.as_bytes(),
            derived_from: Some(source_id),
            conversation_id,
        };
        match timeout_at(deadline, self.store.put(put)).await {
            Ok(Ok(stored)) => Some(stored.id),
            Ok(Err(_)) | Err(_) => {
                tracing::warn!(
                    "the derived text could not be stored; the file is kept without text"
                );
                None
            }
        }
    }
}

/// What every attachment of one message shares.
#[derive(Clone, Copy)]
struct Turn<'a> {
    origin: &'a Origin,
    conversation_id: Option<&'a str>,
    deadline: Instant,
}

struct Budget {
    /// Bytes of distinct content stored so far in this message.
    total: u64,
    /// Content already stored in this message, by SHA-256.
    seen: HashMap<Vec<u8>, Done>,
}

/// Inline payloads: a standard-base64 string, or an object with
/// `data_base64`. Nothing else. The length is checked before decoding so a
/// huge string never allocates a decoded copy.
fn decode_inline(content: Option<&Value>) -> Result<Vec<u8>, Note> {
    let raw = match content {
        Some(Value::String(s)) => s.as_str(),
        Some(Value::Object(o)) => o
            .get("data_base64")
            .and_then(Value::as_str)
            .ok_or(BAD_INLINE)?,
        _ => return Err(BAD_INLINE),
    };
    let raw = raw.trim();
    if raw.len() as u64 > MAX_FILE_BYTES.div_ceil(3) * 4 {
        return Err(FILE_TOO_LARGE);
    }
    let bytes = B64.decode(raw).map_err(|_| BAD_INLINE)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(FILE_TOO_LARGE);
    }
    Ok(bytes)
}

fn fetch_note(err: FetchError) -> Note {
    match err {
        FetchError::TooLarge => FILE_TOO_LARGE,
        FetchError::MissingCredential => Note::new(
            "fetch_failed",
            "the channel credential needed to download it is not available",
        ),
        FetchError::Denied(_) => Note::new("fetch_failed", "the channel refused the download"),
        FetchError::Status(_) | FetchError::Transport(_) => {
            Note::new("fetch_failed", "the download failed")
        }
        FetchError::BadReference => Note::new(
            "fetch_failed",
            "the channel's file reference could not be resolved",
        ),
        FetchError::BlockedHost => Note::new("fetch_failed", "the download address is not allowed"),
        FetchError::TooManyRedirects => {
            Note::new("fetch_failed", "the download was redirected too many times")
        }
        FetchError::NotThisChannel => Note::new(
            "fetch_failed",
            "the file reference does not belong to the channel it arrived on",
        ),
    }
}

fn store_note(err: StoreError) -> Note {
    match err {
        StoreError::TooLarge => FILE_TOO_LARGE,
        StoreError::Unsupported => Note::new("unsupported_type", "this file type is not supported"),
        StoreError::Quota => Note::new(
            "quota_exceeded",
            "the storage quota for this conversation is used up",
        ),
        StoreError::Rejected(_)
        | StoreError::NotGranted
        | StoreError::Unavailable(_)
        | StoreError::NotFound => Note::new("door_unavailable", "it could not be stored right now"),
    }
}
