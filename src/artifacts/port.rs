//! The extension host's `artifact.put`, backed by ONE unit's artifacts door.
//!
//! Built per unit and installed on that unit's `RevisionHostOptions`
//! (`with_ext_artifact_port`): the revision path never reads `HostBuilder`
//! ports, and a door and its token belong to one unit, so there is no tenant
//! lookup and nothing to disambiguate. A unit without a door gets no port and
//! its extensions are told `unsupported` by the extension runtime.
//!
//! Rules, each pinned by `port_tests`:
//! - the tenant is decided by the door from the unit's token; the call's
//!   tenant is only checked to be present and is never sent;
//! - size, name and media type are checked again here, whatever the extension
//!   runtime already did: the bytes go to a store this crate owns;
//! - every failure is a fixed sentence: no token, URL or door body reaches the
//!   guest;
//! - the port blocks on the CALLER's runtime, taken at call time (activation
//!   runs on a runtime that may be gone by the time an extension runs), and
//!   refuses a current-thread runtime or no runtime instead of panicking.

use std::sync::{Arc, Weak};

use greentic_ext_runtime::host_ports::{
    ArtifactPort, ArtifactPortError, ArtifactPutRequest, HostCallContext,
};

use super::recent_puts::{PutRecord, RecentPuts};
use super::store::{ArtifactStore, PutRequest, StoreError, is_artifact_id};
use super::unit::{Off, UnitAttachments, UnitCell};
use crate::operator_log;

/// Bounds one extension `put` end to end, the store's retries included: a
/// tool waiting on a door that is down gets `unavailable` after this, never
/// the store's full retry span (three 20 s attempts).
pub(crate) const PORT_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// Largest file an extension may store (the door's per-artifact cap).
pub(crate) const MAX_PUT_BYTES: usize = 10 * 1024 * 1024;
/// Longest name sent to the door, in bytes.
const MAX_NAME_BYTES: usize = 255;
/// The name used when nothing printable is left.
const FALLBACK_NAME: &str = "file";

pub(crate) struct DoorArtifactPort {
    store: Arc<dyn ArtifactStore>,
    /// The unit's live decision. A re-probe that ends `purpose_not_granted`
    /// replaces it after the port was installed; from then on the port says
    /// `unsupported` without asking the door (and without a warning per call).
    unit: Option<Weak<UnitCell>>,
    /// Where accepted puts are recorded, so outbound shaping links only the
    /// files this unit's extensions created (`recent_puts`).
    recent: Option<Arc<RecentPuts>>,
    budget: std::time::Duration,
}

impl std::fmt::Debug for DoorArtifactPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorArtifactPort").finish_non_exhaustive()
    }
}

impl DoorArtifactPort {
    pub(crate) fn new(store: Arc<dyn ArtifactStore>) -> Self {
        Self {
            store,
            unit: None,
            recent: None,
            budget: PORT_BUDGET,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_budget(mut self, budget: std::time::Duration) -> Self {
        self.budget = budget;
        self
    }

    /// Reads `cell` on every call (see [`Self::unit`]).
    pub(crate) fn gated_by(mut self, cell: &Arc<UnitCell>) -> Self {
        self.unit = Some(Arc::downgrade(cell));
        self
    }

    /// Records every put the door accepts into `recent`.
    pub(crate) fn with_recent(mut self, recent: Arc<RecentPuts>) -> Self {
        self.recent = Some(recent);
        self
    }

    fn not_granted(&self) -> bool {
        self.unit
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|cell| matches!(*cell.current(), UnitAttachments::Off(Off::NotGranted)))
    }
}

fn unavailable(reason: &str) -> ArtifactPortError {
    ArtifactPortError::Unavailable(reason.to_string())
}

/// The handle to block on, when blocking is safe from here: a running
/// multi-thread runtime (a worker or blocking-pool thread of it).
fn blocking_handle() -> Option<tokio::runtime::Handle> {
    let handle = tokio::runtime::Handle::try_current().ok()?;
    (handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread).then_some(handle)
}

impl ArtifactPort for DoorArtifactPort {
    fn put(
        &self,
        extension_id: &str,
        ctx: &HostCallContext,
        request: ArtifactPutRequest,
    ) -> Result<String, ArtifactPortError> {
        if self.not_granted() {
            return Err(ArtifactPortError::Unsupported);
        }
        if ctx
            .tenant
            .as_deref()
            .map(str::trim)
            .is_none_or(str::is_empty)
        {
            return Err(unavailable("this call carries no tenant"));
        }
        if request.bytes.is_empty() || request.bytes.len() > MAX_PUT_BYTES {
            return Err(unavailable("the artifact is empty or too large"));
        }
        let mime = clean_mime(&request.mime_type).ok_or(ArtifactPortError::InvalidMediaType)?;
        let name = clean_name(&request.name);
        let Some(handle) = blocking_handle() else {
            return Err(unavailable(
                "artifact put needs a multi-thread async runtime",
            ));
        };
        let put = self.store.put(PutRequest {
            name: &name,
            mime: &mime,
            bytes: &request.bytes,
            derived_from: None,
            // A tool call belongs to no conversation here: the door applies
            // the per-tenant byte quota only.
            conversation_id: None,
        });
        let stored = tokio::task::block_in_place(|| {
            handle.block_on(async { tokio::time::timeout(self.budget, put).await })
        })
        .map_err(|_| map_error(extension_id, StoreError::Unavailable("timeout".into())))?
        .map_err(|err| map_error(extension_id, err))?;
        if !is_artifact_id(&stored.id) {
            return Err(unavailable("the artifacts door answered an invalid id"));
        }
        if let Some(recent) = &self.recent {
            // The door's answer (sniffed type, size), never the caller's claim.
            recent.record(
                &stored.id,
                PutRecord {
                    mime_type: stored.mime_type.clone(),
                    name,
                    size_bytes: stored.size_bytes,
                    at: unix_now(),
                },
            );
        }
        Ok(stored.id)
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Fixed sentences only: a token, URL or door body never reaches the guest.
fn map_error(extension_id: &str, err: StoreError) -> ArtifactPortError {
    let code = match &err {
        StoreError::Unsupported => return ArtifactPortError::InvalidMediaType,
        StoreError::Quota => return ArtifactPortError::QuotaExceeded,
        StoreError::TooLarge => "too_large",
        StoreError::NotGranted => "purpose_not_granted",
        StoreError::Rejected(_) => "rejected",
        StoreError::NotFound => "not_found",
        StoreError::Unavailable(_) => "unavailable",
    };
    operator_log::warn(
        module_path!(),
        format!("artifact put from extension `{extension_id}` refused by the door ({code})"),
    );
    unavailable("the artifacts door did not accept the request")
}

/// Zero-width, directional, bidi embedding/isolate, invisible-operator and BOM
/// characters: invisible, and able to disguise an extension.
fn is_format_or_bidi(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
    )
}

/// One line of display text usable as a file name: no path separators, no
/// control or invisible characters, at most [`MAX_NAME_BYTES`], never `.`/`..`.
pub(crate) fn clean_name(raw: &str) -> String {
    let mapped: String = raw
        .chars()
        .filter(|c| !c.is_control() && !is_format_or_bidi(*c))
        .map(|c| if c == '/' || c == '\\' { '_' } else { c })
        .collect();
    let trimmed = mapped.trim();
    let mut out = String::new();
    for c in trimmed.chars() {
        if out.len() + c.len_utf8() > MAX_NAME_BYTES {
            break;
        }
        out.push(c);
    }
    let out = out.trim_end().to_string();
    if out.is_empty() || out == "." || out == ".." {
        FALLBACK_NAME.to_string()
    } else {
        out
    }
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$&^_.+-".contains(c)
}

/// `type/subtype`, lowercased, parameters dropped; `None` when malformed.
pub(crate) fn clean_mime(raw: &str) -> Option<String> {
    let base = raw.split(';').next()?.trim().to_ascii_lowercase();
    let (kind, sub) = base.split_once('/')?;
    let ok = |part: &str| !part.is_empty() && part.len() <= 63 && part.chars().all(is_token_char);
    (ok(kind) && ok(sub)).then_some(base)
}
