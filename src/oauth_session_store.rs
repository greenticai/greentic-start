//! File-based OAuth session store for state token + PKCE verifier persistence.
//!
//! Storage layout: {bundle_root}/state/oauth-sessions/{state_token}.json
//! TTL: callers should pass `Duration::from_secs(600)` to gc_expired.
//!
//! Concurrency: each session has a unique random state token, so writes
//! never collide. consume() does read+remove and treats remove failures as
//! best-effort (the read already succeeded).

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct SessionTicket {
    pub state_token: String,
    pub code_verifier: String,
    pub code_challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSession {
    pub state_token: String,
    pub code_verifier: String,
    pub provider_id: String,
    pub provider_pack_id: String,
    pub tenant: String,
    pub team: Option<String>,
    pub conversation_id: String,
    pub created_at_unix_ms: i64,
}

#[derive(Debug, Clone)]
pub struct OauthSessionStore {
    bundle_root: PathBuf,
}

impl OauthSessionStore {
    pub fn new(bundle_root: impl Into<PathBuf>) -> Self {
        Self {
            bundle_root: bundle_root.into(),
        }
    }

    fn sessions_dir(&self) -> PathBuf {
        self.bundle_root.join("state").join("oauth-sessions")
    }

    fn session_path(&self, state_token: &str) -> PathBuf {
        self.sessions_dir().join(format!("{state_token}.json"))
    }

    pub fn create(
        &self,
        provider_id: &str,
        provider_pack_id: &str,
        tenant: &str,
        team: Option<&str>,
        conversation_id: &str,
    ) -> Result<SessionTicket> {
        // Best-effort GC of stale sessions.
        let _ = self.gc_expired(Duration::from_secs(600));

        let state_token = random_url_safe(32);
        let code_verifier = random_url_safe(64);
        let code_challenge = pkce_challenge_s256(&code_verifier);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        let session = PersistedSession {
            state_token: state_token.clone(),
            code_verifier: code_verifier.clone(),
            provider_id: provider_id.to_string(),
            provider_pack_id: provider_pack_id.to_string(),
            tenant: tenant.to_string(),
            team: team.map(str::to_string),
            conversation_id: conversation_id.to_string(),
            created_at_unix_ms: now,
        };

        std::fs::create_dir_all(self.sessions_dir())
            .with_context(|| "failed to create oauth-sessions dir")?;
        let path = self.session_path(&state_token);
        let body =
            serde_json::to_vec_pretty(&session).with_context(|| "failed to serialize session")?;
        std::fs::write(&path, body)
            .with_context(|| format!("failed to write session file {}", path.display()))?;

        // Restrict perms on POSIX (best-effort).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(SessionTicket {
            state_token,
            code_verifier,
            code_challenge,
        })
    }

    pub fn consume(&self, state_token: &str) -> Result<PersistedSession> {
        let path = self.session_path(state_token);
        let raw = std::fs::read_to_string(&path)
            .map_err(|err| anyhow!("session not found ({state_token}): {err}"))?;
        let session: PersistedSession =
            serde_json::from_str(&raw).with_context(|| format!("session {state_token} corrupt"))?;
        // Best-effort delete.
        let _ = std::fs::remove_file(&path);
        Ok(session)
    }

    pub fn gc_expired(&self, max_age: Duration) -> Result<usize> {
        let dir = self.sessions_dir();
        if !dir.exists() {
            return Ok(0);
        }
        let cutoff_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
            - max_age.as_millis() as i64;
        let mut removed = 0usize;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            // Try parsing the session to compare timestamps; if parse fails,
            // delete it (corrupt file).
            let parse_attempt: Option<PersistedSession> = std::fs::read_to_string(&path)
                .ok()
                .and_then(|raw| serde_json::from_str(&raw).ok());
            let stale = match parse_attempt {
                Some(s) => s.created_at_unix_ms < cutoff_ms,
                None => true,
            };
            if stale && std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

fn random_url_safe(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    rand::rng().fill(bytes.as_mut_slice());
    URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_challenge_s256(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use tempfile::tempdir;

    #[test]
    fn create_persists_session_file_with_random_state_and_verifier() {
        let dir = tempdir().unwrap();
        let store = OauthSessionStore::new(dir.path());
        let ticket = store
            .create(
                "github",
                "oauth-oidc-generic",
                "demo",
                Some("default"),
                "conv-1",
            )
            .unwrap();
        assert!(!ticket.state_token.is_empty());
        assert!(!ticket.code_verifier.is_empty());
        assert!(!ticket.code_challenge.is_empty());
        let path = dir
            .path()
            .join("state/oauth-sessions")
            .join(format!("{}.json", ticket.state_token));
        assert!(path.exists(), "session file should exist");
    }

    #[test]
    fn create_returns_unique_state_tokens_across_calls() {
        let dir = tempdir().unwrap();
        let store = OauthSessionStore::new(dir.path());
        let a = store.create("github", "p", "demo", None, "c1").unwrap();
        let b = store.create("github", "p", "demo", None, "c2").unwrap();
        assert_ne!(a.state_token, b.state_token);
        assert_ne!(a.code_verifier, b.code_verifier);
    }

    #[test]
    fn consume_returns_session_and_deletes_file() {
        let dir = tempdir().unwrap();
        let store = OauthSessionStore::new(dir.path());
        let ticket = store
            .create(
                "github",
                "oauth-oidc-generic",
                "demo",
                Some("default"),
                "conv-1",
            )
            .unwrap();
        let session = store.consume(&ticket.state_token).unwrap();
        assert_eq!(session.provider_id, "github");
        assert_eq!(session.conversation_id, "conv-1");
        assert_eq!(session.code_verifier, ticket.code_verifier);
        let path = dir
            .path()
            .join("state/oauth-sessions")
            .join(format!("{}.json", ticket.state_token));
        assert!(!path.exists(), "session file should be deleted");
    }

    #[test]
    fn consume_errors_on_unknown_state_token() {
        let dir = tempdir().unwrap();
        let store = OauthSessionStore::new(dir.path());
        let err = store.consume("nonexistent-state").unwrap_err();
        assert!(err.to_string().contains("session not found"));
    }

    #[test]
    fn gc_expired_removes_old_sessions() {
        let dir = tempdir().unwrap();
        let store = OauthSessionStore::new(dir.path());
        let ticket = store.create("github", "p", "demo", None, "c1").unwrap();
        // Backdate the session by mutating the file directly.
        let path = dir
            .path()
            .join("state/oauth-sessions")
            .join(format!("{}.json", ticket.state_token));
        let mut session: PersistedSession =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        session.created_at_unix_ms = 0;
        std::fs::write(&path, serde_json::to_vec(&session).unwrap()).unwrap();

        // Sleep a hair to advance the clock.
        thread::sleep(Duration::from_millis(10));

        let removed = store.gc_expired(Duration::from_millis(1)).unwrap();
        assert_eq!(removed, 1);
        assert!(!path.exists());
    }

    #[test]
    fn code_challenge_is_base64url_sha256_of_verifier() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let actual = pkce_challenge_s256(verifier);
        assert_eq!(actual, expected);
    }
}
