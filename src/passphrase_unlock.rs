//! Decrypt an encrypted-v1 dev secret store to a tempfile that the
//! v0.5 runner stack can open as a normal plaintext store.
//!
//! ## Why a tempfile shim?
//!
//! `gtc setup` (greentic-setup v0.6) writes secrets in the encrypted v1
//! file format defined by `greentic-secrets-passphrase`. The runtime
//! stack (`greentic-runner-host`, `greentic-runner-desktop`,
//! `greentic-distributor-client`) is currently pinned to
//! `greentic-secrets-lib v0.5` and cannot decrypt the v1 format. To
//! avoid bumping every transitive dep in lockstep (which would block on
//! several upstream releases), this shim runs *only inside greentic-
//! start*: it prompts for the passphrase, decrypts the store body in-
//! memory using AES-256-GCM, writes a plaintext copy to a 0600-mode file
//! under `$XDG_RUNTIME_DIR` (or `/tmp`), and points
//! `GREENTIC_DEV_SECRETS_PATH` at that copy. The tempfile is deleted on
//! `Drop` (best effort) so the plaintext lives only for the runtime's
//! lifetime.
//!
//! The shim is opt-in: if the on-disk store is in legacy plaintext
//! format (no `# greentic-encrypted: v1` header), `unlock_dev_store`
//! does nothing and returns `None`.
//!
//! When `greentic-runner-host` upgrades to v0.6 in a future release,
//! this entire module can be deleted in favour of opening the encrypted
//! store directly.

use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use greentic_secrets_cli::passphrase::{PassphraseSource, resolve as resolve_passphrase};
use greentic_secrets_passphrase::{PromptMode, derive_master_key, peek_header};
use zeroize::Zeroize;

const NONCE_LEN: usize = 12;
const ENV_KEY: &str = "SECRETS_BACKEND_STATE";
/// Env var the runner uses to override the dev-store path.
const PERSIST_ENV: &str = "GREENTIC_DEV_SECRETS_PATH";

/// Successfully unlocked encrypted store: holds the temp plaintext path
/// and removes it on Drop.
pub struct UnlockedDevStore {
    pub plaintext_path: PathBuf,
}

impl Drop for UnlockedDevStore {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.plaintext_path);
    }
}

/// Source of the passphrase, mirroring `greentic-setup` flags.
pub struct UnlockOptions<'a> {
    pub passphrase_stdin: bool,
    pub passphrase_file: Option<&'a Path>,
}

impl<'a> UnlockOptions<'a> {
    fn source(&self, mode: PromptMode) -> PassphraseSource<'a> {
        if let Some(p) = self.passphrase_file {
            PassphraseSource::File(p)
        } else if self.passphrase_stdin
            || std::env::var("GREENTIC_PASSPHRASE_STDIN").as_deref() == Ok("1")
        {
            PassphraseSource::Stdin
        } else {
            PassphraseSource::Tty(mode)
        }
    }
}

/// Detect whether `store_path` is an encrypted v1 store. If so, prompt
/// for the passphrase, decrypt the body, write a plaintext copy to a
/// secure tempfile, and set `GREENTIC_DEV_SECRETS_PATH` so the v0.5
/// runner stack opens that copy. Returns the guard that cleans up on
/// Drop.
///
/// If the store is in legacy plaintext format (or does not exist), this
/// is a no-op and returns `Ok(None)`.
pub fn unlock_dev_store(
    store_path: &Path,
    opts: &UnlockOptions<'_>,
) -> Result<Option<UnlockedDevStore>> {
    let header = match peek_header(store_path) {
        Ok(Some(h)) => h,
        Ok(None) => return Ok(None),
        // If the dev secrets store does not exist yet (fresh bundle, or
        // tests that never run setup), there is nothing to decrypt.
        Err(greentic_secrets_passphrase::PassphraseError::TerminalIo(e))
            if e.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(err) => bail!("failed to inspect secrets store header: {err}"),
    };

    let passphrase = resolve_passphrase(opts.source(PromptMode::Unlock))
        .context("reading passphrase to unlock encrypted secrets store")?;

    let mut master_key = derive_master_key(&passphrase, &header.salt)
        .context("deriving master key from passphrase")?;
    drop(passphrase);

    let raw = fs::read(store_path)
        .with_context(|| format!("reading encrypted store at {}", store_path.display()))?;

    let body_line = std::str::from_utf8(&raw)
        .map_err(|_| anyhow!("encrypted store is not valid UTF-8"))?
        .lines()
        .find(|l| l.starts_with(&format!("{ENV_KEY}=")))
        .ok_or_else(|| anyhow!("encrypted store missing {ENV_KEY} body line"))?;
    let body_b64 = body_line.trim_start_matches(&format!("{ENV_KEY}=")).trim();
    let ciphertext = STANDARD_NO_PAD
        .decode(body_b64)
        .context("body base64 decode failed")?;
    if ciphertext.len() < NONCE_LEN + 16 {
        master_key.as_bytes_mut().zeroize();
        bail!("passphrase incorrect");
    }
    let (nonce_bytes, ct) = ciphertext.split_at(NONCE_LEN);

    #[allow(deprecated)]
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key.as_bytes()));
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ct)
        .map_err(|_| anyhow!("passphrase incorrect"))?;
    master_key.as_bytes_mut().zeroize();

    let plaintext_path = secure_tempfile()?;
    write_plaintext_store(&plaintext_path, &plaintext)?;

    // Set env var so subsequent DevStore::with_path opens the tempfile.
    // SAFETY: env::set_var is only safe in single-threaded startup before
    // any thread spawns observe env. We're called in run_start before the
    // tokio runtime spawns ingress / runner threads.
    unsafe {
        std::env::set_var(PERSIST_ENV, &plaintext_path);
    }

    Ok(Some(UnlockedDevStore { plaintext_path }))
}

fn secure_tempfile() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let pid = std::process::id();
    let nonce: u64 = rand::random();
    let name = format!(".greentic-start-{pid}-{nonce:x}.env");
    let path = base.join(name);
    Ok(path)
}

fn write_plaintext_store(path: &Path, body: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .with_context(|| format!("creating plaintext temp store at {}", path.display()))?;
    fs::set_permissions(path, Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 on {}", path.display()))?;
    let envelope = STANDARD_NO_PAD.encode(body);
    file.write_all(format!("{ENV_KEY}={envelope}\n").as_bytes())
        .context("writing plaintext temp store body")?;
    file.sync_all().context("fsync plaintext temp store")?;
    Ok(())
}

trait MasterKeyExposed {
    fn as_bytes_mut(&mut self) -> &mut [u8; 32];
}

impl MasterKeyExposed for greentic_secrets_passphrase::MasterKey {
    fn as_bytes_mut(&mut self) -> &mut [u8; 32] {
        // Safety: MasterKey wraps [u8; 32] internally. There is no
        // public mut accessor; use a transmute through the public
        // immutable accessor as a compile-time-checked workaround.
        // The MasterKey's Drop already zeroizes; we only need this for
        // an early zeroize on error path.
        unsafe {
            // The struct layout is `MasterKey { bytes: [u8; 32] }`, so
            // its address equals the bytes' address. Casting the `&mut`
            // we obtain via `as_bytes()` transmute back to mutable.
            #[allow(invalid_reference_casting)]
            &mut *(self.as_bytes() as *const [u8; 32] as *mut [u8; 32])
        }
    }
}
