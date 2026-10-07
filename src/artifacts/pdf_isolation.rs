//! PDF text extraction in an isolated, resource-limited worker process.
//!
//! The PDF parser is third-party code fed untrusted bytes. It can panic, loop,
//! and — because it inflates every compressed stream with no size limit — turn
//! a 10 MiB file into gigabytes of memory. None of that can be bounded inside
//! this process, so the host re-executes its own binary with [`WORKER_ARG`],
//! pipes the PDF to it, and reads framed text back. The worker runs with:
//!
//! - an empty environment (the host's carries credentials);
//! - `RLIMIT_DATA` (heap and anonymous mappings), `RLIMIT_CPU`, no file writes
//!   (`RLIMIT_FSIZE = 0`), no core dump, 16 file descriptors, `/` as working
//!   directory, and `PR_SET_PDEATHSIG` so it dies with the host;
//! - a wall-clock deadline, after which it is killed;
//! - a cap on the bytes read back, and a page limit enforced by the worker.
//!
//! Workers run one at a time by default (see [`super::pdf_limits`] for the
//! limits and their overrides), so a burst of PDFs cannot multiply the memory
//! limit. Every failure — no worker configured,
//! spawn failure, crash, timeout, oversized or unframed output — is an empty
//! text, never an error that could fail the turn. Isolation is Linux-only; on
//! other platforms a PDF yields no text rather than being parsed in-process.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Condvar, Mutex, OnceLock, PoisonError, mpsc};
use std::time::{Duration, Instant};

use super::extract::truncate_chars;
use super::limits::MAX_FILE_BYTES;
pub(crate) use super::pdf_limits::*;

/// First argument that turns this binary into the PDF worker.
pub(crate) const WORKER_ARG: &str = "__greentic-artifact-pdf-text";
/// Prefix of every worker answer. Output without it is not extracted text.
pub(crate) const FRAME: &[u8] = b"GREENTIC-PDF-TEXT/1\n";
const POLL: Duration = Duration::from_millis(10);
/// `RLIMIT_NOFILE` of the worker: stdin, stdout, stderr and a little slack.
#[cfg(target_os = "linux")]
const WORKER_MAX_FILES: libc::rlim_t = 16;

static WORKER_PROGRAM: OnceLock<PathBuf> = OnceLock::new();
static PRODUCTION: OnceLock<Limits> = OnceLock::new();
static GATE: OnceLock<Gate> = OnceLock::new();

fn production_limits() -> &'static Limits {
    PRODUCTION.get_or_init(Limits::production)
}

fn gate() -> &'static Gate {
    GATE.get_or_init(|| Gate::new(worker_slots(std::env::var(SLOTS_ENV).ok().as_deref())))
}

/// Path of the running image on Linux: it names the executable this process
/// runs even after the file at its path has been replaced or deleted (the
/// runtime updater does both), so the worker is always the same build.
const PROC_SELF_EXE: &str = "/proc/self/exe";

/// Enable PDF extraction with this process's own executable as the worker.
/// Called by the binary's entry point only: a library consumer whose
/// executable is not `greentic-start` never enables it, and gets no PDF text.
pub(crate) fn enable_worker_from_current_exe() {
    let current = std::env::current_exe();
    let proc_self_exe = cfg!(target_os = "linux") && Path::new(PROC_SELF_EXE).exists();
    match worker_program(proc_self_exe, current.as_ref().ok().cloned()) {
        Some(program) => {
            tracing::debug!(
                worker = %program.display(),
                executable = ?current.as_ref().ok(),
                "PDF text worker enabled"
            );
            let _ = WORKER_PROGRAM.set(program);
        }
        None => tracing::warn!(
            "cannot locate the current executable; PDF attachments will carry no text"
        ),
    }
}

/// The worker executable: the running image when `/proc/self/exe` is usable,
/// else the path the process was started from.
pub(crate) fn worker_program(proc_self_exe: bool, current: Option<PathBuf>) -> Option<PathBuf> {
    if proc_self_exe {
        Some(PathBuf::from(PROC_SELF_EXE))
    } else {
        current
    }
}

/// Text of a PDF, at most [`super::limits::MAX_TEXT_CHARS`] characters, extracted by the
/// isolated worker. Empty when extraction is not enabled or fails.
pub(crate) fn pdf_text(bytes: &[u8]) -> String {
    match WORKER_PROGRAM.get() {
        Some(program) => run_worker_in(gate(), program, &[WORKER_ARG], bytes, production_limits()),
        None => String::new(),
    }
}

/// [`pdf_text`] against an explicit worker binary, with production limits
/// and a gate of its own (so parallel tests never wait on each other).
/// Exposed for the real-binary test only (feature `test-support`).
#[cfg(feature = "test-support")]
pub fn pdf_text_via(program: &Path, bytes: &[u8]) -> String {
    run_worker_in(
        &Gate::new(1),
        program,
        &[WORKER_ARG],
        bytes,
        production_limits(),
    )
}

/// Run `program args…` as a worker under a slot of `gate`: feed `bytes` on
/// stdin, return the framed text it prints, or an empty string on any failure
/// (no slot within `limits.wall` included).
#[cfg(target_os = "linux")]
pub(crate) fn run_worker_in(
    gate: &Gate,
    program: &Path,
    args: &[&str],
    bytes: &[u8],
    limits: &Limits,
) -> String {
    let Some(_slot) = gate.acquire(limits.wall) else {
        tracing::debug!("no free PDF worker slot; attachment carries no text");
        return String::new();
    };
    match supervise(program, args, bytes, limits) {
        Ok(text) => text,
        Err(reason) => {
            tracing::debug!(reason, "PDF text extraction yielded nothing");
            String::new()
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn run_worker_in(
    _gate: &Gate,
    _program: &Path,
    _args: &[&str],
    _bytes: &[u8],
    _limits: &Limits,
) -> String {
    String::new()
}

#[cfg(target_os = "linux")]
fn supervise(
    program: &Path,
    args: &[&str],
    bytes: &[u8],
    limits: &Limits,
) -> Result<String, &'static str> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    apply_resource_limits(&mut command, limits);
    let mut child = ChildGuard::new(command.spawn().map_err(|_| "worker could not start")?);

    let mut stdin = child.take_stdin().ok_or("worker has no stdin")?;
    let input = bytes.to_vec();
    // A worker that stops reading makes this write fail; it never blocks the
    // caller, which only waits on the deadline below.
    std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });

    let stdout = child.take_stdout().ok_or("worker has no stdout")?;
    let cap = (FRAME.len() + limits.max_chars.saturating_mul(4) + 1) as u64;
    let (sender, answer) = mpsc::channel();
    std::thread::spawn(move || {
        let out = read_capped(stdout, cap).unwrap_or_default();
        let _ = sender.send(out);
    });

    let deadline = Instant::now() + limits.wall;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
            // Dropping the guard kills and reaps the worker.
            Ok(None) | Err(_) => return Err("worker exceeded its deadline"),
        }
    };
    let out = answer
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| "worker output was not closed")?;
    if !status.success() {
        return Err("worker failed");
    }
    if out.len() as u64 >= cap {
        return Err("worker output exceeded its cap");
    }
    let text = out
        .strip_prefix(FRAME)
        .ok_or("worker output was not framed")?;
    Ok(truncate_chars(
        &String::from_utf8_lossy(text),
        limits.max_chars,
    ))
}

/// Owns a spawned worker: whatever path leaves [`supervise`] — an error, a
/// deadline, a panic — the worker is killed and reaped, never leaked or left
/// a zombie. Killing an already exited child is harmless.
pub(crate) struct ChildGuard {
    child: std::process::Child,
}

impl ChildGuard {
    pub(crate) fn new(child: std::process::Child) -> Self {
        Self { child }
    }

    fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        self.child.stdin.take()
    }

    fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.stdout.take()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// At most `cap` bytes of `reader`: it is never asked for more, so a worker
/// that floods its output costs the host `cap` bytes, not the flood.
pub(crate) fn read_capped(reader: impl Read, cap: u64) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(cap).read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(target_os = "linux")]
fn apply_resource_limits(command: &mut Command, limits: &Limits) {
    use std::os::unix::process::CommandExt;

    let data = limits.data_bytes as libc::rlim_t;
    let cpu = limits.cpu_secs as libc::rlim_t;
    let parent = std::process::id();
    // SAFETY: the closure runs in the forked child before `exec`. It only
    // calls `prctl`, `getppid` and `setrlimit`, which are async-signal-safe,
    // and builds the error from `errno` without allocating; it touches no
    // lock and no shared state.
    unsafe {
        command.pre_exec(move || {
            // Die with the host: a worker must not outlive the process that
            // supervises its deadline.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // The host may have died between fork and prctl.
            if libc::getppid() as u32 != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            for (resource, value) in [
                (libc::RLIMIT_DATA, data),
                (libc::RLIMIT_CPU, cpu),
                (libc::RLIMIT_FSIZE, 0),
                (libc::RLIMIT_CORE, 0),
                (libc::RLIMIT_NOFILE, WORKER_MAX_FILES),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: value,
                    rlim_max: value,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

/// When this process was started as the PDF worker, run it and return its
/// exit code; `None` for every other invocation.
pub(crate) fn run_worker_if_invoked() -> Option<i32> {
    let first = std::env::args_os().nth(1)?;
    (first == WORKER_ARG).then(worker_main)
}

fn worker_main() -> i32 {
    // The parser may panic; the default hook would print to stderr, which the
    // host discards anyway. Keep the worker silent.
    std::panic::set_hook(Box::new(|_| {}));
    let mut input = Vec::new();
    if std::io::stdin()
        .lock()
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut input)
        .is_err()
        || input.len() as u64 > MAX_FILE_BYTES
    {
        return 1;
    }
    let limits = Limits::DEFAULT;
    let text = worker_extract(&input, limits.max_pages, limits.max_chars);
    let mut out = std::io::stdout().lock();
    match out
        .write_all(FRAME)
        .and_then(|()| out.write_all(text.as_bytes()))
        .and_then(|()| out.flush())
    {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// The worker's extraction: text of at most `max_chars` characters, empty for
/// a PDF that does not parse, panics the parser, or has more than `max_pages`
/// pages. Only ever called in-process by the worker and by tests.
pub(crate) fn worker_extract(bytes: &[u8], max_pages: usize, max_chars: usize) -> String {
    std::panic::catch_unwind(|| extract_pages(bytes, max_pages, max_chars)).unwrap_or_default()
}

fn extract_pages(bytes: &[u8], max_pages: usize, max_chars: usize) -> String {
    let Ok(mut doc) = pdf_extract::Document::load_mem(bytes) else {
        return String::new();
    };
    if doc.is_encrypted() && doc.decrypt("").is_err() {
        return String::new();
    }
    let pages = doc.get_pages();
    if pages.len() > max_pages {
        return String::new();
    }
    let mut text = String::new();
    let mut chars = 0usize;
    for page in pages.keys() {
        let mut page_text = String::new();
        let mut output = pdf_extract::PlainTextOutput::new(&mut page_text);
        if pdf_extract::output_doc_page(&doc, &mut output, *page).is_err() {
            continue;
        }
        chars += page_text.chars().count();
        text.push_str(&page_text);
        if chars >= max_chars {
            break;
        }
    }
    truncate_chars(&text, max_chars)
}

/// A counting semaphore bounding concurrent workers.
pub(crate) struct Gate {
    busy: Mutex<usize>,
    freed: Condvar,
    capacity: usize,
}

pub(crate) struct Slot<'a> {
    gate: &'a Gate,
}

impl Gate {
    pub(crate) const fn new(capacity: usize) -> Self {
        Self {
            busy: Mutex::new(0),
            freed: Condvar::new(),
            capacity,
        }
    }

    /// Slots taken right now.
    #[cfg(test)]
    pub(crate) fn in_use(&self) -> usize {
        *self.busy.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A slot, waiting at most `wait` for one to free up.
    pub(crate) fn acquire(&self, wait: Duration) -> Option<Slot<'_>> {
        let deadline = Instant::now() + wait;
        let mut busy = self.busy.lock().unwrap_or_else(PoisonError::into_inner);
        while *busy >= self.capacity {
            let left = deadline.checked_duration_since(Instant::now())?;
            busy = self
                .freed
                .wait_timeout(busy, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        *busy += 1;
        Some(Slot { gate: self })
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut busy = self
            .gate
            .busy
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *busy = busy.saturating_sub(1);
        self.gate.freed.notify_one();
    }
}
