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
//!   (`RLIMIT_FSIZE = 0`) and no core dump;
//! - a wall-clock deadline, after which it is killed;
//! - a cap on the bytes read back, and a page limit enforced by the worker.
//!
//! At most [`MAX_CONCURRENT_WORKERS`] workers run at once, so a burst of PDFs
//! cannot multiply the memory limit. Every failure — no worker configured,
//! spawn failure, crash, timeout, oversized or unframed output — is an empty
//! text, never an error that could fail the turn. Isolation is Linux-only; on
//! other platforms a PDF yields no text rather than being parsed in-process.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Condvar, Mutex, OnceLock, PoisonError, mpsc};
use std::time::{Duration, Instant};

use super::extract::truncate_chars;
use super::limits::{MAX_FILE_BYTES, MAX_TEXT_CHARS};

/// First argument that turns this binary into the PDF worker.
pub(crate) const WORKER_ARG: &str = "__greentic-artifact-pdf-text";
/// Prefix of every worker answer. Output without it is not extracted text.
pub(crate) const FRAME: &[u8] = b"GREENTIC-PDF-TEXT/1\n";
/// A PDF with more pages than this yields no text.
pub(crate) const MAX_PDF_PAGES: usize = 300;
const MAX_CONCURRENT_WORKERS: usize = 2;
const POLL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// `RLIMIT_DATA` of the worker, in bytes.
    pub data_bytes: u64,
    /// `RLIMIT_CPU` of the worker, in seconds.
    pub cpu_secs: u64,
    /// Wall-clock deadline, also the longest wait for a free worker slot.
    pub wall: Duration,
    pub max_pages: usize,
    pub max_chars: usize,
}

impl Limits {
    pub(crate) const PRODUCTION: Limits = Limits {
        data_bytes: 768 * 1024 * 1024,
        cpu_secs: 15,
        wall: Duration::from_secs(30),
        max_pages: MAX_PDF_PAGES,
        max_chars: MAX_TEXT_CHARS,
    };
}

static WORKER_PROGRAM: OnceLock<PathBuf> = OnceLock::new();
static GATE: Gate = Gate::new(MAX_CONCURRENT_WORKERS);

/// Enable PDF extraction by naming this process's own executable as the
/// worker. Called by the binary's entry point only: a library consumer whose
/// executable is not `greentic-start` never enables it, and gets no PDF text.
pub(crate) fn enable_worker_from_current_exe() {
    match std::env::current_exe() {
        Ok(program) => {
            let _ = WORKER_PROGRAM.set(program);
        }
        Err(err) => tracing::warn!(
            error = %err,
            "cannot locate the current executable; PDF attachments will carry no text"
        ),
    }
}

/// Text of a PDF, at most [`MAX_TEXT_CHARS`] characters, extracted by the
/// isolated worker. Empty when extraction is not enabled or fails.
pub(crate) fn pdf_text(bytes: &[u8]) -> String {
    match WORKER_PROGRAM.get() {
        Some(program) => run_worker(program, &[WORKER_ARG], bytes, &Limits::PRODUCTION),
        None => String::new(),
    }
}

/// [`pdf_text`] against an explicit worker binary, with production limits.
/// Exposed for the real-binary test only.
#[doc(hidden)]
pub fn pdf_text_via(program: &Path, bytes: &[u8]) -> String {
    run_worker(program, &[WORKER_ARG], bytes, &Limits::PRODUCTION)
}

/// Run `program args…` as a worker: feed `bytes` on stdin, return the framed
/// text it prints, or an empty string on any failure.
#[cfg(target_os = "linux")]
pub(crate) fn run_worker(program: &Path, args: &[&str], bytes: &[u8], limits: &Limits) -> String {
    let Some(_slot) = GATE.acquire(limits.wall) else {
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
pub(crate) fn run_worker(
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
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    apply_resource_limits(&mut command, limits);
    let mut child = command.spawn().map_err(|_| "worker could not start")?;

    let mut stdin = child.stdin.take().ok_or("worker has no stdin")?;
    let input = bytes.to_vec();
    // A worker that stops reading makes this write fail; it never blocks the
    // caller, which only waits on the deadline below.
    std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });

    let stdout = child.stdout.take().ok_or("worker has no stdout")?;
    let cap = (FRAME.len() + limits.max_chars.saturating_mul(4) + 1) as u64;
    let (sender, answer) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.take(cap).read_to_end(&mut out);
        let _ = sender.send(out);
    });

    let deadline = Instant::now() + limits.wall;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("worker exceeded its deadline");
            }
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

#[cfg(target_os = "linux")]
fn apply_resource_limits(command: &mut Command, limits: &Limits) {
    use std::os::unix::process::CommandExt;

    let data = limits.data_bytes as libc::rlim_t;
    let cpu = limits.cpu_secs as libc::rlim_t;
    // SAFETY: the closure runs in the forked child before `exec`. It only
    // calls `setrlimit`, which is async-signal-safe, and builds the error from
    // `errno` without allocating; it touches no lock and no shared state.
    unsafe {
        command.pre_exec(move || {
            for (resource, value) in [
                (libc::RLIMIT_DATA, data),
                (libc::RLIMIT_CPU, cpu),
                (libc::RLIMIT_FSIZE, 0),
                (libc::RLIMIT_CORE, 0),
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
    let limits = Limits::PRODUCTION;
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
