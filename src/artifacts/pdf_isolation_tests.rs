use std::path::Path;
use std::time::{Duration, Instant};

use super::pdf_fixture::{flate_content_pdf, text_pdf, zlib_bomb};
use super::pdf_isolation::*;

// --- The worker's own extraction (runs in-process here; benign inputs only) --

#[test]
fn a_text_pdf_yields_its_text() {
    let out = worker_extract(&text_pdf("Hello attachment", 1), 10, 1_000);
    assert!(out.contains("Hello attachment"), "got {out:?}");
}

#[test]
fn a_malformed_pdf_yields_empty_text_not_a_panic() {
    for bytes in [
        &b"%PDF-1.7\nnot really a pdf"[..],
        b"%PDF-",
        b"",
        &[0xff; 64],
    ] {
        assert_eq!(worker_extract(bytes, 10, 1_000), "");
    }
    // Cut off after the catalog: no page tree, no cross-reference table.
    let pdf = text_pdf("Hello", 1);
    assert_eq!(worker_extract(&pdf[..60], 10, 1_000), "");
}

#[test]
fn a_corrupt_flate_stream_yields_no_text() {
    let out = worker_extract(&flate_content_pdf(b"\x78\x9cnot deflate"), 10, 1_000);
    assert!(!out.contains("not deflate"));
}

#[test]
fn the_bomb_fixture_is_a_valid_zlib_stream() {
    // The real-binary test relies on this stream inflating as described; a
    // broken fixture would make "the worker yielded nothing" prove nothing.
    use std::io::Read as _;
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(&zlib_bomb(b"BT ET", 1_000)[..])
        .read_to_end(&mut out)
        .expect("valid zlib, checksum included");
    assert_eq!(out.len(), 5 + 1 + 258 * 1_000);
    assert!(out.starts_with(b"BT ET "));
    assert!(out[5..].iter().all(|&b| b == b' '));
}

#[test]
fn a_small_bomb_is_just_a_document() {
    let content = b"BT /F1 12 Tf 72 712 Td (Survived) Tj ET\n";
    let out = worker_extract(&flate_content_pdf(&zlib_bomb(content, 4_000)), 10, 1_000);
    assert!(out.contains("Survived"), "got {out:?}");
}

#[test]
fn too_many_pages_yields_empty_text() {
    let pdf = text_pdf("Hello", 4);
    assert!(worker_extract(&pdf, 4, 1_000).contains("Hello"));
    assert_eq!(worker_extract(&pdf, 3, 1_000), "");
}

#[test]
fn the_worker_stops_at_the_character_cap() {
    let pdf = text_pdf("abcdefghij", 20);
    let out = worker_extract(&pdf, 50, 25);
    assert_eq!(out.chars().count(), 25);
}

// --- The supervisor, driven with stand-in programs ---------------------------

const SH: &str = "/bin/sh";

fn fast() -> Limits {
    Limits {
        wall: Duration::from_secs(2),
        max_chars: 1_000,
        ..Limits::PRODUCTION
    }
}

fn sh(script: &str, input: &[u8], limits: &Limits) -> String {
    run_worker(Path::new(SH), &["-c", script], input, limits)
}

#[test]
fn a_framed_answer_is_the_text() {
    let script = format!("printf '{}hello'", frame_for_shell());
    assert_eq!(sh(&script, b"", &fast()), "hello");
}

#[test]
fn the_input_reaches_the_worker_on_stdin() {
    let script = format!("printf '{}'; /bin/cat", frame_for_shell());
    assert_eq!(sh(&script, b"pdf bytes", &fast()), "pdf bytes");
}

#[test]
fn an_unframed_answer_is_ignored() {
    // Anything that is not the worker (a different binary, a crash banner)
    // must never be read as extracted text.
    assert_eq!(sh("printf 'hello'", b"", &fast()), "");
}

#[test]
fn a_failed_worker_yields_empty_text() {
    let script = format!("printf '{}hello'; exit 3", frame_for_shell());
    assert_eq!(sh(&script, b"", &fast()), "");
}

#[test]
fn a_worker_past_its_deadline_is_killed() {
    let limits = Limits {
        wall: Duration::from_millis(300),
        ..fast()
    };
    let started = Instant::now();
    assert_eq!(sh("/bin/sleep 30", b"", &limits), "");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a_flooding_worker_is_cut_off() {
    // The host stops reading at the cap and closes the pipe, which ends the
    // worker long before its deadline: the answer is never buffered whole.
    // `yes` keeps constant memory, so nothing but the closed pipe stops it.
    let script = format!("printf '{}'; exec /usr/bin/yes aaaaaaaa", frame_for_shell());
    let limits = Limits {
        wall: Duration::from_secs(4),
        ..fast()
    };
    let started = Instant::now();
    assert_eq!(sh(&script, b"", &limits), "");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn the_worker_runs_under_resource_limits() {
    let script = format!(
        "printf '{}'; printf '%s %s %s %s' \"$(ulimit -d)\" \"$(ulimit -t)\" \"$(ulimit -f)\" \"$(ulimit -c)\"",
        frame_for_shell()
    );
    let limits = Limits::PRODUCTION;
    let expected = format!("{} {} 0 0", limits.data_bytes / 1024, limits.cpu_secs);
    assert_eq!(
        sh(
            &script,
            b"",
            &Limits {
                wall: Duration::from_secs(2),
                ..limits
            }
        ),
        expected
    );
}

#[test]
fn the_worker_gets_no_environment() {
    // The parent's environment carries credentials; a parser of untrusted
    // input never sees them. `cargo test` always exports PATH and CARGO*.
    let script = format!("printf '{}'; export -p", frame_for_shell());
    let limits = Limits {
        max_chars: 1_000_000,
        ..fast()
    };
    let out = sh(&script, b"", &limits);
    assert!(out.contains("export PWD="), "the shell answered: {out}");
    assert!(!out.contains("PATH="), "{out}");
    assert!(!out.contains("CARGO"), "{out}");
}

#[test]
fn a_missing_program_yields_empty_text() {
    let out = run_worker(Path::new("/nonexistent/greentic-start"), &[], b"x", &fast());
    assert_eq!(out, "");
}

#[test]
fn concurrent_workers_are_bounded() {
    let gate = Gate::new(2);
    let a = gate.acquire(Duration::from_millis(10)).expect("first slot");
    let _b = gate
        .acquire(Duration::from_millis(10))
        .expect("second slot");
    assert!(gate.acquire(Duration::from_millis(50)).is_none());
    drop(a);
    assert!(gate.acquire(Duration::from_millis(50)).is_some());
}

/// The frame as a `printf` format string (its newline written as `\n`).
fn frame_for_shell() -> String {
    String::from_utf8(FRAME.to_vec())
        .unwrap()
        .replace('\n', "\\n")
}
