//! The isolated PDF text worker, driven through the real `greentic-start`
//! binary: what the unit tests cannot show is that a hostile PDF is contained
//! by the worker's resource limits instead of taking the host down.

#![cfg(target_os = "linux")]

use std::path::Path;
use std::time::{Duration, Instant};

use greentic_start::artifacts_test_support::pdf_text_via;

#[allow(dead_code)]
#[path = "../src/artifacts/pdf_fixture.rs"]
mod pdf_fixture;

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_greentic-start"))
}

#[test]
fn the_real_worker_extracts_text() {
    let text = pdf_text_via(binary(), &pdf_fixture::text_pdf("Hello attachment", 2));
    assert!(text.contains("Hello attachment"), "got {text:?}");
}

#[test]
fn a_malformed_pdf_yields_empty_text() {
    assert_eq!(pdf_text_via(binary(), b"%PDF-1.7\nnot really a pdf"), "");
}

const SURVIVED: &[u8] = b"BT /F1 12 Tf 72 712 Td (Survived) Tj ET\n";

#[test]
fn a_small_inflating_pdf_is_read_by_the_real_worker() {
    // Control for the bomb below: the same construction, inflating to 1 MiB,
    // is an ordinary document whose text comes back.
    let pdf = pdf_fixture::flate_content_pdf(&pdf_fixture::zlib_bomb(SURVIVED, 4_000));
    assert!(pdf_text_via(binary(), &pdf).contains("Survived"));
}

#[test]
fn a_decompression_bomb_is_contained_by_the_worker() {
    // ~6.5 MiB of PDF inflating to ~1 GiB, past the worker's 768 MiB data
    // limit: the worker dies before it gets to the text, the host gets an
    // empty text, promptly, and keeps running.
    let bomb = pdf_fixture::zlib_bomb(SURVIVED, 4_200_000);
    assert!(bomb.len() < 10 * 1024 * 1024);
    let pdf = pdf_fixture::flate_content_pdf(&bomb);
    let started = Instant::now();
    assert_eq!(pdf_text_via(binary(), &pdf), "");
    assert!(
        started.elapsed() < Duration::from_secs(35),
        "took {:?}",
        started.elapsed()
    );
}
