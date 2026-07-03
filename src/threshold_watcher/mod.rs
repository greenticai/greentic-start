//! Threshold watcher: polls a metric and fires a flow when it crosses a
//! configured threshold.
//!
//! This module mirrors the shape of `crate::timer_scheduler` (background
//! poll loop, `route_events` delivery, discover -> start -> stop wiring on
//! `runtime.rs`). Task 1 lands only the pure evaluation logic (`eval`);
//! config, durable state, HTTP fetch, and the loop + wiring land in later
//! tasks.
// Items are wired up incrementally across the slice's tasks; the loop + the
// `runtime.rs` registration (final task) consume everything. Remove once wired.
#![allow(dead_code)]

pub mod eval;
