//! Threshold watcher: polls a metric and fires a flow when it crosses a
//! configured threshold.
//!
//! This module mirrors the shape of `crate::timer_scheduler` (background
//! poll loop, `route_events` delivery, discover -> start -> stop wiring on
//! `crate::runtime`). [`eval`] holds the pure evaluation logic (`side`,
//! `crossing`), [`config`] the bundle-declared watch list, [`state`] the
//! durable per-watch edge state, [`fetch`] the metric HTTP fetch, and
//! [`watcher`] the poll loop + `ThresholdWatcher` handle that ties them all
//! together and is wired into `crate::runtime`.

pub mod config;
pub mod eval;
pub mod fetch;
pub mod state;
pub mod watcher;

pub use watcher::{ThresholdWatcher, ThresholdWatcherConfig};
