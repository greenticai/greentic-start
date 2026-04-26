//! DirectLine WebSocket streaming endpoint.

pub mod protocol;
pub mod session;

// Re-exports consumed by upcoming upgrade/pump modules in later tasks (Task 11+).
#[allow(unused_imports)]
pub use session::{SessionError, SessionGuard, SessionManager, WsLimits};
