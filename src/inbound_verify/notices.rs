//! Operator lines for inbound verification, bounded so an unauthenticated
//! caller cannot turn them into a log flood:
//!
//! - "this channel is not configured to verify" is said ONCE per
//!   (deployment, channel) — it describes the deployment, not the request;
//! - a refusal or an unavailable key set is said at most once per
//!   [`RATE_WINDOW`] per (channel, reason) — anyone can send a bad signature.
//!
//! No line carries a header value, a token, a secret or a URI.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use greentic_deploy_spec::DeploymentId;

/// Above this many remembered (deployment, channel) pairs the set is cleared:
/// a warning may then be said twice, which is cheaper than unbounded memory.
const MAX_WARNED: usize = 4_096;

pub(crate) const RATE_WINDOW: Duration = Duration::from_secs(60);

type Sink = Box<dyn Fn(&str) + Send + Sync>;

pub(crate) struct Notices {
    warned: DashMap<(DeploymentId, &'static str), ()>,
    last_said: Mutex<HashMap<(&'static str, &'static str), Instant>>,
    sink: Sink,
}

impl Notices {
    fn new(sink: Sink) -> Self {
        Self {
            warned: DashMap::new(),
            last_said: Mutex::new(HashMap::new()),
            sink,
        }
    }

    /// The process-wide instance, writing to the operator log.
    pub(crate) fn production() -> &'static Notices {
        static NOTICES: LazyLock<Notices> = LazyLock::new(|| {
            Notices::new(Box::new(|line| {
                crate::operator_log::warn(module_path!(), line);
            }))
        });
        &NOTICES
    }

    /// An instance recording what it would say.
    #[cfg(test)]
    pub(crate) fn recording() -> (Notices, std::sync::Arc<Mutex<Vec<String>>>) {
        use std::sync::Arc;
        let said = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&said);
        let notices = Notices::new(Box::new(move |line| {
            if let Ok(mut said) = sink.lock() {
                said.push(line.to_string());
            }
        }));
        (notices, said)
    }

    /// Says `line` the first time `(deployment, channel)` reports it.
    pub(crate) fn once(&self, deployment: DeploymentId, channel: &'static str, line: &str) {
        if self.warned.len() >= MAX_WARNED {
            self.warned.clear();
        }
        if self.warned.insert((deployment, channel), ()).is_none() {
            (self.sink)(line);
        }
    }

    /// Says `line` unless `(channel, reason)` was said within [`RATE_WINDOW`].
    pub(crate) fn limited(&self, channel: &'static str, reason: &'static str, line: &str) {
        let now = Instant::now();
        let say = match self.last_said.lock() {
            Ok(mut last) => match last.get(&(channel, reason)) {
                Some(at) if now.duration_since(*at) < RATE_WINDOW => false,
                _ => {
                    last.insert((channel, reason), now);
                    true
                }
            },
            // A poisoned lock only costs the rate bound, never the line.
            Err(_) => true,
        };
        if say {
            (self.sink)(line);
        }
    }
}
