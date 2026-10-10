//! A hard ceiling for tests whose subject is a timeout: if the code under test
//! stops bounding the wait (a mutant without its timeout), the test FAILS in
//! seconds instead of hanging the run.

use std::future::Future;
use std::time::Duration;

/// How long a bounded-wait test may take before it counts as hanging.
pub(crate) const CEILING: Duration = Duration::from_secs(10);

pub(crate) async fn within_ceiling<F: Future>(work: F) -> F::Output {
    tokio::time::timeout(CEILING, work)
        .await
        .expect("the operation was not bounded: it outlived the test ceiling")
}
