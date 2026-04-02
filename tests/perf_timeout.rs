use std::time::{Duration, Instant};

use greentic_start::perf_harness;

#[test]
fn discovery_workload_finishes_quickly() {
    let fixture = perf_harness::create_discovery_fixture(64).expect("fixture");
    let start = Instant::now();

    let discovered = perf_harness::run_discovery(&fixture, true).expect("discover");
    let elapsed = start.elapsed();

    assert_eq!(discovered, 64);
    assert!(
        elapsed < Duration::from_secs(2),
        "discovery workload too slow: {elapsed:?}"
    );
}
