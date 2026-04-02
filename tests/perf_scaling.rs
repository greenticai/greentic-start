use std::sync::Arc;
use std::time::{Duration, Instant};

use greentic_start::perf_harness;

fn run_workload(threads: usize, rounds_per_thread: usize) -> Duration {
    let source = Arc::new(perf_harness::make_gmap_source(2048));
    let start = Instant::now();

    let handles: Vec<_> = (0..threads)
        .map(|thread_idx| {
            let source = Arc::clone(&source);
            std::thread::spawn(move || {
                for _ in 0..rounds_per_thread {
                    let matched = perf_harness::run_gmap_eval(&source, 2047 - (thread_idx % 64))
                        .expect("eval");
                    assert!(matched);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("join worker");
    }

    start.elapsed()
}

#[test]
fn gmap_eval_scales_without_major_regression() {
    let t1 = run_workload(1, 24);
    let t4 = run_workload(4, 24);
    let t8 = run_workload(8, 24);

    assert!(
        t4 <= t1.mul_f64(8.0),
        "4 threads regressed too far: t1={t1:?}, t4={t4:?}"
    );
    assert!(
        t8 <= t4.mul_f64(3.0),
        "8 threads regressed too far: t4={t4:?}, t8={t8:?}"
    );
}
