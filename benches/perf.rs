use criterion::{Criterion, criterion_group, criterion_main};
use greentic_start::perf_harness;

fn bench_discovery(c: &mut Criterion) {
    let fixture = perf_harness::create_discovery_fixture(128).expect("discovery fixture");
    c.bench_function("discovery/cbor_only_128_packs", |b| {
        b.iter(|| {
            let discovered = perf_harness::run_discovery(&fixture, true).expect("discover");
            assert_eq!(discovered, 128);
        })
    });
}

fn bench_gmap_parse(c: &mut Criterion) {
    let source = perf_harness::make_gmap_source(2048);
    c.bench_function("gmap/parse_2048_rules", |b| {
        b.iter(|| {
            let parsed = perf_harness::run_gmap_parse(&source).expect("parse");
            assert_eq!(parsed, 2049);
        })
    });
}

fn bench_gmap_eval(c: &mut Criterion) {
    let source = perf_harness::make_gmap_source(2048);
    c.bench_function("gmap/eval_2048_rules", |b| {
        b.iter(|| {
            let matched = perf_harness::run_gmap_eval(&source, 2047).expect("eval");
            assert!(matched);
        })
    });
}

criterion_group!(benches, bench_discovery, bench_gmap_parse, bench_gmap_eval);
criterion_main!(benches);
