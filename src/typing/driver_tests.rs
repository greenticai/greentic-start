use super::*;
use crate::typing::{SendTypingInV1, SendTypingOutV1};
use std::sync::Mutex;
use std::time::Instant;

fn input() -> SendTypingInV1 {
    SendTypingInV1 {
        v: 1,
        provider_type: "p".into(),
        tenant_id: "acme".into(),
        tenant: crate::messaging_dto::TenantHint {
            tenant: "acme".into(),
            team: None,
            user: None,
            correlation_id: None,
        },
        message: serde_json::json!({"session_id": "s"}),
        config: None,
    }
}

/// Async sender that records (start, end) of every call; each call BLOCKS its thread
/// for `latency`, like the real deployed provider call. Real clock throughout: the
/// loop runs on its own thread with std timers.
struct Fake {
    refresh: Option<u64>,
    latency: Duration,
    ok: bool,
    calls: Mutex<Vec<(Instant, Instant)>>,
}

impl Fake {
    fn new(refresh: Option<u64>, latency_ms: u64) -> Self {
        Self {
            refresh,
            latency: Duration::from_millis(latency_ms),
            ok: true,
            calls: Mutex::new(Vec::new()),
        }
    }
    fn calls(&self) -> Vec<(Instant, Instant)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl TypingSender for Fake {
    async fn send_typing(&self, _: &SendTypingInV1) -> anyhow::Result<SendTypingOutV1> {
        let start = Instant::now();
        std::thread::sleep(self.latency);
        self.calls.lock().unwrap().push((start, Instant::now()));
        Ok(SendTypingOutV1 {
            v: 1,
            ok: self.ok,
            error: None,
            refresh_after_ms: self.refresh,
        })
    }
}

async fn run<F: std::future::Future>(fake: &Arc<Fake>, turn: F) -> F::Output {
    let sender: Arc<dyn TypingSender> = fake.clone();
    keep_typing_while(sender, input(), turn).await
}

fn ms(v: u64) -> Duration {
    Duration::from_millis(v)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refreshes_on_the_clamped_interval_until_the_turn_ends() {
    // refresh_after_ms 1500 -> interval 1000 ms; a 2.5 s turn sees sends at ~0, 1, 2 s.
    let fake = Arc::new(Fake::new(Some(1500), 0));
    let t0 = Instant::now();
    let out = run(&fake, async {
        tokio::time::sleep(ms(2500)).await;
        7
    })
    .await;
    let returned = Instant::now();
    assert_eq!(out, 7, "turn output passes through untouched");
    let calls = fake.calls();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert!(calls.iter().all(|(_, end)| *end <= returned));
    let second = calls[1].0.duration_since(t0);
    assert!(second >= ms(950) && second < ms(1500), "{second:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_in_flight_send_is_awaited_before_the_driver_returns() {
    // The send takes 400 ms; the turn ends at 100 ms, mid-flight.
    let fake = Arc::new(Fake::new(Some(4000), 400));
    let t0 = Instant::now();
    run(&fake, tokio::time::sleep(ms(100))).await;
    let returned = Instant::now();
    let calls = fake.calls();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].1 <= returned, "the reply must not race the send");
    assert!(returned.duration_since(t0) < ms(1500));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_send_is_not_retried_and_the_turn_is_unaffected() {
    let mut fake = Fake::new(Some(1500), 0);
    fake.ok = false;
    let fake = Arc::new(fake);
    let out = run(&fake, async {
        tokio::time::sleep(ms(1500)).await;
        "reply"
    })
    .await;
    assert_eq!(out, "reply");
    assert_eq!(fake.calls().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_refresh_sends_exactly_once() {
    let fake = Arc::new(Fake::new(None, 0));
    run(&fake, tokio::time::sleep(ms(1500))).await;
    assert_eq!(fake.calls().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_erroring_sender_never_fails_the_turn() {
    struct Boom;
    #[async_trait::async_trait]
    impl TypingSender for Boom {
        async fn send_typing(&self, _: &SendTypingInV1) -> anyhow::Result<SendTypingOutV1> {
            anyhow::bail!("op `send_typing` failed")
        }
    }
    assert_eq!(
        keep_typing_while(Arc::new(Boom), input(), async { 3 }).await,
        3
    );
}

/// The deployed provider call blocks its thread (a synchronous join inside one
/// poll). With the production launcher the send runs on the blocking pool, so the
/// turn is never held behind it and the grace bounds the reply.
#[test]
fn a_thread_blocking_send_neither_starves_the_turn_nor_outlives_the_grace() {
    struct Blocks;
    #[async_trait::async_trait]
    impl TypingSender for Blocks {
        async fn send_typing(&self, _: &SendTypingInV1) -> anyhow::Result<SendTypingOutV1> {
            std::thread::sleep(std::time::Duration::from_secs(10));
            anyhow::bail!("unreachable within the test")
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let grace = std::time::Duration::from_millis(500);
    let turn = std::time::Duration::from_millis(300);
    let started = std::time::Instant::now();
    let out = rt.block_on(keep_typing_while_with(
        Arc::new(Blocks),
        input(),
        async move {
            tokio::time::sleep(turn).await;
            "reply"
        },
        grace,
    ));
    let waited = started.elapsed();
    // Do not wait for the abandoned 10 s blocking send.
    rt.shutdown_background();
    assert_eq!(out, "reply");
    assert!(waited >= turn, "{waited:?}");
    assert!(
        waited < std::time::Duration::from_secs(3),
        "a thread-blocking send must not hold the reply past the grace: {waited:?}"
    );
}

// ---- blocking driver (real clock, small durations) ----

struct BlockingFake {
    latency: std::time::Duration,
    log: Arc<Mutex<Vec<&'static str>>>,
}

impl BlockingTypingSender for BlockingFake {
    fn send_typing(&self, _: &SendTypingInV1) -> anyhow::Result<SendTypingOutV1> {
        std::thread::sleep(self.latency);
        self.log.lock().unwrap().push("typing-done");
        Ok(SendTypingOutV1 {
            v: 1,
            ok: true,
            error: None,
            refresh_after_ms: Some(4000),
        })
    }
}

fn blocking_fake(latency_ms: u64) -> (Arc<BlockingFake>, Arc<Mutex<Vec<&'static str>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let fake = Arc::new(BlockingFake {
        latency: std::time::Duration::from_millis(latency_ms),
        log: log.clone(),
    });
    (fake, log)
}

#[test]
fn blocking_waits_for_in_flight_send_before_returning() {
    let (fake, log) = blocking_fake(200);
    let turn_log = log.clone();
    let out = keep_typing_blocking(fake, input(), move || {
        std::thread::sleep(std::time::Duration::from_millis(50));
        turn_log.lock().unwrap().push("turn-done");
        42
    });
    log.lock().unwrap().push("egress");
    assert_eq!(out, 42);
    assert_eq!(
        *log.lock().unwrap(),
        vec!["turn-done", "typing-done", "egress"]
    );
}

#[test]
fn blocking_stops_without_waiting_out_the_refresh_interval() {
    let (fake, log) = blocking_fake(0);
    let started = std::time::Instant::now();
    keep_typing_blocking(fake, input(), || {
        std::thread::sleep(std::time::Duration::from_millis(50))
    });
    assert!(
        started.elapsed() < std::time::Duration::from_millis(1000),
        "stop wakes recv_timeout"
    );
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[test]
fn blocking_hung_send_delays_the_reply_by_at_most_the_grace() {
    // The provider call hangs far past the grace; the turn ends 50 ms in, mid-call. The
    // driver must abandon the call after the grace instead of joining it (plan risk R3).
    let (fake, log) = blocking_fake(5_000);
    let grace = std::time::Duration::from_millis(150);
    let started = std::time::Instant::now();
    let turn = std::time::Duration::from_millis(50);
    let out = keep_typing_blocking_with_grace(
        fake,
        input(),
        || {
            std::thread::sleep(turn);
            "reply"
        },
        grace,
    );
    let waited = started.elapsed();
    assert_eq!(out, "reply");
    assert!(
        waited >= turn + grace,
        "the in-flight send gets the grace: {waited:?}"
    );
    assert!(
        waited < std::time::Duration::from_millis(1500),
        "a hung send must not hold the reply: {waited:?}"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "the hung call is still in flight"
    );
}

/// Regression (e2e on the released binary): the deployed turn future runs sync WASM
/// on a joined thread, so it blocks its task inside ONE poll. The refresh must not
/// share that task, or it never fires until the turn is over.
#[test]
fn a_turn_that_blocks_its_thread_still_gets_refreshed() {
    struct Counts(Mutex<Vec<std::time::Instant>>);
    #[async_trait::async_trait]
    impl TypingSender for Counts {
        async fn send_typing(&self, _: &SendTypingInV1) -> anyhow::Result<SendTypingOutV1> {
            self.0.lock().unwrap().push(std::time::Instant::now());
            Ok(SendTypingOutV1 {
                v: 1,
                ok: true,
                error: None,
                refresh_after_ms: Some(1500), // interval = 1000 ms
            })
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let sender = Arc::new(Counts(Mutex::new(Vec::new())));
    let returned = rt.block_on(keep_typing_while(sender.clone(), input(), async {
        std::thread::sleep(std::time::Duration::from_secs(4));
        std::time::Instant::now()
    }));
    rt.shutdown_background();
    let before = sender
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|t| **t <= returned)
        .count();
    assert!(
        before >= 3,
        "expected sends at ~0, 1, 2, 3 s during a 4 s thread-blocking turn; got {before}"
    );
}
