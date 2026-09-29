use super::*;
use crate::typing::{SendTypingInV1, SendTypingOutV1};
use std::sync::Mutex;
use tokio::time::{Instant, sleep};

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

/// Paused-time tests launch each send with `tokio::spawn` (still off the turn's
/// task); the blocking-pool launcher inhibits paused-time auto-advance.
fn launch_task(sender: Arc<dyn TypingSender>, input: Arc<SendTypingInV1>) -> SendHandle {
    tokio::spawn(async move { sender.send_typing(&input).await })
}

async fn run<S: TypingSender, F: std::future::Future>(
    sender: &Arc<S>,
    input: SendTypingInV1,
    turn: F,
) -> F::Output {
    let sender: Arc<dyn TypingSender> = sender.clone();
    keep_typing_while_with(sender, input, turn, launch_task, STOP_GRACE).await
}

/// Records (start, end) of every call; each call takes `latency`.
struct Fake {
    refresh: Option<u64>,
    latency: Duration,
    ok: bool,
    calls: Mutex<Vec<(Instant, Instant)>>,
}

impl Fake {
    fn new(refresh: Option<u64>, latency: Duration) -> Self {
        Self {
            refresh,
            latency,
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
        sleep(self.latency).await;
        self.calls.lock().unwrap().push((start, Instant::now()));
        Ok(SendTypingOutV1 {
            v: 1,
            ok: self.ok,
            error: None,
            refresh_after_ms: self.refresh,
        })
    }
}

#[tokio::test(start_paused = true)]
async fn refreshes_every_3500ms_until_the_turn_ends() {
    let fake = Arc::new(Fake::new(Some(4000), Duration::ZERO));
    let t0 = Instant::now();
    let out = run(&fake, input(), async {
        sleep(Duration::from_secs(10)).await;
        7
    })
    .await;
    assert_eq!(out, 7, "turn output passes through untouched");
    let starts: Vec<_> = fake
        .calls()
        .iter()
        .map(|(s, _)| s.duration_since(t0))
        .collect();
    assert_eq!(
        starts,
        vec![
            Duration::ZERO,
            Duration::from_millis(3500),
            Duration::from_millis(7000)
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn no_send_starts_after_the_turn_and_in_flight_send_finishes_first() {
    // First call 0→1 s, next would start at 4.5 s; the turn ends at 4.0 s, so the stop
    // wins the sleep and only ONE call happens.
    let fake = Arc::new(Fake::new(Some(4000), Duration::from_secs(1)));
    let t0 = Instant::now();
    run(&fake, input(), sleep(Duration::from_secs(4))).await;
    let returned = Instant::now();
    let calls = fake.calls();
    assert_eq!(calls.len(), 1);
    assert!(calls.iter().all(|(_, end)| *end <= returned));
    assert_eq!(returned.duration_since(t0), Duration::from_secs(4));
}

#[tokio::test(start_paused = true)]
async fn an_in_flight_send_is_awaited_before_the_driver_returns() {
    // Latency 2 s, refresh 3.5 s: calls start at 0 and 5.5; the turn ends at 6.0,
    // mid-flight. The driver must return at 7.5 (end of that call), not 6.0.
    let fake = Arc::new(Fake::new(Some(4000), Duration::from_secs(2)));
    let t0 = Instant::now();
    run(&fake, input(), sleep(Duration::from_secs(6))).await;
    let calls = fake.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        Instant::now().duration_since(t0),
        Duration::from_millis(7500)
    );
    assert!(calls.iter().all(|(_, end)| *end <= Instant::now()));
}

#[tokio::test(start_paused = true)]
async fn a_hung_send_delays_the_reply_by_at_most_the_grace() {
    let fake = Arc::new(Fake::new(Some(4000), Duration::from_secs(600)));
    let t0 = Instant::now();
    run(&fake, input(), sleep(Duration::from_secs(1))).await;
    assert_eq!(
        Instant::now().duration_since(t0),
        Duration::from_secs(1) + STOP_GRACE
    );
}

#[tokio::test(start_paused = true)]
async fn hung_turn_stops_refreshing_at_the_cap() {
    let fake = Arc::new(Fake::new(Some(4000), Duration::ZERO));
    let t0 = Instant::now();
    run(&fake, input(), sleep(Duration::from_secs(600))).await;
    let starts: Vec<_> = fake
        .calls()
        .iter()
        .map(|(s, _)| s.duration_since(t0))
        .collect();
    assert_eq!(starts.len(), 35, "0, 3.5, …, 119.0");
    assert_eq!(*starts.last().unwrap(), Duration::from_millis(119_000));
}

#[tokio::test(start_paused = true)]
async fn a_failed_send_is_not_retried_and_the_turn_is_unaffected() {
    let mut fake = Fake::new(Some(4000), Duration::ZERO);
    fake.ok = false;
    let fake = Arc::new(fake);
    let out = run(&fake, input(), async {
        sleep(Duration::from_secs(10)).await;
        "reply"
    })
    .await;
    assert_eq!(out, "reply");
    assert_eq!(fake.calls().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn absent_refresh_sends_exactly_once() {
    let fake = Arc::new(Fake::new(None, Duration::ZERO));
    run(&fake, input(), sleep(Duration::from_secs(30))).await;
    assert_eq!(fake.calls().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn an_erroring_sender_never_fails_the_turn() {
    struct Boom;
    #[async_trait::async_trait]
    impl TypingSender for Boom {
        async fn send_typing(&self, _: &SendTypingInV1) -> anyhow::Result<SendTypingOutV1> {
            anyhow::bail!("op `send_typing` failed")
        }
    }
    assert_eq!(run(&Arc::new(Boom), input(), async { 3 }).await, 3);
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
        launch_on_blocking_pool,
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
