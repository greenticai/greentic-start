//! Outbound WebSocket tunnel agent — the private-side half of the Greentic
//! self-hosted tunnel (a Rust port of the reference `agent.mjs`).
//!
//! Dials the Greentic Worker tunnel over WebSocket, replays each forwarded HTTP
//! request to the local origin, and streams the response back on the same
//! socket. Runs as the hidden `__tunnel-agent` subcommand, spawned and
//! supervised by [`crate::gtunnel::start_agent`]. Reconnects with backoff so a
//! transient Worker/edge blip does not strand the tunnel.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// Heartbeat cadence — must stay under the Worker's stale-eviction window (60s).
const PING: Duration = Duration::from_secs(25);
/// Reconnect backoff: starts here, doubles up to the cap, resets on a live connect.
const RECONNECT_MIN: Duration = Duration::from_secs(2);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// Liveness: if no frame arrives from the Worker for this long (~3 missed
/// heartbeat pongs), the socket is treated as dead even without a close frame,
/// and the agent force-reconnects. Guards against half-open connections.
const STALE_AFTER: Duration = Duration::from_secs(75);
/// How often the watchdog checks for staleness.
const WATCHDOG_TICK: Duration = Duration::from_secs(15);
/// Request headers we never forward to the origin.
const DROP_HEADERS: [&str; 5] = [
    "host",
    "content-length",
    "connection",
    "cf-connecting-ip",
    "cf-ray",
];

/// Everything the agent needs to run one tunnel.
pub struct AgentConfig {
    /// Full registration URL, e.g. `wss://host/<tunnelId>/_tunnel`.
    pub edge_url: String,
    pub secret: String,
    /// Local origin base, e.g. `http://127.0.0.1:8080`.
    pub target: String,
}

/// Run the agent forever, reconnecting on failure. Returns only on
/// unrecoverable setup errors (e.g. the runtime cannot be built).
pub fn run(config: AgentConfig) -> Result<()> {
    // Both ring and aws-lc-rs are in the dependency tree, so rustls 0.23 cannot
    // auto-select a process CryptoProvider for the wss:// handshake — install one.
    // Err just means another component already installed it; either is fine.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Build the blocking HTTP client OUTSIDE the async runtime — it owns its own
    // background runtime and constructing it inside tokio can wedge.
    let client = reqwest::blocking::Client::builder()
        .build()
        .context("build tunnel-agent http client")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tunnel-agent runtime")?;
    runtime.block_on(run_loop(config, client));
    Ok(())
}

async fn run_loop(config: AgentConfig, client: reqwest::blocking::Client) {
    let mut backoff = RECONNECT_MIN;
    loop {
        match connect_once(&config, &client).await {
            // Connected (then dropped/stale): a live tunnel flapped — reset backoff.
            Ok(()) => backoff = RECONNECT_MIN,
            // Never connected: back off so a down Worker isn't hammered.
            Err(err) => {
                eprintln!("[tunnel] {err:#}");
                backoff = (backoff * 2).min(RECONNECT_MAX);
            }
        }
        eprintln!("[tunnel] down, retry in {}s", backoff.as_secs());
        tokio::time::sleep(backoff).await;
    }
}

async fn connect_once(config: &AgentConfig, client: &reqwest::blocking::Client) -> Result<()> {
    let mut request = config
        .edge_url
        .as_str()
        .into_client_request()
        .context("build websocket request")?;
    request.headers_mut().insert(
        "x-tunnel-secret",
        config.secret.parse().context("invalid secret header")?,
    );

    let (ws, _resp) = connect_async(request)
        .await
        .with_context(|| format!("connect {}", config.edge_url))?;
    eprintln!("[tunnel] up  {} -> {}", config.edge_url, config.target);

    let (mut write, mut read) = ws.split();
    // One writer task owns the sink; the read loop and the heartbeat both send
    // frames to it over a channel so neither has to hold the sink.
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if write.send(msg).await.is_err() {
                break;
            }
        }
    });

    let hb_tx = tx.clone();
    let heartbeat = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PING);
        ticker.tick().await; // consume the immediate first tick
        loop {
            ticker.tick().await;
            if hb_tx.send(ping()).is_err() {
                break;
            }
        }
    });

    // Liveness: pump stamps `last_seen` on every frame; the watchdog forces a
    // reconnect if the Worker goes silent (half-open socket with no close frame).
    let last_seen = Arc::new(Mutex::new(Instant::now()));
    let watchdog_seen = last_seen.clone();
    let watchdog = async move {
        let mut ticker = tokio::time::interval(WATCHDOG_TICK);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if watchdog_seen.lock().expect("last_seen lock").elapsed() > STALE_AFTER {
                return;
            }
        }
    };

    let result = tokio::select! {
        r = pump(&mut read, &tx, client, &config.target, &last_seen) => r,
        _ = watchdog => {
            eprintln!(
                "[tunnel] no frames from Worker for {}s — reconnecting",
                STALE_AFTER.as_secs()
            );
            Ok(())
        }
    };

    heartbeat.abort();
    writer.abort();
    result
}

/// One frame off the websocket read half.
type WsFrame = Result<Message, tokio_tungstenite::tungstenite::Error>;

/// An origin reply, ready to serialize back to the Worker: (status, headers, body).
type OriginResponse = (u16, Vec<(String, String)>, Vec<u8>);

/// Read forwarded requests until the socket closes, replaying each to the origin.
async fn pump<S>(
    read: &mut S,
    tx: &mpsc::UnboundedSender<Message>,
    client: &reqwest::blocking::Client,
    target: &str,
    last_seen: &Arc<Mutex<Instant>>,
) -> Result<()>
where
    S: StreamExt<Item = WsFrame> + Unpin,
{
    while let Some(msg) = read.next().await {
        // Any frame (request or heartbeat pong) proves the socket is alive.
        *last_seen.lock().expect("last_seen lock") = Instant::now();
        let text = match msg.context("read frame")? {
            Message::Text(t) => t.as_str().to_owned(),
            Message::Close(_) => break,
            _ => continue,
        };
        let req: Value = serde_json::from_str(&text).context("parse frame")?;
        if req.get("t").and_then(Value::as_str) == Some("pong") {
            continue; // heartbeat ack
        }
        let out_tx = tx.clone();
        let client = client.clone();
        let target = target.to_owned();
        // Replay to the origin off the reactor (blocking reqwest on a blocking thread).
        tokio::task::spawn_blocking(move || {
            let reply = replay(&client, &target, &req);
            let _ = out_tx.send(text_frame(reply.to_string()));
        });
    }
    Ok(())
}

/// Replay one forwarded request to the local origin and build the reply frame.
fn replay(client: &reqwest::blocking::Client, target: &str, req: &Value) -> Value {
    let id = req.get("id").and_then(Value::as_str).unwrap_or("");
    let method = req.get("method").and_then(Value::as_str).unwrap_or("GET");
    let path = req.get("path").and_then(Value::as_str).unwrap_or("/");
    let body_b64 = req.get("body").and_then(Value::as_str).unwrap_or("");

    let result = (|| -> Result<OriginResponse> {
        let method = reqwest::Method::from_bytes(method.as_bytes())?;
        let url = format!("{}{}", target.trim_end_matches('/'), path);
        let mut builder = client.request(method, &url);
        if let Some(arr) = req.get("headers").and_then(Value::as_array) {
            for pair in arr {
                let (Some(k), Some(v)) = (
                    pair.get(0).and_then(Value::as_str),
                    pair.get(1).and_then(Value::as_str),
                ) else {
                    continue;
                };
                if !DROP_HEADERS.contains(&k.to_ascii_lowercase().as_str()) {
                    builder = builder.header(k, v);
                }
            }
        }
        if !body_b64.is_empty() {
            builder = builder.body(B64.decode(body_b64).context("decode body")?);
        }
        let resp = builder.send().context("origin request")?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
            .collect();
        let bytes = resp.bytes().context("read origin body")?.to_vec();
        Ok((status, headers, bytes))
    })();

    match result {
        Ok((status, headers, body)) => json!({
            "id": id,
            "status": status,
            "headers": headers,
            "body": B64.encode(body),
        }),
        Err(err) => {
            eprintln!("[tunnel] target error: {err:#}");
            json!({
                "id": id,
                "status": 502,
                "headers": [],
                "body": B64.encode(format!("tunnel agent: {err}").into_bytes()),
            })
        }
    }
}

fn ping() -> Message {
    text_frame(json!({ "t": "ping" }).to_string())
}

fn text_frame(s: String) -> Message {
    Message::Text(s.into())
}
