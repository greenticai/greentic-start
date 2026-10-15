//! A tiny loopback HTTP server standing in for api.typesafe.ai in tests.
//! One canned answer for every request; each request is recorded.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub(super) struct Recorded {
    pub(super) request_line: String,
    pub(super) authorization: Option<String>,
    pub(super) body: String,
}

pub(super) struct MockJev {
    pub(super) endpoint: String,
    pub(super) seen: Arc<Mutex<Vec<Recorded>>>,
}

impl MockJev {
    /// Answer every request with `status` and `body` after `delay`.
    pub(super) fn start(status: u16, body: &'static str, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let endpoint = format!(
            "http://{}/v1/systemone",
            listener.local_addr().expect("addr")
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let log = Arc::clone(&log);
                thread::spawn(move || {
                    let Some(recorded) = read_request(&mut stream) else {
                        return;
                    };
                    log.lock().expect("log").push(recorded);
                    thread::sleep(delay);
                    let reply = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(reply.as_bytes());
                });
            }
        });
        Self { endpoint, seen }
    }

    pub(super) fn requests(&self) -> Vec<Recorded> {
        self.seen.lock().expect("log").clone()
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<Recorded> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let (head_end, content_length) = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (pos + 4, len);
        }
    };
    while buf.len() < head_end + content_length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let authorization = head.lines().find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.eq_ignore_ascii_case("authorization")
            .then(|| value.trim().to_string())
    });
    Some(Recorded {
        request_line: head.lines().next().unwrap_or_default().to_string(),
        authorization,
        body: String::from_utf8_lossy(&buf[head_end..]).to_string(),
    })
}
