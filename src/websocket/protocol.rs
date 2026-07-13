//! DirectLine streaming protocol — minimal frame builders.
//!
//! Per the BotFramework DirectLine 3.0 streaming spec, the server sends
//! `ActivitySet` JSON frames over the WebSocket: `{ activities: [...], watermark: "N" }`.

// These types are consumed by upcoming session/pump/upgrade modules in later tasks.
#![allow(dead_code)]

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct ActivitySet<'a> {
    pub activities: &'a [Value],
    pub watermark: String,
}

impl<'a> ActivitySet<'a> {
    pub fn new(activities: &'a [Value], next_watermark: u64) -> Self {
        Self {
            activities,
            watermark: next_watermark.to_string(),
        }
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

/// Error frame sent before close. Body is opaque to clients.
#[derive(Debug, Serialize)]
pub struct ErrorFrame<'a> {
    pub error: &'a str,
}

impl<'a> ErrorFrame<'a> {
    pub fn new(code: &'a str) -> Self {
        Self { error: code }
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn activity_set_serializes_with_watermark_string() {
        let activities = vec![json!({"type": "message", "text": "hello"})];
        let set = ActivitySet::new(&activities, 42);
        let s = set.to_json().unwrap();
        assert!(s.contains(r#""watermark":"42""#));
        assert!(s.contains(r#""text":"hello""#));
    }

    #[test]
    fn error_frame_serializes_code() {
        let frame = ErrorFrame::new("replay_too_large");
        let s = frame.to_json().unwrap();
        assert_eq!(s, r#"{"error":"replay_too_large"}"#);
    }
}
