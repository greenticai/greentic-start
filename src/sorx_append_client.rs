#![allow(dead_code)]

//! Thin blocking HTTP client for the SoRX external append ingress
//! (`POST /v1/sorx/events`). Best-effort: append failures are surfaced to the
//! caller, which logs and continues (routing must not depend on SoRX).

use anyhow::Context;
use greentic_types::EventEnvelope;

pub struct SorxAppendClient {
    base_url: String,
    secret: Option<String>,
    http: reqwest::blocking::Client,
}

impl SorxAppendClient {
    pub fn new(base_url: String, secret: Option<String>) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            secret,
            http: reqwest::blocking::Client::new(),
        }
    }

    pub(crate) fn events_url(&self) -> String {
        format!("{}/v1/sorx/events", self.base_url)
    }

    /// Append a fired business event to SoRX. Returns an error on non-2xx or
    /// transport failure; the caller decides whether that is fatal (it is not).
    pub fn append(&self, tenant_id: &str, event: &EventEnvelope) -> anyhow::Result<()> {
        let mut req = self
            .http
            .post(self.events_url())
            .header("x-greentic-tenant-id", tenant_id)
            .header("x-greentic-caller-id", "greentic-start-scheduler")
            .header("x-greentic-caller-role", "system")
            .json(event);
        if let Some(secret) = &self.secret {
            req = req.header("x-greentic-sorx-secret", secret);
        }
        let resp = req.send().context("POST /v1/sorx/events")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            anyhow::bail!("sorx append failed: {status} {body}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_events_endpoint_url() {
        let client = SorxAppendClient::new("https://sorx.example".into(), None);
        assert_eq!(client.events_url(), "https://sorx.example/v1/sorx/events");
    }

    #[test]
    fn trims_trailing_slash_in_base_url() {
        let client = SorxAppendClient::new("https://sorx.example/".into(), None);
        assert_eq!(client.events_url(), "https://sorx.example/v1/sorx/events");
    }
}
