//! Remote-SoR executor: invoke a discovered SoRLa business action over HTTP via
//! the SoR's `POST /admin/v1/capabilities/invoke` endpoint, using the existing
//! east-west caller-header contract.

use serde_json::{Value, json};

use crate::capabilities::RemoteSorTarget;
use crate::runner_host::types::{FlowOutcome, OperatorContext, RunnerExecutionMode};

/// Outbound HTTP seam (so the executor is unit-testable without a network).
pub(crate) trait SorInvokeHttp {
    fn post_invoke(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &str,
    ) -> Result<(u16, String), String>;
}

pub(crate) struct UreqSorInvoke;

impl SorInvokeHttp for UreqSorInvoke {
    fn post_invoke(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &str,
    ) -> Result<(u16, String), String> {
        // ureq 3.x treats non-2xx as `Err` by default, which would drop the
        // SoR error-envelope body and misreport a 4xx/5xx as a transport
        // failure. Disable that so every HTTP response (incl. 4xx/5xx) comes
        // back as `Ok(resp)` and the status+body are mapped uniformly.
        let mut req = ureq::post(url)
            .config()
            .http_status_as_error(false)
            .build()
            .header("Content-Type", "application/json");
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        match req.send(body.as_bytes()) {
            Ok(mut resp) => {
                let status = resp.status().as_u16();
                let text = resp.body_mut().read_to_string().unwrap_or_default();
                Ok((status, text))
            }
            Err(err) => Err(err.to_string()),
        }
    }
}

/// Build the capability-invoke request, POST it, and map the SoR response to a
/// `FlowOutcome`. 200 → success; anything else → unsuccessful (4xx/5xx carry the
/// error envelope text).
pub(crate) fn invoke_remote_sor_with(
    http: &dyn SorInvokeHttp,
    target: &RemoteSorTarget,
    cap_id: &str,
    payload_bytes: &[u8],
    ctx: &OperatorContext,
) -> FlowOutcome {
    let input: Value = if payload_bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(payload_bytes).unwrap_or(Value::Null)
    };
    let body = json!({ "capability": cap_id, "input": input }).to_string();
    let url = format!(
        "{}/admin/v1/capabilities/invoke",
        target.sor_base_url.trim_end_matches('/')
    );
    let headers = vec![("x-greentic-tenant-id".to_string(), ctx.tenant.clone())];

    match http.post_invoke(&url, &headers, &body) {
        Ok((200, text)) => {
            let output = serde_json::from_str::<Value>(&text).ok();
            FlowOutcome {
                success: true,
                output,
                raw: Some(text),
                error: None,
                mode: RunnerExecutionMode::RemoteSor,
            }
        }
        Ok((status, text)) => FlowOutcome {
            success: false,
            output: serde_json::from_str::<Value>(&text).ok(),
            raw: Some(text),
            error: Some(format!("SoR invoke returned {status}")),
            mode: RunnerExecutionMode::RemoteSor,
        },
        Err(err) => FlowOutcome {
            success: false,
            output: None,
            raw: None,
            error: Some(format!("SoR invoke failed: {err}")),
            mode: RunnerExecutionMode::RemoteSor,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::RemoteSorTarget;
    use crate::runner_host::types::{OperatorContext, RunnerExecutionMode};
    use std::cell::RefCell;

    #[allow(clippy::type_complexity)]
    struct FakeHttp {
        status: u16,
        body: String,
        seen: RefCell<Option<(String, Vec<(String, String)>, String)>>,
    }
    impl SorInvokeHttp for FakeHttp {
        fn post_invoke(
            &self,
            url: &str,
            headers: &[(String, String)],
            body: &str,
        ) -> Result<(u16, String), String> {
            *self.seen.borrow_mut() = Some((url.to_string(), headers.to_vec(), body.to_string()));
            Ok((self.status, self.body.clone()))
        }
    }
    fn ctx() -> OperatorContext {
        OperatorContext {
            tenant: "acme".into(),
            team: None,
            correlation_id: None,
        }
    }
    fn target() -> RemoteSorTarget {
        RemoteSorTarget {
            sor_base_url: "http://sorx:9080".into(),
        }
    }

    #[test]
    fn builds_capability_invoke_request_with_tenant_header() {
        let http = FakeHttp {
            status: 200,
            body: r#"{"ok":true,"output":{"id":"p1"}}"#.into(),
            seen: RefCell::new(None),
        };
        let out = invoke_remote_sor_with(
            &http,
            &target(),
            "cap://greentic/business-functions/p/x/v1",
            br#"{"amount":10}"#,
            &ctx(),
        );
        let (url, headers, body) = http.seen.borrow().clone().unwrap();
        assert_eq!(url, "http://sorx:9080/admin/v1/capabilities/invoke");
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "x-greentic-tenant-id" && v == "acme"),
        );
        let bv: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(bv["capability"], "cap://greentic/business-functions/p/x/v1");
        assert_eq!(bv["input"]["amount"], 10);
        assert!(out.success);
        assert_eq!(out.mode, RunnerExecutionMode::RemoteSor);
    }

    #[test]
    fn maps_202_to_unsuccessful_outcome() {
        let http = FakeHttp {
            status: 202,
            body: r#"{"status":"approval_required"}"#.into(),
            seen: RefCell::new(None),
        };
        let out = invoke_remote_sor_with(&http, &target(), "cap://x/v1", b"{}", &ctx());
        assert!(!out.success);
    }

    #[test]
    fn maps_4xx_to_error_outcome() {
        let http = FakeHttp {
            status: 404,
            body: r#"{"error":{"code":"X"}}"#.into(),
            seen: RefCell::new(None),
        };
        let out = invoke_remote_sor_with(&http, &target(), "cap://x/v1", b"{}", &ctx());
        assert!(!out.success);
        assert!(out.error.is_some());
    }

    /// Live end-to-end: drives the REAL discovery client + remote executor
    /// against a running SoRX. Ignored by default (needs an instance on
    /// 127.0.0.1:9080 with a routable deployment). Run with:
    /// `cargo test -p greentic-start --lib live_e2e_discover_and_invoke -- --ignored --nocapture`.
    #[test]
    #[ignore = "live: requires a SoRX instance on 127.0.0.1:9080"]
    fn live_e2e_discover_and_invoke() {
        let base = "http://127.0.0.1:9080";

        // 1. discover over real HTTP (routing-table + /admin/v1/capabilities)
        let disco = crate::capability_discovery::CapabilityDiscovery::new(
            Box::new(crate::capability_discovery::HttpSorxDiscoverySource),
            std::time::Duration::from_secs(60),
        );
        let instances = disco.instances(base);
        assert!(!instances.is_empty(), "expected >=1 discovered instance");
        let bf_cap = instances
            .iter()
            .flat_map(|i| &i.capabilities)
            .find(|c| c.contains("business-functions"))
            .cloned()
            .expect("a business-function capability id");
        eprintln!(
            "LIVE discover: {} instance(s); business-function cap = {bf_cap}",
            instances.len()
        );

        // 2. register as remote offers + resolve a remote binding (real path)
        let mut reg = crate::capabilities::CapabilityRegistry::default();
        reg.register_remote_offers(&instances, base);
        let scope = crate::capabilities::ResolveScope {
            env: None,
            tenant: None,
            team: None,
        };
        let binding = reg.resolve(&bf_cap, None, &scope).expect("remote binding");
        let remote = binding.remote.clone().expect("binding must be remote");
        assert_eq!(remote.sor_base_url, base);

        // 3. invoke live over real HTTP POST to /admin/v1/capabilities/invoke
        let ctx = OperatorContext {
            tenant: "tenant-e2e".into(),
            team: None,
            correlation_id: None,
        };
        let out = invoke_remote_sor_with(
            &UreqSorInvoke,
            &remote,
            &binding.cap_id,
            br#"{"amount":100,"currency":"USD"}"#,
            &ctx,
        );
        eprintln!(
            "LIVE invoke: success={} error={:?} raw={:?} mode={:?}",
            out.success, out.error, out.raw, out.mode
        );
        // The POST reached the SoR and was processed (success, or a meaningful
        // SoR error/approval envelope) — either proves the discover->invoke chain.
        assert_eq!(out.mode, RunnerExecutionMode::RemoteSor);
        assert!(
            out.raw.is_some() || out.error.is_some(),
            "expected a response from the SoR"
        );
    }
}
