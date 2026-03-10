use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value as JsonValue;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchTarget {
    pub tenant: String,
    pub team: Option<String>,
    pub pack: String,
    pub flow: Option<String>,
    pub node: Option<String>,
}

#[derive(Clone, Debug)]
pub struct IngressReply {
    pub text: Option<String>,
    pub card_cbor: Option<JsonValue>,
    pub status_code: Option<u16>,
    pub reason_code: Option<String>,
}

#[derive(Clone, Debug)]
pub enum ControlDirective {
    Continue,
    Dispatch { target: DispatchTarget },
    Respond { reply: IngressReply },
    Deny { reply: IngressReply },
}

pub fn try_parse_control_directive(output: &JsonValue) -> Option<ControlDirective> {
    let decoded = decode_directive_json(output).unwrap_or_else(|| output.clone());
    let action = decoded
        .get("action")
        .and_then(JsonValue::as_str)
        .map(|value| value.trim().to_ascii_lowercase())?;
    match action.as_str() {
        "continue" => Some(ControlDirective::Continue),
        "dispatch" => parse_dispatch(decoded.get("target"))
            .map(|target| ControlDirective::Dispatch { target }),
        "respond" => Some(ControlDirective::Respond {
            reply: parse_reply(&decoded, false),
        }),
        "deny" => Some(ControlDirective::Deny {
            reply: parse_reply(&decoded, true),
        }),
        _ => None,
    }
}

fn decode_directive_json(output: &JsonValue) -> Option<JsonValue> {
    let object = output.as_object()?;
    for key in [
        "hook_decision_cbor_b64",
        "cbor_b64",
        "hook_decision_cbor",
        "result_cbor_b64",
    ] {
        let Some(raw) = object.get(key).and_then(JsonValue::as_str) else {
            continue;
        };
        let Ok(bytes) = STANDARD.decode(raw) else {
            continue;
        };
        if let Ok(value) = serde_cbor::from_slice::<JsonValue>(&bytes) {
            return Some(value);
        }
    }
    None
}

fn parse_dispatch(raw: Option<&JsonValue>) -> Option<DispatchTarget> {
    let raw = raw?;
    if let Some(target) = raw.as_str() {
        return parse_dispatch_target_string(target);
    }
    let map = raw.as_object()?;
    let tenant = map.get("tenant")?.as_str()?.trim().to_string();
    let team = map
        .get("team")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let pack = map.get("pack")?.as_str()?.trim().to_string();
    let flow = map
        .get("flow")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let node = map
        .get("node")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    if tenant.is_empty() || pack.is_empty() {
        return None;
    }
    Some(DispatchTarget {
        tenant,
        team,
        pack,
        flow,
        node,
    })
}

fn parse_dispatch_target_string(raw: &str) -> Option<DispatchTarget> {
    let segments = raw
        .split('/')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if segments.len() < 3 || segments.len() > 5 {
        return None;
    }
    let tenant = segments[0].to_string();
    let team = Some(segments[1].to_string()).filter(|value| !value.is_empty());
    let pack = segments[2].to_string();
    if tenant.is_empty() || pack.is_empty() {
        return None;
    }
    Some(DispatchTarget {
        tenant,
        team,
        pack,
        flow: segments.get(3).map(|value| value.to_string()),
        node: segments.get(4).map(|value| value.to_string()),
    })
}

fn parse_reply(decoded: &JsonValue, deny: bool) -> IngressReply {
    let text = decoded
        .get("response_text")
        .and_then(JsonValue::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            if deny {
                decoded
                    .get("reason")
                    .and_then(|value| value.get("text"))
                    .and_then(JsonValue::as_str)
                    .map(ToString::to_string)
            } else {
                None
            }
        });
    let reason_code = decoded
        .get("reason_code")
        .and_then(JsonValue::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            decoded
                .get("reason")
                .and_then(|value| value.get("code"))
                .and_then(JsonValue::as_str)
                .map(ToString::to_string)
        });
    let status_code = decoded
        .get("status_code")
        .and_then(JsonValue::as_u64)
        .map(|value| value as u16)
        .or(if deny { Some(403) } else { Some(200) });
    IngressReply {
        text,
        card_cbor: decoded.get("response_card").cloned(),
        status_code,
        reason_code,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parse_dispatch_string_target() {
        let directive = try_parse_control_directive(&json!({
            "action": "dispatch",
            "target": "acme/default/pack-a/flow-x/node-y"
        }))
        .expect("directive");
        let ControlDirective::Dispatch { target } = directive else {
            panic!("expected dispatch");
        };
        assert_eq!(target.tenant, "acme");
        assert_eq!(target.team.as_deref(), Some("default"));
        assert_eq!(target.pack, "pack-a");
        assert_eq!(target.flow.as_deref(), Some("flow-x"));
        assert_eq!(target.node.as_deref(), Some("node-y"));
    }

    #[test]
    fn parse_respond_directive() {
        let directive = try_parse_control_directive(&json!({
            "action": "respond",
            "response_text": "ok"
        }))
        .expect("directive");
        let ControlDirective::Respond { reply } = directive else {
            panic!("expected respond");
        };
        assert_eq!(reply.text.as_deref(), Some("ok"));
        assert_eq!(reply.status_code, Some(200));
    }

    #[test]
    fn parse_dispatch_target_requires_min_segments() {
        let directive = try_parse_control_directive(&json!({
            "action": "dispatch",
            "target": "acme/default"
        }));
        assert!(directive.is_none());
    }

    #[test]
    fn parse_deny_defaults_to_forbidden() {
        let directive = try_parse_control_directive(&json!({
            "action": "deny",
            "reason": { "code": "blocked", "text": "denied by policy" }
        }))
        .expect("directive");
        let ControlDirective::Deny { reply } = directive else {
            panic!("expected deny");
        };
        assert_eq!(reply.reason_code.as_deref(), Some("blocked"));
        assert_eq!(reply.text.as_deref(), Some("denied by policy"));
        assert_eq!(reply.status_code, Some(403));
    }
}
