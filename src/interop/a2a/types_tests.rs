//! Golden JSON for every A2A type: each test pins the exact wire form, and
//! round-trips it back so a lossy field cannot hide.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::*;

/// Serialize `value`, compare to `golden`, then parse `golden` back and
/// compare to `value`.
fn golden<T>(value: &T, golden: Value)
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let out = serde_json::to_value(value).expect("serialize");
    assert_eq!(out, golden, "serialized form drifted");
    let back: T = serde_json::from_value(golden).expect("golden parses");
    assert_eq!(&back, value, "golden does not round-trip");
    assert_eq!(
        first_snake_case_key(&out),
        None,
        "snake_case key on the wire"
    );
}

/// Keys only: A2A VALUES legitimately contain underscores (`ROLE_USER`).
fn first_snake_case_key(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => map.iter().find_map(|(key, child)| {
            if key.contains('_') {
                Some(key.clone())
            } else {
                first_snake_case_key(child)
            }
        }),
        Value::Array(items) => items.iter().find_map(first_snake_case_key),
        _ => None,
    }
}

fn bearer_scheme() -> SecurityScheme {
    SecurityScheme::HttpAuth(HttpAuthSecurityScheme {
        description: None,
        scheme: "bearer".into(),
        bearer_format: Some("gtw".into()),
    })
}

fn skill() -> AgentSkill {
    AgentSkill {
        id: "converse".into(),
        name: "Converse".into(),
        description: "Talk to the worker.".into(),
        tags: vec!["chat".into()],
        examples: vec!["hello".into()],
        input_modes: vec!["text/plain".into()],
        output_modes: vec!["text/plain".into()],
    }
}

fn message() -> Message {
    Message {
        message_id: "m-1".into(),
        context_id: Some("ctx-1".into()),
        task_id: None,
        role: Role::Agent,
        parts: vec![Part::text("hi")],
        metadata: Some(json!({"awaitingInput": true})),
        extensions: vec![],
        reference_task_ids: vec![],
    }
}

fn task() -> Task {
    Task {
        id: "t-1".into(),
        context_id: "ctx-1".into(),
        status: TaskStatus {
            state: TaskState::Completed,
            message: None,
            timestamp: Some("2026-09-23T00:00:00Z".into()),
        },
        artifacts: vec![Artifact {
            artifact_id: "a-1".into(),
            name: Some("out".into()),
            parts: vec![Part::text("x")],
        }],
        history: vec![],
        metadata: None,
    }
}

#[test]
fn agent_card() {
    let card = AgentCard {
        name: "Support Bot".into(),
        description: "Answers.".into(),
        supported_interfaces: vec![AgentInterface {
            url: "https://w.example/a2a".into(),
            protocol_binding: "JSONRPC".into(),
            protocol_version: "1.0".into(),
            tenant: None,
        }],
        version: "1.0.0".into(),
        capabilities: AgentCapabilities {
            streaming: Some(false),
            push_notifications: Some(false),
            extended_agent_card: None,
        },
        default_input_modes: vec!["text/plain".into()],
        default_output_modes: vec!["text/plain".into()],
        skills: vec![skill()],
        provider: Some(AgentProvider {
            url: "https://greentic.ai".into(),
            organization: "Greentic".into(),
        }),
        documentation_url: None,
        icon_url: None,
        security_schemes: BTreeMap::from([("bearer".to_string(), bearer_scheme())]),
        security_requirements: vec![SecurityRequirement {
            schemes: BTreeMap::from([("bearer".to_string(), StringList::default())]),
        }],
    };
    golden(
        &card,
        json!({
            "name": "Support Bot",
            "description": "Answers.",
            "supportedInterfaces": [{
                "url": "https://w.example/a2a",
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0"
            }],
            "version": "1.0.0",
            "capabilities": {"streaming": false, "pushNotifications": false},
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "skills": [{
                "id": "converse", "name": "Converse", "description": "Talk to the worker.",
                "tags": ["chat"], "examples": ["hello"],
                "inputModes": ["text/plain"], "outputModes": ["text/plain"]
            }],
            "provider": {"url": "https://greentic.ai", "organization": "Greentic"},
            "securitySchemes": {
                "bearer": {"httpAuthSecurityScheme": {"scheme": "bearer", "bearerFormat": "gtw"}}
            },
            "securityRequirements": [{"schemes": {"bearer": {"list": []}}}]
        }),
    );
}

/// Trap 1, second half: a requirement's value is a `StringList` MESSAGE, so
/// the JSON is `{"bearer": {"list": []}}`. The bare-array spelling an OpenAPI
/// habit produces must not parse, or a card emitting it would look correct
/// here and be rejected by a client decoding against the proto.
#[test]
fn a_security_requirement_wraps_its_scopes_in_a_string_list() {
    golden(
        &SecurityRequirement {
            schemes: BTreeMap::from([
                ("bearer".to_string(), StringList::default()),
                (
                    "oauth".to_string(),
                    StringList {
                        list: vec!["read".into(), "write".into()],
                    },
                ),
            ]),
        },
        json!({"schemes": {
            "bearer": {"list": []},
            "oauth": {"list": ["read", "write"]}
        }}),
    );
    // What matters is what we EMIT: the bare-array spelling must never be
    // produced. (serde will read `{"bearer": []}` as a struct-from-sequence
    // with `list` defaulted, which is harmless here — this server never
    // consumes a card — but it is why this is an assertion about the
    // serialized bytes rather than about parsing.)
    let emitted = serde_json::to_string(&SecurityRequirement {
        schemes: BTreeMap::from([("bearer".to_string(), StringList::default())]),
    })
    .expect("serialize");
    assert_eq!(emitted, r#"{"schemes":{"bearer":{"list":[]}}}"#);
}

#[test]
fn agent_interface_with_tenant() {
    golden(
        &AgentInterface {
            url: "u".into(),
            protocol_binding: "HTTP+JSON".into(),
            protocol_version: "1.0".into(),
            tenant: Some("acme".into()),
        },
        json!({"url": "u", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0", "tenant": "acme"}),
    );
}

#[test]
fn agent_capabilities() {
    golden(
        &AgentCapabilities {
            streaming: Some(false),
            push_notifications: Some(false),
            extended_agent_card: Some(false),
        },
        json!({"streaming": false, "pushNotifications": false, "extendedAgentCard": false}),
    );
    golden(&AgentCapabilities::default(), json!({}));
}

#[test]
fn agent_skill_and_provider() {
    golden(
        &AgentSkill {
            input_modes: vec![],
            output_modes: vec![],
            examples: vec![],
            ..skill()
        },
        json!({"id": "converse", "name": "Converse", "description": "Talk to the worker.", "tags": ["chat"]}),
    );
    golden(
        &AgentProvider {
            url: "u".into(),
            organization: "o".into(),
        },
        json!({"url": "u", "organization": "o"}),
    );
}

/// Trap 1: the member name discriminates; there is no `type` field.
#[test]
fn security_scheme_is_a_oneof_without_a_type_field() {
    golden(
        &bearer_scheme(),
        json!({"httpAuthSecurityScheme": {"scheme": "bearer", "bearerFormat": "gtw"}}),
    );
    golden(
        &SecurityScheme::ApiKey(ApiKeySecurityScheme {
            description: Some("d".into()),
            location: "header".into(),
            name: "X-Key".into(),
        }),
        json!({"apiKeySecurityScheme": {"description": "d", "location": "header", "name": "X-Key"}}),
    );
    assert!(
        serde_json::from_value::<SecurityScheme>(json!({"type": "http", "scheme": "bearer"}))
            .is_err(),
        "an OpenAPI-shaped scheme must not parse"
    );
}

#[test]
fn role_and_task_state_use_proto_enum_names() {
    golden(&Role::User, json!("ROLE_USER"));
    golden(&Role::Agent, json!("ROLE_AGENT"));
    golden(&Role::Unspecified, json!("ROLE_UNSPECIFIED"));
    for (state, wire) in [
        (TaskState::Unspecified, "TASK_STATE_UNSPECIFIED"),
        (TaskState::Submitted, "TASK_STATE_SUBMITTED"),
        (TaskState::Working, "TASK_STATE_WORKING"),
        (TaskState::Completed, "TASK_STATE_COMPLETED"),
        (TaskState::Failed, "TASK_STATE_FAILED"),
        (TaskState::Canceled, "TASK_STATE_CANCELED"),
        (TaskState::InputRequired, "TASK_STATE_INPUT_REQUIRED"),
        (TaskState::Rejected, "TASK_STATE_REJECTED"),
        (TaskState::AuthRequired, "TASK_STATE_AUTH_REQUIRED"),
    ] {
        golden(&state, json!(wire));
    }
    assert!(serde_json::from_value::<TaskState>(json!("TASK_STATE_CANCELLED")).is_err());
    assert!(serde_json::from_value::<Role>(json!("user")).is_err());
}

#[test]
fn parts_are_flat() {
    golden(&Part::text("hi"), json!({"text": "hi"}));
    golden(
        &Part::data(
            json!({"type": "AdaptiveCard"}),
            "application/vnd.microsoft.card.adaptive+json",
        ),
        json!({"data": {"type": "AdaptiveCard"}, "mediaType": "application/vnd.microsoft.card.adaptive+json"}),
    );
    golden(
        &Part {
            raw: Some("aGk=".into()),
            filename: Some("a.txt".into()),
            metadata: Some(json!({"k": 1})),
            ..Part::default()
        },
        json!({"raw": "aGk=", "filename": "a.txt", "metadata": {"k": 1}}),
    );
    golden(
        &Part {
            url: Some("https://x/y".into()),
            ..Part::default()
        },
        json!({"url": "https://x/y"}),
    );
}

#[test]
fn message_golden() {
    golden(
        &message(),
        json!({
            "messageId": "m-1", "contextId": "ctx-1", "role": "ROLE_AGENT",
            "parts": [{"text": "hi"}], "metadata": {"awaitingInput": true}
        }),
    );
    golden(
        &Message {
            task_id: Some("t".into()),
            extensions: vec!["e".into()],
            reference_task_ids: vec!["r".into()],
            context_id: None,
            metadata: None,
            role: Role::User,
            ..message()
        },
        json!({
            "messageId": "m-1", "taskId": "t", "role": "ROLE_USER", "parts": [{"text": "hi"}],
            "extensions": ["e"], "referenceTaskIds": ["r"]
        }),
    );
}

#[test]
fn task_status_artifact_task() {
    golden(
        &task(),
        json!({
            "id": "t-1", "contextId": "ctx-1",
            "status": {"state": "TASK_STATE_COMPLETED", "timestamp": "2026-09-23T00:00:00Z"},
            "artifacts": [{"artifactId": "a-1", "name": "out", "parts": [{"text": "x"}]}]
        }),
    );
    golden(
        &TaskStatus {
            state: TaskState::InputRequired,
            message: Some(message()),
            timestamp: None,
        },
        json!({"state": "TASK_STATE_INPUT_REQUIRED", "message": {
            "messageId": "m-1", "contextId": "ctx-1", "role": "ROLE_AGENT",
            "parts": [{"text": "hi"}], "metadata": {"awaitingInput": true}
        }}),
    );
}

#[test]
fn send_message_request_and_configuration() {
    let request = SendMessageRequest {
        message: Message {
            role: Role::User,
            metadata: None,
            ..message()
        },
        tenant: Some("t".into()),
        configuration: Some(SendMessageConfiguration {
            accepted_output_modes: vec!["text/plain".into()],
            history_length: Some(3),
            blocking: Some(true),
        }),
        metadata: Some(json!({"k": "v"})),
    };
    golden(
        &request,
        json!({
            "message": {"messageId": "m-1", "contextId": "ctx-1", "role": "ROLE_USER", "parts": [{"text": "hi"}]},
            "tenant": "t",
            "configuration": {"acceptedOutputModes": ["text/plain"], "historyLength": 3, "blocking": true},
            "metadata": {"k": "v"}
        }),
    );
}

/// `SendMessageResponse` is a oneof: `{"message": …}` / `{"task": …}`.
#[test]
fn send_message_response_is_wrapped() {
    golden(
        &SendMessageResponse::Message(message()),
        json!({"message": {
            "messageId": "m-1", "contextId": "ctx-1", "role": "ROLE_AGENT",
            "parts": [{"text": "hi"}], "metadata": {"awaitingInput": true}
        }}),
    );
    let wrapped = serde_json::to_value(SendMessageResponse::Task(task())).expect("serialize");
    assert_eq!(wrapped["task"]["id"], "t-1");
}

#[test]
fn task_requests() {
    golden(
        &GetTaskRequest {
            id: "t".into(),
            tenant: None,
            history_length: Some(2),
        },
        json!({"id": "t", "historyLength": 2}),
    );
    golden(
        &CancelTaskRequest {
            id: "t".into(),
            tenant: Some("x".into()),
        },
        json!({"id": "t", "tenant": "x"}),
    );
    golden(
        &ListTasksRequest {
            context_id: Some("c".into()),
            page_size: Some(10),
            ..ListTasksRequest::default()
        },
        json!({"contextId": "c", "pageSize": 10}),
    );
}

#[test]
fn list_tasks_response_always_carries_its_required_fields() {
    golden(
        &ListTasksResponse::default(),
        json!({"tasks": [], "nextPageToken": "", "pageSize": 0, "totalSize": 0}),
    );
}

#[test]
fn json_rpc_envelopes() {
    let request: JsonRpcRequest = serde_json::from_value(json!({
        "jsonrpc": "2.0", "id": "abc", "method": "SendMessage", "params": {"x": 1}
    }))
    .expect("parses");
    assert_eq!(request.id, Some(JsonRpcId::Str("abc".into())));
    assert_eq!(request.method, "SendMessage");

    golden(
        &JsonRpcResponse::ok(JsonRpcId::Number(7), json!({"ok": true})),
        json!({"jsonrpc": "2.0", "id": 7, "result": {"ok": true}}),
    );
    golden(
        &JsonRpcResponse::err(
            JsonRpcId::Null,
            JsonRpcError {
                code: codes::TASK_NOT_FOUND,
                message: "task not found".into(),
                data: Some(json!({"id": "t"})),
            },
        ),
        json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32001, "message": "task not found", "data": {"id": "t"}}}),
    );
}

/// Trap 4: PascalCase RPC names, not the 0.x slash form.
#[test]
fn rpc_names_are_pascal_case() {
    for name in [
        methods::SEND_MESSAGE,
        methods::SEND_STREAMING_MESSAGE,
        methods::GET_TASK,
        methods::LIST_TASKS,
        methods::CANCEL_TASK,
        methods::SUBSCRIBE_TO_TASK,
        methods::CREATE_PUSH_CONFIG,
        methods::GET_PUSH_CONFIG,
        methods::LIST_PUSH_CONFIGS,
        methods::DELETE_PUSH_CONFIG,
        methods::GET_EXTENDED_AGENT_CARD,
    ] {
        assert!(!name.contains('/'), "{name}");
        assert!(name.starts_with(|c: char| c.is_ascii_uppercase()), "{name}");
    }
}

/// Trap 3: patch is ignored.
#[test]
fn protocol_version_negotiates_on_major_minor() {
    let v = ProtocolVersion::parse;
    assert_eq!(v("1.0"), Some(ProtocolVersion::SUPPORTED));
    assert_eq!(v("1.0.1"), Some(ProtocolVersion::SUPPORTED));
    assert_eq!(v(" 1.0.7 "), Some(ProtocolVersion::SUPPORTED));
    assert_eq!(v("1"), Some(ProtocolVersion::SUPPORTED));
    assert_eq!(v("0.3"), Some(ProtocolVersion { major: 0, minor: 3 }));
    assert_eq!(
        v("1.1").map(|p| p == ProtocolVersion::SUPPORTED),
        Some(false)
    );
    for bad in ["", "x", "1.x", "1.0.x", "1.0.0.0"] {
        assert_eq!(v(bad), None, "{bad}");
    }
    assert_eq!(ProtocolVersion::SUPPORTED.to_string(), "1.0");
}

/// `wire_name` exists so telemetry can name a task state without serializing
/// one, and it is only safe while it IS the serde name. A second vocabulary
/// is how the contract's own §9.1 note describes this going wrong.
#[test]
fn every_task_state_wire_name_matches_its_serde_name() {
    for state in [
        TaskState::Unspecified,
        TaskState::Submitted,
        TaskState::Working,
        TaskState::Completed,
        TaskState::Failed,
        TaskState::Canceled,
        TaskState::InputRequired,
        TaskState::Rejected,
        TaskState::AuthRequired,
    ] {
        assert_eq!(
            serde_json::to_value(state).expect("serialize"),
            json!(state.wire_name()),
            "{state:?}"
        );
    }
}

/// A caller's method string becomes OUR `&'static str` or nothing at all.
/// Nothing in between, because the return value is recorded in telemetry.
#[test]
fn only_a_method_this_server_serves_is_recognised() {
    assert_eq!(methods::known("SendMessage"), Some(methods::SEND_MESSAGE));
    assert_eq!(methods::known("GetTask"), Some(methods::GET_TASK));
    for unknown in ["sendMessage", "message/send", "", "SendMessage "] {
        assert_eq!(methods::known(unknown), None, "{unknown}");
    }
    assert_eq!(
        methods::ALL.len(),
        11,
        "the eleven A2AService RPCs; a new one needs a handler arm too"
    );
}
