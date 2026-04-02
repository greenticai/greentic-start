use std::sync::{Arc, OnceLock};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dashmap::DashMap;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// JWT generation (reusable, extracted from http_ingress)
// ---------------------------------------------------------------------------

type HmacSha256 = Hmac<sha2::Sha256>;

const JWT_TTL_SECONDS: i64 = 1800;

/// Generate an HS256 JWT compatible with the Direct Line token format used by
/// the messaging ingress facade. When `conv_id` is `Some`, the claim is bound
/// to a specific conversation.
pub fn generate_legacy_directline_jwt(
    signing_key: &[u8],
    tenant: &str,
    team: &str,
    sub: &str,
    conv_id: Option<&str>,
) -> String {
    let now = chrono::Utc::now();
    let iat = now.timestamp();
    let exp = iat + JWT_TTL_SECONDS;

    let header = json!({"alg": "HS256", "typ": "JWT"});

    let mut claims = json!({
        "iss": "greentic.messaging",
        "aud": "directline",
        "sub": sub,
        "iat": iat,
        "nbf": iat,
        "exp": exp,
        "ctx": {
            "tenant": tenant,
            "team": team,
        }
    });

    if let Some(cid) = conv_id {
        claims["conversationId"] = JsonValue::String(cid.to_string());
    }

    let header_enc = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
    let payload_enc = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap().as_bytes());

    let mut mac = HmacSha256::new_from_slice(signing_key).expect("HMAC accepts any key length");
    mac.update(header_enc.as_bytes());
    mac.update(b".");
    mac.update(payload_enc.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_enc = URL_SAFE_NO_PAD.encode(signature);

    format!("{header_enc}.{payload_enc}.{signature_enc}")
}

// ---------------------------------------------------------------------------
// Stored activity
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredActivity {
    pub id: String,
    pub type_: String,
    pub text: Option<String>,
    pub from_id: String,
    pub from_role: String,
    pub timestamp_ms: i64,
    pub watermark: u64,
    pub raw: JsonValue,
}

// ---------------------------------------------------------------------------
// Conversation state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct ConversationState {
    pub next_watermark: u64,
    pub activities: Vec<StoredActivity>,
}

impl ConversationState {
    pub fn bump_watermark(&mut self) -> u64 {
        self.next_watermark += 1;
        self.next_watermark
    }

    pub fn add_activity(&mut self, activity: StoredActivity) {
        self.activities.push(activity);
    }

    pub fn activities_since(&self, watermark: Option<u64>) -> Vec<&StoredActivity> {
        match watermark {
            Some(wm) => self
                .activities
                .iter()
                .filter(|a| a.watermark > wm)
                .collect(),
            None => self.activities.iter().collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// DirectLine state (shared across requests)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct LegacyDirectLineState {
    conversations: Arc<DashMap<String, ConversationState>>,
}

impl Default for LegacyDirectLineState {
    fn default() -> Self {
        Self::new()
    }
}

impl LegacyDirectLineState {
    pub fn new() -> Self {
        Self {
            conversations: Arc::new(DashMap::new()),
        }
    }

    /// Insert a new (empty) conversation. Always returns `true` — if the
    /// conversation already existed, the existing state is preserved.
    pub fn create_conversation(&self, conv_id: &str) -> bool {
        self.conversations.entry(conv_id.to_string()).or_default();
        true
    }

    pub fn conversation_exists(&self, conv_id: &str) -> bool {
        self.conversations.contains_key(conv_id)
    }

    pub fn add_user_activity(
        &self,
        conv_id: &str,
        text: Option<String>,
        from_id: &str,
        raw: JsonValue,
    ) -> Option<String> {
        let mut entry = self.conversations.get_mut(conv_id)?;
        let wm = entry.bump_watermark();
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let now_ms = now.timestamp_millis();
        // Enrich raw activity with required DirectLine fields
        let mut enriched = raw;
        if let Some(obj) = enriched.as_object_mut() {
            obj.insert("id".to_string(), JsonValue::String(id.clone()));
            obj.insert("timestamp".to_string(), JsonValue::String(now.to_rfc3339()));
            obj.entry("from".to_string())
                .or_insert_with(|| serde_json::json!({"id": from_id, "role": "user"}));
            if let Some(from) = obj.get_mut("from").and_then(|v| v.as_object_mut()) {
                from.entry("role".to_string())
                    .or_insert_with(|| JsonValue::String("user".to_string()));
            }
        }
        entry.add_activity(StoredActivity {
            id: id.clone(),
            type_: "message".to_string(),
            text,
            from_id: from_id.to_string(),
            from_role: "user".to_string(),
            timestamp_ms: now_ms,
            watermark: wm,
            raw: enriched,
        });
        Some(id)
    }

    pub fn add_bot_activity(
        &self,
        conv_id: &str,
        text: Option<String>,
        attachments: Option<JsonValue>,
    ) -> Option<String> {
        let mut entry = self.conversations.get_mut(conv_id)?;
        let wm = entry.bump_watermark();
        let id = format!("bot-{wm}");
        let now_ms = chrono::Utc::now().timestamp_millis();

        let mut raw = json!({
            "type": "message",
            "id": &id,
            "from": {"id": "bot", "name": "Bot", "role": "bot"},
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        // Only include "text" when there are no attachments so clients do not
        // render a redundant text bubble above the card payload.
        if attachments.is_none()
            && let Some(ref t) = text
        {
            raw["text"] = JsonValue::String(t.clone());
        }
        if let Some(ref att) = attachments {
            raw["attachments"] = att.clone();
        }

        entry.add_activity(StoredActivity {
            id: id.clone(),
            type_: "message".to_string(),
            text,
            from_id: "bot".to_string(),
            from_role: "bot".to_string(),
            timestamp_ms: now_ms,
            watermark: wm,
            raw,
        });
        Some(id)
    }

    pub fn get_activities(
        &self,
        conv_id: &str,
        watermark: Option<u64>,
    ) -> Option<(Vec<JsonValue>, String)> {
        let entry = self.conversations.get(conv_id)?;
        let activities: Vec<JsonValue> = entry
            .activities_since(watermark)
            .iter()
            .map(|a| a.raw.clone())
            .collect();
        let next_wm = entry.next_watermark.to_string();
        Some((activities, next_wm))
    }
}

#[derive(Clone, Default)]
pub struct LegacyDirectLineCompat {
    state: Arc<OnceLock<LegacyDirectLineState>>,
}

#[derive(Clone, Copy)]
pub struct LegacyDirectLineReplyTarget<'a> {
    compat: &'a LegacyDirectLineCompat,
    conversation_id: &'a str,
}

impl LegacyDirectLineCompat {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> &LegacyDirectLineState {
        self.state.get_or_init(LegacyDirectLineState::new)
    }

    pub fn create_conversation(&self, conv_id: &str) -> bool {
        self.state().create_conversation(conv_id)
    }

    pub fn conversation_exists(&self, conv_id: &str) -> bool {
        self.state().conversation_exists(conv_id)
    }

    pub fn inject_user_activity(
        &self,
        conv_id: &str,
        text: Option<String>,
        from_id: &str,
        raw: JsonValue,
    ) -> Option<String> {
        self.state().add_user_activity(conv_id, text, from_id, raw)
    }

    pub fn inject_bot_activity(
        &self,
        conv_id: &str,
        text: Option<String>,
        attachments: Option<JsonValue>,
    ) -> Option<String> {
        self.state().add_bot_activity(conv_id, text, attachments)
    }

    pub fn get_activities(
        &self,
        conv_id: &str,
        watermark: Option<u64>,
    ) -> Option<(Vec<JsonValue>, String)> {
        self.state().get_activities(conv_id, watermark)
    }

    pub fn reply_target<'a>(&'a self, conversation_id: &'a str) -> LegacyDirectLineReplyTarget<'a> {
        LegacyDirectLineReplyTarget {
            compat: self,
            conversation_id,
        }
    }

    pub fn create_conversation_response(
        &self,
        tenant: &str,
        team: &str,
        signing_key: &[u8],
    ) -> JsonValue {
        let conv_id = uuid::Uuid::new_v4().to_string();
        self.create_conversation(&conv_id);

        let token =
            generate_legacy_directline_jwt(signing_key, tenant, team, "anonymous", Some(&conv_id));

        json!({
            "conversationId": conv_id,
            "token": token,
            "expires_in": JWT_TTL_SECONDS,
            "streamUrl": null
        })
    }

    pub fn token_response(tenant: &str, team: &str, signing_key: &[u8]) -> JsonValue {
        let token = generate_legacy_directline_jwt(signing_key, tenant, team, "anonymous", None);

        json!({
            "token": token,
            "expires_in": JWT_TTL_SECONDS,
            "conversationId": ""
        })
    }

    pub fn post_activity_response(&self, conv_id: &str, body: &JsonValue) -> Option<JsonValue> {
        let text = body.get("text").and_then(|v| v.as_str()).map(String::from);
        let from_id = body
            .get("from")
            .and_then(|f| f.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("anonymous");

        let activity_id = self.inject_user_activity(conv_id, text, from_id, body.clone())?;
        Some(json!({ "id": activity_id }))
    }

    pub fn get_activities_response(
        &self,
        conv_id: &str,
        watermark: Option<u64>,
    ) -> Option<JsonValue> {
        let (activities, next_wm) = self.get_activities(conv_id, watermark)?;
        Some(json!({
            "activities": activities,
            "watermark": next_wm
        }))
    }

    pub fn build_user_envelope(
        tenant: &str,
        team: &str,
        provider: &str,
        conversation_id: &str,
        body: &JsonValue,
    ) -> Result<greentic_types::ChannelMessageEnvelope, serde_json::Error> {
        let text = body.get("text").and_then(|v| v.as_str()).map(String::from);
        let from_id = body
            .get("from")
            .and_then(|f| f.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("anonymous")
            .to_string();

        let mut metadata = BTreeMap::new();
        metadata.insert("provider".to_string(), provider.to_string());
        metadata.insert("tenant".to_string(), tenant.to_string());
        metadata.insert("team".to_string(), team.to_string());
        if let Some(locale) = body.get("locale").and_then(|v| v.as_str()) {
            metadata.insert("locale".to_string(), locale.to_string());
        }
        if let Some(value_obj) = body.get("value").and_then(|v| v.as_object()) {
            for (k, v) in value_obj {
                let val_str = match v {
                    JsonValue::String(s) => s.clone(),
                    other => other.to_string(),
                };
                metadata.insert(k.clone(), val_str);
            }
        }

        serde_json::from_value(serde_json::json!({
            "id": format!("directline-{conversation_id}"),
            "tenant": {
                "env": "dev",
                "tenant": tenant,
                "tenant_id": tenant,
                "team": team,
                "attempt": 0
            },
            "channel": conversation_id,
            "session_id": conversation_id,
            "from": {
                "id": from_id,
                "kind": "user"
            },
            "text": text,
            "metadata": metadata
        }))
    }
}

impl LegacyDirectLineReplyTarget<'_> {
    pub fn inject_bot_activity(
        &self,
        text: Option<String>,
        attachments: Option<JsonValue>,
    ) -> Option<String> {
        self.compat
            .inject_bot_activity(self.conversation_id, text, attachments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn decode_jwt_claims(token: &str) -> JsonValue {
        let payload = token.split('.').nth(1).expect("jwt payload");
        let bytes = URL_SAFE_NO_PAD.decode(payload).expect("base64 payload");
        serde_json::from_slice(&bytes).expect("claims json")
    }

    #[test]
    fn generate_jwt_includes_context_and_optional_conversation_id() {
        let with_conversation = generate_legacy_directline_jwt(b"secret", "tenant-a", "team-a", "user-1", Some("c1"));
        let claims = decode_jwt_claims(&with_conversation);
        assert_eq!(claims["ctx"]["tenant"], "tenant-a");
        assert_eq!(claims["ctx"]["team"], "team-a");
        assert_eq!(claims["sub"], "user-1");
        assert_eq!(claims["conversationId"], "c1");

        let without_conversation = generate_legacy_directline_jwt(b"secret", "tenant-a", "team-a", "user-1", None);
        let claims = decode_jwt_claims(&without_conversation);
        assert!(claims.get("conversationId").is_none());
    }

    #[test]
    fn activities_since_excludes_the_last_seen_watermark() {
        let mut state = ConversationState::default();
        state.add_activity(StoredActivity {
            id: "a1".to_string(),
            type_: "message".to_string(),
            text: Some("one".to_string()),
            from_id: "user".to_string(),
            from_role: "user".to_string(),
            timestamp_ms: 1,
            watermark: 1,
            raw: json!({"id": "a1"}),
        });
        state.add_activity(StoredActivity {
            id: "a2".to_string(),
            type_: "message".to_string(),
            text: Some("two".to_string()),
            from_id: "user".to_string(),
            from_role: "user".to_string(),
            timestamp_ms: 2,
            watermark: 2,
            raw: json!({"id": "a2"}),
        });

        let ids: Vec<_> = state
            .activities_since(Some(1))
            .into_iter()
            .map(|activity| activity.id.as_str())
            .collect();
        assert_eq!(ids, vec!["a2"]);
    }

    #[test]
    fn directline_state_roundtrips_user_and_bot_activities() {
        let state = LegacyDirectLineState::new();
        assert!(state.create_conversation("conv-1"));

        let user_id = state
            .add_user_activity(
                "conv-1",
                Some("hello".to_string()),
                "user-1",
                json!({"text": "hello"}),
            )
            .expect("user activity");
        assert!(user_id.len() > 10);

        let bot_id = state
            .add_bot_activity(
                "conv-1",
                Some("hi".to_string()),
                Some(json!([{"type": "card"}])),
            )
            .expect("bot activity");
        assert_eq!(bot_id, "bot-2");

        let (activities, watermark) = state.get_activities("conv-1", Some(1)).expect("activities");
        assert_eq!(watermark, "2");
        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0]["id"], "bot-2");
        assert_eq!(activities[0]["attachments"][0]["type"], "card");
    }

    #[test]
    fn endpoint_helpers_require_existing_conversations() {
        let compat = LegacyDirectLineCompat::new();
        assert!(compat
            .post_activity_response("missing", &json!({"text": "hello"}))
            .is_none());
        assert!(compat.get_activities_response("missing", None).is_none());
    }

    #[test]
    fn create_and_post_handlers_populate_expected_fields() {
        let compat = LegacyDirectLineCompat::new();
        let created = compat.create_conversation_response("tenant-a", "team-a", b"secret");
        let conversation_id = created["conversationId"].as_str().expect("conversation id");
        assert!(compat.conversation_exists(conversation_id));
        assert_eq!(created["expires_in"], JWT_TTL_SECONDS);

        let posted = compat
            .post_activity_response(conversation_id, &json!({"text": "hello", "from": {"id": "user-1"}}))
            .expect("post result");
        assert!(posted["id"].as_str().is_some());

        let activities = compat
            .get_activities_response(conversation_id, None)
            .expect("activities");
        assert_eq!(activities["activities"][0]["text"], "hello");
        assert_eq!(activities["activities"][0]["from"]["role"], "user");
    }
}
