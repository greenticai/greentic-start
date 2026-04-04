use serde_json::{Value, json};

pub fn webhook_result_from_flow_output(output: Option<&Value>) -> Option<Value> {
    let output = output?;
    let webhook_ops = output.get("webhook_ops")?.as_array()?;
    if webhook_ops.is_empty() {
        return None;
    }
    let subscription_ops = output
        .get("subscription_ops")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let oauth_ops = output
        .get("oauth_ops")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    Some(json!({
        "ok": true,
        "mode": "flow_output",
        "webhook_ops": webhook_ops,
        "subscription_ops": subscription_ops,
        "oauth_ops": oauth_ops,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_output_webhook_result_uses_declared_ops() {
        let output = json!({
            "config_patch": {"public_base_url": "https://demo.example"},
            "webhook_ops": [{"op": "register", "url": "https://demo.example/webhook"}],
            "subscription_ops": [{"op": "sync", "provider": "graph"}],
            "oauth_ops": []
        });

        let result = webhook_result_from_flow_output(Some(&output)).expect("flow result");
        assert_eq!(result["ok"], Value::Bool(true));
        assert_eq!(result["mode"], Value::String("flow_output".to_string()));
        assert_eq!(
            result["webhook_ops"][0]["op"],
            Value::String("register".to_string())
        );
        assert_eq!(
            result["subscription_ops"][0]["op"],
            Value::String("sync".to_string())
        );
    }

    #[test]
    fn flow_output_webhook_result_skips_empty_ops() {
        let output = json!({
            "webhook_ops": [],
            "subscription_ops": [{"op": "sync"}]
        });

        assert!(webhook_result_from_flow_output(Some(&output)).is_none());
        assert!(webhook_result_from_flow_output(None).is_none());
        assert!(
            webhook_result_from_flow_output(Some(&json!({
                "webhook_ops": "not-an-array"
            })))
            .is_none()
        );
    }

    #[test]
    fn flow_output_webhook_result_defaults_optional_arrays() {
        let output = json!({
            "webhook_ops": [{"op": "register"}]
        });

        let result = webhook_result_from_flow_output(Some(&output)).expect("flow result");
        assert_eq!(result["subscription_ops"], json!([]));
        assert_eq!(result["oauth_ops"], json!([]));
    }
}
