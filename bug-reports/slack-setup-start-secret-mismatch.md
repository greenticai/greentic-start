# Slack setup completes but `gtc start` cannot configure webhook

## Summary

After running setup for `messaging-slack`, the bundle records a completed Slack OAuth/setup action and persists Slack setup answers, but `gtc start` cannot configure the Slack webhook. Startup invokes `messaging-provider-slack` `setup_webhook`, which looks for `slack_app_id` / `SLACK_APP_ID`; setup currently stores the created Slack app id as `app_id`.

The result is that webhook setup is skipped at start:

```text
secret lookup failed secret=SLACK_APP_ID canonical=slack_app_id
{"error":"slack_app_id and slack_configuration_access_token required","ok":true,"reason":"slack app registration not configured","skipped":true}
```

## Local Reproduction Evidence

Bundle:

```text
/Users/maarten/tests/hr-onboarding-demo-bundle
```

Observed setup output state:

```text
state/config/messaging-slack/setup-answers.json keys:
  app_id
  client_id
  client_secret
  public_base_url
  slack_client_id
  slack_configuration_access_token
  slack_configuration_refresh_token

state/config/setup-actions/demo/default/messaging-slack.json:
  action status: complete
  action contains app_id
```

Observed startup log:

```text
logs/system.log:
  WASM secrets read requested uri=secrets://dev/demo/_/messaging-slack/slack_app_id
  secret lookup failed secret=SLACK_APP_ID canonical=slack_app_id
  setup_webhook provider=messaging-slack value_preview={"error":"slack_app_id and slack_configuration_access_token required","ok":true,"reason":"slack app registration not configured","skipped":true}
```

## Code Path

`greentic-setup` persists stripped setup answers before runtime:

- `../greentic-setup/src/engine/executors.rs:175` extracts and persists setup actions.
- `../greentic-setup/src/engine/executors.rs:186` strips `setup_actions`.
- `../greentic-setup/src/engine/executors.rs:192` writes `state/config/<provider>/setup-answers.json`.
- `../greentic-setup/src/engine/executors.rs:230` persists setup answers to the dev secrets store.

The Slack setup spec names the registration app id output `app_id`:

- `../greentic-messaging-providers/packs/messaging-slack/assets/setup.yaml:23`
- `../greentic-messaging-providers/packs/messaging-slack/assets/setup.yaml:28`

```yaml
registration:
  op: setup_app_registration
  app_id_output: app_id
```

The Slack provider `setup_webhook` expects `slack_app_id` in the input, or falls back to `SLACK_APP_ID` from the secrets API:

- `../greentic-messaging-providers/components/messaging-provider-slack/src/ops/webhook.rs:104`
- `../greentic-messaging-providers/components/messaging-provider-slack/src/ops/webhook.rs:110`
- `../greentic-messaging-providers/components/messaging-provider-slack/src/lib.rs:31`

```rust
parsed.get("slack_app_id")
    ...
    .or_else(|| secret_string(DEFAULT_APP_ID_KEY));
```

`greentic-start` webhook refresh builds the provider config from `public_base_url`, tenant/team/provider, and secret requirement keys:

- `src/webhook_updater.rs:421`
- `src/webhook_updater.rs:437`
- `src/webhook_updater.rs:447`

The packed Slack secret requirements include the Slack configuration tokens, but not `SLACK_APP_ID`, so `app_id` from setup is not converted to `slack_app_id` for startup webhook registration.

## Expected

After Slack setup completes and creates/registers the Slack app, a later `gtc start` should have enough data to run `messaging-provider-slack setup_webhook` and update the Slack app manifest URL to the current tunnel.

## Actual

`gtc start` only finds the configuration token path, then fails/skips because `slack_app_id` is absent. The logs mark the WASM op as succeeded because the provider returns `ok: true` with `skipped: true`, which hides the configuration failure.

## Likely Fix Options

1. In `greentic-messaging-providers`, change Slack `assets/setup.yaml` registration output from `app_id` to `slack_app_id`, or also emit an alias.
2. In `greentic-setup`, when a registration spec says `app_id_output: app_id`, persist an additional provider-specific alias `slack_app_id` for `messaging-slack`.
3. In `greentic-start`, merge `state/config/messaging-slack/setup-answers.json` into webhook setup config and map `app_id` to `slack_app_id` before invoking `setup_webhook`.
4. Make `messaging-provider-slack setup_webhook` accept `app_id` as a legacy alias in addition to `slack_app_id`.

Preferred fix: align setup output with provider runtime input at the provider/setup contract boundary, then make `setup_webhook` return `ok:false` when required registration values are missing so startup does not report a skipped webhook as updated.
