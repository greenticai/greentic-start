# Teams setup completes but `gtc start` has no usable Graph subscription config

## Summary

After running setup for `messaging-teams`, the bundle records the Teams device-code action as complete, but the runtime does not have the Graph credentials and channel selection needed to create Microsoft Graph change-notification subscriptions. `gtc start` only updates the `public_base_url` secret for Teams; no Teams webhook or subscription setup is invoked.

This leaves Teams non-interactive: there is no Azure Bot Framework bot chat path here, and the Graph subscription path is not being completed.

## Local Reproduction Evidence

Bundle:

```text
/Users/maarten/tests/hr-onboarding-demo-bundle
```

Observed setup answers:

```text
state/config/messaging-teams/setup-answers.json keys:
  client_id
  public_base_url
```

Missing from setup answers and from `.greentic/dev/.dev.secrets.env` key names:

```text
tenant_id
team_id
channel_id
refresh_token
access_token
MS_GRAPH_TENANT_ID
MS_GRAPH_CLIENT_ID
MS_GRAPH_REFRESH_TOKEN
MS_GRAPH_ACCESS_TOKEN
```

Observed setup action state:

```text
state/config/setup-actions/demo/default/messaging-teams.json:
  action id: teams-device-code
  kind: oauth_device_code
  status: complete
  secrets_out:
    client_id -> MS_GRAPH_CLIENT_ID
    refresh_token -> MS_GRAPH_REFRESH_TOKEN
    access_token -> MS_GRAPH_ACCESS_TOKEN
  config_out:
    tenant_id -> tenant_id
    user_id -> user_id
    team_id -> team_id
    channel_id -> channel_id
```

Observed startup log:

```text
logs/system.log:
  [webhook-updater] public_base_url secret updated for messaging-teams
```

There is no later `messaging-teams` `setup_webhook`, `sync_subscriptions`, Graph subscription, or ingress event in the logs.

## Code Path

The Teams setup spec declares a device-code action that should produce Graph secrets and config:

- `../greentic-messaging-providers/packs/messaging-teams/assets/setup.yaml:4`
- `../greentic-messaging-providers/packs/messaging-teams/assets/setup.yaml:24`
- `../greentic-messaging-providers/packs/messaging-teams/assets/setup.yaml:35`
- `../greentic-messaging-providers/packs/messaging-teams/assets/setup.yaml:41`

The packed provider also declares a subscription component:

- `../greentic-messaging-providers/packs/messaging-teams/pack.manifest.json:693`
- `../greentic-messaging-providers/packs/messaging-teams/pack.manifest.json:698`

```json
"messaging.subscriptions.v1": {
  "component_ref": "messaging-ingress-teams",
  "export": "sync-subscriptions"
}
```

The Teams ingress subscription component requires:

- `tenant_id` and `client_id` in config.
- `MS_GRAPH_REFRESH_TOKEN` from the secrets store.
- `webhook_url` and non-empty `desired_subscriptions` in state.

References:

- `../greentic-messaging-providers/components/messaging-ingress-teams/src/lib.rs:77`
- `../greentic-messaging-providers/components/messaging-ingress-teams/src/lib.rs:80`
- `../greentic-messaging-providers/components/messaging-ingress-teams/src/lib.rs:84`
- `../greentic-messaging-providers/components/messaging-ingress-teams/src/lib.rs:474`

However, `greentic-start` webhook refresh only handles declared `webhook_ops` or provider `setup_webhook`:

- `src/webhook_updater.rs:306`
- `src/webhook_updater.rs:331`
- `src/webhook_updater.rs:335`

The Teams provider component does not expose `setup_webhook`:

- `../greentic-messaging-providers/components/messaging-provider-teams/src/lib.rs:157`
- `../greentic-messaging-providers/components/messaging-provider-teams/src/lib.rs:165`

So `gtc start` has no path that turns the Teams `messaging.subscriptions.v1` declaration into an actual Graph subscription.

In embedded runner mode, the external subscription services are skipped:

- `src/runtime.rs:1182`
- `src/runtime.rs:1190`

## Expected

After completing Teams device-code setup:

1. The device-code result should persist `MS_GRAPH_CLIENT_ID`, `MS_GRAPH_REFRESH_TOKEN`, and any returned access token/tenant id to the same dev secrets scope used by `gtc start`.
2. The selected `team_id` and `channel_id` should be persisted into provider setup answers or equivalent runtime config.
3. `gtc start` should create or renew Microsoft Graph subscriptions using `messaging.subscriptions.v1` for the current tunnel URL.

## Actual

The action is marked complete, but the runtime-visible config only contains `client_id` and `public_base_url`. No Teams Graph subscription creation is attempted at startup.

## Likely Fix Options

1. In `greentic-setup`, implement/repair `oauth_device_code` completion persistence so `secrets_out` and `config_out` are written to `setup-answers.json` and the dev secrets store.
2. In `greentic-start`, add support for provider `messaging.subscriptions.v1` during tunnel startup: build `webhook_url`, build `desired_subscriptions` from `team_id`/`channel_id`, and invoke `sync-subscriptions` on `messaging-ingress-teams`.
3. Ensure the Teams provider pack includes the secret requirements needed by startup discovery, or make startup read `messaging.oauth.v1.secret_keys` / `messaging.oauth_device_code.v1.secrets_out` for subscription setup.
4. Do not mark an `oauth_device_code` action complete unless the required `secrets_out` and `config_out` values were persisted and read back successfully.

Preferred fix: treat Teams as a subscription provider rather than a webhook provider. Setup should persist the Graph credentials and selected Team/channel, and `gtc start` should reconcile Graph subscriptions from `messaging.subscriptions.v1` whenever the public tunnel URL changes.
