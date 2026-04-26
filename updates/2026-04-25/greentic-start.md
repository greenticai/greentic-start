# greentic-start — channelData propagation verification (2026-04-25)

## Outcome — Case A (no patch needed in greentic-start path)

Verified end-to-end that `ChannelMessageEnvelope.extensions["channel_data"]`
populated by `messaging-provider-webchat` (after the 0.5.10 split-envelope
work) reaches the WASM input verbatim. greentic-start does **not** strip
extensions anywhere between the HTTP ingress and `engine.execute`.

## Verified path (envelope -> WASM input JSON)

1. `http_ingress::messaging::route_messaging_envelopes`
   (`src/http_ingress/messaging.rs:14`) iterates incoming
   `Vec<ChannelMessageEnvelope>` (the envelope is forwarded by reference to
   `run_app_flow_safe` at line 84/88; no field filtering).
2. `messaging_app::run_app_flow` (`src/messaging_app.rs:198`) builds the
   runner request as
   `json!({ "input": envelope, "tenant": ..., "team": ..., "correlation_id": ... })`
   at line 214 — `envelope` is serialised whole via `serde_json::to_value`,
   so every populated field on `ChannelMessageEnvelope` (including
   `extensions`) survives.
3. `runner_exec::run_provider_pack_flow` (`src/runner_exec.rs:31`) hands the
   JSON straight into `RunOptions { input: request.input, ... }`
   (line 115) and calls
   `greentic_runner_desktop::run_pack_with_options`.
4. `greentic_runner_desktop::run_pack_async` (`greentic-runner/.../lib.rs:450`)
   passes `opts.input.clone()` into `engine.execute(ctx, ...)`. The flow
   engine stores it verbatim as `ExecutionState.entry` /
   `ExecutionState.input` (`runner-host/.../engine.rs:1245`); no field
   whitelist exists between the host JSON and the template context.

`ChannelMessageEnvelope.extensions` is defined in `greentic-types` 0.5.2 as a
`BTreeMap<String, serde_json::Value>` with `serde(default,
skip_serializing_if = "BTreeMap::is_empty")` — i.e. omitted only when empty;
populated entries are serialised under the snake_case JSON key
`extensions`. Well-known extension key names live in
`greentic_types::messaging::extensions::ext_keys`; `CHANNEL_DATA =
"channel_data"`.

## Canonical JSON Pointer

Inside the runner's flow template context (`{{ entry.* }}`), the user's
DirectLine `channelData` payload is at:

```
/input/extensions/channel_data
```

For R1 demo's `r1_principals` field, the full pointer is:

```
/input/extensions/channel_data/r1_principals
```

Equivalent Handlebars in a flow node `input.mapping`:

```
{{ entry.input.extensions.channel_data.r1_principals }}
```

Both names are **snake_case** (`extensions`, `channel_data`) — Bot Framework's
camelCase `channelData` is normalised by the WebChat provider before the
envelope leaves the messaging-providers crate.

## Reproduction (scratch)

`/tmp/extensions-repro/src/main.rs` constructs the same envelope shape the
WebChat provider emits, runs it through the exact `json!({"input":
envelope, ...})` shape `run_app_flow` builds, and prints the resulting JSON
plus the JSON Pointer lookup. Output (full transcript captured in the
investigation):

```
JSON Pointer /input/extensions/channel_data/r1_principals -> {"country":"US","industry":"telecom"}
OK: channel_data survives the greentic-start request_input shape.
```

## Test pinned

`messaging_app::tests::run_app_flow_input_preserves_envelope_extensions_channel_data`
(`src/messaging_app.rs`) — pins both the JSON Pointer and the snake_case
naming so a future refactor that flattens / renames / whitelists the
envelope cannot silently break the R1 demo without breaking this test.

## Recommendation for R1 demo authors

Read from the snake_case key path. In the flow's
`node.input.mapping`:

```yaml
mapping:
  r1_principals: "{{ entry.input.extensions.channel_data.r1_principals }}"
```

WASM components that look at top-level `input.channelData` (camelCase) or
`input.channel_data` (no `extensions` prefix) will see `null` even though
the host did its job.

## Open questions

- The runner's template engine receives the full `entry` object, but each
  flow's `node.input.mapping` decides what the WASM actually sees. We
  cannot verify the R1 demo's mapping from this repo. Worth confirming that
  the demo's `rag-direct` node mapping forwards the `channel_data` extension
  rather than only the envelope's top-level fields.

## Follow-up: promote stringified `metadata.extensions` into typed extensions

End-to-end testing on the morning of 2026-04-25 (script
`greentic-e2e/scripts/regression/2026_04_25_extensions_passthrough.sh`)
showed `r1_principals` STILL not reaching the WASM input even after the
two fixes above. Layer-by-layer instrumentation between
`http_ingress::messaging::route_messaging_envelopes` (Layer 1),
`messaging_app::run_app_flow` (Layer 2), `engine::execute` (Layer 3),
and the final WASM payload boundary (Layer 4) revealed why.

Layer 1 captured envelope shape (from the published
`messaging-webchat-gui:latest` provider WASM) was:
```
{
  ...,
  "metadata": {
    ...,
    "extensions": "{\"channel_data\":{\"r1_principals\":{...}}}"
  }
}
```
— a JSON-encoded string under `metadata`, not the typed
`envelope.extensions` field. Root cause: the published WASM is built
against `greentic-types` 0.4.x via the v0.4.84 "neutral presentation"
refactor (see `greentic-messaging-providers` PR #132 commit message
for full context). `greentic-types` 0.5.x — what greentic-start
deserializes into — does have the typed field, but it arrives empty
because the WASM never populated it.

Net: `parse_messaging_envelopes` was handing the runner an envelope
with empty typed extensions, and the runner had no way to look inside
the metadata string.

Fix (`src/ingress_dispatch.rs::promote_metadata_extensions_string`):
After successful strict-decode of an inbound envelope, parse
`metadata["extensions"]` as JSON. When it's an object, copy each key
into `envelope.extensions` with `Entry::or_insert` semantics so
already-typed envelopes (from compliant future providers) still win.

Tests pinning the contract:
- `parse_messaging_envelopes_promotes_metadata_extensions_string` —
  regression for the WASM-side stringified shape.
- `parse_messaging_envelopes_keeps_existing_typed_extensions` —
  precedence guarantee.

After the runner-side fix in `greentic-runner` (commit `dbd70ce`,
fall-back to `scope.input.extensions` for the wrapped flow shape) the
end-to-end script passes:
```
$ RUN_E2E=1 PORT=8080 ./scripts/regression/2026_04_25_extensions_passthrough.sh
…
PASS: extensions passthrough — extensions.channel_data.r1_principals reached WASM input
```
