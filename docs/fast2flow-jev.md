# Fast2Flow: the Jev routing tier

A routed channel can classify a free-text message with Jev (TypeSafe AI's
typed-decision API, `POST https://api.typesafe.ai/v1/systemone`) when the host
router (BM25) found nothing. Order of a turn: host router, **Jev**, the embedded
LLM fallback, then the pack's miss policy. `Deny`/`Respond` from the host still
stop routing before Jev is asked.

**Off by default.** With no `jev` block anywhere the tier never runs: no secret
is read, no request is made, nothing is logged.

## Configuration

`bundle.yaml` (operator; legacy `--bundle` ingress, and a veto/override for
packs):

```yaml
jev:
  endpoint: https://api.typesafe.ai/v1/systemone   # optional; https or loopback only
  api_key_secret: jev/api_key                      # a secret NAME (default)
  timeout_ms: 2000                                 # 100..=10000, default 2000
  min_confidence: 0.5                              # default 0.5
  model: jev-latest                                # optional
  enabled: false                                   # optional kill switch
```

The pack (`assets/fast2flow.json`, what a deployed router unit carries):

```json
{ "schema": "greentic.fast2flow-config.v1", "jev": { "timeout_ms": 1500 } }
```

Rules:

* There is no field for a key; `api_key:` is a parse error. `api_key_secret`
  is a NAME, read from the secrets store at call time (same scopes as a
  channel secret of the router pack: unit scope, then pack scope).
* A pack cannot set `endpoint`, and a pack's secret name must start with
  `jev/`, so a pack cannot send another secret, or any secret elsewhere, to a
  third party. Either violation turns the tier off for that pack (one `warn`).
* `enabled: false` in `bundle.yaml` turns the tier off whatever a pack says.

## Behaviour

The pack's `assets/intent-index.json` entries become the options of ONE
`choice` question (plus a `none` option). Jev's answer is accepted only if it
names an offered option, is not `none`, and has `confidence >= min_confidence`;
it then dispatches exactly like an LLM route (`source: "jev"` in the route
signal).

Fails open: a missing/unreadable secret, timeout, transport error, non-2xx
status, undecodable or answer-less body, low confidence or an unknown option
all return the turn to the next tier. The first occurrence of each cause is a
`warn`, later ones `debug`. Logs carry classes and status codes only: never the
key, a response body, or the message text.

The message text (first 2000 characters) leaves the process for the Jev
endpoint. Enable the tier only where that is acceptable.
