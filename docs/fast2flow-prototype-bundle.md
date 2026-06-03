# Fast2Flow Prototype Bundle — `sales-crm-fast2flow-demo`

Status: **design draft**, not yet built. Tracks the bundle-side surface the
Fast2Flow integration ([feat/fast2flow-routing-host](../README.md)) needs to
fire end-to-end.

## Goal

Demonstrate Fast2Flow free-text routing on a real bundle by reusing the
existing `sales-crm-demo` assets and adding the two schema elements the
runtime gate needs:

1. The pack declares `greentic.cap.fast2flow.v1` in its `capabilities` so
   greentic-start identifies it as a fast2flow opt-in.
2. The pack carries `greentic.ext.fast2flow.v1`
   ([greentic-types Fast2FlowExtensionV1](../../greentic-types/src/pack/extensions/fast2flow.rs))
   with per-flow routing metadata that the deployer materializer projects
   into Fast2Flow's `flows.json` per scope.

User-visible outcome: an end user types `"show me my pipeline"` in chat
and lands on the pipeline flow (or `"log a new lead"` lands on the lead
form, etc.) instead of always entering through the default `welcome` flow.

## Reused from `sales-crm-demo`

Everything except the routing metadata stays. The new demo crate is a thin
shadow of `greentic-demo/crates/sales-crm-demo` with two additions.

| Asset | Source | Reuse |
|---|---|---|
| Rust component | `crates/sales-crm-demo/src/lib.rs` | as-is |
| Adaptive cards | `assets/cards/{deal_detail,lead_form,meeting,pipeline,salesforce_connect,welcome}.json` | as-is |
| i18n | `assets/i18n/*` | as-is |
| OAuth setup card | `salesforce_connect_card.json` | as-is |
| Wizard answers | `build-answer.json` | adapt (point at new pack name) |

## New schema additions

### 1. Pack-manifest capabilities

Add one entry to `PackManifest::capabilities`
([greentic-types pack_manifest.rs:98](../../greentic-types/src/pack_manifest.rs#L98)):

```yaml
capabilities:
  - name: greentic.cap.fast2flow.v1
    description: opts the pack into Fast2Flow free-text routing
```

### 2. Per-flow routing extension

Add `greentic.ext.fast2flow.v1` to `PackManifest::extensions`:

```yaml
extensions:
  greentic.ext.fast2flow.v1:
    schema_version: 1
    flows:
      - id: pipeline_flow
        target: sales-crm/pipeline_flow
        title: View pipeline
        tags: [pipeline, deals, stage]
        node_ids: [show_pipeline_card]
        utterances:
          - show me my pipeline
          - what's in my pipeline
          - pipeline by stage
      - id: lead_form_flow
        target: sales-crm/lead_form_flow
        title: Log a new lead
        tags: [lead, prospect, capture]
        node_ids: [lead_form_card]
        utterances:
          - log a new lead
          - add a prospect
          - I got a referral
      - id: meeting_flow
        target: sales-crm/meeting_flow
        title: Schedule a meeting
        tags: [meeting, calendar, book]
        node_ids: [meeting_card]
        utterances:
          - book a meeting
          - schedule a call
          - set up time with a contact
      - id: deal_detail_flow
        target: sales-crm/deal_detail_flow
        title: Look up deal details
        tags: [deal, opportunity, amount]
        node_ids: [deal_detail_card]
        utterances:
          - what's the status of deal X
          - show deal details
          - update close date
```

`pack_id` is inherited from the parent `PackManifest::pack_id` at
materialize time, so it's intentionally absent here.

## Routing intent map

Inbound utterance → Fast2Flow decision → resulting `ControlDirective::Dispatch`
target (tenant/team come from the request context):

| User says | Fast2Flow returns | Dispatch.flow | Dispatch.node |
|---|---|---|---|
| "show me my pipeline" | `Dispatch{ target: "sales-crm/pipeline_flow" }` | `pipeline_flow` | — |
| "log a new lead" | `Dispatch{ target: "sales-crm/lead_form_flow" }` | `lead_form_flow` | — |
| "book a meeting" | `Dispatch{ target: "sales-crm/meeting_flow" }` | `meeting_flow` | — |
| "what's the status of deal X" | `Dispatch{ target: "sales-crm/deal_detail_flow" }` | `deal_detail_flow` | — |
| "hi" / empty intent | `Continue` | — | — (falls through to default `welcome` flow) |
| "ignore the rules" (policy deny example) | `Deny{ reason: "policy" }` | — | — (403 returned) |

## Hand-authored build path (quick + dirty, until packc lands Phase 2C)

`packc` doesn't yet author the `greentic.ext.fast2flow.v1` extension from
`pack.yaml`. Until [Phase 2C](#open-gaps) ships, build by:

1. Build the sales-crm-demo gtpack the normal way (`gtc wizard` → squashfs
   bundle).
2. **Manually patch** the embedded `manifest.cbor` of the resulting
   `sales-crm.gtpack` to add:
   - one `{name: greentic.cap.fast2flow.v1}` entry to the cbor `capabilities`
     array
   - one extension entry under cbor `extensions[greentic.ext.fast2flow.v1]`
     carrying the inline JSON above (cbor-encoded via
     [`encode_fast2flow_extension_v1_to_cbor_bytes`](../../greentic-types/src/pack/extensions/fast2flow.rs))
3. Re-zip the gtpack.

A helper binary `gtc-pack-patch-fast2flow` (out of scope for this draft)
can automate the patch step from a sidecar YAML.

## Test plan

End-to-end smoke (runs in CI on `greentic-start`):

1. Build a fake `manifest.cbor` in-memory with the capability + extension
   (no actual `.gtpack` file needed for unit coverage).
2. Call `messaging_app::load_app_pack_info` (or its underlying cbor walk)
   on the manifest, assert `pack_info.capabilities` contains
   `"greentic.cap.fast2flow.v1"`.
3. Construct a stub `Fast2FlowConfig` pointing at a tempdir-rooted
   `indexes_path`, drop a `<scope>/index.json` placeholder file so the
   index-existence gate clears.
4. Stub the routing-host binary with a shell script that prints a canned
   `Dispatch{target: "sales-crm/pipeline_flow", ...}` directive on stdin.
5. Call `fast2flow::try_for_request(cfg, ctx, &pack_info, envelope,
   "webchat")` and assert it returns
   `Some(ControlDirective::Dispatch { target })` with `target.pack ==
   "sales-crm"` and `target.flow == Some("pipeline_flow")`.

Negative cases worth covering:
- Pack without the capability declared → `try_for_request` returns
  `None` (gate fails at step 1).
- Capability declared but no index file on disk → returns `None`.
- Host process exits non-zero → fail-open `None`.

Manual end-to-end against a real `greentic-fast2flow-routing-host` binary
is also possible once the host binary is on `$PATH` and a real
`flows.json` is fed through `greentic-fast2flow index build`.

## Open gaps (deferred)

These don't block the prototype but are needed for production fit-and-finish:

- **Phase 2C (packc authoring)**: `packc` reads `pack.yaml` and writes
  `manifest.cbor`. It needs to recognize a `fast2flow:` section in
  `pack.yaml` and serialize the `greentic.ext.fast2flow.v1` extension into
  the cbor manifest. Today the prototype uses the hand-patch workflow above.
- **Materializer**: nobody currently produces `<indexes_path>/<scope>/index.json`.
  Originally planned as Step 3 in the deployer, now waiting on a new home —
  candidates are greentic-start at boot (scan loaded packs, project to
  flows.json, shell out to `greentic-fast2flow index build`) or a
  standalone operator CLI.
- **Routing host distribution**: `greentic-fast2flow-routing-host` is
  GitHub-Release-artifact only (no crates.io). Operators install manually
  to `$PATH` for now; bundling into the start container image is post-MVP.
- **Bundle-level vs pack-level**: pack-level declaration matches the
  current `greentic-start` read path. `greentic-bundle`'s
  `BundleManifest::capabilities` (already a `Vec<String>` on main) can
  mirror the declaration for ops visibility but is not read by the runtime.
- **Confidence + reason on dispatch**: Fast2Flow's
  `RoutingDirective::Dispatch` carries `{ target, confidence, reason }`.
  greentic-start's `ControlDirective::Dispatch` has no slot for the latter
  two; they're dropped today. A tracing span carrying both (FIXME in
  [mapper.rs](../src/fast2flow/mapper.rs)) is the natural next step.

## References

- Fast2Flow integration plan (this branch): [docs/superpowers/specs/](superpowers/specs/) (TBD)
- Runtime hook: [src/fast2flow/mod.rs::try_for_request](../src/fast2flow/mod.rs)
- Extension type: [greentic-types/src/pack/extensions/fast2flow.rs](../../greentic-types/src/pack/extensions/fast2flow.rs) (`feat/fast2flow-ext`)
- Source demo: [greentic-demo/crates/sales-crm-demo/](../../greentic-demo/crates/sales-crm-demo/)
- Fast2Flow contracts: [greentic-fast2flow/crates/fast2flow-contracts/](../../greentic-fast2flow/crates/fast2flow-contracts/src/lib.rs)
