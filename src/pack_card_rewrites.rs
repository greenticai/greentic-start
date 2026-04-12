//! Generic card marker rewrite mechanism.
//!
//! Packs can declare a `card_rewrite` field in their `*.provider_ingress.v1`
//! extension:
//! ```json
//! "card_rewrite": { "marker": "oauth://start", "capability_id": "...", "op": "..." }
//! ```
//! At egress time, for envelopes with `adaptive_card` metadata, this module
//! checks if the card body contains a declared marker and dispatches the
//! corresponding capability to resolve/rewrite it.

use anyhow::{Result, anyhow};
use greentic_types::{ChannelMessageEnvelope, ExtensionInline, decode_pack_manifest};
use serde::Deserialize;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

#[derive(Debug, Clone)]
pub struct CardRewriteDecl {
    pub marker: String,
    pub capability_id: String,
    pub op: String,
}

/// Discover all `card_rewrite` declarations from pack manifests in a bundle.
pub fn discover_card_rewrites_from_bundle(bundle_root: &Path) -> Result<Vec<CardRewriteDecl>> {
    let pack_dirs = [
        bundle_root.join("providers/oauth"),
        bundle_root.join("providers/messaging"),
        bundle_root.join("providers/events"),
        bundle_root.join("providers/state"),
    ];
    let mut rewrites = Vec::new();
    for dir in &pack_dirs {
        if !dir.exists() {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("gtpack") {
                continue;
            }
            if let Ok(pack_rewrites) = read_pack_card_rewrites(&path) {
                rewrites.extend(pack_rewrites);
            }
        }
    }
    Ok(rewrites)
}

fn read_pack_card_rewrites(pack_path: &Path) -> Result<Vec<CardRewriteDecl>> {
    let file = std::fs::File::open(pack_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest_entry = archive.by_name("manifest.cbor")?;
    let mut bytes = Vec::new();
    manifest_entry.read_to_end(&mut bytes)?;
    let manifest = decode_pack_manifest(&bytes)?;

    let mut result = Vec::new();
    if let Some(extensions) = manifest.extensions.as_ref() {
        for (key, ext) in extensions.iter() {
            if !key.ends_with(".provider_ingress.v1") {
                continue;
            }
            if let Some(ExtensionInline::Other(value)) = ext.inline.as_ref()
                && let Some(rewrite) = value.get("card_rewrite")
            {
                let decoded: CardRewriteRecord = serde_json::from_value(rewrite.clone())?;
                result.push(CardRewriteDecl {
                    marker: decoded.marker,
                    capability_id: decoded.capability_id,
                    op: decoded.op,
                });
            }
        }
    }
    Ok(result)
}

#[derive(Deserialize)]
struct CardRewriteRecord {
    marker: String,
    capability_id: String,
    op: String,
}

/// Apply declared rewrites to a single envelope.
///
/// For each matching marker, dispatches the capability and swaps the resolved
/// card in the envelope metadata. The first matching rewrite wins. If dispatch
/// fails, returns the error — caller decides fail-soft vs fail-hard.
pub fn apply_card_rewrites(
    rewrites: &[CardRewriteDecl],
    envelope: &mut ChannelMessageEnvelope,
    mut dispatcher: impl FnMut(&str, &str, &[u8]) -> Result<serde_json::Value>,
) -> Result<()> {
    let Some(card_str) = envelope.metadata.get("adaptive_card").cloned() else {
        return Ok(());
    };

    for decl in rewrites {
        if !card_str.contains(&decl.marker) {
            continue;
        }

        let team = envelope
            .tenant
            .team
            .as_ref()
            .map(|t| t.as_str())
            .or_else(|| envelope.tenant.team_id.as_ref().map(|t| t.as_str()));

        let inner_input = serde_json::json!({
            "adaptive_card": card_str,
            "tenant": envelope.tenant.tenant_id.as_str(),
            "team": team,
            "conversation_id": envelope.session_id,
            "provider_pack_id": "oauth-oidc-generic",
        });
        let input_bytes = serde_json::to_vec(&inner_input)?;
        let result = dispatcher(&decl.capability_id, &decl.op, &input_bytes)?;
        let resolved_card = result
            .get("resolved_card")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("card rewrite response missing resolved_card"))?;
        envelope
            .metadata
            .insert("adaptive_card".to_string(), resolved_card.to_string());
        break; // first matching rewrite wins
    }
    Ok(())
}
