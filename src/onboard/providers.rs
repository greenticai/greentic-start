use hyper::StatusCode;
use serde_json::{Value, json};

use crate::domains::{self, Domain};
use crate::operator_log;
use crate::{project, provider_config_envelope};

use super::api::{OnboardResult, OnboardState, error_response, into_error, json_ok};

/// GET /api/onboard/providers
///
/// Lists available provider packs across all domains.
pub fn list_providers(state: &OnboardState) -> OnboardResult {
    let bundle_root = state.runner_host.bundle_root();
    let mut providers = Vec::new();

    for domain in [Domain::Messaging, Domain::Events] {
        let packs = domains::discover_provider_packs(bundle_root, domain).map_err(|err| {
            operator_log::error(
                module_path!(),
                format!("[onboard] discover packs domain={:?}: {err}", domain),
            );
            into_error(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("discover packs: {err}"),
            ))
        })?;

        let domain_name = domains::domain_name(domain);
        for pack in &packs {
            let display_name = pack
                .pack_id
                .strip_prefix("messaging-")
                .or_else(|| pack.pack_id.strip_prefix("events-"))
                .unwrap_or(&pack.pack_id);
            let display_name = capitalize(display_name);

            providers.push(json!({
                "pack_id": pack.pack_id,
                "domain": domain_name,
                "file_name": pack.file_name,
                "display_name": display_name,
                "entry_flows": pack.entry_flows,
            }));
        }
    }

    operator_log::info(
        module_path!(),
        format!("[onboard] listed {} provider packs", providers.len()),
    );

    json_ok(json!({
        "providers": providers
    }))
}

/// GET /api/onboard/tenants
///
/// Lists available tenants and teams from the bundle directory.
pub fn list_tenants(state: &OnboardState) -> OnboardResult {
    let bundle_root = state.runner_host.bundle_root();
    let tenants_dir = bundle_root.join("tenants");

    let mut tenants = Vec::new();

    if tenants_dir.exists() {
        let entries = std::fs::read_dir(&tenants_dir).map_err(|err| {
            into_error(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("read tenants dir: {err}"),
            ))
        })?;

        for entry in entries.flatten() {
            if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                continue;
            }
            let tenant_name = entry.file_name().to_string_lossy().to_string();
            let mut teams = Vec::new();

            let teams_dir = entry.path().join("teams");
            if teams_dir.exists()
                && let Ok(team_entries) = std::fs::read_dir(&teams_dir)
            {
                for team_entry in team_entries.flatten() {
                    if team_entry
                        .file_type()
                        .map(|ft| ft.is_dir())
                        .unwrap_or(false)
                    {
                        teams.push(team_entry.file_name().to_string_lossy().to_string());
                    }
                }
            }

            tenants.push(json!({
                "tenant": tenant_name,
                "teams": teams,
            }));
        }
    }

    // Always include "default" if not present
    if !tenants.iter().any(|t| t["tenant"] == "default") {
        tenants.insert(
            0,
            json!({
                "tenant": "default",
                "teams": [],
            }),
        );
    }

    json_ok(json!({ "tenants": tenants }))
}

/// GET /api/onboard/status
///
/// Returns deployment status for configured providers.
pub fn deployment_status(state: &OnboardState) -> OnboardResult {
    let bundle_root = state.runner_host.bundle_root();
    let mut deployed = Vec::new();

    // Check for provider config envelopes
    let providers_dir = bundle_root.join(".providers");
    if providers_dir.exists()
        && let Ok(entries) = std::fs::read_dir(&providers_dir)
    {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let provider_id = entry.file_name().to_string_lossy().to_string();
                // Skip internal directories (e.g. _contracts)
                if provider_id.starts_with('_') {
                    continue;
                }
                // Look for config files inside (yaml, json, cbor — skip .bak)
                let mut config_files = Vec::new();
                if let Ok(config_entries) = std::fs::read_dir(entry.path()) {
                    for config_entry in config_entries.flatten() {
                        let name = config_entry.file_name().to_string_lossy().to_string();
                        if name.ends_with(".bak") {
                            continue;
                        }
                        if name.ends_with(".yaml")
                            || name.ends_with(".json")
                            || name.ends_with(".cbor")
                        {
                            config_files.push(name);
                        }
                    }
                }
                // Read metadata from config envelope
                let envelope_config =
                    provider_config_envelope::read_provider_config_envelope(
                        &providers_dir,
                        &provider_id,
                    )
                    .ok()
                    .flatten()
                    .map(|env| env.config);

                let mut entry_json = json!({
                    "provider_id": provider_id,
                    "configured": true,
                    "config_files": config_files,
                });
                if let Some(ref cfg) = envelope_config {
                    if let Some(label) = cfg.get("instance_label").and_then(Value::as_str) {
                        entry_json["instance_label"] = Value::String(label.to_string());
                    }
                    if let Some(t) = cfg.get("_scope_tenant").and_then(Value::as_str) {
                        entry_json["scope_tenant"] = Value::String(t.to_string());
                    }
                    if let Some(t) = cfg.get("_scope_team").and_then(Value::as_str) {
                        entry_json["scope_team"] = Value::String(t.to_string());
                    }
                }
                deployed.push(entry_json);
            }
        }
    }

    // Also check gmap for policy entries
    let gmap_path = bundle_root.join("tenants/default/tenant.gmap");
    let gmap_entries = if gmap_path.exists() {
        std::fs::read_to_string(&gmap_path).unwrap_or_default()
    } else {
        String::new()
    };

    json_ok(json!({
        "deployed": deployed,
        "gmap_raw": gmap_entries,
    }))
}

/// POST /api/onboard/tenants/create
///
/// Creates a new tenant directory.
/// Body: `{ "tenant": "my-tenant" }`
pub fn create_tenant(state: &OnboardState, body: &Value) -> OnboardResult {
    let tenant = body["tenant"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if tenant.is_empty() {
        return Err(into_error(error_response(
            StatusCode::BAD_REQUEST,
            "tenant name is required",
        )));
    }
    if !is_valid_identifier(&tenant) {
        return Err(into_error(error_response(
            StatusCode::BAD_REQUEST,
            "tenant name must be alphanumeric with hyphens only",
        )));
    }

    let bundle_root = state.runner_host.bundle_root();
    project::add_tenant(bundle_root, &tenant).map_err(|err| {
        operator_log::error(
            module_path!(),
            format!("[onboard] create tenant {tenant}: {err}"),
        );
        into_error(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("create tenant: {err}"),
        ))
    })?;

    operator_log::info(
        module_path!(),
        format!("[onboard] created tenant: {tenant}"),
    );

    list_tenants(state)
}

/// POST /api/onboard/tenants/teams/create
///
/// Creates a new team under a tenant.
/// Body: `{ "tenant": "my-tenant", "team": "sales" }`
pub fn create_team(state: &OnboardState, body: &Value) -> OnboardResult {
    let tenant = body["tenant"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let team = body["team"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if tenant.is_empty() {
        return Err(into_error(error_response(
            StatusCode::BAD_REQUEST,
            "tenant name is required",
        )));
    }
    if team.is_empty() {
        return Err(into_error(error_response(
            StatusCode::BAD_REQUEST,
            "team name is required",
        )));
    }
    if !is_valid_identifier(&tenant) {
        return Err(into_error(error_response(
            StatusCode::BAD_REQUEST,
            "tenant name must be alphanumeric with hyphens only",
        )));
    }
    if !is_valid_identifier(&team) {
        return Err(into_error(error_response(
            StatusCode::BAD_REQUEST,
            "team name must be alphanumeric with hyphens only",
        )));
    }

    let bundle_root = state.runner_host.bundle_root();
    project::add_team(bundle_root, &tenant, &team).map_err(|err| {
        operator_log::error(
            module_path!(),
            format!("[onboard] create team {tenant}/{team}: {err}"),
        );
        into_error(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("create team: {err}"),
        ))
    })?;

    operator_log::info(
        module_path!(),
        format!("[onboard] created team: {tenant}/{team}"),
    );

    list_tenants(state)
}

/// Validate an identifier: non-empty, lowercase alphanumeric + hyphens, no leading/trailing hyphens.
fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => format!("{}{}", c.to_ascii_uppercase(), chars.as_str()),
        None => String::new(),
    }
}
