//! D7 gate for provider setup surfaces on the legacy `--bundle` listener.
//!
//! The revision listener gates a setup surface in `revision_serve`; this is the
//! same decision for the single-bundle boot, where a non-loopback peer (a
//! tunnel exposes the box, a bind to `0.0.0.0` reaches the LAN) would otherwise
//! reach a wizard that starts real logins. Same verdict function, same
//! credential, same refusal — see [`crate::ingress_auth`].
//!
//! The legacy boot has no deployment, so the "unit" the credential is read for
//! is the bundle directory's name, under the `{tenant}` of the declared path
//! (`default` when the path has none).

use std::net::SocketAddr;

use http_body_util::Full;
use hyper::{Request, Response, body::Bytes};

use super::HttpIngressState;
use crate::ingress_auth;

/// The remote address of a connection, recorded on each request by the accept
/// loop. A request without one (an in-process caller) is treated as REMOTE:
/// the safe reading when trust cannot be established.
#[derive(Clone, Copy, Debug)]
pub(super) struct PeerAddr(pub SocketAddr);

/// `Ok(true)`: the path is a setup surface and the caller may proceed (the
/// response must then be hardened). `Ok(false)`: not a setup surface.
/// `Err`: the refusal to return.
pub(super) async fn gate<B>(
    req: &Request<B>,
    path: &str,
    state: &HttpIngressState,
) -> Result<bool, Response<Full<Bytes>>> {
    let Some(matched) = state
        .active_route_table
        .setup_surfaces()
        .match_request(path, None)
    else {
        return Ok(false);
    };
    let peer_is_loopback = req
        .extensions()
        .get::<PeerAddr>()
        .is_some_and(|peer| peer.0.ip().to_canonical().is_loopback());
    let gate_enabled = ingress_auth::generic_ingress_auth_enabled(
        std::env::var(ingress_auth::GENERIC_INGRESS_AUTH_ENV)
            .ok()
            .as_deref(),
    );
    if peer_is_loopback || !gate_enabled {
        return Ok(true);
    }
    let bundle_id = state
        .runner_host
        .bundle_root()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bundle")
        .to_string();
    let tenant = matched.tenant.as_deref().unwrap_or("default");
    let secrets = state.runner_host.secrets_manager();
    let env = crate::resolve_env(None);
    let config = ingress_auth::load_unit_config(secrets.as_ref(), &env, tenant, &bundle_id).await;
    let authorization = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let verdict = ingress_auth::decide_generic(
        peer_is_loopback,
        gate_enabled,
        &config,
        authorization,
        ingress_auth::now_ms(),
    );
    match ingress_auth::refusal(&verdict, &config, &bundle_id) {
        None => Ok(true),
        Some(response) => Err(response),
    }
}
