//! Shared Redis-over-TLS bootstrap.
//!
//! Enabling the `redis` crate's rustls features (see `Cargo.toml`) is a
//! crate-global switch: *every* `redis::Client` in this binary then accepts
//! `rediss://`. redis builds its TLS `ClientConfig` through
//! `rustls::ClientConfig::builder()` (redis `connection.rs`), which reads the
//! process-global default [`rustls::crypto::CryptoProvider`]; with both `ring`
//! and `aws-lc-rs` in the dependency tree rustls cannot auto-select a backend
//! and that builder **panics**. So every `rediss://` connection site must call
//! [`ensure_crypto_provider_for`] before constructing its `ConnectionManager` —
//! today that is [`crate::revision_pin::RedisPinStore::from_url`] and
//! [`crate::notifier::redis::RedisNotifier::build`].

/// True for a Redis URL whose scheme requires TLS (`rediss://`).
fn is_tls_url(url: &str) -> bool {
    url.split_once("://")
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("rediss"))
}

/// Install a process-default rustls crypto provider (ring) the first time a TLS
/// Redis endpoint is opened. A no-op for plaintext `redis://` URLs, so a
/// deployment that never uses TLS pays nothing. Idempotent: if another
/// component installed a provider first it wins and the returned error is
/// ignored. ring matches the backend `admin_server`/`admin_relay` already use.
///
/// Call this immediately before opening any `redis::Client`, not at a single
/// caller — the panic fires from whichever `rediss://` connection runs first.
pub(crate) fn ensure_crypto_provider_for(url: &str) {
    use std::sync::Once;
    if !is_tls_url(url) {
        return;
    }
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_tls_url_detects_rediss_scheme() {
        assert!(is_tls_url("rediss://cache:6380/0"));
        assert!(is_tls_url("REDISS://cache:6380")); // scheme is case-insensitive
        assert!(!is_tls_url("redis://cache:6379/0"));
        assert!(!is_tls_url("cache:6379")); // no scheme
    }

    #[test]
    fn crypto_provider_install_lets_rustls_build_a_client_config() {
        // Without a default provider installed, `ClientConfig::builder()` panics
        // when both ring and aws-lc-rs are compiled in. Verify the guard (rediss://,
        // not the plaintext no-op) prevents that — reproduces redis' TLS path, no I/O.
        ensure_crypto_provider_for("redis://plaintext:6379"); // no-op
        ensure_crypto_provider_for("rediss://cache.example:6380"); // installs
        let _config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
    }
}
