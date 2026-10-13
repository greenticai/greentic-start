//! A cluster-internal address for the agent card, when no public base URL is
//! known.
//!
//! A worker behind a ClusterIP Service has no tunnel, no `PUBLIC_BASE_URL` and
//! no Cloud Run capture, so it used to answer the card with `503`. Its
//! in-cluster callers (for example a fast2flow router) reach it by the Service
//! DNS name, which arrives as the `Host` header.
//!
//! The card carries a URL the client will call, so `Host` is attacker-chosen
//! input. It is accepted ONLY when it is shaped like an in-cluster Service
//! name: `<service>.<namespace>.svc` or `<service>.<namespace>.svc.cluster.local`,
//! each label a DNS-1123 label, with an optional numeric port. Anything else
//! (an IP, a single label, a public name, a path, userinfo, a trailing dot)
//! yields `None`, and the card stays `503`. The result is plain `http`, which
//! is what an in-cluster Service speaks.

/// `http://<host>` when `host` is a cluster-internal Service name.
pub(crate) fn base_from_host(host: &str) -> Option<String> {
    let host = host.trim();
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) => {
            if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let value: u32 = port.parse().ok()?;
            if value == 0 || value > 65535 {
                return None;
            }
            (name, Some(port))
        }
        None => (host, None),
    };
    let lower = name.to_ascii_lowercase();
    let stem = lower
        .strip_suffix(".svc.cluster.local")
        .or_else(|| lower.strip_suffix(".svc"))?;
    let labels: Vec<&str> = stem.split('.').collect();
    if labels.len() != 2 || !labels.iter().all(|label| is_dns_label(label)) {
        return None;
    }
    let suffix = &lower[stem.len()..];
    Some(match port {
        Some(port) => format!("http://{stem}{suffix}:{port}"),
        None => format!("http://{stem}{suffix}"),
    })
}

/// [`base_from_host`] joined with the unit's mount prefix, the same join the
/// public base URL gets.
pub(crate) fn unit_base(host: &str, mount: &str) -> Option<String> {
    base_from_host(host).map(|base| crate::deployment_routes::public_base_with_mount(&base, mount))
}

fn is_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::{base_from_host, unit_base};

    #[test]
    fn accepts_service_namespace_svc_with_and_without_port() {
        assert_eq!(
            base_from_host("gtc-worker-x.gtc-local.svc:8080").as_deref(),
            Some("http://gtc-worker-x.gtc-local.svc:8080")
        );
        assert_eq!(
            base_from_host("Worker.NS.svc").as_deref(),
            Some("http://worker.ns.svc")
        );
    }

    #[test]
    fn accepts_the_fully_qualified_cluster_local_form() {
        assert_eq!(
            base_from_host("w.ns.svc.cluster.local:8080").as_deref(),
            Some("http://w.ns.svc.cluster.local:8080")
        );
    }

    #[test]
    fn rejects_public_and_look_alike_hosts() {
        for host in [
            "evil.com",
            "w.ns.svc.evil.com",
            "w.ns.svc.cluster.local.evil.com",
            "svc",
            ".svc",
            "ns.svc",
            "a.b.c.svc",
            "10.0.0.1",
            "localhost:8080",
            "w.ns.svc.",
            "w.ns.svc:",
            "w.ns.svc:0",
            "w.ns.svc:99999",
            "w.ns.svc:80a",
            "user@w.ns.svc",
            "w.ns.svc/x",
            "w ns.svc",
            "-w.ns.svc",
            "w_x.ns.svc",
            "",
        ] {
            assert_eq!(base_from_host(host), None, "{host}");
        }
    }

    #[test]
    fn the_unit_mount_is_appended_and_the_root_mount_adds_nothing() {
        assert_eq!(
            unit_base("w.ns.svc:8080", "/support-bot").as_deref(),
            Some("http://w.ns.svc:8080/support-bot")
        );
        assert_eq!(
            unit_base("w.ns.svc:8080", "/").as_deref(),
            Some("http://w.ns.svc:8080")
        );
        assert_eq!(unit_base("evil.com", "/support-bot"), None);
    }
}
