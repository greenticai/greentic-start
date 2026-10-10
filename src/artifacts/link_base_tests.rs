use super::link::LinkPath;
use super::link_base::{LinkBase, link_base, link_url};

fn abs(s: &str) -> LinkBase {
    LinkBase::Absolute(s.to_string())
}

#[test]
fn configured_wins_then_captured_then_tunnel() {
    let c = Some("https://configured.example");
    let r = Some("https://svc-abc.a.run.app");
    let t = Some("https://tunnel.trycloudflare.com");
    assert_eq!(link_base(c, r, t), abs("https://configured.example"));
    assert_eq!(link_base(None, r, t), abs("https://svc-abc.a.run.app"));
    assert_eq!(
        link_base(None, None, t),
        abs("https://tunnel.trycloudflare.com")
    );
    assert_eq!(
        link_base(Some("  "), None, t),
        abs("https://tunnel.trycloudflare.com")
    );
    assert_eq!(link_base(None, None, None), LinkBase::RelativeOnly);
}

#[test]
fn a_configured_url_that_is_not_usable_is_never_replaced_by_a_guess() {
    // An operator-configured value always wins; an unusable one disables
    // absolute links rather than silently falling through to another source.
    assert_eq!(
        link_base(
            Some("http://public.example"),
            Some("https://x.run.app"),
            None
        ),
        LinkBase::RelativeOnly
    );
}

#[test]
fn https_is_required_except_to_loopback() {
    assert_eq!(
        link_base(Some("http://public.example"), None, None),
        LinkBase::RelativeOnly
    );
    assert_eq!(
        link_base(Some("http://10.0.0.5:8080"), None, None),
        LinkBase::RelativeOnly
    );
    assert_eq!(
        link_base(Some("http://127.0.0.1:8080"), None, None),
        abs("http://127.0.0.1:8080")
    );
    assert_eq!(
        link_base(Some("http://127.9.9.9"), None, None),
        abs("http://127.9.9.9")
    );
    assert_eq!(
        link_base(Some("http://localhost:3000/"), None, None),
        abs("http://localhost:3000")
    );
    assert_eq!(
        link_base(Some("http://[::1]:8080"), None, None),
        abs("http://[::1]:8080")
    );
    assert_eq!(
        link_base(Some("ftp://files.example"), None, None),
        LinkBase::RelativeOnly
    );
    assert_eq!(
        link_base(Some("localhost:8080"), None, None),
        LinkBase::RelativeOnly
    );
}

#[test]
fn the_base_is_a_bare_origin() {
    assert_eq!(
        link_base(Some("https://x.run.app/"), None, None),
        abs("https://x.run.app")
    );
    assert_eq!(
        link_base(Some("HTTPS://X.Run.App"), None, None),
        abs("https://x.run.app")
    );
    for bad in [
        "https://user:pw@x.run.app",
        "https://user@x.run.app",
        "https://x.run.app/?a=b",
        "https://x.run.app/#frag",
        "https://x.run.app/mount",
        "https://x.run.app/mount/",
        "not a url",
    ] {
        assert_eq!(
            link_base(Some(bad), None, None),
            LinkBase::RelativeOnly,
            "{bad}"
        );
    }
}

#[test]
fn a_link_url_joins_the_origin_and_the_path() {
    let path = LinkPath {
        deployment: "01J0000000000000000000000A".into(),
        artifact_hex: "a".repeat(64),
        exp: 1_800_086_400,
        mac_hex: "0".repeat(32),
    };
    assert_eq!(
        link_url(&abs("https://x.run.app"), &path),
        format!("https://x.run.app{}", path.to_path())
    );
    assert_eq!(link_url(&LinkBase::RelativeOnly, &path), path.to_path());
}
