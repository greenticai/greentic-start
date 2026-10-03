#!/usr/bin/env python3
"""Register the greentic-start distroless image as a platform release.

UNARMED by default: nothing is sent unless BOTH ADMIN (the admin base URL) and
KEY (a `gts_` key scoped `release_publisher`) are set and DRY_RUN is not
"true". The request body is always written to OUT so it can be inspected as a
workflow artifact. See docs/runtime-release-registration.md.

Environment: DIGEST (sha256:<64 lowercase hex>, the image INDEX digest),
VERSION (semver, no leading "v"), GITHUB_SHA, ADMIN, KEY, DRY_RUN, OUT.

Exit codes: 0 success / unarmed / dry run (invalid input only warns when
unarmed); 1 admin refused (409 included) or transport error; 2 invalid input
when armed.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# https://semver.org official regex.
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
SOURCE_REPO = "greenticai/greentic-start"
IMAGE = "ghcr.io/greenticai/greentic-start-distroless"
ARTIFACT_NAME = "greentic-start-distroless"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"


def build_request(version, digest, sha):
    """Exactly one runtime-image artifact, so the release is executable."""
    if not SEMVER_RE.match(version):
        raise ValueError(f"version {version!r} is not semver (no leading 'v')")
    if not DIGEST_RE.match(digest):
        raise ValueError(f"digest {digest!r} is not sha256:<64 lowercase hex>")
    return {
        "kind": "platform",
        "publisher": f"github:{SOURCE_REPO}",
        "name": "greentic-start",
        "version": version,
        "artifacts": [
            {
                "name": ARTIFACT_NAME,
                "version": version,
                "digest": digest,
                "media_type": OCI_INDEX,
                "source": IMAGE,
            }
        ],
        "dependencies": [],
        "compatibility": {},
        "provenance": {
            "source_repo": SOURCE_REPO,
            "source_revision": sha,
            "builder": "github-actions",
        },
        "rollback": {"supported": True},
        "migrations": [],
    }


def main(env=None):
    env = os.environ if env is None else env
    version = env.get("VERSION", "")
    digest = env.get("DIGEST", "")
    sha = env.get("GITHUB_SHA", "")
    out = env.get("OUT") or "release-request.json"
    admin = env.get("ADMIN", "").strip()
    key = env.get("KEY", "")
    dry_run = env.get("DRY_RUN", "").strip().lower() == "true"
    armed = bool(admin and key) and not dry_run
    try:
        body = build_request(version, digest, sha)
    except ValueError as err:
        if armed:
            print(f"::error::{err}")
            return 2
        # Unarmed must never fail the image publish.
        print(f"::warning::release request not buildable (unarmed, ignored): {err}")
        return 0
    payload = json.dumps(body, indent=2, sort_keys=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(payload + "\n")
    print(payload)

    if dry_run:
        print("::notice::dry run: release request written, nothing sent.")
        return 0
    if not armed:
        print(
            "::notice::RELEASE_ADMIN_URL / RELEASE_PUBLISHER_KEY not set: "
            "release not registered (unarmed)."
        )
        return 0

    req = urllib.request.Request(
        admin.rstrip("/") + "/api/v1/releases",
        data=payload.encode("utf-8"),
        method="POST",
        headers={
            "authorization": f"Bearer {key}",
            "idempotency-key": f"{ARTIFACT_NAME}-{version}",
            "content-type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            status = resp.status
            text = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        status = err.code
        text = err.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as err:
        print(f"::error::registration transport error: {err}")
        return 1
    if status in (200, 201):
        print(f"registered runtime release {version} (HTTP {status})")
        return 0
    if status == 409:
        print(
            f"::error::release {version} already exists with different content "
            f"(409 release_version_immutable): {text}"
        )
        return 1
    print(f"::error::registration refused: HTTP {status}: {text}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
