# Fast2Flow routing host: where greentic-start finds it, and how to ship it

A pack that declares `greentic.cap.fast2flow.v1` makes greentic-start ask the
**routing host** (`greentic-fast2flow-routing-host`) where each free-text turn
should go. It is a separate binary from the public
`greenticai/greentic-fast2flow` releases, licensed **Commercial** (not open
source; the repository being public does not change the license). greentic-start
itself never builds or downloads it at run time; the distroless image ships a
pinned copy (see below).

## How greentic-start resolves it

At every routed turn (`src/fast2flow/config.rs`, `src/fast2flow/host_process.rs`):

1. `GREENTIC_FAST2FLOW_HOST_BIN`, when set, is used as-is (an absolute path
   is the safe choice).
2. Otherwise the bare name `greentic-fast2flow-routing-host` is spawned, so the
   OS looks it up on the `PATH` greentic-start itself runs with.

`bin_resolver` (and its unverified auto-install) is NOT used for it.

When the binary cannot be found, the turn **fails open**: on the revision-serve
path the default flow runs, on the legacy path the miss policy applies (see
`docs/fast2flow-miss-and-route-signal.md`). Each such turn logs
`[fast2flow] routing host failed … reason=spawn …`, and once per process (per
host path) greentic-start logs a warn naming where it looked and the two fixes
below.

## On a host: `gtc install`

`gtc install` (`greentic-dev install --tenant`) writes tools into
`$CARGO_HOME/bin`, default `~/.cargo/bin`. That directory is normally on
`PATH`, so the bare-name lookup finds the routing host once a tenant is
entitled to the `greentic-fast2flow-routing-host` descriptor that the
greentic-fast2flow release publishes. If greentic-start runs under a service
manager with a different `PATH`, set `GREENTIC_FAST2FLOW_HOST_BIN` to the
absolute path instead.

The descriptor's Linux entries point at the static musl builds, which run on
any Linux; the gnu build needs glibc 2.38 or newer.

## In the distroless image (shipped by default)

`Dockerfile.distroless` ships the routing host at
`/usr/local/bin/greentic-fast2flow-routing-host` and sets
`GREENTIC_FAST2FLOW_HOST_BIN` to that absolute path, so no deployment needs to
configure anything. `/usr/local/bin` is also on the base image's `PATH`
(`gcr.io/distroless/static-debian12` sets
`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`); the
absolute path is set anyway so the lookup does not depend on a `PATH` an
orchestrator might replace. Setting `GREENTIC_FAST2FLOW_HOST_BIN` on the
container overrides it.

The pinned release is **v1.1.2**. It is fetched anonymously from the public
`greenticai/greentic-fast2flow` GitHub release (the old
`greentic-biz/greentic-fast2flow` URL redirects there) and checked with
`sha256sum -c` against the per-arch digest pinned in the Dockerfile; the
release's own `.sha256` sidecar is never trusted at build time. A mismatch
fails the build.

**License.** The routing host is Commercial software, so every image built
from this Dockerfile with the default build args, including the published
`greentic-start-distroless` images, carries a Commercial binary next to the
open-source greentic-start. It is inert unless a pack declares
`greentic.cap.fast2flow.v1`. Anyone redistributing the image is redistributing
that binary too; build without it (below) if that is not acceptable.

Build args:

| arg | default | meaning |
|---|---|---|
| `FAST2FLOW_ROUTING_HOST_VERSION` | `1.1.2` | release version (a leading `v` is stripped). **Empty turns the routing host OFF.** |
| `FAST2FLOW_ROUTING_HOST_SHA256_AMD64` | digest of the v1.1.2 asset | sha256 of `greentic-fast2flow-routing-host-v<ver>-x86_64-unknown-linux-musl.tar.gz` |
| `FAST2FLOW_ROUTING_HOST_SHA256_ARM64` | digest of the v1.1.2 asset | sha256 of `greentic-fast2flow-routing-host-v<ver>-aarch64-unknown-linux-musl.tar.gz` |
| `FAST2FLOW_ROUTING_HOST_BASE_URL` | `https://github.com/greenticai/greentic-fast2flow/releases/download` | where `v<ver>/<asset>` is fetched from (point it at a mirror for an offline build) |

Moving the version means moving BOTH digests in the same change. Take each
digest from the release you are pinning, ONCE, when you pin it, and check it
against the asset you downloaded rather than copying the sidecar blindly.

To build the image **without** the routing host:

```bash
docker buildx build -f Dockerfile.distroless \
  --build-arg FAST2FLOW_ROUTING_HOST_VERSION= \
  -t greentic-start-distroless .
```

With an empty version the final stage is plain `runtime`, the fetch stage is
never run, and the image is the one built before the routing host was added
(no binary, no `GREENTIC_FAST2FLOW_HOST_BIN`).

The stage needs the **musl** assets (static-pie; no libc in the distroless
base). v1.1.1 shipped gnu assets only and does not work here; v1.1.2 is the
first release with both musl targets.
