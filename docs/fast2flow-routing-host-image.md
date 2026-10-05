# Fast2Flow routing host: where greentic-start finds it, and how to ship it

A pack that declares `greentic.cap.fast2flow.v1` makes greentic-start ask the
**routing host** (`greentic-fast2flow-routing-host`) where each free-text turn
should go. It is a separate, commercial binary from the private
`greentic-biz/greentic-fast2flow` releases. Nothing in greentic-start builds
or downloads it.

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

## In the distroless image (opt-in, OFF by default)

`Dockerfile.distroless` can copy the routing host into `/usr/local/bin`, which
is on the image `PATH`, so the bare-name lookup finds it. It is OFF by default:
with no build args the final image is the same image as before this option
existed (the fetch stage is never run; verified by comparing the OCI manifest
digest of a reproducible build with and without the change).

It is opt-in on purpose. The routing host is a commercial binary, and baking it
into an image, especially a published one, is a licensing decision, not a
build setting.

Build args:

| arg | meaning |
|---|---|
| `FAST2FLOW_ROUTING_HOST_VERSION` | release version, e.g. `1.2.0` (a leading `v` is stripped). Non-empty turns the option ON. |
| `FAST2FLOW_ROUTING_HOST_SHA256_AMD64` | sha256 of `greentic-fast2flow-routing-host-v<ver>-x86_64-unknown-linux-musl.tar.gz` |
| `FAST2FLOW_ROUTING_HOST_SHA256_ARM64` | sha256 of `greentic-fast2flow-routing-host-v<ver>-aarch64-unknown-linux-musl.tar.gz` |
| `FAST2FLOW_ROUTING_HOST_BASE_URL` | where `v<ver>/<asset>` is fetched from; defaults to the GitHub release download URL |

The digest for the platform being built is required and checked with
`sha256sum -c`; the release's own `.sha256` sidecar is never trusted at build
time. Take the digest from the release you are pinning, ONCE, when you pin it.

```bash
docker buildx build -f Dockerfile.distroless \
  --build-arg FAST2FLOW_ROUTING_HOST_VERSION=1.2.0 \
  --build-arg FAST2FLOW_ROUTING_HOST_SHA256_AMD64=<64 hex> \
  --build-arg FAST2FLOW_ROUTING_HOST_BASE_URL=https://mirror.internal/fast2flow \
  -t greentic-start-fast2flow .
```

**The release repository is private**, so the default base URL answers 404 to
an anonymous fetch and the build fails. Either point
`FAST2FLOW_ROUTING_HOST_BASE_URL` at a location that serves the asset (an
internal mirror), or add a BuildKit secret mount
(`RUN --mount=type=secret,id=…`) to that stage's `curl`. No secret mount is
included, and no token must ever be passed as a build arg: build args are
recorded in the image history.

The stage needs the **musl** assets. They exist only in greentic-fast2flow
releases built after the musl rows were added to its release matrix; v1.1.1
ships gnu assets only, which do not run in this image.

Inside the image no environment variable is needed. To use a different copy,
set `GREENTIC_FAST2FLOW_HOST_BIN`.
