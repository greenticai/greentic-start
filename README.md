# greentic-start

`greentic-start` is the program that opens a Greentic bundle and keeps it running on your machine.

If you are not a systems programmer, a good way to think about it is:

- a **bundle** is a packaged Greentic app
- `greentic-start` is the **launcher**
- it starts the local services that bundle needs
- it keeps logs and runtime state in the bundle folder
- it can also stop or restart that running bundle later

## Who This README Is For

This README is written for:

- people exploring Greentic for the first time
- app builders who are comfortable editing YAML or JSON but do not want to learn the whole runtime internals
- non-technical or lightly technical teammates who need to understand what `greentic-start` does

If you are a coding agent, automation tool, or someone changing runtime behavior, do not use this README as your main source of truth.

Read [docs/coding-agents.md](docs/coding-agents.md) instead.

That guide explains:

- how `greentic-start` is expected to be used
- what commands and options exist
- what each option does
- which behaviors are automatic
- which settings come from the bundle versus the CLI

## What `greentic-start` Does

When you run `greentic-start`, it can:

- find the bundle you want to run
- load the bundle's runtime configuration
- start local services such as the HTTP gateway
- optionally start helper services such as NATS
- optionally create a public tunnel with Cloudflare Tunnel or ngrok
- expose an admin API over mTLS if you enable it
- write logs so you can inspect what happened
- keep runtime state under the bundle's `state/` area

In everyday terms, it is the part that turns “I have a bundle on disk” into “the app is now running locally.”

## The Most Common Thing To Do

Most people only need one command:

```bash
greentic-start start --bundle /path/to/your-bundle
```

This starts the bundle using its own configuration files.

If your bundle is already the current folder, you will often see people use:

```bash
greentic-start start --bundle .
```

In some situations, `greentic-start` may choose a tunnel automatically for local development. That is normal behavior in this project.

## The Main Commands

`greentic-start` has four main commands:

- `start`
  Starts the bundle.
- `up`
  Same meaning as `start`.
- `stop`
  Stops a running bundle.
- `restart`
  Starts again, and can also restart selected runtime services.

Examples:

```bash
greentic-start start --bundle /tmp/my-bundle
greentic-start stop --bundle /tmp/my-bundle
greentic-start restart --bundle /tmp/my-bundle
```

## A Few Practical Examples

### Start a bundle quietly

```bash
greentic-start start --bundle /tmp/my-bundle --quiet
```

This reduces log noise on the terminal.

### Start a bundle and show more detail

```bash
greentic-start start --bundle /tmp/my-bundle --verbose
```

This is useful when something is not working and you want more clues.

### Start with ngrok instead of Cloudflare Tunnel

```bash
greentic-start start --bundle /tmp/my-bundle --ngrok on
```

### Start with an external NATS server

```bash
greentic-start start \
  --bundle /tmp/my-bundle \
  --nats external \
  --nats-url nats://127.0.0.1:4222
```

### Enable the admin API

```bash
greentic-start start --bundle /tmp/my-bundle --admin --admin-port 8443
```

This enables a protected admin endpoint intended for operational control.

## What You Need Before Starting

Usually you need:

- a Greentic bundle on disk
- any required local tools your bundle expects
- setup answers or secrets already provided if the bundle depends on them

Important detail:

- `greentic-start` starts and hosts the bundle
- it does **not** invent missing app configuration on its own
- if your app flow needs explicit runtime config in a node, that config still has to come from the bundle design or runtime contract that supports it

## Where Things Are Stored

When the bundle runs, `greentic-start` writes data into the bundle area, especially:

- `logs/`
- `state/`
- `.greentic/` for some persisted setup/runtime helpers

This means the bundle folder is not just input; it also becomes the local runtime workspace.

## Troubleshooting Basics

If something seems wrong, check these first:

- did you point `--bundle` at the right directory?
- does the bundle have the expected config files?
- are required secrets already provisioned?
- are the ports already in use by another process?
- did the logs in `logs/` show a startup or policy error?

Good first debugging steps:

```bash
greentic-start start --bundle /tmp/my-bundle --verbose
```

Then inspect:

- `logs/flow.log`
- `logs/operator.log`
- bundle `state/` output for the specific run

## For Coding Agents And Maintainers

If you are changing code, reviewing runtime behavior, or trying to automate `greentic-start`, go to [docs/coding-agents.md](docs/coding-agents.md).

That document is the operational guide for:

- command behavior
- option-by-option meaning
- bundle resolution
- automatic tunnel behavior
- restart semantics
- admin API flags
- logging and runtime expectations

## Repository Notes

This repository focuses on lifecycle execution for Greentic bundles. It is not the place for every product-level behavior in the broader platform.

If you need deeper ownership boundaries, see [docs/ownership.md](docs/ownership.md).
