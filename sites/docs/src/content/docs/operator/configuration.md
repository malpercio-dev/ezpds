---
title: Configuration
description: The configuration and environment surface that tunes a deployment.
---

A Custos deployment is configured through environment variables and a small set
of runtime settings. This page is the operator's map of that surface.

:::note[This page will become generated]
In a later phase this reference is generated directly from the PDS configuration
type in Rust (serde field names + doc-comments), and a `just docs-check` parity
gate fails the build when a config field has no entry here — the same anti-drift
model as `just bruno-check`. Until then, treat this as the hand-authored scaffold.
:::

## Secrets

These are injected at runtime and never baked into the image:

| Variable | Role |
| --- | --- |
| `EZPDS_SIGNING_KEY_MASTER_KEY` | Master key (64 hex chars = 32 bytes) — the AES-256-GCM key that encrypts all at-rest signing material: every account's repo signing key, the server's OAuth signing key, the JWT secret, and the node identity. |
| `EZPDS_ADMIN_TOKEN` | Bearer token guarding the admin/operator endpoints. |

:::danger[The master key must never change out from under the database]
The master key **is** the AES-256-GCM key those secrets are encrypted with; it is
used directly. Changing the environment variable alone on a populated instance
makes all existing secrets undecryptable — the server fails to load account repo
signing keys, and repo writes break. **Losing it is unrecoverable.** So: store it
in a secret manager (agenix / sops / your platform's secret store) never in the
repository or the image, and back it up.
:::

Rotation is supported, but only as a deliberate offline operation: the
`pds rewrap-master-key` subcommand re-encrypts every stored secret from the old
key to the new one in a single atomic transaction, with the server stopped. Old
and new keys are supplied via `EZPDS_REWRAP_OLD_MASTER_KEY` /
`EZPDS_REWRAP_NEW_MASTER_KEY` environment variables (never CLI arguments), a
wrong old key aborts with no writes, and only after the re-wrap succeeds do you
point `EZPDS_SIGNING_KEY_MASTER_KEY` at the new key and restart. Never rotate by
changing the environment variable alone.

## Runtime

| Variable | Role |
| --- | --- |
| `PORT` | Injected by the platform; the server binds it. |
| `EZPDS_PUBLIC_URL` | The externally reachable origin of the PDS. |
| `EZPDS_AVAILABLE_USER_DOMAINS` | Domains users may claim handles on. |

The authoritative list is the PDS configuration type in the codebase; the table
above is the operator-facing subset. The generated version (see the note above)
will make this list exhaustive and drift-proof.
