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
| `EZPDS_SIGNING_KEY_MASTER_KEY` | Master key (64 hex chars) that seals per-account signing material. |
| `EZPDS_ADMIN_TOKEN` | Bearer token guarding the admin/operator endpoints. |

:::danger[Treat these as crown jewels]
The master key protects every account's signing material. Store it in a secret
manager (agenix / sops / your platform's secret store), never in the repository
or the image, and rotate it deliberately.
:::

## Runtime

| Variable | Role |
| --- | --- |
| `PORT` | Injected by the platform; the server binds it. |
| `EZPDS_PUBLIC_URL` | The externally reachable origin of the PDS. |
| `EZPDS_AVAILABLE_USER_DOMAINS` | Domains users may claim handles on. |

The authoritative list is the PDS configuration type in the codebase; the table
above is the operator-facing subset. The generated version (see the note above)
will make this list exhaustive and drift-proof.
