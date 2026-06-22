---
type: entity
category: project
created: 2026-06-22
updated: 2026-06-22
sources: [sources/SRC-2026-06-22-001, sources/SRC-2026-06-22-002, sources/SRC-2026-06-22-003]
---

# Relay Server

The Axum-based HTTP server and the sole [[concepts/functional-core-imperative-shell|Imperative Shell]] in the [[concepts/ezpds-workspace|ezpds workspace]]. It is the only crate that touches SQLite (via [[entities/sqlx|sqlx]]), handles HTTP, or manages process-level state.

## Purpose

Implements the ATProto provisioning API, XRPC endpoints, and OAuth 2.0 flows. Stores accounts, DIDs, handles, and signing keys in SQLite.

## Module Structure

- **`auth/`** — Authentication primitives (no HTTP, no DB schema ownership). Submodules: `jwt.rs` (Functional Core), `password.rs` (Functional Core), `rate_limit.rs` (Functional Core), `bearer.rs` (Functional Core), `extractors.rs` (Imperative Shell), `signing_key.rs` (Imperative Shell), `dpop.rs` (Mixed).
- **`db/`** — SQL query functions by domain entity. Submodules: `accounts.rs`, `oauth.rs`, `password_reset.rs`. Each accepts `&SqlitePool` and returns data.
- **`routes/`** — One file per HTTP endpoint. Each handler is a thin Imperative Shell: gather → process → respond. ~30 route files covering provisioning, XRPC, OAuth, and well-known endpoints.

## Key Rules

1. **Routes must not import from other routes.** Shared logic belongs in `auth/` or `db/`.
2. **Every `.rs` file with runtime behavior must have a pattern comment.**
3. **`db/` submodules own queries, not transactions.** Multi-table transactions live in route handlers.

## Endpoints

**Provisioning API** (`/v1/...`): Account creation (desktop + mobile), DID creation, handle registration, device registration, relay signing key management.

**XRPC** (`/xrpc/...`): `com.atproto.server.createSession` / `getSession` / `refreshSession` / `deleteSession`, `com.atproto.server.describeServer`, `com.atproto.identity.resolveHandle`, catch-all for unimplemented NSIDs.

**OAuth 2.0** (`/oauth/...`): Authorization server metadata, authorize, PAR, token exchange, JWKS, client metadata.

## Related

- [[entities/crypto|Crypto Crate]] — Called by relay for key generation and did:plc operations
- [[entities/db|DB Module]] — SQLite query layer
- [[entities/auth|Auth Module]] — Authentication primitives
- [[concepts/functional-core-imperative-shell|Functional Core / Imperative Shell]]
- [[sources/SRC-2026-06-22-003]] — Full architecture documentation
