# custos-agents

Last verified: 2026-10-22

The auth.md agent feature crate: the `/auth.md` document, agent registration, the owner-confirmed
claim ceremony, sovereign child agents, the provider event endpoint, the owner's `/v1/agents`
management API, the claim-attempt expiry sweep, and the `agents` capability entry. It depends on
[`custos-core`](../custos-core/AGENTS.md) and [`custos-db`](../custos-db/AGENTS.md), never on `pds`
or a sibling feature. The token endpoint's agent grants (jwt-bearer, claim polling) are
[`custos-oauth`](../custos-oauth/AGENTS.md)'s; the machinery both share lives below them
(`custos_core::auth::agent_assertion`, `CoreState.poll_tracker`, `custos_db::{agent_auth,
agent_audit}`). The feature-crate contract is
[`custos-spaces`' map](../custos-spaces/AGENTS.md#what-pds-consumes); this crate owns no state.

The cross-endpoint journeys (register → claim → token exchange → revoke) span this crate and
`custos-oauth`, so they live in `pds`'s `routes/agent_auth_test.rs`, against the full app.

This file is a map; mechanism and invariants live in each module's `//!` doc.

## What `pds` consumes

| Export | Use in `pds` |
|---|---|
| `router()` / `internal_router()` | merged into `app.rs`'s public (CORS'd) and `/v1/*` (no-CORS) groups before the layer stack. No router gate: each registration flow checks its own `[agent_auth]` switch |
| `spawn_sweeps(&mut Scheduler, &AgentAuthConfig)` | `main.rs`; registers the claim-attempt expiry sweep on `pds`'s scheduler |
| `CAPABILITY` | `agents`, listed in `pds`'s `CAPABILITIES` in its original slot |
| `purge_account_rows` / `PURGE_ACCOUNT_SQL` / `child_dids` | `account_delete::purge_account` reads `child_dids` to cascade-schedule a parent's children, then runs `purge_account_rows` inside its transaction; its schema-walking FK test reads `PURGE_ACCOUNT_SQL` |
| `test_support` (`test-support` feature) | `test_app(state)`, `post_json_with_bearer`, the sovereign-child fixtures (`state_with_plc`, `state_with_grace`, `mint_child_for`, `child_request`) `pds`'s account-reaper test uses, plus `custos_core::test_support` re-exported |

`purge.rs` owns which `agent_*` rows an account purge removes; `pds` owns the ordering and the
child cascade. Its test walks the schema's account FKs on `agent_*` tables, so a new agent table
without a purge statement fails here.

## Module Map

```
src/
  lib.rs            — the exports above; aliases `custos_core`'s `auth`, `firehose`, `identity`, `metrics`, `sweep`, `sweep_status` at the crate root so the moved files' `crate::…` paths resolve
  router.rs         — both route tables (`scripts/bruno-parity.sh` and `scripts/generate-docs-reference.mjs` read its `.route(` literals)
  capability.rs     — `CAPABILITY`, the `agents` entry of the `describeServer` table
  agent_child_core.rs  — the verify → provision → publish → finalize core behind sovereign child accounts, shared by every route that provisions one; resumable rather than atomic, because the plc.directory publish can't join a SQLite transaction; its steps run under `ceremony_journal::Journal`, with the provisioning row as the cursor — see module doc
  purge.rs          — this crate's account-purge step (`PURGE_ACCOUNT_SQL`, `purge_account_rows`, `child_dids`) — see module doc
  agent_claim_sweep.rs — periodic sweep flipping lapsed agent claim attempts to `expired` — see module doc
  db/               — `agent_child_deletions.rs` (below); `custos_db` is re-exported crate-privately
  routes/           — one file per surface (table below); private, only handler functions leave it
  test_support.rs   — `test-support` feature (and this crate's own tests): `test_app` wraps both routers in the layers `pds` applies, so a path no agents route claims is a plain 404 here
```

### `db/`

- `agent_child_deletions.rs` - Query functions for V049 (see "Latest Updates"): `upsert_child_deletion` (record a parent's child-deletion tombstone, generic over the executor so it writes inside the schedule transaction; `INSERT … ON CONFLICT(child_did)` makes a re-delete idempotent) and `list_child_deletions_of_parent` (newest-first, for the parent's durable audit view). The tombstone deliberately survives the child's purge; the purge step reclaims it only when the parent is deleted.

### `routes/`

| File | Endpoint |
|---|---|
| `auth_md.rs` | `GET /auth.md` — the auth.md document, rendered from `assets/auth.md` with this instance's URLs |
| `agent_identity.rs` | `POST /agent/identity` — auth.md registration (Step 3), dispatching on `type` (`identity_assertion`/`service_auth`/`anonymous`); every flow operator-opt-in, scopes clamped to current config — see module doc |
| `agent_claim.rs` | `POST /agent/identity/claim` + `/claim/confirm` — the auth.md claim ceremony (Step 4): public agent initiate, owner-authed confirm flips `active → claimed`; polling collection lives at the token endpoint. Confirm has two arms — bind the agent to the confirming account, or (with a `child` block, ownerless anonymous registrations only) mint it an account of its own via `agent_child_core.rs` and convert the registration in place — see module doc |
| `agent_child.rs` | `POST /agent/child` (mint), `GET /agent/child` (list), `POST /agent/child/{assertion,revoke,delete}` — parent-owned sovereign child agents; the mint body lives in `agent_child_core.rs` so the claim ceremony can share it. Owner-guarded throughout: agent-derived callers are refused, a foreign child DID is a uniform 404, and its lifecycle verbs are the custody ladder (renew the capability / revoke it / schedule the hosting for deletion) — see module doc |
| `agent_event.rs` | `POST /agent/event/notify` — auth.md `events_endpoint`: a trusted-issuer SET (RFC 8417/8935) revokes the matching registration; idempotent 202 — see module doc |
| `agents.rs` | `GET /v1/agents`, `POST /v1/agents/claim-preview`, `POST /v1/agents/{registration_id}/revoke`, `GET /v1/agents/{registration_id}/audit` — owner-guarded "My agents" management; agent-derived callers refused, a parent operates its sovereign children — see module doc |

## Rules

- **Routes do not import routes.** Shared route support goes in `agent_child_core.rs`, `auth`, or
  `db/`.
- **Never depend on `pds` or a sibling feature crate.** Anything another feature also needs moves
  down to `custos-core` (or `custos-db` for a table).
- **A new agents route** is registered in `router.rs` and gets a `.bru` file in `bruno/` (root
  AGENTS.md).
- **Migrations stay in `custos-db`.**
