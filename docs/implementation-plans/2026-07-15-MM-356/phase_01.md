# Hosted Custos MCP — Phase 1: Agent-as-child-identity minting

**Child issue:** [MM-368](https://linear.app/malpercio/issue/MM-368) — Agent-as-child-identity minting (sovereign child DID + repo + handle + wallet recovery).

**Goal:** A parent account owner on this PDS can mint a **sovereign child agent
identity** — its own DID, its own repo, its own handle — whose recovery/rotation
key is held in the parent's Obsign wallet, and whose day-to-day signing is a
delegated, scope-clamped, revocable capability. Minting is gated by the ownership
graph: no parent account on this PDS, no child.

**Architecture:** Reuse, do not reinvent. Child DID/repo bootstrapping goes through
the **existing** genesis machinery (`repo_engine::build_genesis_repo` →
`identity::genesis::build_genesis_car` → `promote_account`, the same path
`routes/create_did.rs` drives); the client supplies a self-signed `plcOp` whose
`rotationKeys` are the wallet's, exactly as user onboarding does — the PDS
**verifies** the genesis op (`crypto::verify_genesis_op`) and never mints a
server-custodied DID. The child's usable credential reuses the auth.md
assertion/token machinery (`RegistrationType`, `agent_identities`,
`mint_identity_assertion`); minting adds a **parent→child ownership link** and a
new `child` registration path on top of it. A new `agent_child.rs` route owns the
mint/list/revoke surface; the parent-owner gate reuses
`auth::guards::authenticate_account_owner`.

**Tech Stack:** Rust, axum 0.8, sqlx (SQLite), `crates/crypto` (P-256 + did:plc),
`crates/repo-engine`. All internal — no new external dependencies expected.

**Scope:** Phase 1 of 4 from [`docs/implementation-plans/2026-07-15-MM-356/`](./);
verifies **AC1** in [`docs/test-plans/2026-07-15-MM-356.md`](../../test-plans/2026-07-15-MM-356.md).
Design: [`docs/design-plans/2026-07-14-hosted-custos-mcp.md`](../../design-plans/2026-07-14-hosted-custos-mcp.md)
§1, §2, §8. Decisions fixed by
[ADR-0023](../../architecture/decisions/0023-sovereign-child-agent-identities.md).

**Codebase verified:** 2026-07-15.

---

## Acceptance Criteria Coverage

**Verifies:** `MM-356.AC1.1` … `AC1.7` (child minting: DID/repo/handle, wallet
recovery key, flat-subdomain handle policy, ownership-graph gate, parent↔child
link, delegated/revocable signing, revocation-without-recovery-loss). Live
confirmation of AC1.1/AC1.2 is HV-1 in the test-requirements.

---

<!-- START_TASK_1 -->
### Task 1: Confirm the flat-subdomain handle policy for agent handles

**Files:**
- Modify: `crates/pds/src/identity/handle.rs` (add agent-handle policy tests; reuse `validate_handle`, `is_reserved_name`)

**Implementation:**

Agent handles share the user-handle namespace and must respect both
`available_user_domains` and `reserved_handles`. For this slice, only **flat**
`<name>.<served-domain>` handles are allowed; nested `writer.alice.obsign.org` is
Phase 2 (needs on-demand TLS — design plan §2). Confirm `validate_handle` already
enforces flat structure against the served domain and that a reserved name is
refused; if nested-under-user handles are not already rejected by structure, add
the guard here rather than in the route.

No new config field is needed — agent handles allocate from the same
`EZPDS_AVAILABLE_USER_DOMAINS` wildcard the user handles use.

**Verification:**
Run: `cargo test -p pds identity::handle`
Expected: a flat `bot.<served-domain>` handle validates; a nested
`a.b.<served-domain>` handle and a reserved name are refused. (AC1.3)

**Commit:** `test(pds): pin flat-subdomain policy for agent handles`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Parent↔child ownership link — schema + queries

**Files:**
- Create: `crates/pds/src/db/migrations/V0XX__agent_children.sql` (next free migration number)
- Modify: `crates/pds/src/db/agent_auth.rs` (add child-link columns/queries, following the `NewAgentIdentity`/`AgentIdentityRow` + `insert_agent_identity` pattern)

**Implementation:**

Record which parent account owns each child agent. Two viable shapes — pick the one
that fits the existing `agent_identities` table:

1. Add a nullable `parent_did TEXT` column to `agent_identities` (a child row is an
   `agent_identities` row whose `parent_did` is set), plus a `RegistrationType::Child`
   variant; or
2. A dedicated `agent_children(child_did, parent_did, created_at)` link table.

Prefer (1) if the child's credential lifecycle is the same `agent_identities`
lifecycle (it is — the child re-uses assertion/token machinery); (1) keeps
minting, claiming, and revoking on one table. Add query fns mirroring the existing
generic-executor helpers: `list_children_of_parent(parent_did)`,
`get_child(child_did)`, and ensure `revoke_agent_identity` covers child rows.

The ownership link is also the **entitlement boundary** (design plan §8): a child
must have a `parent_did` that resolves to a live local account.

**Verification:**
Run: `cargo test -p pds db::agent_auth`
Expected: insert a child with a parent DID, read it back, list it under the parent,
and confirm the link survives a fresh connection. (AC1.5)

**Commit:** `feat(pds): persist parent→child agent ownership link`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: `POST /agent/child` mint route (gated, wallet-keyed genesis)

**Files:**
- Create: `crates/pds/src/routes/agent_child.rs` (`// pattern: Imperative Shell`)
- Modify: `crates/pds/src/app.rs` (register the route beside the other `/agent/*` routes, ~`:237–243`)

**Implementation:**

Add `post_agent_child` (mint) that:

1. **Gates on parent ownership** — `auth::guards::authenticate_account_owner`
   resolves the authenticated caller to a local parent account; no local account ⇒
   401/403, nothing written. (AC1.4, design plan §8)
2. **Bootstraps the child DID + repo** via the existing genesis path
   (`repo_engine::build_genesis_repo` → `identity::genesis::build_genesis_car` →
   `promote_account`), taking a **client-supplied self-signed `plcOp`** whose
   `rotationKeys` are the wallet's — the PDS verifies it with
   `crypto::verify_genesis_op` and never custodies a rotation key (mirrors
   `routes/create_did.rs::create_did_handler`). (AC1.1, AC1.2)
3. **Allocates the child handle** through the same handle path user onboarding uses
   (flat subdomain, Task 1 policy), inserting into `handles`. (AC1.3)
4. **Records the child identity** as an `agent_identities` row with `parent_did`
   set (Task 2) and a **scope-clamped agent profile**; issues the delegated,
   short-lived signing capability via the existing `mint_identity_assertion`
   machinery — not a standing full session. (AC1.6)
5. Returns the child DID, handle, and the credential material the wallet/agent
   needs to begin the auth.md exchange.

Keep route isolation and DB-ownership rules per `crates/pds/AGENTS.md` (the route is
the Imperative Shell; genesis/verify are the Functional Core). No ticket references
in source comments (project convention).

**Testing:**
Inline `#[cfg(test)] mod tests` driving `app(state).oneshot(...)` with
`seed_account_with_repo` for the parent and wiremock for `plc.directory` (the
`agent_identity.rs` / `sovereign_session.rs` test modules are the reference). Assert
AC1.1 (distinct child DID/repo/handle), AC1.2 (persisted rotation set == wallet
key, operator key absent), AC1.4 (no-parent ⇒ refused, nothing written), AC1.6
(clamped scopes, short-lived token).

**Verification:**
Run: `cargo test -p pds routes::agent_child`
Expected: all mint cases pass.
Run: `just ci-pds`
Expected: fmt, clippy (`-D warnings`), tests, audit, deny all green.

**Commit:** `feat(pds): mint sovereign child agent identities (POST /agent/child)`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Revoke a child without surrendering its recovery key

**Files:**
- Modify: `crates/pds/src/routes/agent_child.rs` (add revoke + list handlers)
- Modify: `crates/pds/src/app.rs` (register `/agent/child/revoke` or a RESTful sibling)

**Implementation:**

Parent-gated revocation that flips the child's `agent_identities` status via
`revoke_agent_identity`, killing the **delegated capability** only. The wallet-held
rotation/recovery key is never stored server-side (Task 3), so revocation cannot and
must not touch it — assert this explicitly (ADR-0023 custody ladder). Add a
parent-scoped `list children` handler for the wallet/console to enumerate and manage
its agents.

**Bruno parity (mandatory):** add `.bru` files for the new `/agent/child` routes
(new `seq`), per `bruno/` rules — `just bruno-check` gates path coverage.

**Testing:**
Assert AC1.7: after revoke, a token exchange for the child fails `access_denied`;
the persisted rotation set is unchanged; the parent's child list reflects the
revoked status.

**Verification:**
Run: `cargo test -p pds routes::agent_child`
Expected: revoke + list cases pass.
Run: `just bruno-check`
Expected: route ⇄ Bruno parity holds for the new routes.

**Commit:** `feat(pds): revoke + list child agents (delegated capability only)`
<!-- END_TASK_4 -->

---

## Live verification (HV-1)

After this phase, run HV-1 from the test-requirements against **staging**: mint a
child of a real staging account, confirm the child DID resolves through the real
PLC directory, its genesis frames appear on the firehose, its repo is describable,
and the resolved DID document's `rotationKeys` are the wallet's — not the operator's.
This is the gate before Phase 3's end-to-end `create_post` can be attributed to the
child.
