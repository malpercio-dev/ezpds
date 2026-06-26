# Phase 04 — Public wire API (server side)

**Goal:** Rename the public HTTP routes, handler functions, response structs, and response field names that carry `relay` to `pds`. This is a **breaking wire-API change** — it must merge in lockstep with Phase 05 (iOS app) and Phase 06 (Bruno).

**Architecture:** Rename route paths and the Rust handler surface in `crates/pds/`. To avoid breaking already-deployed app builds during the rollout, the old paths are kept as **deprecated aliases** routed to the same handlers for one release cycle.

**Scope:** Phase 4 of 6.

**Codebase verified:** 2026-06-26.

**Verifies:** None (refactor — verified by route tests + `cargo test -p pds`).

> ⚠️ The SQL table `relay_signing_keys` is immutable (overview constraint 1). The `get_pds_signing_key` handler keeps its `FROM relay_signing_keys` / `INSERT INTO relay_signing_keys` SQL **unchanged**. Only the Rust/HTTP surface renames.

---

## Name mapping (server wire surface)

| Old | New |
|---|---|
| route `GET /v1/devices/:id/relay` | `GET /v1/devices/:id/pds` |
| handler `get_device_relay` (file `routes/get_device_relay.rs`) | `get_device_pds` (file `routes/get_device_pds.rs`) |
| struct `GetDeviceRelayResponse` | `GetDevicePdsResponse` |
| response field `relay_url` | `pds_url` |
| route `GET/POST /v1/relay/keys` | `GET/POST /v1/pds/keys` |
| handler `get_relay_signing_key` (file `routes/get_relay_signing_key.rs`) | `get_pds_signing_key` (file `routes/get_pds_signing_key.rs`) |
| struct `GetRelaySigningKeyResponse` | `GetPdsSigningKeyResponse` |
| SQL table `relay_signing_keys` | **unchanged (kept)** |

> Field `websocket_url` already has no `relay` token — unchanged.

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->
<!-- START_TASK_1 -->
### Task 1: Rename the device-PDS route handler file + symbols

**Files:**
- Rename: `crates/pds/src/routes/get_device_relay.rs` → `crates/pds/src/routes/get_device_pds.rs`
- Modify (within it): struct `GetDeviceRelayResponse` → `GetDevicePdsResponse`; fn `get_device_relay` → `get_device_pds`; response field `relay_url` → `pds_url`; any local var still named `relay_url` → `pds_url`; test fn names.

**Implementation:**
```bash
git mv crates/pds/src/routes/get_device_relay.rs crates/pds/src/routes/get_device_pds.rs
```
Then in the file: rename the struct, fn, and the `pds_url` field. The handler returns `Json(GetDevicePdsResponse { pds_url, websocket_url })`. Keep all logic identical.

**Testing:** the existing in-file tests (`*_matches_config_public_url`, `websocket_url_is_derived_from_*`) keep their assertions; rename their identifiers to `pds_url`.

**Verification:** `cargo build -p pds` (will fail on `app.rs` imports until Task 3 — expected; build after Task 3).
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Rename the PDS signing-key route handler file + symbols (keep SQL)

**Files:**
- Rename: `crates/pds/src/routes/get_relay_signing_key.rs` → `crates/pds/src/routes/get_pds_signing_key.rs`
- Modify (within it): struct `GetRelaySigningKeyResponse` → `GetPdsSigningKeyResponse`; fn `get_relay_signing_key` → `get_pds_signing_key`.
- **KEEP** the SQL string `... FROM relay_signing_keys ...` exactly as-is.
- Check `crates/pds/src/routes/create_signing_key.rs` — it shares the `/v1/pds/keys` POST. Its SQL `INSERT INTO relay_signing_keys` stays; only update it if it references the renamed struct/fn.

**Implementation:**
```bash
git mv crates/pds/src/routes/get_relay_signing_key.rs crates/pds/src/routes/get_pds_signing_key.rs
grep -n 'relay' crates/pds/src/routes/get_pds_signing_key.rs crates/pds/src/routes/create_signing_key.rs
```
Rename Rust symbols; confirm the only remaining `relay` token is the kept SQL table name.

**Verification:** `grep -n 'relay' crates/pds/src/routes/get_pds_signing_key.rs` → only `relay_signing_keys` (SQL) remains.
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Update app.rs imports + routes, with deprecated aliases

**Files:**
- Modify: `crates/pds/src/app.rs:35` — `use crate::routes::get_device_relay::get_device_relay;` → `use crate::routes::get_device_pds::get_device_pds;`
- Modify: `crates/pds/src/app.rs:38` — `use crate::routes::get_relay_signing_key::get_relay_signing_key;` → `use crate::routes::get_pds_signing_key::get_pds_signing_key;`
- Modify: `crates/pds/src/app.rs:237` and `:243-244` — route paths.
- Check: `crates/pds/src/routes/mod.rs` — update the `pub mod get_device_relay;` / `pub mod get_relay_signing_key;` declarations to the new module names.

**Implementation:** Register the new paths and keep the old ones as deprecated aliases pointing at the same handlers, so deployed app builds keep working during rollout:

```rust
// new canonical paths
.route("/v1/devices/:id/pds", get(get_device_pds))
.route("/v1/pds/keys", get(get_pds_signing_key).post(create_signing_key))
// deprecated aliases (remove after the next coordinated app release)
.route("/v1/devices/:id/relay", get(get_device_pds))
.route("/v1/relay/keys", get(get_pds_signing_key).post(create_signing_key))
```

Add a `// DEPRECATED: relay-named aliases, remove once all clients use /pds (see rename plan)` comment above the alias block. **Do not** change `app.rs:158/160` doc-comments (Sense-B).

**Verification:**
```bash
cargo build -p pds && cargo test -p pds
```
Expected: green. Both old and new paths resolve.
<!-- END_TASK_3 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_TASK_3B -->
### Task 3b: Rename the user-facing OAuth template copy

**Files:**
- Modify: `crates/pds/src/routes/oauth_templates.rs` — **all three** Sense-A lines: `:162` (footer "which relay is serving this page"), `:8` (doc-comment "relay's own /static/fonts route"), `:198` ("served by the relay at /static/fonts"). The `:162` footer is user-facing copy; `:8`/`:198` are internal comments.
- Modify: `crates/common/src/config.rs:38` — stale comment `// e.g., POST /v1/relay/keys` → `// e.g., POST /v1/pds/keys` (this `common` comment references the wire route this phase renames; Phase 03's `common` sweep is Sense-A prose only, so fix it here alongside the route rename).

**Implementation:** For the user-facing `:162` footer apply the same wording decision as Phase 05's UX-copy rule — brand/plain language, e.g. "served by **Custos**" (or "served by this server"), not "relay" and not the jargon "PDS". Keep `:8`/`:198` consistent ("the PDS's own /static/fonts route").

**Verification:** `grep -n 'relay' crates/pds/src/routes/oauth_templates.rs` → no matches; `grep -n '/v1/relay/keys' crates/common/src/config.rs` → no matches; rendered page no longer says "relay".
<!-- END_TASK_3B -->

<!-- START_TASK_4 -->
### Task 4: Add a route test for the alias + new path, then commit

**Files:**
- Modify/add test: in `get_device_pds.rs` or the app/router test module — assert that both `GET /v1/devices/:id/pds` and the deprecated `GET /v1/devices/:id/relay` return the same shape, and that the response field is now `pds_url`.

**Testing (describe — task-implementor writes the code against actual test patterns):**
- New path `/v1/devices/:id/pds` returns 200 with `pds_url` + `websocket_url`.
- Deprecated alias `/v1/devices/:id/relay` returns the same body (regression guard for the transition window).

Follow the existing router/handler test pattern in `crates/pds/src/routes/` (e.g. how `test_utils.rs` builds a test app).

**Verification:**
```bash
cargo test -p pds
cargo clippy -p pds --all-targets -- -D warnings
```
Expected: green.

**Commit:**
```bash
git add -A
git commit -m "refactor(pds)!: rename relay wire API to pds (with deprecated aliases)

/v1/devices/:id/relay -> /v1/devices/:id/pds
/v1/relay/keys        -> /v1/pds/keys
response field relay_url -> pds_url; handlers/structs renamed.
Old paths kept as deprecated aliases for one release cycle.
SQL table relay_signing_keys kept (immutable migration).

BREAKING: clients must move to /pds paths and read pds_url.
Lands with the identity-wallet update (phase 05)."
```
<!-- END_TASK_4 -->
