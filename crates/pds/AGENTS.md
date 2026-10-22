# PDS Crate (Custos)

Last verified: 2026-10-21

## Purpose

The PDS is the axum-based web server and the composition root: it builds `AppState`, merges the
route table, and spawns the sweeps. It sits on two library crates it shares with the feature
crates — [`custos-db`](../custos-db/AGENTS.md) (pool, migrations, cross-feature queries) and
[`custos-core`](../custos-core/AGENTS.md) (`CoreState`, the auth verification core, identity,
lexicons, rate limiting, metrics, sweeps) — over the pure cores `crypto`, `repo-engine`, and
`common`. Each feature crate is a dependency `pds` composes and nothing else may: today only
[`custos-spaces`](../custos-spaces/AGENTS.md) (the Atproto Spaces surface). `main.rs` aliases the modules that moved to `custos-core` at the crate root, so
`crate::identity::…`, `crate::time::…`, and their siblings resolve to it; `auth/mod.rs`
re-exports `custos_core::auth` the same way.

This file is a map. Each entry is what the module is plus the fact or two an agent needs
before opening it; mechanism and invariants live in the module's own `//!` doc.

## Module Map

```
src/
  main.rs          — startup: open pool, run migrations, bind server
  telemetry.rs     — OTel tracing-subscriber init (`init_subscriber`) + shutdown-flushing `OtelGuard`; `[telemetry]` config incl. `log_format = "json"` — see module doc
  app.rs           — router construction (route table; each group is wrapped by `custos_core::public_surface` / `internal_surface`); re-exports `AppState` (and the `#[cfg(test)]` constructors) from `state.rs` so existing `crate::app::AppState` imports stay unchanged. Each feature crate's `router`/`internal_router` merges in unconditionally before the layer stack; the feature gate lives inside the crate
  state.rs         — the composite `AppState`: `core: CoreState` plus the fields only `pds`'s features read (iroh, notify sender, email, repo write locks). `Deref<Target = CoreState>` for field reads, `FromRef<AppState>` for `CoreState` and `SpacesState` (built from `AppState.core`); writes go through `state.core`. `set_notify_sender` is the one switch that turns notifications on: it sets `notify_sender` and installs `notifications::RelayNotifier` as `CoreState.notifier`. `#[cfg(test)]`: `AppState::for_test(core)` and the `test_state` constructors
  rate_limit_test.rs — the rate-limit middleware tests that need the full `app()` router (CORS on a 429, the `getRepo` exemption, per-endpoint caps); the limiter's unit tests are in `custos_core::rate_limit`
  xrpc_dispatch.rs — catch-all XRPC proxy dispatcher (`xrpc_handler` at `/xrpc/{method}`): upstream resolution for the three proxied namespaces + the read-after-write branch — see module doc
  email.rs         — pluggable outbound email (`Arc<dyn EmailSender>`: log default, SMTP, Mailtrap HTTPS) behind the token-delivery flows; `[email]` / `EZPDS_EMAIL_*` — see module doc
  iroh_tunnel.rs   — opt-in (`[iroh] enabled`) NAT-traversing QUIC endpoint devices dial by node id; v0.1 echo ALPN, IPv6 gate for v4-only hosts — see module doc
  notify_relay_client.rs — outbound iroh leg to the notification relay (`ezpds/notify/0`) + the fire-and-forget send worker; lazy cached connection, self-healing enrollment — see module doc
  notifications.rs — sending side: pad + HPKE-seal one payload per registered device and enqueue; `RelayNotifier` is the `custos_core::notify::Notifier` features push through, `notify_admin_devices` the operator channel; inert when `[notifications] relay` is unset — see module doc
  record_write.rs  — shared repo write flow + firehose commit emission + post-commit block GC (one reachability walk per commit); every commit passes the MST integrity check (new head's key count vs the maintained `accounts.record_count` witness, V068) before the CAS — see module doc
  repo_rev.rs      — shared `read_repo_rev`, homed beside `record_write.rs` so the public sync endpoints share it without a route-to-route import
  account_delete.rs— shared permanent account-deletion transaction (FK-ordered child tables, blob-file reclamation, `#account` deleted frame), used by deleteAccount and the reaper — see module doc
  account_genesis.rs— the steps the two account-genesis transactions (`create_did.rs`, `create_account_xrpc.rs`) share: the `accounts` row, the genesis blocks + staged `#commit`/`#sync`, and the post-commit announce. Deliberately not one merged promotion — the module doc says what differs around it
  account_reaper.rs— periodic sweep permanently deleting deactivated accounts past `deleteAfter`
  labeler_watch.rs — periodic labeler watcher reconciling `account_labels` (V051) to the labels currently in force; first pass runs at boot; genuinely new flags fire ONE batched operator push per pass, seeding-suppressed via `labels_seeded` (V072) — see module doc
  label_state.rs   — Functional Core for the watcher: reduce raw label events to the in-force set and diff against persisted rows
  admin_nonce_sweep.rs— periodic stale `admin_nonces` sweep (pure storage reclamation; retention stays above the replay-acceptance window) — see module doc
  sovereign_session_nonce_sweep.rs— hourly `sovereign_session_nonces` sweep; a compile-time assertion keeps retention above the replay window
  transfer.rs      — planned device-transfer accept/complete/cancel workflows; `custos_db::transfers` owns the SQL, this module owns the cross-table ordering — see module doc
  session_issuer.rs— shared legacy access+refresh JWT issuance transaction; explicit full-access vs app-password authority — see module doc
  capabilities.rs  — the `CAPABILITIES` table behind `describeServer`'s `custos` extension; a feature crate contributes its entry as a `CAPABILITY` constant listed in its slot, and a golden test pins the fully-enabled order; an entry's `enabled` predicate must be the same condition its routes enforce, and `just capability-docs-check` gates the operator docs. Also owns `IDENTIFYING_VERSION` — see module doc
  uniqueness.rs    — email/handle pre-flight uniqueness DB checks, shared by the account-creation routes (the pure `normalize_email` / `is_plausible_email` and claim-code generation live in `common`)
  platform.rs      — device `Platform` enum, shared by the device-registration routes
  rewrap.rs        — offline `pds rewrap-master-key` KEK rotation (inventory in `custos_db::kek`; keys env-only, server stopped) — see module doc
  recovery_share.rs— the KEK boundary for PDS-held Shamir Share 2: base32↔bytes, authenticated wrap/unwrap, idempotent startup data migration — see module doc
  read_after_write/— buffered AppView response munge path for read-after-write (see section below)
  auth/            — authentication primitives + route guards (HTTP-aware, no DB schema ownership)
  db/              — feature-local SQL query functions (no business logic); the pool, migrations, and cross-feature queries are `crates/custos-db`
  routes/          — HTTP handlers, one file per endpoint
```

### `read_after_write/`

Buffered munge path for the six munged AppView NSIDs — merges the requester's not-yet-indexed
records into the AppView's response. `mod.rs`'s module doc is the authority: the NSID list,
rev-comparison selection, the five-rung fallback ladder, the 10 MiB buffering cap,
`Atproto-Upstream-Lag` semantics, the `service_proxy::proxy_request` shared extraction, and the
`[appview]` config keys (`EZPDS_APPVIEW_URL`/`_DID`/`_CDN_URL`). Submodules: `munge.rs`
(per-NSID munges), `viewer.rs` (`LocalViewer` hydration), `types.rs` (`LocalRecords`).

### `auth/`

`auth/mod.rs` only re-exports [`custos_core::auth`](../custos-core/AGENTS.md) (the verification
core and the auth.md agent machinery), so `crate::auth::…` paths resolve to it. The OAuth server's
response mode moved with the server to [`custos-oauth`](../custos-oauth/AGENTS.md).

**Rule:** `auth/` has no knowledge of specific routes. Route handlers call into `auth/`; `auth/` never imports from `routes/`.

### `db/`

SQL query functions organised by domain entity. Each submodule exposes plain data structs
and async query functions; no business logic lives here.

The pool, the migration log and runner, `DbError`, the unique-violation / retry helpers, and
the cross-feature modules (`accounts`, `dids`, `handles`, `blobs`, `blocks`, `kek`,
`admin_audit`, `sessions`, `refresh_tokens`, `server_stats`, `oauth`, `agent_auth`,
`agent_audit`, plus `admin_devices`, `iroh_identity`, `jwt_secret`, `repo_keys`, `transfers`,
which the auth guards and signing-key loaders read) live in
[`crates/custos-db`](../custos-db/AGENTS.md); `db/mod.rs` re-exports those `pds` still reads, so
`db::accounts::…` paths resolve unchanged. The table below lists only what stays in `pds`.

| File | Contents |
|---|---|
| `mod.rs` | `open_pool`, `run_migrations`, `DbError`, `is_unique_violation` |
| `app_passwords.rs` | app-password store (V031) — see module doc; revocation's multi-table delete lives in `routes/revoke_app_password.rs` |
| `claim_codes.rs` | invite/claim-code store (V004/V041): preflight, mint, keyset inventory page, revoke — see module doc |
| `password_reset.rs` | password-reset token store (the hashed 1-hour single-use envelope) — see module doc |
| `plc_operation_tokens.rs` | PLC-operation email-token store (V033), gating `signPlcOperation` — see module doc |
| `account_deletion_tokens.rs` | account-deletion email-token store (V034, same hashed envelope) — see module doc |
| `email_tokens.rs` | email verification token store (V036, purpose-discriminated single-use envelope) — see module doc |
| `preferences.rs` | preferences blob get/put, executor-generic for the one-transaction read-merge-write — see module doc |
| `relay_signing_keys.rs` | operator-level PDS signing keys (V003) backing `/v1/pds/keys` — see module doc |
| `recovery_escrow.rs` | PDS-held Shamir Share 2 escrow (V050) plus the release state machine — see module doc |
| `recovery_otps.rs` | recovery-release email OTP store (V053) — see module doc |
| `recovery_audit.rs` | append-only recovery-escrow audit log (V050, the V040 doctrine) — see module doc |
| `sovereign_session_nonces.rs` | sovereign-session anti-replay store (V043); the sweep-retention rule is in the module doc |
| `waitlist.rs` | public waitlist signup store (V057, no FKs — off the purge path) — see module doc |
| `account_labels.rs` | watched-labeler flag store (V051) — see module doc; the filtered listing predicates live beside `list_accounts_admin` in `accounts.rs` |

Migration history and invariants: [`crates/custos-db/AGENTS.md`](../custos-db/AGENTS.md).

**Rule:** `db/` submodules never import from `routes/` or `auth/`. They accept `&SqlitePool`
and return data; callers decide what to do with it.

### `routes/`

One file per HTTP endpoint. Each handler is a thin Imperative Shell:
**gather** (extract state/body/headers) → **process** (call `auth/` or `db/`) → **respond**.
Rows below name the endpoint and the fact to know before opening the file; the module doc has
the rest. The OAuth endpoints live in [`custos-oauth`](../custos-oauth/AGENTS.md).

| File | Endpoint |
|---|---|
| `atproto_did.rs` | `GET /.well-known/atproto-did` |
| `did_json.rs` | `GET /.well-known/did.json` — the serving half of Custos-managed did:web hosting; module doc covers the opt-in gate and the config-synthesized server-DID exception |
| `did_web_hosting.rs` | `POST /v1/did-web/hosting` + `POST /v1/did-web/document` — owner-authed did:web hosting opt-in and non-PLC document edit — see module doc |
| `notifications.rs` | `POST/DELETE /v1/notifications/register[/{deviceUuid}]`, `GET /v1/notifications/sender-keys` — the account push surface, keyed on `(did, device_uuid)`; the relay round trip stays out of the request path — see module doc |
| `admin_notifications.rs` | `POST /v1/admin/notifications/register`, `GET /v1/admin/notifications/sender-keys` — the operator analog; registration is device-signed only (master token → 400) — see module doc |
| `notification_views.rs` | shared handler-free support for both notification surfaces (routes may not import one another): enabled-check, registration validators, `sender-keys` shape |
| `static_assets.rs` | `GET /static/*path` — embedded brand fonts and future web-UI assets |
| `landing.rs` | `GET /` — the instance landing page (embedded `assets/landing.html`): config facts, a `_health` status chip, joiner/developer pointers |
| `create_session.rs` | `POST /xrpc/com.atproto.server.createSession` — password auth with app-password fallback — see module doc |
| `sovereign_session.rs` | `POST /v1/sessions/sovereign` — passwordless full session from a rotation-key-signed proof; envelope and verification rules in the module doc |
| `create_app_password.rs` | `POST /xrpc/com.atproto.server.createAppPassword` — mint a named app password; secret returned once, full access required, duplicate name → 409; off-lexicon `personalDetails` grant (ADR-0033) |
| `list_app_passwords.rs` | `GET /xrpc/com.atproto.server.listAppPasswords` — metadata only, never the secret; full access required |
| `revoke_app_password.rs` | `POST /xrpc/com.atproto.server.revokeAppPassword` — delete an app password and its sessions atomically (idempotent 200); full access required |
| `get_session.rs` | `GET /xrpc/com.atproto.server.getSession` |
| `get_service_auth.rs` | `GET /xrpc/com.atproto.server.getServiceAuth` — mint a short-lived inter-service JWT for a requested `aud`, optional `lxm`/`exp` bounds; shares the mint helper with `service_proxy.rs` |
| `update_subject_status.rs` | `POST /xrpc/com.atproto.admin.updateSubjectStatus` — apply/clear an account takedown; admin-authed; subject-kind limits and firehose semantics in the module doc |
| `get_subject_status.rs` | `GET /xrpc/com.atproto.admin.getSubjectStatus` — report an account's takedown status; admin-authed — see module doc |
| `admin_subject_defs.rs` | shared `com.atproto.admin.defs` response view types for the two subject-status routes (Functional Core, no handler) |
| `refresh_session.rs` | `POST /xrpc/com.atproto.server.refreshSession` |
| `request_password_reset.rs` | `POST /xrpc/com.atproto.server.requestPasswordReset` — mint + email a reset token; always 200 to prevent enumeration |
| `reset_password.rs` | `POST /xrpc/com.atproto.server.resetPassword` |
| `request_email_confirmation.rs` | `POST /xrpc/com.atproto.server.requestEmailConfirmation` — mint + email a single-use 1-hour confirm token; full access required |
| `confirm_email.rs` | `POST /xrpc/com.atproto.server.confirmEmail` — consume the confirm token, set `email_confirmed_at`; full access required |
| `request_email_update.rs` | `POST /xrpc/com.atproto.server.requestEmailUpdate` — returns `{tokenRequired}`; mints the update token when the current email is confirmed |
| `update_email.rs` | `POST /xrpc/com.atproto.server.updateEmail` — change the address (token required iff confirmed), reset `email_confirmed_at`; duplicate → 400 |
| `reserve_signing_key.rs` | `POST /xrpc/com.atproto.server.reserveSigningKey` — public standard-migration signing-key reservation |
| `get_repo_signing_key.rs` | `GET /v1/repo-signing-key` — idempotently issue the pending account's repo signing key for the mobile DID ceremony — see module doc |
| `create_did.rs` | `POST /v1/dids` — device-signed DID ceremony + promotion, dual-mode on share custody (client-share did:plc / no-escrow did:web) — see module doc |
| `get_did.rs` | `GET /v1/dids/:did` |
| `create_account.rs` | `POST /v1/accounts` |
| `create_account_xrpc.rs` | `POST /xrpc/com.atproto.server.createAccount` — standard onboarding + resumable migration, dual-mode on `did` presence — see module doc |
| `create_handle.rs` | `POST /v1/handles` |
| `delete_handle.rs` | `DELETE /v1/handles/:handle` |
| `create_mobile_account.rs` | `POST /v1/accounts/mobile` |
| `account_usage.rs` | `GET /v1/accounts/:id/usage` — operator usage metrics (counts, bytes, last-active); admin-authed, reports deactivated accounts too — see module doc |
| `account_storage.rs` | `GET /v1/accounts/:id/storage` — operator blob-storage metrics incl. the `uploadedBlob*` second witness for lost ownership rows; admin-authed — see module doc |
| `admin_list_accounts.rs` | `GET /v1/admin/accounts` — operator listing/search, flagged accounts first behind a two-part cursor; filters, per-row storage + `didWebHosting` + flags — see module doc |
| `admin_recovery_releases.rs` | `GET /v1/admin/recovery-releases` — operator view of in-flight escrow releases; the share ciphertext is never returned — see module doc |
| `admin_health.rs` | `GET /v1/admin/health` — literal server-health readout (the JSON counterpart of `/metrics`), no ok/warn verdicts; admin-authed — see module doc |
| `admin_revoke_credentials.rs` | `POST /v1/admin/accounts/{id}/revoke-credentials` — operator kill-switch: one-transaction credential sweep with per-family counts; admin-authed — see module doc |
| `admin_account_repair.rs` | `POST /v1/admin/accounts/{id}/email` + `.../reset-token` — operator account-repair pair; reset tokens refused for passwordless accounts — see module doc |
| `admin_audit.rs` | `GET /v1/admin/audit` — the server-wide admin audit log, newest first, attributed per credential; admin-authed; filters, writer inventory, and logging rules in the module doc |
| `admin_transfers.rs` | `GET /v1/admin/transfers` + `POST /v1/admin/transfers/{id}/cancel` — in-flight device-transfer visibility and interruption; the 6-char code is never returned (it is a live account-takeover credential) — see module doc |
| `waitlist_signup.rs` | `POST /waitlist` — public CORS'd interest signup, 404 unless `[waitlist] enabled`; handle validated but never resolved — see module doc |
| `admin_waitlist.rs` | `GET /v1/admin/waitlist` — operator waitlist readout, available even when signup is off; admin-authed — see module doc |
| `admin_devices.rs` | `POST /v1/admin/pairing-codes`, `POST/GET /v1/admin/devices`, `POST /v1/admin/devices/:id/revoke` — companion-app device pairing/management; auth model in the module doc |
| `create_signing_key.rs` | `POST /v1/pds/keys` (deprecated alias: `POST /v1/relay/keys`) |
| `recovery_escrow.rs` | `PUT/DELETE /v1/recovery/escrow-share` — owner deposit/replace/opt-out of the escrowed Share 2 — see module doc |
| `recovery_release.rs` | `POST /v1/recovery/{initiate,release,release/cancel}` — the escrow release gate (OTP → cancellable delay → one-time share), uniform-401 no-oracle posture — see module doc |
| `repo_key_rotation.rs` | `POST /v1/repo-keys/rotation` + `/complete` — stage-then-cutover repo signing-key rotation under the repo write lock (ADR-0025) — see module doc |
| `register_device.rs` | `POST /v1/devices` |
| `transfer_initiate.rs` | `POST /v1/transfer/initiate` — open a planned device-swap session (6-char code, one active per account, 409 otherwise) |
| `transfer_accept.rs` | `POST /v1/transfer/accept` — accept a device-swap code from the new device (the code is the credential); advances the transfer to `accepted` atomically |
| `transfer_complete.rs` | `POST /v1/transfer/complete` — finalize an accepted swap (source session or accepted target token); revokes superseded credentials, records the audit event |
| `get_device_pds.rs` | `GET /v1/devices/:id/pds` |
| `describe_server.rs` | `GET /xrpc/com.atproto.server.describeServer` — lexicon fields plus the off-lexicon `custos` capability extension — see module doc |
| `sync_get_blocks.rs` | `GET /xrpc/com.atproto.sync.getBlocks` — requested repo blocks as a rootless CAR; a foreign account's CID reads as `BlockNotFound` |
| `sync_get_latest_commit.rs` | `GET /xrpc/com.atproto.sync.getLatestCommit` — current commit CID and rev |
| `sync_get_record.rs` | `GET /xrpc/com.atproto.sync.getRecord` — a record with its MST proof as a CAR (200 inclusion or exclusion proof; only an unknown DID 404s) |
| `get_repo.rs` | `GET /xrpc/com.atproto.sync.getRepo` — repository CAR export; optional `since` makes it incremental |
| `sync_get_repo_status.rs` | `GET /xrpc/com.atproto.sync.getRepoStatus` — hosting status of a single repo |
| `list_repos.rs` | `GET /xrpc/com.atproto.sync.listRepos` — all hosted repositories, paginated |
| `apply_writes.rs` | `POST /xrpc/com.atproto.repo.applyWrites` — a batch of record writes in one atomic commit |
| `import_repo.rs` | `POST /xrpc/com.atproto.repo.importRepo` — migration CAR ingest, idempotent + CAS-guarded for return migration — see module doc |
| `create_record.rs` | `POST /xrpc/com.atproto.repo.createRecord` |
| `get_record.rs` | `GET /xrpc/com.atproto.repo.getRecord` |
| `list_records.rs` | `GET /xrpc/com.atproto.repo.listRecords` |
| `put_record.rs` | `POST /xrpc/com.atproto.repo.putRecord` |
| `delete_record.rs` | `POST /xrpc/com.atproto.repo.deleteRecord` |
| `describe_repo.rs` | `GET /xrpc/com.atproto.repo.describeRepo` |
| `service_proxy.rs` | `GET/POST /xrpc/{app.bsky,chat.bsky,com.atproto.moderation}.*` — dual-path proxy (namespace defaults / SSRF-guarded header targets); dispatch, munge routing, and the header-forwarding seam are in the module doc |
| `get_preferences.rs` | `GET /xrpc/app.bsky.actor.getPreferences` — local read, registered ahead of the catch-all; app-password callers never see full-access-only types unless minted with the personal-details grant (ADR-0033) |
| `put_preferences.rs` | `POST /xrpc/app.bsky.actor.putPreferences` — local scope-limited write; an ungranted app-password write preserves full-access-only entries |
| `preference_scope.rs` | shared (non-handler): which preference `$type`s are full-access-only, matching the reference PDS; the personal-details grant is the one divergence (ADR-0033) |
| `resolve_handle.rs` | `GET /xrpc/com.atproto.identity.resolveHandle` |
| `resolve_identity.rs` | `GET resolveDid` / `GET resolveIdentity` / `POST refreshIdentity` — shared local→network resolution; the refresh `#identity` change-gate is in the module doc |
| `get_recommended_did_credentials.rs` | `GET /xrpc/com.atproto.identity.getRecommendedDidCredentials` — the PLC-op fields this PDS recommends (ADR-0002) — see module doc |
| `request_plc_operation_signature.rs` | `POST …identity.requestPlcOperationSignature` — mint the `signPlcOperation` email token (interop path); the shared `ensure_did_plc` guard is documented here |
| `sign_plc_operation.rs` | `POST …identity.signPlcOperation` — two-factor PDS-signed repoint op, returned unsubmitted (interop, ADR-0002) — see module doc |
| `submit_plc_operation.rs` | `POST …identity.submitPlcOperation` — verify (current rotation key + `prev` chain) then submit to plc.directory and refresh the cached doc — see module doc |
| `claim_codes.rs` | `POST/GET /v1/accounts/claim-codes` + `POST …/revoke` — claim-code mint, inventory, and revoke; admin-authed; status derivation in the module doc |
| `standard_signup.rs` | the standard-signup interop NSIDs (`createInviteCode(s)`, `getAccountInviteCodes`, `temp.checkHandleAvailability`, `temp.checkSignupQueue`) mapped onto claim-code primitives; each NSID's quirks in the module doc |
| `get_pds_signing_key.rs` | `GET /v1/pds/keys` (deprecated alias: `GET /v1/relay/keys`) |
| `health.rs` | `GET /xrpc/_health` — `version` is the self-identifying `custos vX.Y.Z` diagnostic tooling fingerprints on — see module doc |
| `get_metrics.rs` | `GET /metrics` — Prometheus exposition, outside the CORS/tracing/rate-limit stack; gated by `metrics_enabled`/`metrics_require_admin` — see module doc |
| `delete_session.rs` | `POST /xrpc/com.atproto.server.deleteSession` (session revocation) |
| `deactivate_account.rs` | `POST /xrpc/com.atproto.server.deactivateAccount` — flip to deactivated, store optional `deleteAfter`, `#account` frame on transition |
| `activate_account.rs` | `POST /xrpc/com.atproto.server.activateAccount` — clear deactivation, `#account` (+ chained `#sync`) on transition |
| `request_account_delete.rs` | `POST /xrpc/com.atproto.server.requestAccountDelete` — mint + email the single-use 1-hour deletion token; full access required |
| `delete_account.rs` | `POST /xrpc/com.atproto.server.deleteAccount` — body-credential deletion (password OR the `custos.proof` envelope) + email token; factor rules and no-oracle posture in the module doc |
| `check_account_status.rs` | `GET /xrpc/com.atproto.server.checkAccountStatus` — activation/repo/blob completeness report for migration tooling |
| `provisioning_session.rs` | provisioning session creation (email + password → session token) |
| `test_utils.rs` | test helpers (excluded from production builds): re-exports `custos_core::test_support`, shadows its state constructors with `AppState` versions, and adds the fixtures that need a `pds` type (failing email sender, `post_json_with_bearer` over `app()`) |

## Hard Rules

**Routes must not import from other routes.**
If two routes share logic, that logic belongs in `auth/` (pure), `db/` (queries), `identity/`,
a top-level module such as `account_genesis.rs`, or one of the handler-free support modules under
`routes/` (`notification_views.rs`, `preference_scope.rs`, `test_utils.rs`). A route importing from another route creates hidden
coupling and makes it impossible to reason about a handler in isolation. The rule bars route→route
imports only — it is not a reason to copy a `db/`, `auth/`, or `test_utils` helper into a route.

**Extend the shared helper; never copy a sibling.**
Before writing a struct, query, fixture, or loop that resembles one that already exists, diff
against it and extend or parametrise it. The concrete homes (see the index below): a SQL statement
needed by two routes goes in `db/`; an auth check shared by two surfaces goes in `auth/guards.rs`;
a fixture needed by two test modules goes in `custos_core::test_support` (or `routes/test_utils.rs`
when it needs a `pds`-only type; add the missing knob rather than forking the helper); a periodic
task is a `custos_core::sweep::Sweep<AppState>` impl run by `custos_core::sweep::Scheduler`.

**Tests: one whole-document assertion per constant response, one table per contract.**
A route that serves a constant document (metadata, JWKS, capabilities) gets one `assert_eq!`
against the whole expected document, not one `#[tokio::test]` per field. A generic HTTP contract
(`missing auth → 401`, `non-empty body → 400`, `invalid DID → 400`) is one table-driven test over
a route list, not a per-route copy. Test names describe behaviour, never acceptance-criteria ids.

**`#[allow(dead_code)]` outside `#[cfg(test)]` needs a one-line reason that is true.**
The accepted exception is a `sqlx::FromRow` column fetched by `SELECT *` that only tests read.
Anything else is deleted, wired, or moved under `#[cfg(test)]`; "kept for later" is not a reason.

### Shared helpers index

Look here before writing a helper. Each row is the one home; copies elsewhere are bugs.

| Need | Use |
|---|---|
| epoch seconds / RFC 3339 now / SQLite datetime → RFC 3339 | `custos_core::time::{unix_now, unix_now_secs, now_rfc3339, to_rfc3339_utc}` |
| log an internal failure and answer 500 | `common::ApiResultExt::{or_internal, or_internal_as}` on the `Result` |
| the OAuth issuer / public URL without a trailing slash | `Config::issuer()` |
| cache a freshly authored or resolved DID document | `db::dids::upsert_did_document` (UPDATE-only heal: `rewrite_did_document`) |
| authenticate the account owner and map to XRPC errors | `auth::guards::authenticate_owner` |
| insert a generated value, retrying on a UNIQUE collision | `db::insert_with_retry_on_collision` |
| open an auth.md claim ceremony | `custos_core::auth::agent_assertion::start_claim_attempt` |
| the account row + genesis repo + announce shared by account promotion | `account_genesis` |
| a periodic background pass | `custos_core::sweep::Sweep` run by `custos_core::sweep::Scheduler` (tests call `custos_core::sweep::run_once`) |
| a nonce store's retention-above-replay rule | `common::{replay_span_secs, retention_covers_replay}` |
| lower-case hex of a SHA-256 digest | `common::token::sha256_hex` (inside `crates/crypto` itself: its crate-private `hex::to_hex`) |
| percent-encoding | `urlencoding::encode` |
| a validated DID or handle (parse once at the boundary; `name()`/`domain()` instead of re-finding the dot) | `common::{Did, Handle}` — `Deref<Target = str>`, serde and sqlx (SQLite TEXT) both run the validator |
| test state, accounts, tokens, DPoP proofs, request builders, body decoding | `custos_core::test_support` (through `routes::test_utils`, whose state constructors return `AppState`) |
| the space route tests' router, request builders, and record bodies | `custos_spaces::test_support` |
| a generic HTTP contract asserted over every route it binds (missing auth → 401, spurious body → 400, invalid DID → 400, closed pool → 500) | `routes::contract_tests` |

**Every `.rs` file with runtime behavior must have a pattern comment.**
Add `// pattern: Functional Core`, `// pattern: Imperative Shell`, or
`// pattern: Mixed (unavoidable)` at the top of any file containing functions or
orchestration logic. Files with only types, constants, or re-exports are exempt.

**`db/` submodules own queries, not transactions.**
Business-logic transactions (multi-table atomic operations) live in the route handler or
a dedicated helper called by the handler — not inside `db/` functions. `db/` functions
accept `&SqlitePool` or `&mut SqliteTransaction`; they never open transactions themselves
unless the operation is inherently single-table.

**Authentication must never be cookie-based; permissive CORS on the public surface depends on it.**
`custos_core::public_surface` applies permissive CORS to the public surface (landing, `.well-known`, OAuth,
agent registration, all XRPC, static assets) but deliberately **not** to the admin/provisioning
`/v1/*` surface (same-origin only). Permissive CORS is safe only because every auth path is
Bearer/DPoP/signed-request — never an ambient cookie — so a hostile origin cannot ride a logged-in
user's credentials. If any future auth mechanism becomes cookie-based, the permissive CORS layer
must be tightened (explicit origin allowlist + credentials handling) in the same change.

## Adding a New Route

1. Create `src/routes/<name>.rs` with `// pattern: Imperative Shell` at the top.
2. If the handler needs shared auth logic → add to `auth/` (pure) or use an existing extractor.
3. If the handler needs a new DB query → add to the appropriate `db/` submodule.
4. If it's an XRPC procedure: a JSON input body is parsed with `LexiconInput<T>` (never bare
   `axum::Json<T>`) after vendoring its lexicon document (`crates/custos-core/lexicons/README.md`); a
   no-input procedure takes `NoInputBody` instead. Both must be the handler's final extractor.
5. Register in `src/app.rs` router.
6. Add a `.bru` file in `bruno/` (see root AGENTS.md).

## Adding a New DB Query

1. Identify the owning entity (`accounts`, `oauth`, etc.).
2. Add the function to the matching `db/<entity>.rs` file, or `crates/custos-db/src/<entity>.rs`
   for a cross-feature entity.
3. If no matching file exists, create one with `// pattern: Imperative Shell`.
4. Export the function and any new data struct via `db/mod.rs` (`pub mod <entity>;`). A new
   table's migration goes in `crates/custos-db` (see its AGENTS.md).
