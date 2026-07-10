# Code Quality Hardening Design

## Summary

A full-workspace audit (2026-07-07) found the codebase in notably strong shape — constant-time
comparisons wherever secret equality matters, pinned JWT algorithms, argon2id with an
enumeration-resistant timing dummy, CAS-based repo writes with the firehose row in the same
transaction, fully parameterized SQL, zeroized key material. The remaining findings are small,
individually PR-sized hardening items that are cheapest to fix now, before the patterns they
represent proliferate. This plan bundles six of them. Each item below is independent; implement as
separate commits (or separate PRs) in any order.

## Definition of Done

1. **Async blob I/O.** `crates/pds/src/blob_store.rs` currently uses synchronous `std::fs`
   (`write`/`read`/`create_dir_all`/`remove_file`/`read_dir`), called directly from async handlers
   (`routes/upload_blob.rs`, `routes/get_blob.rs`) — each call parks a Tokio worker for the full
   disk I/O of a potentially multi-MB blob. Convert the module to `tokio::fs` (or
   `spawn_blocking` for the directory-walk paths where async fs is awkward). While there, replace
   the module-wide `#![allow(dead_code)]` with targeted per-item allows or remove it. This is the
   highest-priority item: the module is young and synchronous by construction, and future blob
   backends will copy whatever pattern it establishes.

2. **`Sensitive`-wrap `admin_token`.** `crates/common/src/config.rs` declares
   `pub admin_token: Option<String>` while sibling secrets (`signing_key_master_key`,
   `smtp_password`) use the `Sensitive<T>` wrapper whose `Debug` prints `***`. `Config` derives
   `Debug`, so the break-glass admin bearer token would leak in cleartext if config is ever
   debug-logged (latent today — no such log exists — but it's one `tracing::debug!(?config)`
   away). Wrap it: `Option<Sensitive<String>>`, updating the raw-config plumbing and the
   constant-time comparison site in `auth/guards.rs`.

3. **Scope CORS off admin/provisioning routes + document the invariant.**
   `crates/pds/src/app.rs` applies `CorsLayer::permissive()` to the entire router. This is safe
   today only because no auth is cookie-based (all Bearer/DPoP/signed-request), and it is correct
   for the public XRPC surface — but `/v1/admin/*` and the `/v1/*` provisioning routes have no
   cross-origin use case. Restructure so the permissive layer covers the XRPC/OAuth/public
   surface while admin/provisioning routes get no CORS layer (same-origin only), and add the
   invariant to `crates/pds/CLAUDE.md`: **"Authentication must never be cookie-based; permissive
   CORS on the public surface depends on it."**

4. **Fix modulo bias in short-code generation.** `crates/pds/src/code_gen.rs` maps random bytes
   with `CHARSET[(b as usize) % CHARSET.len()]`; with a 36-char set, `256 % 36 = 4`, so the first
   four characters are ~14% (relative) more likely per position. These codes back invite codes,
   claim codes, transfer codes, and admin pairing codes. Not practically exploitable
   (36^6 ≈ 2.2B), but it is a crypto code smell in a security product. Switch to rejection
   sampling (draw a byte, discard ≥ 252, i.e. the largest multiple of 36) — keep it dependency-free
   rather than pulling `rand::Uniform` distributions in for one function. Add a test asserting all
   charset members are reachable and (statistically loose) roughly uniform.

5. **Tighten rate limiting on `POST /v1/transfer/accept`.** The per-endpoint IP limiter
   (`crates/pds/src/rate_limit.rs`) tightens createAccount/createSession/resetPassword/
   updateHandle, but `transfer/accept` authenticates on a bare 6-char code and is protected only
   by the generous global cap (3000/5min) plus code expiry and one-active-transfer-per-account.
   Add it to the tight per-endpoint limiter with a budget in line with createSession. When the
   claim-ceremony confirm endpoint lands (wallet consent plan), it joins the same list — note
   this in `rate_limit.rs`'s pattern comment so short-code-authenticated endpoints are added by
   default.

6. **`cargo-deny` gate.** Add `deny.toml` (license allowlist reflecting current dependencies;
   bans for duplicate major versions where the workspace already tracks them via Cargo.toml
   comments; the advisory check can stay delegated to the existing `cargo-audit` step to avoid
   double-reporting). Add `cargo-deny` to the devenv shell, a `just deny` recipe, wire it into
   `just ci`/`ci-pds`, and document it in `AGENTS.md` alongside the audit.toml conventions
   (rationale comments required for every exception, same as `.cargo/audit.toml`).

**Explicitly out of scope:** metrics (own plan), any behavior change to the public XRPC surface,
dependency upgrades (axum 0.8 is MM-154).

## Acceptance Criteria

### hardening.AC1: Async blob I/O
- **AC1.1:** No `std::fs` calls remain in `blob_store.rs`; upload/get/GC paths pass existing
  tests unchanged.
- **AC1.2:** The module-wide `#![allow(dead_code)]` is gone; `cargo clippy --workspace -- -D
  warnings` stays green.

### hardening.AC2: Sensitive admin token
- **AC2.1:** `format!("{:?}", config)` output contains `***` and not the token value (add a test
  beside the existing `Sensitive` tests).
- **AC2.2:** Admin auth (master token path in `auth/guards.rs`) still verifies constant-time and
  all guard tests pass.

### hardening.AC3: CORS scoping
- **AC3.1:** Preflight `OPTIONS` against an `/xrpc/*` route still returns permissive headers;
  against `/v1/admin/*` it returns no `Access-Control-Allow-Origin`.
- **AC3.2:** The no-cookie-auth invariant is stated in `crates/pds/CLAUDE.md`.

### hardening.AC4: Code generation
- **AC4.1:** Rejection sampling replaces the modulo; a uniformity test exists; all existing
  code-consuming flows (invite, transfer, pairing, claim) pass unchanged.

### hardening.AC5: Transfer rate limit
- **AC5.1:** Exceeding the new `transfer/accept` budget returns 429 with `RateLimit-*`/
  `Retry-After` headers, matching the existing limited endpoints' envelope.

### hardening.AC6: cargo-deny
- **AC6.1:** `just deny` passes locally and in CI on a clean checkout; a deliberately added
  disallowed license (in a scratch branch) fails the gate.
- **AC6.2:** `deny.toml` exceptions each carry a rationale comment.

## Implementation notes

- Items 1–5 touch security-adjacent code: no route imports routes, keep changes inside the
  owning module, and run the full `just ci-pds` gate per change.
- Item 3 changes router layering in `app.rs` — verify the rate-limit and trace layers still wrap
  everything they did before (layer ordering in axum is easy to silently reorder; the existing
  router tests plus a new CORS test in the `app.rs` test module cover this).
- Item 6 adds a tool to the Nix dev shell (`devenv.nix`) — follow the pattern used for
  `cargo-audit`; do not install globally.
