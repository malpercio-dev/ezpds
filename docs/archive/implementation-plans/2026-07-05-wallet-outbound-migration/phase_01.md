# Wallet Outbound Migration — Phase 1: OAuthClient Bearer-session mode + binary POST

**Goal:** Give `OAuthClient` a second authentication mode (legacy Bearer session) and a binary-body POST method, so the destination (migrated, deactivated) account can be driven with the plain `accessJwt`/`refreshJwt` that migration-mode `createAccount` returns, and so CAR/blob bytes can be uploaded.

**Architecture:** `OAuthClient` currently sends `Authorization: DPoP {token}` + a `DPoP` proof header on every request and refreshes via `/oauth/token`. This phase adds an internal `AuthMode { Dpop, Bearer }` field. In `Bearer` mode the client sends `Authorization: Bearer {token}` with **no** `DPoP` header and refreshes via `com.atproto.server.refreshSession`. The existing DPoP path is untouched. A new `post_bytes` method sends a raw byte body with a caller-chosen `Content-Type`.

**Tech Stack:** Rust, `reqwest` (rustls TLS at crate level), `httpmock` 0.8 for tests, `tokio` test runtime. Serde for the refresh response.

**Scope:** Phase 1 of 7.

**Codebase verified:** 2026-07-05.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### wallet-outbound-migration.AC6: OAuthClient supports a Bearer-session mode
- **wallet-outbound-migration.AC6.1 Success:** A Bearer-mode client sends `Authorization: Bearer {token}` and no `DPoP` header.
- **wallet-outbound-migration.AC6.2 Success:** A Bearer-mode client refreshes via `com.atproto.server.refreshSession`, not `/oauth/token`.
- **wallet-outbound-migration.AC6.3 Success:** `post_bytes` sends the provided body with the given `Content-Type` (e.g. `application/vnd.ipld.car`).
- **wallet-outbound-migration.AC6.4 Success:** The existing DPoP mode is unchanged — its tests still pass.

---

## Verified codebase facts (from investigation)

File: `apps/identity-wallet/src-tauri/src/oauth_client.rs`.

- `OAuthClient` struct (lines 22–27):
  ```rust
  pub struct OAuthClient {
      inner: Client,
      dpop: DPoPKeypair,
      session: Arc<Mutex<OAuthSession>>,
      base_url: String,
  }
  ```
- Constructors: `new(session, base_url) -> Result<Self, OAuthError>` (lines 37–45, loads DPoP keypair via `DPoPKeypair::get_or_create()`); `#[cfg(test)] new_for_test(keypair, session, base_url) -> Self` (lines 290–302).
- Public request methods: `get(&self, path) ` (48–52) and `post<B: Serialize + Sync>(&self, path, body)` (55–63). Both call `execute_with_retry(method, url, body)`.
- `execute_with_retry` (68–132): calls `maybe_refresh_token()`, reads `dpop_nonce`, calls `send_with_dpop(...)`, and on a `400` with `{"error":"use_dpop_nonce"}` stores the `DPoP-Nonce` header and retries exactly once.
- `send_with_dpop` (135–172): computes `ath = DPoPKeypair::compute_ath(&access_token)`, builds a proof via `self.dpop.make_proof(method, url, nonce, Some(&ath))`, then attaches headers (158–160):
  ```rust
  builder = builder
      .header("Authorization", format!("DPoP {access_token}"))
      .header("DPoP", &proof);
  ```
  For POST with a body it calls `.json(b)`.
- `maybe_refresh_token` (175–189): refreshes when `session.expires_at < now + 60`.
- `refresh_token` (195–287): POSTs form-encoded `grant_type=refresh_token` to `/oauth/token` with a DPoP proof (no `ath`), handles the `use_dpop_nonce` retry, then `apply_token_response`.
- `apply_token_response` (305–335): parses `crate::http::TokenResponse { access_token, refresh_token, expires_in }`, computes `expires_at = now + expires_in`, **writes tokens to the Keychain via `keychain::store_oauth_tokens(...)`**, and updates the session.
- `OAuthSession` fields: `access_token: String`, `refresh_token: String`, `expires_at: u64`, `dpop_nonce: Option<String>`.
- `OAuthError` variants used here: `NotAuthenticated`, `TokenRefreshFailed`, `InvalidGrant`, `KeychainError`.
- Existing tests (338–609) use `httpmock::MockServer::start()` and `DPoPKeypair::get_or_create()`; they are **not** `#[ignore]`d and run inline. Representative helpers: `make_session(access, refresh, expires_in_secs)`, `token_response_body()`, `decode_dpop_payload(req)`, `dpop_has_no_ath(req)`, `dpop_has_no_nonce(req)`.

Verified server/protocol facts:
- Bearer refresh endpoint is `com.atproto.server.refreshSession`: `POST /xrpc/com.atproto.server.refreshSession` with `Authorization: Bearer {refreshJwt}` (the **refresh** token is the bearer for this call), empty body, response `{ accessJwt, refreshJwt, handle, did }` (camelCase). Confirmed against the interop CLI's `ensureSession` (`account.js`), which refreshes with `token: account.refreshJwt`.
- `importRepo` enforces its 100 MiB cap by reading the `Content-Length` header; `reqwest` sets `Content-Length` automatically for a `Vec<u8>` body, so `post_bytes` must send an owned byte body (not a stream).

---

## Design decisions locked for this phase

1. **Add a field `auth_mode: AuthMode` to `OAuthClient`.** Keep `dpop: DPoPKeypair` non-optional; `new_bearer` still populates it via `get_or_create()` (harmless — it is simply never read in Bearer mode). This is the minimal-blast-radius change: header/refresh construction branches on `auth_mode` at the two existing choke points (`send_with_dpop`, `refresh_token`).
2. **Bearer refresh must NOT write to the Keychain.** The DPoP `apply_token_response` calls `keychain::store_oauth_tokens`, which persists the wallet's **primary** identity session. The Bearer client authenticates the **transient destination** account during migration; persisting its tokens would corrupt the primary session. Bearer refresh updates only the in-memory `OAuthSession`.
3. **`new_bearer` derives `expires_at` from the access JWT's `exp` claim** (base64url-decode the payload, read `exp`). Fall back to `now` (forcing an immediate refresh) only if the claim is unparseable. This makes the refresh path deterministically testable by handing `new_bearer` a token whose `exp` is already in the past.
4. **`post_bytes` branches on `auth_mode`** exactly like `send_with_dpop` (Bearer → `Authorization: Bearer`, no proof; DPoP → `Authorization: DPoP` + proof with `ath`). Migration only exercises the Bearer branch, but implement both for symmetry.
5. **The `use_dpop_nonce` retry loop is DPoP-only.** In Bearer mode, send once and return the response. A Bearer server never returns `use_dpop_nonce`, so gating the retry on `AuthMode::Dpop` is a clarity/safety measure, not a behavior change.

---

<!-- START_SUBCOMPONENT_A (tasks 1-4) -->

<!-- START_TASK_1 -->
### Task 1: Add `AuthMode` and the `auth_mode` field

**Verifies:** wallet-outbound-migration.AC6.4 (foundational — no behavior change yet)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth_client.rs` (struct at lines 22–27; constructors at 37–45 and 290–302)

**Implementation:**
- Add above the struct:
  ```rust
  /// How this client authenticates its XRPC requests.
  ///
  /// `Dpop` is the wallet's normal OAuth mode (DPoP-bound access token + proof header,
  /// refresh via `/oauth/token`). `Bearer` is the legacy session mode used ONLY for the
  /// migrated (deactivated) destination account, whose credentials are the plain
  /// `accessJwt`/`refreshJwt` that migration-mode `createAccount` returns.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  enum AuthMode {
      Dpop,
      Bearer,
  }
  ```
- Add `auth_mode: AuthMode` to the `OAuthClient` struct.
- In `new` (37–45) set `auth_mode: AuthMode::Dpop`.
- In `new_for_test` (290–302) set `auth_mode: AuthMode::Dpop`.

**Testing:** No new test — this task is a pure refactor that must keep all existing `oauth_client.rs` tests green (AC6.4). It is grouped with Tasks 2–4 under Subcomponent A; the subcomponent's tests (Task 4) prove the whole change.

**Verification:**
Run from repo root (see "How to run tests" at the bottom of this file):
```
cargo test -p identity-wallet --lib oauth_client
```
Expected: compiles; all pre-existing `oauth_client` tests pass.

**Commit:** `refactor(wallet): add AuthMode field to OAuthClient (Dpop default)`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `new_bearer` constructor + Bearer-aware header construction

**Verifies:** wallet-outbound-migration.AC6.1

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth_client.rs` (add `new_bearer`; branch `send_with_dpop` at 135–172; gate the nonce retry in `execute_with_retry` at 68–132)

**Implementation:**
- Add a `new_bearer` constructor:
  ```rust
  /// Build a Bearer-session client for a migrated destination account. `access_jwt` /
  /// `refresh_jwt` are the legacy tokens returned by migration-mode `createAccount`.
  /// `expires_at` is derived from the access token's `exp` claim so proactive refresh works.
  pub fn new_bearer(access_jwt: String, refresh_jwt: String, base_url: String)
      -> Result<Self, OAuthError>
  {
      let expires_at = jwt_exp_claim(&access_jwt).unwrap_or(0);
      let session = OAuthSession {
          access_token: access_jwt,
          refresh_token: refresh_jwt,
          expires_at,
          dpop_nonce: None,
      };
      Ok(Self {
          inner: Client::new(),
          dpop: DPoPKeypair::get_or_create()?,
          session: Arc::new(Mutex::new(session)),
          base_url,
          auth_mode: AuthMode::Bearer,
      })
  }
  ```
  (Confirm the exact `OAuthSession` construction against its definition in `oauth.rs`; if it has additional fields, populate them with their empty/default values.)
- Add a small private helper `jwt_exp_claim(token: &str) -> Option<u64>` that splits on `.`, base64url-decodes the payload segment, `serde_json`-parses it, and reads the `exp` field as `u64`. Return `None` on any failure.
- In `send_with_dpop` (135–172), branch on `self.auth_mode`:
  - `AuthMode::Bearer`: read `access_token` from the session, select the HTTP method, attach only `.header("Authorization", format!("Bearer {access_token}"))` (NO `DPoP` header, no proof, no `ath`, no `nonce`). For POST-with-body, still call `.json(b)`.
  - `AuthMode::Dpop`: existing code path unchanged.
- In `execute_with_retry` (68–132), short-circuit the nonce dance for Bearer: when `self.auth_mode == AuthMode::Bearer`, call `send_with_dpop` once and return its result without inspecting for `use_dpop_nonce`.

**Testing:**
Tests must verify (AC6.1):
- A Bearer client built with `new_bearer` (or a Bearer test session) issuing a `get`/`post` sends `Authorization: Bearer {token}` and sends **no** `DPoP` header. Assert via an `httpmock` matcher on the `Authorization` header value and an assertion that the `DPoP` header is absent.
- Add a Bearer test-session helper mirroring `make_session`, e.g. `make_bearer_client(access, refresh, base_url)` that constructs a Bearer `OAuthClient` for the mock server's `base_url`. To exercise both a valid and an expired token, craft the access JWT with a chosen `exp` (a `header.payload.sig` string where `payload` is base64url of `{"exp": <ts>}`; the signature segment can be a dummy — `jwt_exp_claim` never verifies it).

**Verification:**
```
cargo test -p identity-wallet --lib oauth_client
```
Expected: new Bearer-header test passes; existing DPoP tests still pass.

**Commit:** `feat(wallet): OAuthClient Bearer-session header mode + new_bearer`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Bearer refresh via `com.atproto.server.refreshSession`

**Verifies:** wallet-outbound-migration.AC6.2

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth_client.rs` (branch `refresh_token` at 195–287; add a Bearer refresh-response type)

**Implementation:**
- Add a response type:
  ```rust
  #[derive(Debug, Deserialize)]
  #[serde(rename_all = "camelCase")]
  struct RefreshSessionResponse {
      access_jwt: String,
      refresh_jwt: String,
  }
  ```
- At the top of `refresh_token`, branch on `self.auth_mode`. Keep the existing DPoP body under `AuthMode::Dpop`. For `AuthMode::Bearer`, implement a separate path:
  - Read `refresh_token` from the session (clone out, drop the lock).
  - `POST {base_url}/xrpc/com.atproto.server.refreshSession` with header `Authorization: Bearer {refresh_token}` and an empty body.
  - On non-2xx: map to `OAuthError::TokenRefreshFailed` (or `InvalidGrant` when the body clearly indicates an expired/invalid refresh token, matching the DPoP path's discrimination).
  - On 2xx: parse `RefreshSessionResponse`, then update the session **in memory only** — set `access_token`, `refresh_token`, and recompute `expires_at = jwt_exp_claim(&new_access).unwrap_or(now)`. **Do NOT** call `keychain::store_oauth_tokens` (see Design decision 2).
- Leave `maybe_refresh_token` (175–189) unchanged — it is mode-agnostic (`expires_at < now + 60`).

**Testing:**
Tests must verify (AC6.2):
- A Bearer client whose session `expires_at` is in the past, when it issues any request, first hits `POST /xrpc/com.atproto.server.refreshSession` (assert the mock was hit exactly once) and does **not** hit `/oauth/token` (assert that mock has 0 hits). After refresh, the follow-up request carries the new access token.
- Assert the refresh request's `Authorization` header is `Bearer {old_refresh_token}`.
- (Guard for Design decision 2) After a Bearer refresh, the Keychain store is not invoked. If a direct assertion is impractical, assert behaviorally that the primary DPoP session is unaffected, and leave a `// Bearer refresh must not persist to Keychain` comment at the refresh site.

**Verification:**
```
cargo test -p identity-wallet --lib oauth_client
```
Expected: Bearer-refresh test passes; DPoP refresh tests (`refresh_dpop_proof_has_no_ath_claim`, `refresh_invalid_grant_returns_invalid_grant`, `refresh_token_nonce_retry_sends_exactly_two_requests`) still pass (AC6.4).

**Commit:** `feat(wallet): Bearer refresh via com.atproto.server.refreshSession`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: `post_bytes` for binary bodies (CAR + blobs)

**Verifies:** wallet-outbound-migration.AC6.3, wallet-outbound-migration.AC6.4

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth_client.rs` (add `post_bytes`)

**Implementation:**
- Add a public method:
  ```rust
  /// POST a raw byte body with a caller-chosen Content-Type. Used for `importRepo`
  /// (`application/vnd.ipld.car`) and `uploadBlob` (the blob's MIME type). Branches on
  /// `auth_mode` for the auth header exactly like `send_with_dpop`.
  pub async fn post_bytes(
      &self,
      path: &str,
      content_type: &str,
      body: Vec<u8>,
  ) -> Result<Response, OAuthError> {
      // 1. maybe_refresh_token().await? (same proactive refresh as execute_with_retry)
      // 2. build url = format!("{}/{}", self.base_url, path.trim_start_matches('/'))
      // 3. build the POST request with .header("Content-Type", content_type).body(body)
      // 4. match self.auth_mode:
      //    Bearer -> .header("Authorization", format!("Bearer {access}"))   // no DPoP
      //    Dpop   -> proof = make_proof("POST", &url, nonce, Some(&ath));
      //              .header("Authorization", format!("DPoP {access}")).header("DPoP", &proof)
      //    (For Dpop, mirror execute_with_retry's single use_dpop_nonce retry; for Bearer send once.)
      // 5. send, map network errors to OAuthError::NotAuthenticated
  }
  ```
- Reuse the existing helpers (`maybe_refresh_token`, `make_proof`, `compute_ath`, session locking) rather than duplicating logic. Factor shared body-agnostic header construction if it reduces duplication with `send_with_dpop`, but do not regress the DPoP path.

**Testing:**
Tests must verify (AC6.3):
- A Bearer client `post_bytes("/xrpc/com.atproto.repo.importRepo", "application/vnd.ipld.car", bytes)` sends a request whose `Content-Type` is exactly `application/vnd.ipld.car`, whose body bytes equal `bytes`, and whose `Authorization` is `Bearer {token}` with no `DPoP` header. Assert via `httpmock` body + header matchers.

**Verification:**
```
cargo test -p identity-wallet --lib oauth_client
```
Expected: `post_bytes` test passes; all existing tests pass (AC6.4).

**Commit:** `feat(wallet): OAuthClient::post_bytes for binary CAR/blob uploads`
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_A -->

---

## How to run tests (all phases)

The `identity-wallet` Tauri backend is a normal Rust crate in the workspace (crate name `identity-wallet`), **excluded from the CI `just ci-pds` lane** because the iOS toolchain is absent there. Run its tests directly. From the **repo root** (devenv provides the toolchain; `CARGO_HOME`/`RUSTUP_HOME` resolve relative to the workspace root):

```
cargo test -p identity-wallet --lib oauth_client
```

Inline `httpmock` tests bind an ephemeral localhost socket. In a sandboxed shell, socket binding can be denied ("Operation not permitted"); if so, re-run with the sandbox disabled. Do not add `#[ignore]` to these Phase 1 tests — they follow `oauth_client.rs`'s existing inline convention. (Later phases that spin up `MockServer` inside the state-machine module follow `migrate.rs`/`recovery.rs` and DO use `#[ignore] // Requires socket binding; ignore in sandboxed environments`.)

## Phase 1 done when

- `AuthMode { Dpop, Bearer }` exists; `OAuthClient` carries `auth_mode`.
- `new_bearer` builds a Bearer client; `send_with_dpop` and `post_bytes` send `Authorization: Bearer` with no `DPoP` header in Bearer mode.
- Bearer refresh hits `com.atproto.server.refreshSession` (not `/oauth/token`) and does not touch the Keychain.
- `post_bytes` sends the given `Content-Type` and body.
- All pre-existing DPoP tests still pass.
- Covers wallet-outbound-migration.AC6.1–AC6.4.
