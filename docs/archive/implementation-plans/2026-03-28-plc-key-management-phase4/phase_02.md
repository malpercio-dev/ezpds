# Claim Flow Backend — Phase 2: start_pds_auth and request_claim_verification

**Goal:** Implement OAuth authentication to an arbitrary PDS and the email verification trigger command.

**Architecture:** `start_pds_auth` reuses the existing OAuth PKCE+DPoP infrastructure (`pkce::generate`, `DPoPKeypair`, `generate_state_param`, `handle_deep_link`) but targets an arbitrary PDS via `PdsClient` methods instead of the relay. After successful authentication, an `OAuthClient` pointing at the old PDS is stored in `ClaimState.pds_oauth_client`. `request_claim_verification` uses that client to call the XRPC endpoint `requestPlcOperationSignature`.

**Tech Stack:** Rust, tauri, tokio, reqwest, serde

**Scope:** 4 phases from design Phase 4 (this is phase 2 of 4)

**Codebase verified:** 2026-03-28

---

## Acceptance Criteria Coverage

This phase implements and tests:

### plc-key-management.AC4: Claim flow executes end-to-end
- **plc-key-management.AC4.2 Success:** `request_claim_verification` calls `requestPlcOperationSignature` on the old PDS

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Implement start_pds_auth command

**Verifies:** None (infrastructure — OAuth flow wiring; verified operationally by downstream commands)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/claim.rs`

**Implementation:**

Add `start_pds_auth` Tauri command to `claim.rs`. This command performs OAuth PKCE+DPoP against an arbitrary PDS discovered via `PdsClient`. It reuses the existing deep-link callback mechanism (`handle_deep_link` in `oauth.rs`).

The function:

1. Reads `ClaimState.did` and `ClaimState.pds_url` from `AppState.claim_state` (set by `resolve_identity` in Phase 1). Returns `ClaimError::Unauthorized` if claim state is empty.
2. Calls `PdsClient::discover_auth_server(pds_url)` to get `AuthServerMetadata`.
3. Generates PKCE verifier/challenge via `oauth::pkce::generate()`.
4. Generates CSRF state via `oauth::generate_state_param()`.
5. Gets DPoP keypair via `oauth::DPoPKeypair::get_or_create()`, computes JWK thumbprint.
6. Builds DPoP proof for PAR: `dpop.make_proof("POST", &metadata.pushed_authorization_request_endpoint, None, None)`.
7. Calls `PdsClient::pds_par(metadata, pkce_challenge, state, dpop_proof, dpop_jkt, Some(did))` — passes the DID as `login_hint` so the PDS pre-selects the correct account.
8. Sets up `tokio::sync::oneshot::channel()` and stores `PendingOAuthFlow { tx, pkce_verifier, csrf_state }` in `AppState.pending_auth`.
9. Builds authorize URL via `PdsClient::build_pds_authorize_url(metadata, request_uri, Some(did))`.
10. Opens Safari via `app.opener().open_url(authorize_url)`.
11. Awaits the oneshot receiver. On timeout or channel drop, returns `ClaimError::Unauthorized`.
12. On receiving `CallbackParams { code, .. }`:
    - Builds DPoP proof for token exchange: `dpop.make_proof("POST", &metadata.token_endpoint, None, None)`
    - Calls `PdsClient::pds_token_exchange(metadata, code, pkce_verifier, dpop_proof)`
    - Implements nonce retry: if response status is 400 and contains `DPoP-Nonce` header with `"use_dpop_nonce"` error, rebuild proof with nonce and retry once
    - Parses successful response JSON to extract `access_token`, `refresh_token`, `expires_in`
13. Creates `OAuthSession { access_token, refresh_token, expires_at: now + expires_in, dpop_nonce: nonce_from_response }`.
14. Creates `OAuthClient::new(Arc::new(Mutex::new(session)), pds_url)`. **Note:** This creates a new `OAuthClient` instance that shares the same DPoP keypair (loaded from Keychain) as the relay's `OAuthClient`. This is intentional and safe — the DPoP keypair is used to generate per-request proofs with `htu` (target URI) binding, and DPoP nonces are tracked per-session (the `OAuthSession` object), not per-keypair. The PDS session and relay session are fully independent.
15. Stores the `OAuthClient` in `ClaimState.pds_oauth_client`.
16. Emits a `"pds_auth_ready"` Tauri event (frontend listens for this to advance the UI).

The Tauri command signature:

```rust
#[tauri::command]
pub async fn start_pds_auth(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::oauth::AppState>,
    pds_url: String,
) -> Result<(), ClaimError>
```

Map errors:
- `PdsClientError::*` → `ClaimError::NetworkError { message }`
- `OAuthError::StateMismatch` → `ClaimError::Unauthorized`
- `OAuthError::CallbackAbandoned` → `ClaimError::Unauthorized`
- Channel drop / timeout → `ClaimError::Unauthorized`

Note: `start_pds_auth` uses `pds_url` from the frontend parameter (passed from `IdentityInfo.pdsUrl` returned by `resolve_identity`). It also reads `ClaimState.did` for the login_hint. If `ClaimState` is empty, the user hasn't called `resolve_identity` first — return `Unauthorized`.

**Verification:**

Run: `cargo check -p identity-wallet-tauri`
Expected: Compiles without errors

Note: Full integration testing of OAuth flows requires Safari and deep-links which are not available in `cargo test`. The OAuth path is verified indirectly through `request_claim_verification` and `sign_and_verify_claim` tests that mock the `OAuthClient`. The token exchange nonce retry logic follows the same proven pattern from `exchange_code_with_retry` in `oauth.rs`.

**Commit:** `feat(identity-wallet): implement start_pds_auth command`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Implement request_claim_verification command with tests

**Verifies:** plc-key-management.AC4.2

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/claim.rs`

**Implementation:**

Add `request_claim_verification` Tauri command. This command calls the `requestPlcOperationSignature` XRPC endpoint on the old PDS to trigger email verification.

The function:
1. Reads `ClaimState` from `AppState.claim_state`. Returns `ClaimError::Unauthorized` if empty.
2. Reads `pds_oauth_client` from ClaimState. Returns `ClaimError::Unauthorized` if `None` (user hasn't completed PDS auth).
3. Calls `pds_client::request_plc_operation_signature(oauth_client)`.
4. Returns `Ok(())` on success.

Map errors:
- `PdsClientError::NetworkError { message }` → `ClaimError::NetworkError { message }`
- `PdsClientError::InvalidResponse { message }` → `ClaimError::NetworkError { message }`
- Any non-2xx → `ClaimError::NetworkError` with status description

The Tauri command signature:

```rust
#[tauri::command]
pub async fn request_claim_verification(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<(), ClaimError>
```

**Testing:**
Tests must verify AC4.2:
- plc-key-management.AC4.2: request_claim_verification calls requestPlcOperationSignature on the old PDS

Test approach: Use `httpmock::MockServer` to mock the PDS's XRPC endpoint. Create an `OAuthClient` via `OAuthClient::new_for_test()` pointing at the mock server. Construct a `ClaimState` with the test `OAuthClient` and store it in an `AppState`.

Specific test cases:
1. **Success — calls XRPC endpoint:** Set up mock expecting POST `/xrpc/com.atproto.identity.requestPlcOperationSignature` returning 200. Call core logic function. Assert mock was hit exactly once.
2. **Unauthorized — no claim state:** Call with empty claim state. Assert `ClaimError::Unauthorized`.
3. **Unauthorized — no OAuth client:** Set up ClaimState without `pds_oauth_client`. Assert `ClaimError::Unauthorized`.
4. **Network error — PDS returns 500:** Mock returns 500. Assert `ClaimError::NetworkError`.

To make the core logic testable without Tauri's `State`, extract a helper:
```rust
pub(crate) async fn request_claim_verification_impl(
    claim_state: &ClaimState,
) -> Result<(), ClaimError>
```

Follow existing pattern from `home.rs` (`load_home_data_with_urls` helper).

**Verification:**

Run: `cargo test -p identity-wallet-tauri -- claim::tests::request_claim`
Expected: All tests pass

**Commit:** `feat(identity-wallet): implement request_claim_verification command (AC4.2)`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->
