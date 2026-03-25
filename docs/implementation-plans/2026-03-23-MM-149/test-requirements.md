# Test Requirements: MM-149 OAuth PKCE Client

## Summary

MM-149 spans 8 acceptance criteria groups (AC1--AC8) with 25 individual criteria. Of these, 19 are covered by automated tests (unit or integration) across two crates (`relay` and `identity-wallet`), and 6 require human verification in the iOS Simulator because they depend on system browser interaction, iOS Keychain hardware, or WKWebView rendering that cannot be exercised in `cargo test`.

**Test file inventory:**

| File | Test Count | Type |
|------|-----------|------|
| `crates/relay/src/db/mod.rs` | 1 | Unit |
| `apps/identity-wallet/src-tauri/src/oauth.rs` | 12 | Unit (+ 2 ignored integration) |
| `apps/identity-wallet/src-tauri/src/oauth_client.rs` | 6 | Unit (httpmock) |
| Manual (iOS Simulator) | 6 criteria | Human verification |

---

## Automated Tests

### AC1: PAR flow completes successfully

| Criterion | Test Type | File | Test Name Pattern | Phase | Notes |
|-----------|-----------|------|-------------------|-------|-------|
| MM-149.AC1.1 | Integration (ignored) | `apps/identity-wallet/src-tauri/src/oauth.rs` | `par_integration_returns_201_with_request_uri` | 4 | Requires running relay at localhost:8080. Run with `cargo test -p identity-wallet par_integration -- --include-ignored`. Verifies PAR POST returns 201 with `request_uri` starting with `urn:ietf:params:oauth:request_uri:`. |
| MM-149.AC1.2 | Human | -- | -- | 5/7 | See Human Verification section. Authorization URL opened in Safari cannot be asserted from `cargo test`. |
| MM-149.AC1.3 | Unit (existing) | `crates/relay/src/routes/oauth_par.rs` | Existing relay test suite | -- | Already tested by the relay's PAR handler tests (unknown client_id returns 4xx). Phase 1 migration test indirectly verifies the inverse: the seeded client_id IS accepted. |
| MM-149.AC1.3 (inverse) | Unit | `crates/relay/src/db/mod.rs` | `v013_seeds_identity_wallet_oauth_client` | 1 | Verifies the V013 migration inserts the `dev.malpercio.identitywallet` client row with correct `redirect_uris` and `dpop_bound_access_tokens: true`. |
| MM-149.AC1.4 | Integration (ignored) | `apps/identity-wallet/src-tauri/src/oauth.rs` | `par_missing_code_challenge_returns_client_error` | 4 | Requires running relay. Sends a PAR POST without `code_challenge` field and asserts a 4xx response. |

### AC2: OAuth callback received and code exchanged

| Criterion | Test Type | File | Test Name Pattern | Phase | Notes |
|-----------|-----------|------|-------------------|-------|-------|
| MM-149.AC2.1 | Unit | `apps/identity-wallet/src-tauri/src/oauth.rs` | `handle_deep_link_delivers_code_and_state` | 5 | Constructs a fake `AppState` with a pending flow, calls `handle_deep_link` with a matching callback URL, and asserts the `oneshot` receiver gets `Ok(CallbackParams { code, state })`. |
| MM-149.AC2.2 | Human | -- | -- | 7 | Full token exchange requires a live relay with user consent in Safari. See Human Verification section. |
| MM-149.AC2.3 | Unit | `apps/identity-wallet/src-tauri/src/oauth.rs` | `handle_deep_link_csrf_mismatch_returns_state_mismatch_error` | 5 | Calls `handle_deep_link` with a state param that does not match `flow.csrf_state`. Asserts the receiver gets `Err(OAuthError::StateMismatch)` and that `pending_auth` is cleared. |
| MM-149.AC2.4 | Unit | `apps/identity-wallet/src-tauri/src/oauth.rs` | `handle_deep_link_replay_is_silently_ignored` | 5 | Calls `handle_deep_link` twice with the same URL. First call succeeds; second call sees `pending_auth = None` and returns without panic or send. |
| MM-149.AC2.5 | Human | -- | -- | 5/7 | The `exchange_code_with_retry` function handles this, but testing it requires a relay that issues `use_dpop_nonce` at the token endpoint. See Human Verification section. The code path is structurally verified by the OAuthClient nonce-retry tests in AC5.2 (same retry pattern). |

### AC3: DPoP proofs are correctly formed

| Criterion | Test Type | File | Test Name Pattern | Phase | Notes |
|-----------|-----------|------|-------------------|-------|-------|
| MM-149.AC3.1 | Unit | `apps/identity-wallet/src-tauri/src/oauth.rs` | `dpop_proof_header_has_required_fields` | 3 | Decodes the base64url header of a generated proof. Asserts `typ = "dpop+jwt"`, `alg = "ES256"`, `jwk.kty = "EC"`, `jwk.crv = "P-256"`, non-empty `x` and `y`. |
| MM-149.AC3.2 | Unit | `apps/identity-wallet/src-tauri/src/oauth.rs` | `dpop_proof_claims_has_required_fields` | 3 | Decodes the base64url claims. Asserts `jti` is non-empty, `htm` and `htu` match inputs, `iat` is within 5 seconds of current time. |
| MM-149.AC3.3 | Unit | `apps/identity-wallet/src-tauri/src/oauth.rs` | `dpop_proof_includes_ath_when_supplied` | 3 | Generates proof with `ath = Some("abc123")` and asserts `claims.ath = "abc123"`. Generates without ath and asserts `claims.ath` is absent. |
| MM-149.AC3.4 | Unit | `apps/identity-wallet/src-tauri/src/oauth.rs` | `dpop_proof_includes_nonce_when_supplied` | 3 | Generates with `nonce = Some("nonce123")` and asserts presence. Generates without and asserts absence. |
| MM-149.AC3.5 | Unit | `apps/identity-wallet/src-tauri/src/oauth.rs` | `dpop_proof_signature_verifies_against_embedded_jwk` | 3 | Extracts the JWK `x`/`y` coordinates from the proof header, reconstructs a `VerifyingKey`, and calls `.verify()` on the signing input. |

**Supplementary test:**

| Criterion | Test Type | File | Test Name Pattern | Phase | Notes |
|-----------|-----------|------|-------------------|-------|-------|
| (AC3.3 helper) | Unit | `apps/identity-wallet/src-tauri/src/oauth.rs` | `compute_ath_matches_sha256_base64url` | 3 | Verifies `DPoPKeypair::compute_ath()` output matches independently computed `base64url(SHA-256(token))`. |

### AC4: Tokens stored securely and loaded on restart

| Criterion | Test Type | File | Test Name Pattern | Phase | Notes |
|-----------|-----------|------|-------------------|-------|-------|
| MM-149.AC4.1 | Human | -- | -- | 5/7 | Keychain storage is exercised by `start_oauth_flow` after token exchange. Verification requires checking the iOS Simulator Keychain or confirming no `tracing::error` lines from `store_oauth_tokens`. See Human Verification section. |
| MM-149.AC4.2 | Human | -- | -- | 7 | On app relaunch, `setup()` calls `load_oauth_tokens()` and emits `auth_ready`. Verification requires iOS Simulator relaunch. The `setup()` code path cannot be exercised in unit tests (requires Tauri runtime). See Human Verification section. |
| MM-149.AC4.3 | Human | -- | -- | 7 | Tokens must NOT appear in `localStorage`, `sessionStorage`, or any JS-accessible storage. Operational check only. See Human Verification section. |

### AC5: Authenticated requests carry DPoP proofs

| Criterion | Test Type | File | Test Name Pattern | Phase | Notes |
|-----------|-----------|------|-------------------|-------|-------|
| MM-149.AC5.1 | Unit (httpmock) | `apps/identity-wallet/src-tauri/src/oauth_client.rs` | `dpop_and_authorization_headers_present_on_get` | 6 | Uses `httpmock::MockServer` to intercept the outgoing GET. Asserts `Authorization: DPoP my_access_token` and `DPoP: <three-part-JWT>` headers are present. |
| MM-149.AC5.2 | Unit (httpmock) | `apps/identity-wallet/src-tauri/src/oauth_client.rs` | `nonce_retry_sends_exactly_two_requests` | 6 | First mock returns 400 with `DPoP-Nonce: test-server-nonce`. Second mock returns 200. Asserts exactly 2 requests hit the server and the retry DPoP proof contains `nonce = "test-server-nonce"` in its claims. |
| MM-149.AC5.3 | Unit (httpmock) | `apps/identity-wallet/src-tauri/src/oauth_client.rs` | `empty_access_token_does_not_panic` | 6 | Creates a session with `access_token = ""`. Asserts the request completes (server returns 401) without panicking. |

### AC6: Token refresh works transparently

| Criterion | Test Type | File | Test Name Pattern | Phase | Notes |
|-----------|-----------|------|-------------------|-------|-------|
| MM-149.AC6.1 | Unit (httpmock) | `apps/identity-wallet/src-tauri/src/oauth_client.rs` | `lazy_refresh_fires_when_expiry_near` | 6 | Creates session with `expires_at = now + 30` (below the 60-second threshold). Mocks `/oauth/token` (200 with new tokens) and `/resource` (200). Asserts refresh was called before the resource request, and session updated with `new_access_token`. |
| MM-149.AC6.2 | Unit (httpmock) | `apps/identity-wallet/src-tauri/src/oauth_client.rs` | `refresh_dpop_proof_has_no_ath_claim` | 6 | Calls `refresh_token()` directly. Captures the DPoP header from the mock. Decodes claims and asserts `ath` is null/absent. |
| MM-149.AC6.3 | Unit (httpmock) | `apps/identity-wallet/src-tauri/src/oauth_client.rs` | `refresh_invalid_grant_returns_token_refresh_failed` | 6 | Mock returns 400 with `{"error": "invalid_grant"}`. Asserts result is `Err(OAuthError::TokenRefreshFailed)`. |

### AC7: Frontend authentication screens

All AC7 criteria require human verification. See Human Verification section below.

### AC8: Failed auth recovery

All AC8 criteria require human verification. See Human Verification section below.

---

## PKCE Utility Tests (No Direct AC, Foundation for AC1)

These tests validate the PKCE primitives used by `start_oauth_flow` to satisfy AC1.

| Test Name Pattern | Test Type | File | Phase | Notes |
|-------------------|-----------|------|-------|-------|
| `pkce_verifier_is_43_unreserved_chars` | Unit | `apps/identity-wallet/src-tauri/src/oauth.rs` | 4 | Asserts base64url of 32 bytes = 43 chars, all RFC 7636 unreserved. |
| `pkce_challenge_equals_sha256_base64url_of_verifier` | Unit | `apps/identity-wallet/src-tauri/src/oauth.rs` | 4 | Independently computes `base64url(SHA-256(verifier))` and asserts equality. |
| `state_param_is_22_chars` | Unit | `apps/identity-wallet/src-tauri/src/oauth.rs` | 4 | Asserts base64url of 16 bytes = 22 chars. |
| `pkce_verifiers_are_unique` | Unit | `apps/identity-wallet/src-tauri/src/oauth.rs` | 4 | Two sequential `generate()` calls produce different verifiers. |

---

## Human Verification

The following criteria cannot be automated because they require the iOS Simulator runtime, system browser interaction, or the full Tauri application lifecycle. Each includes a step-by-step verification approach.

### MM-149.AC1.2: Authorization URL opened in system browser

**Justification:** Opening a URL in Safari via `tauri-plugin-opener` requires the iOS runtime. The Tauri `OpenerExt` API is not mockable in unit tests, and `cargo test` cannot observe Safari launching.

**Verification steps:**
1. Start the relay: `cargo run -p relay`
2. Launch the app: `cd apps/identity-wallet && cargo tauri ios dev`
3. Complete onboarding through step 10 (DID ceremony + Shamir backup)
4. Tap "Continue" on the `complete` step
5. **Verify:** Safari opens with a URL containing `client_id=dev.malpercio.identitywallet` and `request_uri=urn:ietf:params:oauth:request_uri:...`

### MM-149.AC2.2: Token exchange succeeds

**Justification:** The full code-for-token exchange requires a live relay, a completed user consent in Safari, and a deep-link callback routed through iOS. These cannot be orchestrated in a unit test.

**Verification steps:**
1. Complete steps 1--5 from AC1.2 above (app transitions to `authenticating`, Safari opens)
2. Complete the authorization consent in Safari
3. **Verify:** Safari redirects to the app; app transitions from `authenticating` to `authenticated`
4. **Verify:** No error messages in the `cargo tauri ios dev` console

### MM-149.AC2.5: use_dpop_nonce retry on token exchange

**Justification:** The relay always requires a DPoP nonce at the token endpoint. On the first token exchange attempt in `exchange_code_with_retry`, the nonce is absent; the relay returns 400 with `use_dpop_nonce`. The retry path is always exercised during normal operation, but verifying it requires a live relay.

**Verification steps:**
1. Complete the full OAuth flow (steps 1--3 from AC2.2 above)
2. In the `cargo tauri ios dev` console output, search for the tracing log line:
   ```
   DEBUG identity_wallet::oauth: retrying token exchange with server nonce nonce=...
   ```
3. **Verify:** The log line appears, confirming the retry path was taken and succeeded (app reached `authenticated`)

**Rationale for not automating:** The `exchange_code_with_retry` function is tightly coupled to `RelayClient::token_exchange` which returns a raw `reqwest::Response`. Mocking would require extracting the retry logic into a testable function, which the current design does not do. The same retry pattern IS tested in `OAuthClient::execute_with_retry` (AC5.2) using httpmock, providing structural confidence.

### MM-149.AC4.1: Tokens stored in iOS Keychain

**Justification:** The `security-framework` crate's Keychain operations require macOS/iOS Keychain Services, which are not available in `cargo test` (unless running on macOS with Keychain access). The identity-wallet's test builds redirect Keychain calls to an in-memory store, so production Keychain persistence cannot be verified in CI.

**Verification steps:**
1. Complete the full OAuth flow (AC2.2 steps above)
2. In the `cargo tauri ios dev` console, confirm **no** `tracing::error` lines mentioning "Keychain error" appear after "OAuth flow complete; session stored"
3. Alternatively, after a successful flow, force-quit the app and relaunch. If the app skips onboarding and shows `authenticated` directly, the Keychain store and load paths both work (this also covers AC4.2)

### MM-149.AC4.2: Tokens loaded on restart

**Justification:** The `setup()` closure runs during Tauri app initialization, which requires the full Tauri runtime. It cannot be invoked from `cargo test`.

**Verification steps:**
1. Complete the full OAuth flow to reach `authenticated` state
2. Force-quit the app (swipe up from app switcher or press Home + stop the Simulator process)
3. Relaunch the app (tap the icon or run `cargo tauri ios dev` again)
4. **Verify:** Onboarding is skipped; app shows `authenticated` directly
5. **Verify:** Console shows the `auth_ready` event emission log (if tracing is enabled)

### MM-149.AC4.3: Tokens not in JS storage

**Justification:** This is a negative security assertion about the WKWebView's JavaScript context. There is no automated way to inspect `localStorage`/`sessionStorage` from Rust tests.

**Verification steps:**
1. Complete the full OAuth flow to reach `authenticated` state
2. In Safari (macOS), open Web Inspector for the iOS Simulator (Develop menu > Simulator > identity-wallet)
3. In the Web Inspector Console, run:
   ```javascript
   JSON.stringify(localStorage)
   JSON.stringify(sessionStorage)
   ```
4. **Verify:** Neither output contains `access_token`, `refresh_token`, or any OAuth credential strings
5. Also inspect IndexedDB and cookies in Web Inspector's Storage tab
6. **Verify:** No OAuth tokens present in any JS-accessible storage

### MM-149.AC7.1: Auto-advance to authenticating after onboarding

**Justification:** Requires SvelteKit rendering in WKWebView (Tauri runtime) and user interaction through 10 onboarding steps.

**Verification steps:**
1. Start the relay
2. Launch the app in the iOS Simulator (`cargo tauri ios dev`)
3. Complete all 10 onboarding steps (welcome through Shamir backup)
4. On the `complete` step, tap "Continue"
5. **Verify:** Screen transitions to the `authenticating` step (spinner visible, "Opening browser for authentication..." text)
6. **Verify:** Safari opens automatically

### MM-149.AC7.2: Successful auth transitions to authenticated

**Verification steps:**
1. Continue from AC7.1 (Safari is open with the consent page)
2. Complete the authorization in Safari
3. **Verify:** App transitions from `authenticating` to `authenticated` (checkmark icon, "Your identity wallet is ready." text)

### MM-149.AC7.3: Relaunch with stored tokens skips onboarding

**Verification steps:**
1. Same as AC4.2 (force-quit and relaunch)
2. **Verify:** The `welcome` step never appears; app starts at `authenticated`

### MM-149.AC7.4: Auth failure transitions to auth_failed

**Verification steps:**
1. Stop the relay (so PAR will fail)
2. Launch the app fresh (uninstall first to clear Keychain)
3. Complete onboarding through step 10
4. Tap "Continue"
5. **Verify:** App transitions to `auth_failed` step (X icon, "Authentication Failed" heading, error code displayed)

### MM-149.AC8.1: "Try again" re-invokes start_oauth_flow

**Verification steps:**
1. Reach the `auth_failed` state (AC7.4 steps above)
2. Start the relay (so the retry can succeed)
3. Tap "Try again"
4. **Verify:** App transitions to `authenticating` (spinner appears, browser opens)
5. **Verify:** No stale error state — `authError` is cleared before re-entering `authenticating`

### MM-149.AC8.2: "Start over" resets to step 1

**Verification steps:**
1. Reach the `auth_failed` state (AC7.4 steps above)
2. Tap "Start over"
3. **Verify:** App transitions to the `welcome` step (first step of onboarding)
4. **Verify:** All form state is reset (no pre-filled fields from the previous attempt)

---

## Coverage Matrix

| Criterion | Automated | Human | Implementation Phase |
|-----------|-----------|-------|---------------------|
| MM-149.AC1.1 | Integration (ignored) | -- | 4 |
| MM-149.AC1.2 | -- | iOS Simulator | 5, 7 |
| MM-149.AC1.3 | Unit (relay) | -- | 1 (+ existing relay tests) |
| MM-149.AC1.4 | Integration (ignored) | -- | 4 |
| MM-149.AC2.1 | Unit | -- | 5 |
| MM-149.AC2.2 | -- | iOS Simulator | 5, 7 |
| MM-149.AC2.3 | Unit | -- | 5 |
| MM-149.AC2.4 | Unit | -- | 5 |
| MM-149.AC2.5 | -- | iOS Simulator (log check) | 5, 7 |
| MM-149.AC3.1 | Unit | -- | 3 |
| MM-149.AC3.2 | Unit | -- | 3 |
| MM-149.AC3.3 | Unit | -- | 3 |
| MM-149.AC3.4 | Unit | -- | 3 |
| MM-149.AC3.5 | Unit | -- | 3 |
| MM-149.AC4.1 | -- | iOS Simulator | 5, 7 |
| MM-149.AC4.2 | -- | iOS Simulator | 7 |
| MM-149.AC4.3 | -- | iOS Simulator (Web Inspector) | 7 |
| MM-149.AC5.1 | Unit (httpmock) | -- | 6 |
| MM-149.AC5.2 | Unit (httpmock) | -- | 6 |
| MM-149.AC5.3 | Unit (httpmock) | -- | 6 |
| MM-149.AC6.1 | Unit (httpmock) | -- | 6 |
| MM-149.AC6.2 | Unit (httpmock) | -- | 6 |
| MM-149.AC6.3 | Unit (httpmock) | -- | 6 |
| MM-149.AC7.1 | -- | iOS Simulator | 7 |
| MM-149.AC7.2 | -- | iOS Simulator | 7 |
| MM-149.AC7.3 | -- | iOS Simulator | 7 |
| MM-149.AC7.4 | -- | iOS Simulator | 7 |
| MM-149.AC8.1 | -- | iOS Simulator | 7 |
| MM-149.AC8.2 | -- | iOS Simulator | 7 |

---

## Test Execution Commands

```bash
# All automated tests (relay + identity-wallet)
cargo test -p relay v013_seeds_identity_wallet_oauth_client
cargo test -p identity-wallet

# DPoP proof tests only
cargo test -p identity-wallet dpop

# PKCE tests only
cargo test -p identity-wallet pkce

# handle_deep_link tests only
cargo test -p identity-wallet handle_deep_link

# OAuthClient httpmock tests only
cargo test -p identity-wallet oauth_client

# Integration tests (require running relay at localhost:8080)
cargo test -p identity-wallet par_ -- --include-ignored --nocapture

# Full suite including integration tests
cargo test -p identity-wallet -- --include-ignored --nocapture
```
