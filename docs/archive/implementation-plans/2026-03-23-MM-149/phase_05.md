# MM-149 OAuth PKCE Client Implementation Plan

**Goal:** Implement the full single-command OAuth round-trip: PKCE + DPoP + PAR + Safari + oneshot channel + CSRF validation + token exchange + Keychain storage.

**Architecture:** `start_oauth_flow` is a `#[tauri::command]` that drives the entire round-trip. It generates all cryptographic material, calls PAR, opens Safari, then parks on a `tokio::sync::oneshot::Receiver`. When Safari completes authorization, `handle_deep_link` fires on a separate OS thread, takes `PendingOAuthFlow` from `AppState`, validates CSRF, and sends `CallbackParams` on the `Sender`. `start_oauth_flow` wakes, exchanges the code for tokens (with one retry on `use_dpop_nonce`), stores tokens in Keychain, and updates `AppState.oauth_session`.

**Tech Stack:** `tokio = "1"` (oneshot channel, async command), `tauri-plugin-opener` (open Safari), `reqwest 0.12` (form POST for token exchange)

**Scope:** 7 phases from original design (phase 5 of 7)

**Codebase verified:** 2026-03-23

---

## Acceptance Criteria Coverage

This phase implements and tests:

### MM-149.AC1: PAR flow completes successfully
- **MM-149.AC1.1 Success:** `start_oauth_flow` posts to `/oauth/par` with a valid DPoP proof and receives a `request_uri` (201 response)
- **MM-149.AC1.2 Success:** Authorization URL opened in system browser includes `client_id` and `request_uri` parameters

### MM-149.AC2: OAuth callback received and code exchanged
- **MM-149.AC2.1 Success:** Deep-link handler receives `dev.malpercio.identitywallet:/oauth/callback?code=...&state=...` and wakes the parked `start_oauth_flow` command
- **MM-149.AC2.2 Success:** Token exchange succeeds — relay returns `access_token`, `refresh_token`, and `token_type: "DPoP"`
- **MM-149.AC2.3 Failure:** `state` mismatch between generated param and callback param aborts with `StateMismatch` error
- **MM-149.AC2.4 Failure:** A second (replayed) deep-link callback with the same scheme is silently ignored
- **MM-149.AC2.5 Edge:** `use_dpop_nonce` error on token exchange triggers one retry with server-provided nonce; retry succeeds

### MM-149.AC4: Tokens stored securely and loaded on restart
- **MM-149.AC4.1 Success:** After successful exchange, `access_token`, `refresh_token`, and DPoP private key bytes are present in iOS Keychain under the expected account keys

### MM-149.AC5: Authenticated requests carry DPoP proofs
- **MM-149.AC5.3 Failure:** Request after token is deliberately cleared returns an auth error, not a panic

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->

<!-- START_TASK_1 -->
### Task 1: Add tokio dependency to identity-wallet Cargo.toml

**Verifies:** None (infrastructure)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/Cargo.toml`

Tokio is in the workspace with `features = ["full"]`. identity-wallet needs it for `tokio::sync::oneshot` and `#[tokio::main]` tests.

**Step 1: Add tokio**

Add to `[dependencies]` in `apps/identity-wallet/src-tauri/Cargo.toml`:

```toml
tokio = { workspace = true }
```

**Step 2: Build to verify**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors.

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Update PendingOAuthFlow and OAuthSession types in oauth.rs, and add token exchange to http.rs

**Verifies:** None (types needed by Task 3)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth.rs`
- Modify: `apps/identity-wallet/src-tauri/src/http.rs`

**Step 1: Replace the stub PendingOAuthFlow in oauth.rs**

Find the stub `PendingOAuthFlow` struct (from Phase 2) and replace it with the real version:

Old (stub from Phase 2):
```rust
pub struct PendingOAuthFlow {
    /// The CSRF state parameter generated at the start of the flow.
    pub csrf_state: String,
}
```

Replace with:
```rust
pub struct PendingOAuthFlow {
    /// Channel to deliver the callback result back to `start_oauth_flow`.
    ///
    /// Sends `Ok(CallbackParams)` on success or `Err(OAuthError::StateMismatch)` on
    /// CSRF mismatch, so the command can distinguish a mismatch from a dropped channel.
    pub tx: tokio::sync::oneshot::Sender<Result<CallbackParams, OAuthError>>,
    /// PKCE code_verifier to include in the token exchange.
    pub pkce_verifier: String,
    /// CSRF state parameter — validated against the callback's state param.
    pub csrf_state: String,
}
```

**Step 2: Replace the stub OAuthSession in oauth.rs**

Find the stub `OAuthSession` struct (from Phase 2) and replace it:

Old (stub from Phase 2):
```rust
pub struct OAuthSession {
    pub access_token: String,
    pub refresh_token: String,
}
```

Replace with:
```rust
/// Active OAuth session stored in AppState after successful token exchange.
pub struct OAuthSession {
    pub access_token: String,
    pub refresh_token: String,
    /// Unix timestamp (seconds) when the access token expires.
    pub expires_at: u64,
    /// The most recent DPoP nonce issued by the server.
    /// Starts as None; updated whenever the server sends a DPoP-Nonce header.
    pub dpop_nonce: Option<String>,
}
```

**Step 3: Add the token exchange method to RelayClient in http.rs**

The relay's token endpoint (`POST /oauth/token`) uses the same form-urlencoded format as PAR. Add after the existing `par()` method:

First, add the response type after `ParResponse`:
```rust
/// Successful response from `POST /oauth/token` (RFC 6749 §5.1).
#[derive(Debug, serde::Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: String,
}

/// Error response from `POST /oauth/token` (RFC 6749 §5.2).
#[derive(Debug, serde::Deserialize)]
pub struct TokenErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}
```

Then add to `impl RelayClient`:
```rust
/// POST `/oauth/token` — exchange an authorization code for tokens.
///
/// Sends the authorization code, PKCE verifier, and DPoP proof.
/// Returns the token response body on 200, or an error.
/// The caller is responsible for reading the `DPoP-Nonce` response header
/// if the server returns one (the full `reqwest::Response` is returned for this).
pub async fn token_exchange(
    &self,
    code: &str,
    pkce_verifier: &str,
    dpop_proof: &str,
) -> Result<reqwest::Response, OAuthError> {
    let url = format!("{}/oauth/token", self.base_url);
    let resp = self
        .client
        .post(&url)
        .header("DPoP", dpop_proof)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", "dev.malpercio.identitywallet:/oauth/callback"),
            ("client_id", "dev.malpercio.identitywallet"),
            ("code_verifier", pkce_verifier),
        ])
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "token exchange network error");
            OAuthError::TokenExchangeFailed
        })?;
    Ok(resp)
}
```

**Step 4: Build to verify**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors.

<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Implement start_oauth_flow and complete handle_deep_link in oauth.rs

**Verifies:** MM-149.AC1.1, MM-149.AC1.2, MM-149.AC2.1, MM-149.AC2.2, MM-149.AC2.3, MM-149.AC2.4, MM-149.AC2.5, MM-149.AC4.1

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth.rs`
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs`

**Step 1: Add the start_oauth_flow command to oauth.rs**

Add after the `handle_deep_link` function. This is the most complex function in the file — read it carefully before implementing.

```rust
// ── Tauri command ─────────────────────────────────────────────────────────────

/// Drive the full OAuth 2.0 PKCE + DPoP authorization round-trip.
///
/// Called from the SvelteKit frontend via `invoke('start_oauth_flow')`.
/// Parks on a Tokio oneshot channel until `handle_deep_link` delivers
/// the authorization code from the system browser redirect.
///
/// # Flow
/// 1. Generate PKCE verifier/challenge and CSRF state parameter
/// 2. Get-or-create DPoP keypair; build PAR DPoP proof
/// 3. POST /oauth/par → receive request_uri
/// 4. Open system browser to /oauth/authorize?client_id=...&request_uri=...
/// 5. Park on oneshot receiver; handle_deep_link will send the code+state
/// 6. Validate CSRF state matches
/// 7. POST /oauth/token (authorization_code grant + PKCE verifier + DPoP proof)
///    → on use_dpop_nonce 400: retry with server-issued nonce
/// 8. Store access_token + refresh_token in Keychain
/// 9. Populate AppState.oauth_session
#[tauri::command]
pub async fn start_oauth_flow(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    login_hint: Option<String>,
) -> Result<(), OAuthError> {
    use tauri::Manager;
    // OpenerExt adds the `.opener()` method to AppHandle.
    use tauri_plugin_opener::OpenerExt;

    let relay = crate::http::RelayClient::new();

    // 1. Generate PKCE and CSRF state.
    let (pkce_verifier, pkce_challenge) = pkce::generate();
    let csrf_state = generate_state_param();

    // 2. Get-or-create DPoP keypair.
    let dpop = DPoPKeypair::get_or_create()?;
    let dpop_jkt = dpop.public_jwk_thumbprint();

    let par_htu = format!("{}/oauth/par", crate::http::RelayClient::base_url());
    let par_proof = dpop.make_proof("POST", &par_htu, None, None)?;

    // 3. PAR call.
    let par_resp = relay
        .par(&pkce_challenge, &csrf_state, &par_proof, &dpop_jkt, login_hint.as_deref())
        .await?;

    // 4. Set up the oneshot channel and park pending_auth.
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<CallbackParams, OAuthError>>();
    {
        let mut pending = state.pending_auth.lock().unwrap();
        *pending = Some(PendingOAuthFlow {
            tx,
            pkce_verifier: pkce_verifier.clone(),
            csrf_state: csrf_state.clone(),
        });
    } // Mutex guard dropped here — not held across .await.

    // 5. Open Safari to the authorization endpoint.
    let auth_url = {
        let base = crate::http::RelayClient::base_url();
        let request_uri_encoded = url::form_urlencoded::byte_serialize(
            par_resp.request_uri.as_bytes(),
        )
        .collect::<String>();
        let mut u = format!(
            "{base}/oauth/authorize?client_id=dev.malpercio.identitywallet&request_uri={request_uri_encoded}"
        );
        if let Some(hint) = &login_hint {
            let hint_encoded = url::form_urlencoded::byte_serialize(hint.as_bytes())
                .collect::<String>();
            u.push_str(&format!("&login_hint={hint_encoded}"));
        }
        u
    };

    app.opener()
        .open_url(&auth_url, None::<&str>)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to open system browser for OAuth");
            OAuthError::ParFailed
        })?;

    // 6. Wait for the deep-link callback to deliver the authorization code.
    // The outer ? handles RecvError (channel dropped) → CallbackAbandoned.
    // The inner ? propagates OAuthError::StateMismatch if handle_deep_link detected a CSRF mismatch.
    let callback = rx.await.map_err(|_| OAuthError::CallbackAbandoned)??;

    // 7. Token exchange.
    let token_htu = format!("{}/oauth/token", crate::http::RelayClient::base_url());
    let (token_resp, initial_nonce) = exchange_code_with_retry(
        &relay,
        &dpop,
        &callback.code,
        &pkce_verifier,
        &token_htu,
    )
    .await?;

    // 8. Store tokens in Keychain.
    crate::keychain::store_oauth_tokens(&token_resp.access_token, &token_resp.refresh_token)
        .map_err(|_| OAuthError::KeychainError)?;

    // 9. Update AppState.
    // Seed dpop_nonce from the token response to avoid a guaranteed use_dpop_nonce retry
    // on the first OAuthClient request immediately after login.
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| OAuthError::TokenExchangeFailed)?
        .as_secs()
        + token_resp.expires_in;

    let mut session = state.oauth_session.lock().unwrap();
    *session = Some(OAuthSession {
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token,
        expires_at,
        dpop_nonce: initial_nonce,
    });

    tracing::info!("OAuth flow complete; session stored");
    Ok(())
}

/// Perform the authorization code token exchange with one retry on `use_dpop_nonce`.
///
/// Returns the token response and the `DPoP-Nonce` header value from the successful
/// response (if present). Storing this nonce in the session avoids a guaranteed
/// `use_dpop_nonce` retry on the very first `OAuthClient` request after login.
///
/// The relay always requires a DPoP nonce at the token endpoint (RFC 9449 §8).
/// On the first attempt, the nonce is absent; the relay returns 400 with `use_dpop_nonce`
/// and a `DPoP-Nonce` response header. We retry exactly once with that nonce.
async fn exchange_code_with_retry(
    relay: &crate::http::RelayClient,
    dpop: &DPoPKeypair,
    code: &str,
    pkce_verifier: &str,
    token_htu: &str,
) -> Result<(crate::http::TokenResponse, Option<String>), OAuthError> {
    let proof = dpop.make_proof("POST", token_htu, None, None)?;
    let resp = relay.token_exchange(code, pkce_verifier, &proof).await?;

    if resp.status().as_u16() == 200 {
        // Capture DPoP-Nonce before consuming the body.
        let nonce = resp
            .headers()
            .get("DPoP-Nonce")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let token = resp.json::<crate::http::TokenResponse>().await.map_err(|e| {
            tracing::error!(error = %e, "token response deserialization failed");
            OAuthError::TokenExchangeFailed
        })?;
        return Ok((token, nonce));
    }

    // Check for use_dpop_nonce — extract the nonce from the DPoP-Nonce header.
    let nonce = resp
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let error_body = resp
        .json::<crate::http::TokenErrorResponse>()
        .await
        .unwrap_or_else(|_| crate::http::TokenErrorResponse {
            error: "unknown".into(),
            error_description: None,
        });

    if error_body.error == "use_dpop_nonce" {
        if let Some(nonce_val) = nonce {
            tracing::debug!(nonce = %nonce_val, "retrying token exchange with server nonce");
            let proof_with_nonce = dpop.make_proof("POST", token_htu, Some(&nonce_val), None)?;
            let retry_resp = relay
                .token_exchange(code, pkce_verifier, &proof_with_nonce)
                .await?;
            if retry_resp.status().as_u16() == 200 {
                // Capture DPoP-Nonce from the retry response too.
                let retry_nonce = retry_resp
                    .headers()
                    .get("DPoP-Nonce")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let token = retry_resp
                    .json::<crate::http::TokenResponse>()
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "retry token response deserialization failed");
                        OAuthError::TokenExchangeFailed
                    })?;
                return Ok((token, retry_nonce));
            }
            tracing::error!("token exchange failed after nonce retry");
            return Err(OAuthError::TokenExchangeFailed);
        }
    }

    tracing::error!(error = %error_body.error, "token exchange failed");
    Err(OAuthError::TokenExchangeFailed)
}
```

> **url crate note:** The code above uses `url::form_urlencoded::byte_serialize()` to percent-encode the request_uri. The `url` crate is a transitive dependency via `tauri-plugin-deep-link`. If the compiler cannot resolve `url::form_urlencoded`, add `url = "2"` explicitly to `apps/identity-wallet/src-tauri/Cargo.toml`.

**Step 2: Complete the handle_deep_link function**

Find the existing `handle_deep_link` stub in oauth.rs and replace it entirely:

```rust
/// Process URLs received from the deep-link plugin's `on_open_url` event.
///
/// Filters for the OAuth callback path, extracts `code` and `state`, validates the
/// CSRF state against the pending flow, and sends `CallbackParams` on the oneshot channel.
///
/// Called from the `on_open_url` closure in lib.rs (sync context — no async).
/// A second callback (replay) is silently ignored because `pending_auth.take()` clears
/// the slot on first receipt (MM-149.AC2.4).
pub fn handle_deep_link(urls: Vec<url::Url>, app_state: &AppState) {
    for url in &urls {
        let scheme = url.scheme();
        let path = url.path();

        if scheme == "dev.malpercio.identitywallet" && path == "/oauth/callback" {
            tracing::info!(url = %url, "OAuth deep-link callback received");

            // Take the pending flow — clears the slot so replays are silently ignored.
            let pending = app_state.pending_auth.lock().unwrap().take();
            let Some(flow) = pending else {
                tracing::warn!("OAuth callback received but no flow is pending; ignoring (replay?)");
                return;
            };

            // Extract code and state from query parameters.
            let mut code_opt: Option<String> = None;
            let mut state_opt: Option<String> = None;
            for (key, value) in url.query_pairs() {
                match key.as_ref() {
                    "code" => code_opt = Some(value.into_owned()),
                    "state" => state_opt = Some(value.into_owned()),
                    _ => {}
                }
            }

            let (Some(code), Some(callback_state)) = (code_opt, state_opt) else {
                tracing::error!("OAuth callback URL missing code or state parameters");
                return;
            };

            // Validate CSRF state — must match before sending on the channel.
            if callback_state != flow.csrf_state {
                tracing::error!(
                    expected = %flow.csrf_state,
                    received = %callback_state,
                    "CSRF state mismatch in OAuth callback; aborting flow"
                );
                // Send the error explicitly so start_oauth_flow returns StateMismatch,
                // not CallbackAbandoned (which would occur if we just dropped tx).
                let _ = flow.tx.send(Err(OAuthError::StateMismatch));
                return;
            }

            let _ = flow.tx.send(Ok(CallbackParams {
                code,
                state: callback_state,
            }));
            return;
        }

        tracing::debug!(url = %url, "ignoring non-OAuth deep-link");
    }
}
```

**Step 3: Register start_oauth_flow in lib.rs**

Find the `invoke_handler` in `run()` (lib.rs:401-406) and add the new command:

```rust
.invoke_handler(tauri::generate_handler![
    create_account,
    get_or_create_device_key,
    sign_with_device_key,
    perform_did_ceremony,
    oauth::start_oauth_flow,
])
```

**Step 4: Build to verify**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors.

<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 4-5) -->

<!-- START_TASK_4 -->
### Task 4: Write unit tests for handle_deep_link and the CSRF/replay logic

**Verifies:** MM-149.AC2.3 (state mismatch), MM-149.AC2.4 (replay silently ignored)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth.rs` (add tests to existing `#[cfg(test)]` module)

The `handle_deep_link` function can be tested synchronously without a running relay. We construct a fake `AppState` with a pending flow and drive it directly.

**Tests must verify:**

- **MM-149.AC2.3:** When `handle_deep_link` receives a callback URL whose `state` param does not match `flow.csrf_state`, the oneshot receiver is dropped (receives `Err(RecvError)`), proving the flow was aborted without sending.
- **MM-149.AC2.4:** When `handle_deep_link` is called twice with matching state but the first call already cleared `pending_auth`, the second call sees `None` pending and returns silently (no panic, no send).

**Step 1: Add tests to the existing `#[cfg(test)]` mod in oauth.rs**

```rust
    // handle_deep_link tests
    fn make_test_url(code: &str, state: &str) -> url::Url {
        url::Url::parse(&format!(
            "dev.malpercio.identitywallet:/oauth/callback?code={code}&state={state}"
        ))
        .unwrap()
    }

    #[test]
    fn handle_deep_link_csrf_mismatch_returns_state_mismatch_error() {
        // MM-149.AC2.3: CSRF mismatch sends Err(StateMismatch), not drops the sender.
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<CallbackParams, OAuthError>>();
        let state = AppState {
            pending_auth: std::sync::Mutex::new(Some(PendingOAuthFlow {
                tx,
                pkce_verifier: "v".to_string(),
                csrf_state: "correct-state".to_string(),
            })),
            oauth_session: std::sync::Mutex::new(None),
        };

        let url = make_test_url("code123", "WRONG-STATE");
        handle_deep_link(vec![url], &state);

        // Receiver must get Err(StateMismatch), not a channel-level error.
        assert!(
            matches!(rx.try_recv(), Ok(Err(OAuthError::StateMismatch))),
            "CSRF mismatch must deliver StateMismatch to the command"
        );
        // The pending_auth slot was cleared.
        assert!(state.pending_auth.lock().unwrap().is_none(), "pending_auth must be cleared");
    }

    #[test]
    fn handle_deep_link_replay_is_silently_ignored() {
        // MM-149.AC2.4
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<CallbackParams, OAuthError>>();
        let state = AppState {
            pending_auth: std::sync::Mutex::new(Some(PendingOAuthFlow {
                tx,
                pkce_verifier: "v".to_string(),
                csrf_state: "good-state".to_string(),
            })),
            oauth_session: std::sync::Mutex::new(None),
        };

        // First callback succeeds.
        let url = make_test_url("code123", "good-state");
        handle_deep_link(vec![url.clone()], &state);
        assert!(matches!(rx.try_recv(), Ok(Ok(_))), "first callback must deliver the code");

        // Second callback (replay) — pending_auth is now None.
        handle_deep_link(vec![url], &state); // must not panic
        // pending_auth is still None.
        assert!(state.pending_auth.lock().unwrap().is_none(), "replay must not re-populate pending_auth");
    }

    #[test]
    fn handle_deep_link_delivers_code_and_state() {
        // MM-149.AC2.1
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<CallbackParams, OAuthError>>();
        let state = AppState {
            pending_auth: std::sync::Mutex::new(Some(PendingOAuthFlow {
                tx,
                pkce_verifier: "v".to_string(),
                csrf_state: "expected-state".to_string(),
            })),
            oauth_session: std::sync::Mutex::new(None),
        };

        let url = make_test_url("mycode", "expected-state");
        handle_deep_link(vec![url], &state);

        let params = rx.try_recv()
            .expect("channel must not be empty")
            .expect("callback must succeed");
        assert_eq!(params.code, "mycode");
        assert_eq!(params.state, "expected-state");
    }
```

**Step 2: Run the tests**

```bash
cargo test -p identity-wallet handle_deep_link
```

Expected: 3 tests pass.

**Step 3: Run all tests**

```bash
cargo test -p identity-wallet
```

Expected: all tests pass.

<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Commit

**Step 1: Commit all Phase 5 changes**

```bash
git add apps/identity-wallet/src-tauri/Cargo.toml
git add apps/identity-wallet/src-tauri/src/lib.rs
git add apps/identity-wallet/src-tauri/src/http.rs
git add apps/identity-wallet/src-tauri/src/oauth.rs
git commit -m "feat(identity-wallet): start_oauth_flow command, deep-link handler, token exchange (MM-149 phase 5)"
```

<!-- END_TASK_5 -->

<!-- END_SUBCOMPONENT_B -->
