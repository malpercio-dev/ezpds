// pattern: Mixed (unavoidable)
//
// Types: AppState, PendingOAuthFlow, OAuthSession, CallbackParams (Functional Core)
// handle_deep_link: Imperative Shell (reads OS callback, routes to pending channel)

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing;
use uuid::Uuid;

// ── Shared state ──────────────────────────────────────────────────────────────

/// App-wide OAuth state registered via `.manage()` in lib.rs.
///
/// Both fields are Option-wrapped so the state is cleanly empty before any
/// OAuth flow starts and after a flow completes.
pub struct AppState {
    /// The pending OAuth flow waiting for the deep-link callback.
    /// Set by `start_oauth_flow` before opening Safari; cleared by `handle_deep_link`.
    pub pending_auth: Mutex<Option<PendingOAuthFlow>>,
    /// The active authenticated session after a successful token exchange.
    /// Set by `start_oauth_flow` on success; read by `OAuthClient` for every request.
    pub oauth_session: Mutex<Option<OAuthSession>>,
    /// Runtime custos client. Populated from Keychain on startup or by
    /// `save_pds_url` on first launch. Falls back to the compile-time default if unset.
    custos_client: OnceLock<crate::http::CustosClient>,
    /// PDS client for discovery and XRPC operations against arbitrary PDS endpoints.
    /// Stateless and cheap to construct; available to Phase 4 Tauri commands.
    pds_client: crate::pds_client::PdsClient,
    /// Claim flow state persisted across multi-step claim commands.
    /// Set by `resolve_identity`; used by subsequent `start_pds_auth`,
    /// `request_claim_verification`, `sign_and_verify_claim`, `submit_claim`.
    /// Uses tokio::sync::Mutex because claim commands hold the lock across .await points.
    pub claim_state: tokio::sync::Mutex<Option<crate::claim::ClaimState>>,
    /// Recovery override state persisted between build and submit.
    /// Set by `build_recovery_override` after signing; used by `submit_recovery_override`.
    /// Uses tokio::sync::Mutex because recovery commands hold the lock across .await points.
    pub recovery_state: tokio::sync::Mutex<Option<crate::recovery::RecoveryState>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            pending_auth: Mutex::new(None),
            oauth_session: Mutex::new(None),
            custos_client: OnceLock::new(),
            pds_client: crate::pds_client::PdsClient::new(),
            claim_state: tokio::sync::Mutex::new(None),
            recovery_state: tokio::sync::Mutex::new(None),
        }
    }

    /// Returns the configured custos client, or initializes with the compile-time
    /// default URL if none has been set yet.
    pub fn custos_client(&self) -> &crate::http::CustosClient {
        self.custos_client
            .get_or_init(crate::http::CustosClient::new)
    }

    /// Set the custos client from a runtime URL. Silently ignored if already set
    /// (OnceLock::set semantics — this is only called once on first launch).
    pub fn set_custos_client(&self, url: String) {
        if self
            .custos_client
            .set(crate::http::CustosClient::new_with_url(url.clone()))
            .is_err()
        {
            tracing::warn!(url = %url, "set_custos_client: custos_client already initialized; ignoring");
        }
    }

    /// Returns the PDS client for discovery and XRPC operations.
    pub fn pds_client(&self) -> &crate::pds_client::PdsClient {
        &self.pds_client
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

// ── OAuth error ───────────────────────────────────────────────────────────────

/// Error type for all OAuth-related operations.
///
/// Variants serialize as `{ "code": "SCREAMING_SNAKE_CASE" }` to match the
/// existing error pattern (`CreateAccountError`, `DeviceKeyError`, etc.).
#[derive(Debug, thiserror::Error, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code")]
pub enum OAuthError {
    #[error("DPoP keypair generation failed")]
    DpopKeyGenFailed,
    #[error("DPoP keypair is invalid")]
    DpopKeyInvalid,
    #[error("DPoP proof construction failed")]
    DpopProofFailed,
    #[error("Keychain error")]
    KeychainError,
    #[error("State mismatch in OAuth callback")]
    StateMismatch,
    #[error("OAuth callback abandoned")]
    CallbackAbandoned,
    #[error("PAR request failed")]
    ParFailed,
    #[error("Token exchange failed")]
    TokenExchangeFailed,
    #[error("Token refresh failed")]
    TokenRefreshFailed,
    #[error("Refresh token has been revoked or is invalid")]
    InvalidGrant,
    #[error("Not authenticated")]
    NotAuthenticated,
}

// ── DPoP keypair ─────────────────────────────────────────────────────────────

/// A P-256 keypair used to produce DPoP proofs.
///
/// The private key scalar (32 bytes) is persisted in the iOS Keychain under
/// `"oauth-dpop-key-priv"`. The same key is used for all DPoP proofs across
/// app sessions — it is never rotated by this implementation.
pub struct DPoPKeypair {
    signing_key: SigningKey,
}

impl DPoPKeypair {
    /// Load the DPoP keypair from Keychain, or generate and persist a new one.
    pub fn get_or_create() -> Result<Self, OAuthError> {
        if let Some(private_bytes) = crate::keychain::load_dpop_key() {
            // private_bytes is Zeroizing<[u8; 32]>, which derefs to [u8; 32].
            // Dereference to get &[u8; 32], which coerces to &[u8] for from_slice.
            let signing_key =
                SigningKey::from_slice(&*private_bytes).map_err(|_| OAuthError::DpopKeyInvalid)?;
            return Ok(Self { signing_key });
        }

        // Generate a new P-256 keypair via the shared crypto crate.
        let keypair = crypto::generate_p256_keypair().map_err(|_| OAuthError::DpopKeyGenFailed)?;
        // `private_key_bytes` is `Zeroizing<[u8; 32]>`, which derefs directly to `[u8; 32]`.
        let private_bytes: [u8; 32] = *keypair.private_key_bytes;

        crate::keychain::store_dpop_key(&private_bytes).map_err(|_| OAuthError::KeychainError)?;

        let signing_key =
            SigningKey::from_slice(&private_bytes).map_err(|_| OAuthError::DpopKeyInvalid)?;
        Ok(Self { signing_key })
    }

    /// Build the public JWK for this keypair (EC, P-256, kty/crv/x/y only — no private fields).
    ///
    /// The custos's validator expects exactly: `{"kty":"EC","crv":"P-256","x":"<b64url>","y":"<b64url>"}`.
    pub fn public_jwk(&self) -> serde_json::Value {
        let verifying_key = self.signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false); // false = uncompressed: 04 || x || y
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("P-256 uncompressed point has x"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("P-256 uncompressed point has y"));
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        })
    }

    /// Compute the RFC 7638 JWK thumbprint: `base64url(SHA-256(canonical_jwk_json))`.
    ///
    /// The canonical JSON uses lexicographically-sorted keys (crv, kty, x, y) per RFC 7638 §3.2.
    /// This matches the custos's `jwk_thumbprint()` function in `crates/custos/src/auth/dpop.rs`.
    pub fn public_jwk_thumbprint(&self) -> String {
        let jwk = self.public_jwk();
        // Canonical member set per RFC 7638 §3.2 — lexicographic order for EC keys.
        // serde_json internally represents JSON objects as BTreeMap, which serializes
        // keys in lexicographic order. This is what RFC 7638 §3.2 requires for the
        // canonical JSON. The key ordering here (crv < kty < x < y) is lexicographic.
        let canonical = serde_json::json!({
            "crv": jwk["crv"],
            "kty": jwk["kty"],
            "x": jwk["x"],
            "y": jwk["y"],
        });
        let canonical_json = serde_json::to_string(&canonical)
            .expect("canonical JWK serialization is infallible for known types");
        let hash = Sha256::digest(canonical_json.as_bytes());
        URL_SAFE_NO_PAD.encode(hash)
    }

    /// Build a DPoP proof JWT for the given HTTP method, URL, and optional claims.
    ///
    /// - `htm`: HTTP method in uppercase, e.g. `"POST"` or `"GET"`
    /// - `htu`: Full target URL without query string, e.g. `"https://relay.ezpds.com/oauth/token"`
    /// - `nonce`: Server-issued nonce from a prior `use_dpop_nonce` 400 response (if any)
    /// - `ath`: `base64url(SHA-256(access_token_ascii))` — required for resource requests; None for token requests
    ///
    /// Proof format: `base64url(header_json)`.`base64url(claims_json)`.`base64url(sig)`
    /// where sig is the raw 64-byte R||S P-256 ECDSA signature of the signing input.
    pub fn make_proof(
        &self,
        htm: &str,
        htu: &str,
        nonce: Option<&str>,
        ath: Option<&str>,
    ) -> Result<String, OAuthError> {
        let jwk = self.public_jwk();

        // Header JSON.
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk,
        });
        let header_b64 = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).map_err(|_| OAuthError::DpopProofFailed)?);

        // Claims JSON.
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OAuthError::DpopProofFailed)?
            .as_secs() as i64;

        let mut claims = serde_json::json!({
            "jti": Uuid::new_v4().to_string(),
            "htm": htm,
            "htu": htu,
            "iat": iat,
        });

        if let Some(n) = nonce {
            claims["nonce"] = serde_json::Value::String(n.to_string());
        }
        if let Some(a) = ath {
            claims["ath"] = serde_json::Value::String(a.to_string());
        }

        let claims_b64 = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).map_err(|_| OAuthError::DpopProofFailed)?);

        // Sign `header_b64.claims_b64` bytes with P-256/SHA-256.
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        // Normalize to low-S (consistent with the rest of the codebase, even though
        // the custos's DPoP validator does not require it — low-S is harmless and keeps
        // key usage consistent with ATProto expectations).
        let signature = signature.normalize_s().unwrap_or(signature);
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes().as_slice());

        Ok(format!("{signing_input}.{sig_b64}"))
    }

    /// Compute `base64url(SHA-256(access_token))` — the `ath` claim for resource requests.
    pub fn compute_ath(access_token: &str) -> String {
        let hash = Sha256::digest(access_token.as_bytes());
        URL_SAFE_NO_PAD.encode(hash)
    }
}

// ── PKCE utilities ────────────────────────────────────────────────────────────

pub mod pkce {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand_core::{OsRng, RngCore};
    use sha2::{Digest, Sha256};

    /// Generate a PKCE code_verifier and code_challenge pair.
    ///
    /// - `verifier`: 32 OS-random bytes base64url-encoded (43 chars, all unreserved per RFC 7636 §4.1)
    /// - `challenge`: `base64url(SHA-256(verifier))` (S256 method per RFC 7636 §4.2)
    ///
    /// Returns `(verifier, challenge)`.
    pub fn generate() -> (String, String) {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        (verifier, challenge)
    }
}

/// Generate a CSRF state parameter: 16 OS-random bytes base64url-encoded (22 chars).
pub fn generate_state_param() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

// ── Pending flow ──────────────────────────────────────────────────────────────

/// State parked inside `AppState.pending_auth` while `start_oauth_flow` waits
/// for the deep-link callback.
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

// ── OAuth session ─────────────────────────────────────────────────────────────

/// Active OAuth session stored in AppState after successful token exchange.
#[derive(Clone)]
pub struct OAuthSession {
    pub access_token: String,
    pub refresh_token: String,
    /// Unix timestamp (seconds) when the access token expires.
    pub expires_at: u64,
    /// The most recent DPoP nonce issued by the server.
    /// Starts as None; updated whenever the server sends a DPoP-Nonce header.
    pub dpop_nonce: Option<String>,
}

// ── Callback params ───────────────────────────────────────────────────────────

/// Parameters extracted from the OAuth deep-link callback URL.
pub struct CallbackParams {
    pub code: String,
    pub state: String,
}

// ── Deep-link handler ─────────────────────────────────────────────────────────

/// Process URLs received from the deep-link plugin's `on_open_url` event.
///
/// Filters for the OAuth callback path, extracts `code` and `state`, validates the
/// CSRF state against the pending flow, and sends `CallbackParams` on the oneshot channel.
///
/// Called from the `on_open_url` closure in lib.rs (sync context — no async).
/// A second callback (replay) is silently ignored because `pending_auth.take()` clears
/// the slot on first receipt.
pub fn handle_deep_link(urls: Vec<url::Url>, app_state: &AppState) {
    for url in &urls {
        let scheme = url.scheme();
        let path = url.path();

        if scheme == "dev.malpercio.identitywallet" && path == "/oauth/callback" {
            tracing::info!(url = %url, "OAuth deep-link callback received");

            // Take the pending flow — clears the slot so replays are silently ignored.
            let pending = app_state.pending_auth.lock().unwrap().take();
            let Some(flow) = pending else {
                tracing::warn!(
                    "OAuth callback received but no flow is pending; ignoring (replay?)"
                );
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
                // Send an explicit error instead of silently dropping the sender.
                let _ = flow.tx.send(Err(OAuthError::CallbackAbandoned));
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
    // OpenerExt adds the `.opener()` method to AppHandle.
    use tauri_plugin_opener::OpenerExt;

    let custos = state.custos_client();

    // 1. Generate PKCE and CSRF state.
    let (pkce_verifier, pkce_challenge) = pkce::generate();
    let csrf_state = generate_state_param();

    // 2. Get-or-create DPoP keypair.
    let dpop = DPoPKeypair::get_or_create()?;
    let dpop_jkt = dpop.public_jwk_thumbprint();

    let par_htu = format!("{}/oauth/par", state.custos_client().base_url_str());
    let par_proof = dpop.make_proof("POST", &par_htu, None, None)?;

    // 3. PAR call.
    let par_resp = custos
        .par(
            &pkce_challenge,
            &csrf_state,
            &par_proof,
            &dpop_jkt,
            login_hint.as_deref(),
        )
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
        let base = state.custos_client().base_url_str();
        let request_uri_encoded =
            url::form_urlencoded::byte_serialize(par_resp.request_uri.as_bytes())
                .collect::<String>();
        let mut u = format!(
            "{base}/oauth/authorize?client_id=dev.malpercio.identitywallet&request_uri={request_uri_encoded}"
        );
        if let Some(hint) = &login_hint {
            let hint_encoded =
                url::form_urlencoded::byte_serialize(hint.as_bytes()).collect::<String>();
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
    let token_htu = format!("{}/oauth/token", state.custos_client().base_url_str());
    let (token_resp, initial_nonce) =
        exchange_code_with_retry(custos, &dpop, &callback.code, &pkce_verifier, &token_htu).await?;

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
/// The custos always requires a DPoP nonce at the token endpoint (RFC 9449 §8).
/// On the first attempt, the nonce is absent; the custos returns 400 with `use_dpop_nonce`
/// and a `DPoP-Nonce` response header. We retry exactly once with that nonce.
async fn exchange_code_with_retry(
    custos: &crate::http::CustosClient,
    dpop: &DPoPKeypair,
    code: &str,
    pkce_verifier: &str,
    token_htu: &str,
) -> Result<(crate::http::TokenResponse, Option<String>), OAuthError> {
    let proof = dpop.make_proof("POST", token_htu, None, None)?;
    let resp = custos.token_exchange(code, pkce_verifier, &proof).await?;

    if resp.status().as_u16() == 200 {
        // Capture DPoP-Nonce before consuming the body.
        let nonce = resp
            .headers()
            .get("DPoP-Nonce")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let token = resp
            .json::<crate::http::TokenResponse>()
            .await
            .map_err(|e| {
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
            let retry_resp = custos
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::signature::Verifier;

    fn decode_jwt_part(b64: &str) -> serde_json::Value {
        let bytes = URL_SAFE_NO_PAD.decode(b64).expect("valid base64url");
        serde_json::from_slice(&bytes).expect("valid JSON")
    }

    fn split_proof(proof: &str) -> (&str, &str, &str) {
        let parts: Vec<&str> = proof.splitn(3, '.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");
        (parts[0], parts[1], parts[2])
    }

    #[test]
    fn dpop_proof_header_has_required_fields() {
        let kp = DPoPKeypair::get_or_create().expect("keypair must generate");
        let proof = kp
            .make_proof("POST", "https://example.com/oauth/token", None, None)
            .expect("proof must build");
        let (header_b64, _, _) = split_proof(&proof);
        let header = decode_jwt_part(header_b64);

        assert_eq!(header["typ"].as_str(), Some("dpop+jwt"));
        assert_eq!(header["alg"].as_str(), Some("ES256"));
        assert_eq!(header["jwk"]["kty"].as_str(), Some("EC"));
        assert_eq!(header["jwk"]["crv"].as_str(), Some("P-256"));
        assert!(header["jwk"]["x"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false));
        assert!(header["jwk"]["y"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn dpop_proof_claims_has_required_fields() {
        let kp = DPoPKeypair::get_or_create().expect("keypair must generate");
        let proof = kp
            .make_proof("GET", "https://example.com/xrpc/foo", None, None)
            .expect("proof must build");
        let (_, claims_b64, _) = split_proof(&proof);
        let claims = decode_jwt_part(claims_b64);

        assert!(claims["jti"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false));
        assert_eq!(claims["htm"].as_str(), Some("GET"));
        assert_eq!(claims["htu"].as_str(), Some("https://example.com/xrpc/foo"));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let iat = claims["iat"].as_i64().expect("iat must be integer");
        assert!((now - iat).abs() < 5, "iat must be within 5 seconds of now");
    }

    #[test]
    fn dpop_proof_includes_ath_when_supplied() {
        let kp = DPoPKeypair::get_or_create().expect("keypair must generate");
        let proof_with = kp
            .make_proof("GET", "https://example.com/resource", None, Some("abc123"))
            .expect("proof with ath must build");
        let (_, claims_b64, _) = split_proof(&proof_with);
        let claims = decode_jwt_part(claims_b64);
        assert_eq!(
            claims["ath"].as_str(),
            Some("abc123"),
            "ath must be present"
        );

        let proof_without = kp
            .make_proof("GET", "https://example.com/resource", None, None)
            .expect("proof without ath must build");
        let (_, claims_b64, _) = split_proof(&proof_without);
        let claims = decode_jwt_part(claims_b64);
        assert!(
            claims["ath"].is_null(),
            "ath must be absent when not supplied"
        );
    }

    #[test]
    fn dpop_proof_includes_nonce_when_supplied() {
        let kp = DPoPKeypair::get_or_create().expect("keypair must generate");
        let proof = kp
            .make_proof(
                "POST",
                "https://example.com/oauth/token",
                Some("nonce123"),
                None,
            )
            .expect("proof with nonce must build");
        let (_, claims_b64, _) = split_proof(&proof);
        let claims = decode_jwt_part(claims_b64);
        assert_eq!(
            claims["nonce"].as_str(),
            Some("nonce123"),
            "nonce must be present"
        );

        let proof_no = kp
            .make_proof("POST", "https://example.com/oauth/token", None, None)
            .expect("proof without nonce must build");
        let (_, claims_b64, _) = split_proof(&proof_no);
        let claims = decode_jwt_part(claims_b64);
        assert!(
            claims["nonce"].is_null(),
            "nonce must be absent when not supplied"
        );
    }

    #[test]
    fn dpop_proof_signature_verifies_against_embedded_jwk() {
        use p256::elliptic_curve::sec1::EncodedPoint;

        let kp = DPoPKeypair::get_or_create().expect("keypair must generate");
        let proof = kp
            .make_proof("POST", "https://example.com/oauth/token", None, None)
            .expect("proof must build");
        let (header_b64, claims_b64, sig_b64) = split_proof(&proof);

        // Reconstruct verifying key from the embedded JWK.
        let header = decode_jwt_part(header_b64);
        let x_bytes = URL_SAFE_NO_PAD
            .decode(header["jwk"]["x"].as_str().unwrap())
            .unwrap();
        let y_bytes = URL_SAFE_NO_PAD
            .decode(header["jwk"]["y"].as_str().unwrap())
            .unwrap();
        // Build uncompressed point: 0x04 || x || y
        let mut point_bytes = vec![0x04u8];
        point_bytes.extend_from_slice(&x_bytes);
        point_bytes.extend_from_slice(&y_bytes);
        let point = EncodedPoint::<p256::NistP256>::from_bytes(&point_bytes)
            .expect("valid uncompressed point");
        let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
            .expect("valid verifying key from JWK");

        // Decode the signature.
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .expect("valid base64url sig");
        let signature = p256::ecdsa::Signature::from_bytes(sig_bytes.as_slice().into())
            .expect("valid R||S signature bytes");

        // Verify the signature over the signing input.
        let signing_input = format!("{header_b64}.{claims_b64}");
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature must verify against embedded JWK");
    }

    #[test]
    fn compute_ath_matches_sha256_base64url() {
        let ath = DPoPKeypair::compute_ath("test_access_token");
        // SHA-256("test_access_token") = known value
        let expected = {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(b"test_access_token");
            URL_SAFE_NO_PAD.encode(hash)
        };
        assert_eq!(ath, expected);
    }

    // PKCE tests
    #[test]
    fn pkce_verifier_is_43_unreserved_chars() {
        let (verifier, _) = pkce::generate();
        assert_eq!(verifier.len(), 43, "base64url of 32 bytes must be 43 chars");
        // RFC 7636 §4.1: ALPHA / DIGIT / "-" / "." / "_" / "~"
        assert!(
            verifier
                .chars()
                .all(|c| c.is_alphanumeric() || "-._~".contains(c)),
            "verifier must consist only of unreserved chars: got {verifier}"
        );
    }

    #[test]
    fn pkce_challenge_equals_sha256_base64url_of_verifier() {
        use sha2::{Digest, Sha256};
        let (verifier, challenge) = pkce::generate();
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(
            challenge, expected,
            "challenge must be base64url(sha256(verifier))"
        );
    }

    #[test]
    fn state_param_is_22_chars() {
        let state = generate_state_param();
        assert_eq!(state.len(), 22, "base64url of 16 bytes must be 22 chars");
    }

    #[test]
    fn pkce_verifiers_are_unique() {
        let (v1, _) = pkce::generate();
        let (v2, _) = pkce::generate();
        assert_ne!(
            v1, v2,
            "each generate() call must produce a different verifier"
        );
    }

    /// Integration test: PAR call against a running custos.
    ///
    /// Requires the custos to be running at http://localhost:8080 with the V013
    /// migration applied (identity-wallet client registered).
    ///
    /// Run with: cargo test -p identity-wallet par_integration -- --include-ignored --nocapture
    #[tokio::test]
    #[ignore = "requires running custos at localhost:8080"]
    async fn par_integration_returns_201_with_request_uri() {
        let custos = crate::http::CustosClient::new();
        let keypair = DPoPKeypair::get_or_create().expect("keypair must generate");
        // `htu` is embedded in the DPoP proof JWT claims (the `htu` claim per RFC 9449 §4.2),
        // not used for the HTTP request itself — `custos.par()` constructs the URL internally.
        let htu = format!("{}/oauth/par", crate::http::default_pds_url());
        let dpop_proof = keypair
            .make_proof("POST", &htu, None, None)
            .expect("DPoP proof must build");
        let dpop_jkt = keypair.public_jwk_thumbprint();
        let (_, challenge) = pkce::generate();
        let state = generate_state_param();

        let resp = custos
            .par(&challenge, &state, &dpop_proof, &dpop_jkt, None)
            .await
            .expect("PAR must succeed");

        assert!(
            resp.request_uri
                .starts_with("urn:ietf:params:oauth:request_uri:"),
            "request_uri must use OAuth PAR URN scheme, got: {}",
            resp.request_uri
        );
        assert_eq!(resp.expires_in, 60);
    }

    /// Integration test: PAR call missing code_challenge is rejected by custos.
    ///
    /// The custos returns a client error (400) when code_challenge is absent
    /// from the PAR request.
    ///
    /// Run with: cargo test -p identity-wallet par_missing_challenge -- --include-ignored --nocapture
    #[tokio::test]
    #[ignore = "requires running custos at localhost:8080"]
    async fn par_missing_code_challenge_returns_client_error() {
        // Build a minimal PAR form body with no code_challenge field.
        let base_url = crate::http::default_pds_url();
        let url = format!("{base_url}/oauth/par");
        let keypair = DPoPKeypair::get_or_create().expect("keypair must generate");
        let dpop_proof = keypair
            .make_proof("POST", &url, None, None)
            .expect("DPoP proof must build");

        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .header("DPoP", dpop_proof)
            .form(&[
                ("client_id", "dev.malpercio.identitywallet"),
                (
                    "redirect_uri",
                    "dev.malpercio.identitywallet:/oauth/callback",
                ),
                ("code_challenge_method", "S256"),
                ("state", "somestate"),
                ("response_type", "code"),
                ("scope", "atproto"),
                // code_challenge intentionally omitted
            ])
            .send()
            .await
            .expect("request must reach custos");

        assert!(
            resp.status().is_client_error(),
            "custos must reject PAR without code_challenge with 4xx, got: {}",
            resp.status()
        );
    }

    // handle_deep_link tests
    fn make_test_url(code: &str, state: &str) -> url::Url {
        url::Url::parse(&format!(
            "dev.malpercio.identitywallet:/oauth/callback?code={code}&state={state}"
        ))
        .unwrap()
    }

    #[test]
    fn handle_deep_link_csrf_mismatch_returns_state_mismatch_error() {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<Result<CallbackParams, OAuthError>>();
        let state = AppState {
            pending_auth: std::sync::Mutex::new(Some(PendingOAuthFlow {
                tx,
                pkce_verifier: "v".to_string(),
                csrf_state: "correct-state".to_string(),
            })),
            oauth_session: std::sync::Mutex::new(None),
            custos_client: OnceLock::new(),
            pds_client: crate::pds_client::PdsClient::new(),
            claim_state: tokio::sync::Mutex::new(None),
            recovery_state: tokio::sync::Mutex::new(None),
        };

        let url = make_test_url("code123", "WRONG-STATE");
        handle_deep_link(vec![url], &state);

        // Receiver must get Err(StateMismatch), not a channel-level error.
        assert!(
            matches!(rx.try_recv(), Ok(Err(OAuthError::StateMismatch))),
            "CSRF mismatch must deliver StateMismatch to the command"
        );
        // The pending_auth slot was cleared.
        assert!(
            state.pending_auth.lock().unwrap().is_none(),
            "pending_auth must be cleared"
        );
    }

    #[test]
    fn handle_deep_link_replay_is_silently_ignored() {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<Result<CallbackParams, OAuthError>>();
        let state = AppState {
            pending_auth: std::sync::Mutex::new(Some(PendingOAuthFlow {
                tx,
                pkce_verifier: "v".to_string(),
                csrf_state: "good-state".to_string(),
            })),
            oauth_session: std::sync::Mutex::new(None),
            custos_client: OnceLock::new(),
            pds_client: crate::pds_client::PdsClient::new(),
            claim_state: tokio::sync::Mutex::new(None),
            recovery_state: tokio::sync::Mutex::new(None),
        };

        // First callback succeeds.
        let url = make_test_url("code123", "good-state");
        handle_deep_link(vec![url.clone()], &state);
        assert!(
            matches!(rx.try_recv(), Ok(Ok(_))),
            "first callback must deliver the code"
        );

        // Second callback (replay) — pending_auth is now None.
        handle_deep_link(vec![url], &state); // must not panic
                                             // pending_auth is still None.
        assert!(
            state.pending_auth.lock().unwrap().is_none(),
            "replay must not re-populate pending_auth"
        );
    }

    #[test]
    fn handle_deep_link_delivers_code_and_state() {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<Result<CallbackParams, OAuthError>>();
        let state = AppState {
            pending_auth: std::sync::Mutex::new(Some(PendingOAuthFlow {
                tx,
                pkce_verifier: "v".to_string(),
                csrf_state: "expected-state".to_string(),
            })),
            oauth_session: std::sync::Mutex::new(None),
            custos_client: OnceLock::new(),
            pds_client: crate::pds_client::PdsClient::new(),
            claim_state: tokio::sync::Mutex::new(None),
            recovery_state: tokio::sync::Mutex::new(None),
        };

        let url = make_test_url("mycode", "expected-state");
        handle_deep_link(vec![url], &state);

        let params = rx
            .try_recv()
            .expect("channel must not be empty")
            .expect("callback must succeed");
        assert_eq!(params.code, "mycode");
        assert_eq!(params.state, "expected-state");
    }
}
