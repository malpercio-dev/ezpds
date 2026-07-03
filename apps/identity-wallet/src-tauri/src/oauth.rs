// pattern: Mixed (unavoidable)
//
// Types: AppState, PendingLogin, OAuthPrepared, OAuthSession (Functional Core)
// prepare_oauth_flow / complete_oauth_flow: Imperative Shell (PKCE+PAR, then code→token exchange)

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
    /// The pending create-flow login parked between `prepare_oauth_flow` and
    /// `complete_oauth_flow` while the ASWebAuthenticationSession runs. The PKCE verifier and
    /// CSRF state never leave the Rust backend.
    pub pending_login: Mutex<Option<PendingLogin>>,
    /// The pending claim-flow PDS login parked between `claim::prepare_pds_auth` and
    /// `claim::complete_pds_auth`. Mirrors `pending_login` for the import flow; carries the
    /// discovered auth-server metadata + client_id alongside the verifier/CSRF state.
    pub pending_pds_login: Mutex<Option<crate::claim::PendingPdsLogin>>,
    /// The active authenticated session after a successful token exchange.
    /// Set by `complete_oauth_flow` on success; read by `OAuthClient` for every request.
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
    /// Migration state persisted between build and submit of the self-signed identity leg.
    /// The authenticated destination-PDS client is populated by the W1 orchestrator (MM-228);
    /// `build_migration_op_cmd` reads it, `submit_migration_op_cmd` consumes the signed op.
    /// Uses tokio::sync::Mutex because migration commands hold the lock across .await points.
    pub migration_state: tokio::sync::Mutex<Option<crate::migrate::MigrationState>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            pending_login: Mutex::new(None),
            pending_pds_login: Mutex::new(None),
            oauth_session: Mutex::new(None),
            custos_client: OnceLock::new(),
            pds_client: crate::pds_client::PdsClient::new(),
            claim_state: tokio::sync::Mutex::new(None),
            recovery_state: tokio::sync::Mutex::new(None),
            migration_state: tokio::sync::Mutex::new(None),
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

/// State parked in `AppState.pending_login` between `prepare_oauth_flow` and
/// `complete_oauth_flow`. Holds the secrets that must stay in the Rust backend across the
/// browser session — they are never serialized to the webview.
pub struct PendingLogin {
    /// PKCE code_verifier for the token exchange.
    pub pkce_verifier: String,
    /// CSRF state — validated against the callback URL's `state` param.
    pub csrf_state: String,
}

/// Returned by `prepare_oauth_flow`. The frontend feeds `auth_url` + `callback_scheme` into the
/// auth-session plugin's `start()`, then hands the resulting callback URL to `complete_oauth_flow`.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthPrepared {
    pub auth_url: String,
    pub callback_scheme: String,
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

// ── Tauri command ─────────────────────────────────────────────────────────────

/// Phase 1 of the create-flow login: PKCE + PAR → the `/oauth/authorize` URL.
///
/// Called from the frontend via `invoke('prepare_oauth_flow')`. Generates PKCE/CSRF + the DPoP
/// keypair, performs the PAR call, builds the authorize URL, and parks the PKCE verifier + CSRF
/// state in `AppState.pending_login` — they never reach the webview. The frontend feeds the
/// returned `authUrl`/`callbackScheme` into the auth-session plugin's `start()`, then calls
/// `complete_oauth_flow` with the resulting callback URL.
///
/// This replaces the old single `start_oauth_flow`, which opened external Safari and waited on a
/// deep-link callback — a flow iOS Safari blocks because it will not auto-launch the app from a
/// server-side redirect to a custom scheme. ASWebAuthenticationSession (driven by the plugin)
/// captures the custom-scheme callback itself.
#[tauri::command]
pub async fn prepare_oauth_flow(
    state: tauri::State<'_, AppState>,
    login_hint: Option<String>,
) -> Result<OAuthPrepared, OAuthError> {
    let custos = state.custos_client();

    // 1. PKCE + CSRF state.
    let (pkce_verifier, pkce_challenge) = pkce::generate();
    let csrf_state = generate_state_param();

    // 2. DPoP keypair + PAR proof.
    let dpop = DPoPKeypair::get_or_create()?;
    let dpop_jkt = dpop.public_jwk_thumbprint();
    let par_htu = format!("{}/oauth/par", custos.base_url_str());
    let par_proof = dpop.make_proof("POST", &par_htu, None, None)?;

    // 3. PAR call → request_uri.
    let par_resp = custos
        .par(
            &pkce_challenge,
            &csrf_state,
            &par_proof,
            &dpop_jkt,
            login_hint.as_deref(),
        )
        .await?;

    // 4. Build the authorize URL.
    let auth_url = {
        let base = custos.base_url_str();
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

    // 5. Park the secrets server-side for `complete_oauth_flow`.
    *state.pending_login.lock().unwrap() = Some(PendingLogin {
        pkce_verifier,
        csrf_state,
    });

    Ok(OAuthPrepared {
        auth_url,
        callback_scheme: "dev.malpercio.identitywallet".to_string(),
    })
}

/// Phase 2 of the create-flow login: exchange the authorization code for tokens.
///
/// Called from the frontend via `invoke('complete_oauth_flow', { callbackUrl })` with the URL the
/// auth-session plugin returned. Parses `code`/`state`, validates the CSRF state against the
/// parked `pending_login`, performs the DPoP-bound token exchange (with the one-time nonce
/// retry), stores the tokens in the Keychain, and populates `AppState.oauth_session`.
#[tauri::command]
pub async fn complete_oauth_flow(
    state: tauri::State<'_, AppState>,
    callback_url: String,
) -> Result<(), OAuthError> {
    // Take the parked flow — clears it so a stray second call can't reuse the verifier.
    let pending = state
        .pending_login
        .lock()
        .unwrap()
        .take()
        .ok_or(OAuthError::CallbackAbandoned)?;

    // Parse code + state from the callback URL and validate CSRF before any token exchange.
    let (code, callback_state) = parse_callback_url(&callback_url)?;
    if callback_state != pending.csrf_state {
        // Don't log the state values — the CSRF nonce is backend-only; logging it would leak
        // auth-flow correlation data into device logs.
        tracing::error!("CSRF state mismatch in OAuth callback; aborting flow");
        return Err(OAuthError::StateMismatch);
    }

    // Token exchange (one-time use_dpop_nonce retry handled inside).
    let custos = state.custos_client();
    let dpop = DPoPKeypair::get_or_create()?;
    let token_htu = format!("{}/oauth/token", custos.base_url_str());
    let (token_resp, initial_nonce) =
        exchange_code_with_retry(custos, &dpop, &code, &pending.pkce_verifier, &token_htu).await?;

    // Store tokens in the Keychain.
    crate::keychain::store_oauth_tokens(&token_resp.access_token, &token_resp.refresh_token)
        .map_err(|_| OAuthError::KeychainError)?;

    // Seed dpop_nonce from the token response to avoid a guaranteed use_dpop_nonce retry on the
    // first OAuthClient request immediately after login.
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| OAuthError::TokenExchangeFailed)?
        .as_secs()
        + token_resp.expires_in;

    *state.oauth_session.lock().unwrap() = Some(OAuthSession {
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token,
        expires_at,
        dpop_nonce: initial_nonce,
    });

    tracing::info!("OAuth flow complete; session stored");
    Ok(())
}

/// Extract `code` and `state` from an OAuth callback URL
/// (`dev.malpercio.identitywallet:/oauth/callback?code=...&state=...`). Returns
/// `CallbackAbandoned` if the URL is unparseable or missing either parameter. Shared with the
/// claim flow's `complete_pds_auth`.
pub(crate) fn parse_callback_url(callback_url: &str) -> Result<(String, String), OAuthError> {
    let url = url::Url::parse(callback_url).map_err(|_| OAuthError::CallbackAbandoned)?;
    let mut code_opt: Option<String> = None;
    let mut state_opt: Option<String> = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code_opt = Some(value.into_owned()),
            "state" => state_opt = Some(value.into_owned()),
            _ => {}
        }
    }
    match (code_opt, state_opt) {
        (Some(code), Some(state)) => Ok((code, state)),
        _ => Err(OAuthError::CallbackAbandoned),
    }
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
}
