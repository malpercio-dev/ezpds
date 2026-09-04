// pattern: Mixed (unavoidable)

//! `AppState` (the app-wide Tauri-managed state) plus the wallet's OAuth DPoP client
//! machinery. The types (`AppState`, `OAuthSession`) are Functional Core.
//!
//! **`AppState` slots.** `oauth_session` (`std::sync::Mutex<Option<_>>`, cleanly empty
//! outside a flow — restored from Keychain-persisted tokens on startup; the create-flow login
//! that used to populate it live was retired, see below); `custos_client` (`OnceLock`, set
//! once from the Keychain URL or first-launch config, compile-time default otherwise);
//! `pds_client` (eager — cheap and stateless; exposed via [`AppState::pds_client`] for the
//! claim-flow commands); and the per-flow `tokio::sync::Mutex<Option<_>>` slots
//! (`claim_state`, `recovery_state`, `rotation_state`, `migration_state`,
//! `orchestration_state`, `share_recovery_state`) — tokio mutexes because those commands hold
//! the lock across `.await` points. Neither source login (claim, outbound migration) parks
//! OAuth state here: both are password `createSession` (`claim::authenticate_source_pds`,
//! `migration_orchestrator::authenticate_migration_source`).
//!
//! **The create-flow OAuth login has no live caller.** It used to be `prepare_oauth_flow`
//! (DPoP keygen + PKCE + PAR → authorize URL) and `complete_oauth_flow` (callback validation +
//! DPoP-bound token exchange into `oauth_session` and the Keychain), split around the in-app
//! `ASWebAuthenticationSession`; both were removed once the create flow started ending at
//! `home` with no OAuth round trip. The final authorize step was unreachable for a
//! passwordless account (a password form with no password to enter, and a wallet hand-off
//! pointing at the very app hosting the browser), and the evidence said it proved nothing —
//! `POST /v1/dids` already returns `status: "active"` plus a session token, `oauth_session`
//! had writers but zero readers, and `OAuthClient`'s DPoP mode has no production caller
//! (Bearer construction still initializes the shared [`DPoPKeypair`], but Bearer requests
//! never send DPoP proofs) because every authenticated operation resolves a per-DID session
//! via `SessionProvider::full_access_client` (minted by `sovereign_login`/`password_unlock`
//! against the device key the genesis op pinned at `rotationKeys[0]`). [`DPoPKeypair`], the
//! global `oauth-*` Keychain items, the `auth_ready` startup emit, and the vendored
//! `tauri-plugin-auth-session` remain — `OAuthClient`'s DPoP mode and the claim/migration
//! password logins still depend on them.
//!
//! Also here: [`DPoPKeypair`] (P-256, persisted in Keychain and reused across flows so a
//! server can `jkt`-bind tokens to it). [`OAuthError`] serializes as
//! `{ code: "SCREAMING_SNAKE_CASE" }`; its TypeScript union must match.

use crate::base64url::b64url_encode;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing;
use uuid::Uuid;

// ── Shared state ──────────────────────────────────────────────────────────────

/// App-wide OAuth state registered via `.manage()` in lib.rs.
///
/// Option-wrapped so the state is cleanly empty before any OAuth flow starts and after a
/// flow completes.
pub struct AppState {
    /// The active authenticated session after a successful token exchange.
    /// Restored from the Keychain on startup; read by `OAuthClient` for every request.
    pub oauth_session: Mutex<Option<OAuthSession>>,
    /// Runtime custos client. Populated from Keychain on startup or by
    /// `save_pds_url` on first launch. Falls back to the compile-time default if unset.
    custos_client: OnceLock<crate::http::CustosClient>,
    /// PDS client for discovery and XRPC operations against arbitrary PDS endpoints.
    /// Stateless and cheap to construct; available to Tauri commands.
    pds_client: crate::pds_client::PdsClient,
    /// Claim flow state persisted across multi-step claim commands.
    /// Set by `resolve_identity`; used by subsequent `authenticate_source_pds`,
    /// `request_claim_verification`, `sign_and_verify_claim`, `submit_claim`.
    /// Uses tokio::sync::Mutex because claim commands hold the lock across .await points.
    pub claim_state: tokio::sync::Mutex<Option<crate::claim::ClaimState>>,
    /// Recovery override state persisted between build and submit.
    /// Set by `build_recovery_override` after signing; used by `submit_recovery_override`.
    /// Uses tokio::sync::Mutex because recovery commands hold the lock across .await points.
    pub recovery_state: tokio::sync::Mutex<Option<crate::recovery::RecoveryState>>,
    /// Repo signing-key rotation state persisted between build and submit.
    /// Set by `build_repo_key_rotation_cmd` after signing; used (and cleared on
    /// success) by `submit_repo_key_rotation_cmd`.
    /// Uses tokio::sync::Mutex because rotation commands hold the lock across .await points.
    pub rotation_state: tokio::sync::Mutex<Option<crate::rotate_repo_key::RotationState>>,
    /// Migration state persisted between build and submit of the self-signed identity leg.
    /// The authenticated destination-PDS client is populated by the migration orchestrator;
    /// `build_migration_op_cmd` reads it, `submit_migration_op_cmd` consumes the signed op.
    /// Uses tokio::sync::Mutex because migration commands hold the lock across .await points.
    pub migration_state: tokio::sync::Mutex<Option<crate::migrate::MigrationState>>,
    /// Outbound-migration orchestration state (in-memory only; an app kill restarts from
    /// `prepare_migration`). Tracks the DID, source/dest PDS URLs, OAuth clients, and phase
    /// across multiple outbound migration commands.
    /// Uses tokio::sync::Mutex because migration orchestrator commands hold the lock across .await points.
    pub orchestration_state:
        tokio::sync::Mutex<Option<crate::migration_orchestrator::OutboundMigrationState>>,
    /// Share-recovery ceremony state (collection → verify → re-anchor). In-memory by
    /// design: the pre-anchor phase is restartable from the entry screen, and the
    /// rotation epilogue persists its own durable Keychain record.
    /// Uses tokio::sync::Mutex because recovery commands hold the lock across .await points.
    pub share_recovery_state: tokio::sync::Mutex<Option<crate::share_recovery::ShareRecoveryState>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            oauth_session: Mutex::new(None),
            custos_client: OnceLock::new(),
            pds_client: crate::pds_client::PdsClient::new(),
            claim_state: tokio::sync::Mutex::new(None),
            recovery_state: tokio::sync::Mutex::new(None),
            rotation_state: tokio::sync::Mutex::new(None),
            migration_state: tokio::sync::Mutex::new(None),
            orchestration_state: tokio::sync::Mutex::new(None),
            share_recovery_state: tokio::sync::Mutex::new(None),
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
        let x = b64url_encode(point.x().expect("P-256 uncompressed point has x"));
        let y = b64url_encode(point.y().expect("P-256 uncompressed point has y"));
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
        b64url_encode(hash)
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
        let header_b64 =
            b64url_encode(serde_json::to_vec(&header).map_err(|_| OAuthError::DpopProofFailed)?);

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

        let claims_b64 =
            b64url_encode(serde_json::to_vec(&claims).map_err(|_| OAuthError::DpopProofFailed)?);

        // Sign `header_b64.claims_b64` bytes with P-256/SHA-256.
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        // Normalize to low-S (consistent with the rest of the codebase, even though
        // the custos's DPoP validator does not require it — low-S is harmless and keeps
        // key usage consistent with ATProto expectations).
        let signature = signature.normalize_s().unwrap_or(signature);
        let sig_b64 = b64url_encode(signature.to_bytes().as_slice());

        Ok(format!("{signing_input}.{sig_b64}"))
    }

    /// Compute `base64url(SHA-256(access_token))` — the `ath` claim for resource requests.
    pub fn compute_ath(access_token: &str) -> String {
        let hash = Sha256::digest(access_token.as_bytes());
        b64url_encode(hash)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64url::b64url_decode;
    use p256::ecdsa::signature::Verifier;

    fn decode_jwt_part(b64: &str) -> serde_json::Value {
        let bytes = b64url_decode(b64).expect("valid base64url");
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
        let x_bytes = b64url_decode(header["jwk"]["x"].as_str().unwrap()).unwrap();
        let y_bytes = b64url_decode(header["jwk"]["y"].as_str().unwrap()).unwrap();
        // Build uncompressed point: 0x04 || x || y
        let mut point_bytes = vec![0x04u8];
        point_bytes.extend_from_slice(&x_bytes);
        point_bytes.extend_from_slice(&y_bytes);
        let point = EncodedPoint::<p256::NistP256>::from_bytes(&point_bytes)
            .expect("valid uncompressed point");
        let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
            .expect("valid verifying key from JWK");

        // Decode the signature.
        let sig_bytes = b64url_decode(sig_b64).expect("valid base64url sig");
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
            b64url_encode(hash)
        };
        assert_eq!(ath, expected);
    }
}
