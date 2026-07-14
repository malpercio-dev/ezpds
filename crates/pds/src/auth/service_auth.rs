// pattern: Imperative Shell
//
// Inbound atproto service-auth authentication, scoped to a single lexicon method.
//
// A service-auth JWT is minted by an account (signed with its `#atproto` repo key) and handed to
// another service so that service can call one method on the account's PDS as the account. The
// canonical case: the official app mints a token with `aud` = the user's PDS DID and
// `lxm` = `com.atproto.repo.uploadBlob`, hands it to `video.bsky.app` with a video, and after
// transcoding the video service pushes the transcoded blob to `uploadBlob` on the user's PDS
// authenticated with that token.
//
// This module is the reusable guard the reference PDS's service-auth acceptance maps to. It owns
// two things:
//
//   * `require_service_auth(lxm)` — the route-level guard: extract the token, confirm its `iss` is
//     an account **hosted and active on this server**, then verify it against that account's
//     `#atproto` key with the audience pinned to this server and the `lxm` pinned to the single
//     method the route authorizes. The authorization is deliberately narrow — no session, no scope
//     claims — so a service token can never ride the general `AuthenticatedUser` path.
//
//   * `verify_service_auth_resolving_key` — the shared "resolve the issuer's `#atproto` key
//     cache-first, verify, force-refresh + retry once on a signature mismatch" machinery
//     (originally the migration-`createAccount` verifier). Both this guard and the migration path
//     call it, so the dual-curve verification + fossil-key refresh is derived once.

use axum::http::HeaderMap;
use serde_json::Value;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::jwt::{peek_jwt_iss, verify_service_auth_jwt, ServiceAuthError};
use crate::db::accounts::{account_lifecycle, AccountLifecycle};
use crate::identity::resolution::{
    atproto_verification_key, resolve_did_document, resolve_did_document_force_refresh,
};

/// A caller authenticated by an atproto service-auth JWT, authorized for **exactly one** lexicon
/// method. Carries only the issuing account's DID — no scope, no session identity — because a
/// service token grants nothing beyond the single method the guard was called for.
#[derive(Debug, Clone)]
pub struct ServiceAuthUser {
    /// The issuing account DID (`iss`), verified to be hosted and active on this server. Anything
    /// this request writes lands under this DID exactly as a session-authed request would.
    pub did: String,
}

/// Whether the request's `Authorization` header carries an atproto service-auth JWT (its `iss` is a
/// DID) rather than a server-issued session/OAuth access token.
///
/// A cheap, signature-free discriminator a route uses to choose between the service-auth guard and
/// the standard access-token path. The token is not trusted here — only its shape is inspected;
/// [`require_service_auth`] performs the real verification.
pub fn is_service_auth_request(headers: &HeaderMap) -> bool {
    bearer_service_token(headers)
        .and_then(peek_jwt_iss)
        .is_some_and(|iss| iss.starts_with("did:"))
}

/// Authenticate an inbound service-auth JWT scoped to `lxm`, returning the issuing account.
///
/// Accepts the token iff, in order:
///   1. an `Authorization` token is present and its `iss` claim is a DID;
///   2. that `iss` resolves to an account **hosted on this server** whose lifecycle is `Active`
///      (a missing, deactivated, suspended, or taken-down account is rejected);
///   3. the token verifies against that account's `#atproto` key (dual-curve ES256/ES256K), with
///      `iss` = the account DID, `aud` = this server's DID, `lxm` = `lxm` exactly (when present),
///      and `exp` in the future — force-refreshing a possibly-fossil cached key and retrying once
///      on a signature mismatch.
///
/// Every rejection is a `401` (`InvalidToken`) — an auth failure, not a leak of whether the DID is
/// hosted here.
///
/// No `jti` replay guard: the reference PDS tracks `jti`, but this guard deliberately does not (the
/// same posture as the migration-`createAccount` verifier). The token is already `exp`-bounded and
/// short-lived, and the one method it authorizes — `uploadBlob` — is content-addressed and
/// idempotent, so a replay within the validity window re-stores the same CID rather than causing a
/// new effect. If a future consumer authorizes a non-idempotent method this way, add replay
/// tracking here before doing so.
pub async fn require_service_auth(
    state: &AppState,
    headers: &HeaderMap,
    lxm: &str,
    now: u64,
) -> Result<ServiceAuthUser, ApiError> {
    let token = bearer_service_token(headers).ok_or_else(unauthorized)?;

    // The `iss` is the account the token claims to act as. Read it (unverified) to pick the DID
    // whose `#atproto` key the signature must verify against; the signature check below is what
    // makes it trustworthy.
    let iss = peek_jwt_iss(token)
        .filter(|i| i.starts_with("did:"))
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidToken,
                "service auth token issuer is missing or not a DID",
            )
        })?;

    // The issuer must be an account this server actually hosts, and actively — a service token can
    // only ever act for a live local account. `account_lifecycle` is unfiltered, so we gate on the
    // derived state explicitly: only `Active` may upload.
    match account_lifecycle(&state.db, &iss).await? {
        Some(AccountLifecycle::Active) => {}
        Some(_) => {
            return Err(ApiError::new(
                ErrorCode::InvalidToken,
                "service auth issuer account is not active",
            ))
        }
        None => {
            return Err(ApiError::new(
                ErrorCode::InvalidToken,
                "service auth issuer is not an account on this server",
            ))
        }
    }

    let server_did = state.config.resolve_server_did();
    verify_service_auth_resolving_key(state, token, &iss, &server_did, lxm, now).await?;

    Ok(ServiceAuthUser { did: iss })
}

/// Resolve `iss`'s DID document and verify a service-auth `token` against its `#atproto` key,
/// force-refreshing the cached document and retrying the verification **once** on a signature
/// mismatch. Returns the document that ultimately verified.
///
/// The `did_documents` cache is a persistent store with no TTL, so a DID whose PLC document was
/// rewritten after this server cached it — e.g. an account that rotated its `#atproto` key during
/// an identity-migration leg — presents a provably-valid token that fails against the fossil key.
/// This mirrors the reference PDS's `verifyServiceJwt`: try the cached key, and on a *signature*
/// failure only, re-resolve the key from the authoritative source (plc.directory / did:web) and
/// verify once more. Bounded to a single refetch per verification (and each caller carries its own
/// rate limiting), so it can't be turned into a resolution amplifier. Non-signature failures (bad
/// alg/curve, wrong `iss`/`aud`, expired, wrong `lxm`, or a missing `#atproto` method) skip the
/// refresh — re-resolving the key cannot fix them.
///
/// Shared by the `uploadBlob` service-auth guard and migration-mode `createAccount`; each passes
/// its own `iss`/`aud`/`lxm`.
pub async fn verify_service_auth_resolving_key(
    state: &AppState,
    token: &str,
    iss: &str,
    aud: &str,
    lxm: &str,
    now: u64,
) -> Result<Value, ApiError> {
    let cached = resolve_did_document(state, iss).await?;
    match verify_service_auth_against_doc(token, iss, aud, lxm, &cached, now) {
        Ok(()) => Ok(cached),
        Err(ServiceAuthError::SignatureMismatch) => {
            tracing::info!(
                iss = %iss,
                "service-auth signature failed against the cached DID document; \
                 force-refreshing the #atproto key and retrying once"
            );
            let fresh = resolve_did_document_force_refresh(state, iss).await?;
            verify_service_auth_against_doc(token, iss, aud, lxm, &fresh, now)?;
            Ok(fresh)
        }
        Err(other) => Err(other.into()),
    }
}

/// Pull the `#atproto` verification key out of `did_document` and verify `token` against it. A
/// missing `#atproto` method is a non-retriable `Invalid` (re-resolving cannot conjure one).
fn verify_service_auth_against_doc(
    token: &str,
    iss: &str,
    aud: &str,
    lxm: &str,
    did_document: &Value,
    now: u64,
) -> Result<(), ServiceAuthError> {
    let atproto_key = atproto_verification_key(did_document).ok_or_else(|| {
        ServiceAuthError::Invalid(ApiError::new(
            ErrorCode::InvalidRequest,
            "the DID document has no #atproto verification method",
        ))
    })?;
    verify_service_auth_jwt(token, iss, aud, lxm, &atproto_key, now)
}

/// Extract the raw JWT from the request's `Authorization` header, accepting the `Bearer` (and,
/// leniently, `DPoP`) scheme. Service-auth tokens are Bearer; the scheme is not otherwise
/// meaningful here because the token's trust comes from its `#atproto` signature, not its binding.
fn bearer_service_token(headers: &HeaderMap) -> Option<&str> {
    super::bearer::extract_access_token(headers)
        .ok()
        .map(|(_scheme, token)| token)
}

fn unauthorized() -> ApiError {
    ApiError::new(
        ErrorCode::AuthenticationRequired,
        "a service-auth token is required",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{test_state, test_state_with_plc_url};
    use crate::auth::jwt::mint_service_auth_jwt;
    use crate::routes::test_utils::seed_did_document;
    use axum::http::{header::AUTHORIZATION, HeaderValue};

    const UPLOAD_BLOB_LXM: &str = "com.atproto.repo.uploadBlob";

    /// A DID document whose `#atproto` Multikey holds `kp`'s public key.
    fn did_doc(did: &str, kp: &crypto::P256Keypair) -> Value {
        let multibase = kp.key_id.0.strip_prefix("did:key:").unwrap().to_string();
        serde_json::json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#atproto"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": multibase,
            }],
        })
    }

    /// Seed a local active account with a cached DID document whose `#atproto` key is `kp`.
    async fn seed_active_account(state: &AppState, did: &str, kp: &crypto::P256Keypair) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'svc@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
        seed_did_document(&state.db, did, did_doc(did, kp)).await;
    }

    /// Mint a service-auth JWT signed by `kp` (the DID's `#atproto` key).
    fn service_token(
        kp: &crypto::P256Keypair,
        iss: &str,
        aud: &str,
        lxm: Option<&str>,
        exp: u64,
    ) -> String {
        let key = *kp.private_key_bytes;
        let signer = repo_engine::CommitSigner::from_bytes(&key).expect("signer");
        mint_service_auth_jwt(|b| signer.sign(b), iss, aud, lxm, 1_000, exp)
    }

    fn headers_with(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn accepts_valid_token_for_hosted_active_account() {
        let state = test_state().await;
        let did = "did:plc:svcauthhappy0000000000";
        let kp = crypto::generate_p256_keypair().unwrap();
        seed_active_account(&state, did, &kp).await;
        let aud = state.config.resolve_server_did();
        let token = service_token(&kp, did, &aud, Some(UPLOAD_BLOB_LXM), 4_000);

        let user = require_service_auth(&state, &headers_with(&token), UPLOAD_BLOB_LXM, 1_001)
            .await
            .expect("valid token must be accepted");
        assert_eq!(user.did, did);
    }

    #[tokio::test]
    async fn accepts_es256k_token() {
        // The reference ecosystem signs with secp256k1, so its service tokens arrive as ES256K.
        let state = test_state().await;
        let did = "did:plc:svcauthk2560000000000";
        let (signing_key, key_uri) = k256_test_key();
        let multibase = key_uri.0.strip_prefix("did:key:").unwrap().to_string();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'k@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
        seed_did_document(
            &state.db,
            did,
            serde_json::json!({
                "id": did,
                "verificationMethod": [{
                    "id": format!("{did}#atproto"),
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": multibase,
                }],
            }),
        )
        .await;
        let aud = state.config.resolve_server_did();
        let token = mint_es256k(&signing_key, did, &aud, UPLOAD_BLOB_LXM, 4_000);

        let user = require_service_auth(&state, &headers_with(&token), UPLOAD_BLOB_LXM, 1_001)
            .await
            .expect("ES256K token must be accepted");
        assert_eq!(user.did, did);
    }

    #[tokio::test]
    async fn rejects_wrong_lxm() {
        let state = test_state().await;
        let did = "did:plc:svcauthwronglxm000000";
        let kp = crypto::generate_p256_keypair().unwrap();
        seed_active_account(&state, did, &kp).await;
        let aud = state.config.resolve_server_did();
        let token = service_token(&kp, did, &aud, Some("com.atproto.repo.createRecord"), 4_000);

        let err = require_service_auth(&state, &headers_with(&token), UPLOAD_BLOB_LXM, 1_001)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn rejects_wrong_audience() {
        let state = test_state().await;
        let did = "did:plc:svcauthwrongaud000000";
        let kp = crypto::generate_p256_keypair().unwrap();
        seed_active_account(&state, did, &kp).await;
        let token = service_token(
            &kp,
            did,
            "did:web:other.example.com",
            Some(UPLOAD_BLOB_LXM),
            4_000,
        );

        let err = require_service_auth(&state, &headers_with(&token), UPLOAD_BLOB_LXM, 1_001)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn rejects_expired_token() {
        let state = test_state().await;
        let did = "did:plc:svcauthexpired0000000";
        let kp = crypto::generate_p256_keypair().unwrap();
        seed_active_account(&state, did, &kp).await;
        let aud = state.config.resolve_server_did();
        let token = service_token(&kp, did, &aud, Some(UPLOAD_BLOB_LXM), 2_000);

        // now (3_000) is past exp (2_000).
        let err = require_service_auth(&state, &headers_with(&token), UPLOAD_BLOB_LXM, 3_000)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn rejects_foreign_issuer_not_hosted_here() {
        let state = test_state().await;
        let did = "did:plc:svcauthforeign000000";
        let kp = crypto::generate_p256_keypair().unwrap();
        // Seed the DID document but NOT an account row — a foreign DID, not hosted here.
        seed_did_document(&state.db, did, did_doc(did, &kp)).await;
        let aud = state.config.resolve_server_did();
        let token = service_token(&kp, did, &aud, Some(UPLOAD_BLOB_LXM), 4_000);

        let err = require_service_auth(&state, &headers_with(&token), UPLOAD_BLOB_LXM, 1_001)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn rejects_deactivated_issuer() {
        let state = test_state().await;
        let did = "did:plc:svcauthdeactivated00";
        let kp = crypto::generate_p256_keypair().unwrap();
        seed_active_account(&state, did, &kp).await;
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let aud = state.config.resolve_server_did();
        let token = service_token(&kp, did, &aud, Some(UPLOAD_BLOB_LXM), 4_000);

        let err = require_service_auth(&state, &headers_with(&token), UPLOAD_BLOB_LXM, 1_001)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn rejects_forged_signature() {
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };

        let did = "did:plc:svcauthforged00000000";
        let kp = crypto::generate_p256_keypair().unwrap();
        let doc = did_doc(did, &kp);
        // The DID resolves to its real key on plc.directory, so the signature-mismatch retry
        // completes (force-refresh returns the same correct key) and the forged token is rejected on
        // signature — a 401 — rather than an unresolvable-DID error. A local account always resolves
        // in production, so this is the realistic path.
        let plc = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&doc))
            .mount(&plc)
            .await;
        let state = test_state_with_plc_url(plc.uri()).await;
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'svc@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
        seed_did_document(&state.db, did, doc).await;

        let aud = state.config.resolve_server_did();
        // Signed by a different key than the DID's #atproto key.
        let attacker = crypto::generate_p256_keypair().unwrap();
        let token = service_token(&attacker, did, &aud, Some(UPLOAD_BLOB_LXM), 4_000);

        let err = require_service_auth(&state, &headers_with(&token), UPLOAD_BLOB_LXM, 1_001)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn no_auth_header_is_not_a_service_request() {
        assert!(!is_service_auth_request(&HeaderMap::new()));
    }

    #[test]
    fn is_service_auth_request_discriminates_on_did_issuer() {
        // A token whose iss is a DID is a service-auth request.
        let kp = crypto::generate_p256_keypair().unwrap();
        let signer = repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap();
        let svc = mint_service_auth_jwt(
            |b| signer.sign(b),
            "did:plc:someissuer000000000",
            "did:web:pds.example.com",
            Some(UPLOAD_BLOB_LXM),
            1_000,
            4_000,
        );
        assert!(is_service_auth_request(&headers_with(&svc)));

        // A token whose iss is a URL (an OAuth at+jwt) is not.
        let oauth = mint_service_auth_jwt(
            |b| signer.sign(b),
            "https://pds.example.com",
            "did:web:pds.example.com",
            None,
            1_000,
            4_000,
        );
        assert!(!is_service_auth_request(&headers_with(&oauth)));
    }

    /// A fresh secp256k1 keypair as (signing key, `did:key:zQ3…` URI) — the key shape the reference
    /// ecosystem's `#atproto` signing keys have. Mirrors the helper in `jwt.rs`'s tests.
    fn k256_test_key() -> (k256::ecdsa::SigningKey, crypto::DidKeyUri) {
        let signing_key = k256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(true);
        // secp256k1 multicodec varint prefix (0xe7 0x01) + compressed SEC1 point.
        let mut multikey = vec![0xe7, 0x01];
        multikey.extend_from_slice(point.as_bytes());
        let uri = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &multikey)
        );
        (signing_key, crypto::DidKeyUri(uri))
    }

    /// Mint an ES256K service-auth JWT signed (low-S) by a secp256k1 key.
    fn mint_es256k(
        signing_key: &k256::ecdsa::SigningKey,
        iss: &str,
        aud: &str,
        lxm: &str,
        exp: u64,
    ) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use k256::ecdsa::signature::Signer;

        let header = serde_json::json!({ "typ": "JWT", "alg": "ES256K" });
        let payload = serde_json::json!({
            "iss": iss, "aud": aud, "iat": 1_000, "exp": exp, "lxm": lxm,
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig: k256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
        let sig = sig.normalize_s().unwrap_or(sig);
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }
}
