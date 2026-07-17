// pattern: Imperative Shell
//
// Wallet-driven per-account repo signing-key rotation, account-owner authed:
//
//   POST /v1/repo-keys/rotation           — stage a fresh replacement signing key
//   POST /v1/repo-keys/rotation/complete  — submit the wallet-signed PLC op and cut over
//
// The per-account repo signing key (the DID's `#atproto` verification method, which signs
// every repo commit — ADR-0004) can only be replaced by repointing the DID document, and
// the PDS cannot authorize that itself: the wallet's device key outranks the PDS key in
// `rotationKeys` (ADR-0001), so the rotation op is built and signed in the wallet. This
// surface is the PDS's half of that flow (ADR-0025):
//
//   1. `begin` mints a FRESH P-256 key (never reusing a previously staged one) and stores
//      it as a `'staged'` `signing_keys` row — invisible to commit signing and to
//      `getRecommendedDidCredentials` until the cutover.
//   2. The wallet builds a rotation op installing that key as `verificationMethods.atproto`
//      (+ the PDS slot in `rotationKeys`), signs it with the device key, and POSTs it to
//      `complete` — never straight to plc.directory, so the PDS controls the cutover.
//   3. `complete` verifies the op (signed by a current rotation key, chains onto the head,
//      installs exactly the staged key, leaves `services` untouched), then — holding the
//      account's repo write lock so no commit can interleave — submits it to plc.directory,
//      refreshes the cached DID document, and atomically promotes the staged key while
//      deleting the retired one. An `#identity` firehose frame tells relays to re-resolve.
//
// Holding `RepoWriteLocks` across submit+promote is what guarantees no commit is ever
// signed by a key absent from the DID document: before the lock the document still names
// the old key (which is still the active signer), and by release the promoted key is both
// active locally and live in the document.
//
// Auth is `auth::guards::authenticate_account_owner` (wallet session token or full-access
// OAuth/XRPC token; agent-derived and app-password credentials refused) — the same owner
// guard as `/v1/did-web/*`. These live on the same-origin `/v1/*` surface.

use axum::{
    extract::State,
    http::{HeaderMap, Method, Uri},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::guards::{authenticate_account_owner, OwnerAuthError};
use crate::db::repo_keys::{
    get_signing_key_by_did, get_staged_signing_key, promote_staged_signing_key, stage_rotation_key,
    RepoSigningKey,
};
use crate::identity::plc::{build_did_document_from_op, ensure_did_plc, fetch_current_plc_state};
use common::{ApiError, ErrorCode};

/// The atproto verification-method id a repo signing key is installed under.
const ATPROTO_VERIFICATION_METHOD_ID: &str = "atproto";

/// Map a signing-key query failure to the uniform 500 (`db/repo_keys.rs` returns bare
/// `sqlx::Error`, matching its sibling queries).
fn key_query_error(e: sqlx::Error) -> ApiError {
    tracing::error!(error = %e, "signing-key query failed during rotation");
    ApiError::new(ErrorCode::InternalError, "failed to access signing keys")
}

/// Authenticate the account owner and map the neutral rejection into this surface's
/// vocabulary. Mirrors `did_web_hosting.rs`'s wrapper (routes may not import one another).
async fn authenticate_owner(
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    state: &AppState,
) -> Result<String, ApiError> {
    authenticate_account_owner(headers, method, uri, state)
        .await
        .map_err(|err| match err {
            OwnerAuthError::Unauthenticated(e) => e,
            OwnerAuthError::AgentDerived => ApiError::new(
                ErrorCode::InsufficientScope,
                "this operation is not available to agent-derived credentials",
            ),
            OwnerAuthError::NotFullAccess => ApiError::new(
                ErrorCode::InvalidToken,
                "a session or full-access token is required",
            ),
        })
}

// ── POST /v1/repo-keys/rotation ───────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BeginRotationResponse {
    /// The staged replacement key's `did:key` id — what the wallet's rotation op must
    /// install as `verificationMethods.atproto` (and the PDS `rotationKeys` slot).
    pub signing_key: String,
}

pub async fn begin_repo_key_rotation(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<BeginRotationResponse>, ApiError> {
    let did = authenticate_owner(&headers, &method, &uri, &state).await?;
    ensure_did_plc(&did)?;

    let master_key: &[u8; 32] = state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|s| &*s.0)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::ServiceUnavailable,
                "signing key master key not configured",
            )
        })?;

    // A rotation replaces an existing key; an account with no active signing key has
    // nothing to rotate (and could not have signed a commit anyway).
    if get_signing_key_by_did(&state.db, &did)
        .await
        .map_err(key_query_error)?
        .is_none()
    {
        return Err(ApiError::new(
            ErrorCode::NotFound,
            "no signing key is registered for this account",
        ));
    }

    // Always mint fresh, replacing any previously staged key: in a compromise scenario a
    // key staged before this rotation began must be assumed known to the attacker.
    let kp = crypto::generate_p256_keypair().map_err(|e| {
        tracing::error!(error = %e, "failed to generate rotation signing key");
        ApiError::new(ErrorCode::InternalError, "failed to generate signing key")
    })?;
    let private_key_encrypted = crypto::encrypt_private_key(&kp.private_key_bytes, master_key)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to encrypt rotation signing key");
            ApiError::new(ErrorCode::InternalError, "failed to encrypt signing key")
        })?;
    let staged = RepoSigningKey {
        key_id: kp.key_id.to_string(),
        public_key: kp.public_key.clone(),
        private_key_encrypted,
    };
    stage_rotation_key(&state.db, &did, &staged)
        .await
        .map_err(key_query_error)?;

    tracing::info!(did = %did, key_id = %staged.key_id, "staged repo signing-key rotation");
    Ok(Json(BeginRotationResponse {
        signing_key: staged.key_id,
    }))
}

// ── POST /v1/repo-keys/rotation/complete ──────────────────────────────────────

#[derive(Deserialize)]
pub struct CompleteRotationRequest {
    /// The wallet-signed PLC rotation operation installing the staged key.
    pub operation: serde_json::Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteRotationResponse {
    /// The now-active signing key's `did:key` id.
    pub signing_key: String,
}

pub async fn complete_repo_key_rotation(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Json(request): Json<CompleteRotationRequest>,
) -> Result<Json<CompleteRotationResponse>, ApiError> {
    let did = authenticate_owner(&headers, &method, &uri, &state).await?;
    ensure_did_plc(&did)?;

    let operation_str = serde_json::to_string(&request.operation).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize submitted rotation operation");
        ApiError::new(ErrorCode::InvalidRequest, "operation is not valid JSON")
    })?;

    // The operation must be authorized by, and relate to, the DID's CURRENT PLC state.
    let current = fetch_current_plc_state(
        &state.http_client,
        &state.config.plc_directory_url,
        did.as_str(),
    )
    .await?;
    let authorized_keys: Vec<crypto::DidKeyUri> = current
        .rotation_keys
        .iter()
        .cloned()
        .map(crypto::DidKeyUri)
        .collect();
    let verified = crypto::verify_plc_operation(&operation_str, &authorized_keys).map_err(|e| {
        tracing::warn!(error = %e, did = %did, "rotation operation failed verification");
        ApiError::new(
            ErrorCode::InvalidRequest,
            "operation is not signed by a current rotation key",
        )
    })?;

    // Either the op chains onto the current head (normal path — we submit it), or it IS
    // the current head (a retry after a submit whose cutover didn't land — we only flip).
    let already_landed = verified.cid == current.cid;
    if !already_landed && verified.prev.as_deref() != Some(current.cid.as_str()) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "operation does not chain onto the current PLC head (prev mismatch)",
        ));
    }

    let op_atproto_key = verified
        .verification_methods
        .get(ATPROTO_VERIFICATION_METHOD_ID)
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidRequest,
                "operation has no atproto verification method",
            )
        })?;

    let staged = match get_staged_signing_key(&state.db, &did)
        .await
        .map_err(key_query_error)?
    {
        Some(staged) => staged,
        None => {
            // No rotation in progress. If a previous `complete` already promoted this
            // exact key and the op is the live head, a retry reconciles to success.
            let active = get_signing_key_by_did(&state.db, &did)
                .await
                .map_err(key_query_error)?;
            if already_landed
                && active.as_ref().map(|k| k.key_id.as_str()) == Some(op_atproto_key.as_str())
            {
                return Ok(Json(CompleteRotationResponse {
                    signing_key: op_atproto_key,
                }));
            }
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "no signing-key rotation is in progress for this account",
            ));
        }
    };

    // The op must install exactly the staged key — as the atproto verification method
    // (what signs commits) and in `rotationKeys` (the PDS slot, ADR-0004).
    if op_atproto_key != staged.key_id {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "operation does not install the staged signing key as the atproto verification method",
        ));
    }
    if !verified.rotation_keys.contains(&staged.key_id) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "operation does not include the staged signing key in rotationKeys",
        ));
    }

    // A rotation must not double as a migration: the op's services must be exactly the
    // DID's current services, so the account stays pointed at this PDS. (When the op is
    // already the head, `current` == the op's own state and this holds trivially.)
    if verified.services != current.services {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "a key rotation must not change the DID's services",
        ));
    }

    // Hold the account's repo write lock across submit + cutover: no commit can be
    // signed between plc.directory accepting the new key and the local key flip, so a
    // commit is never signed by a key absent from the DID document. Lock ordering
    // matches `record_write::commit_repo_write` (repo write lock before any firehose
    // emit-lock acquisition; the `#identity` emit below happens after release).
    {
        let _write_guard = state.repo_write_locks.lock(&did).await;

        if !already_landed {
            crate::identity::genesis::post_to_plc_directory(
                &state.http_client,
                &state.config.plc_directory_url,
                &did,
                &operation_str,
            )
            .await?;
        }

        // Refresh the cached DID document so local reads reflect the new key. The PLC
        // directory is the source of truth; a cache-update failure is logged, not fatal.
        match build_did_document_from_op(
            &did,
            &verified.verification_methods,
            &verified.also_known_as,
            &verified.services,
        ) {
            Ok(doc) => {
                if let Err(e) = upsert_cached_did_document(&state.db, &did, &doc).await {
                    tracing::warn!(error = %e, did = %did, "failed to refresh cached DID document after rotation (non-fatal)");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, did = %did, "rotation operation had no renderable DID document; cache left unchanged");
            }
        }

        // Promote staged → active and delete the retired key, atomically. A false return
        // means no staged row matched — acceptable only if a concurrent retry already
        // promoted this exact key.
        let promoted = promote_staged_signing_key(&state.db, &did, &staged.key_id)
            .await
            .map_err(key_query_error)?;
        if !promoted {
            let active = get_signing_key_by_did(&state.db, &did)
                .await
                .map_err(key_query_error)?;
            if active.as_ref().map(|k| k.key_id.as_str()) != Some(staged.key_id.as_str()) {
                tracing::error!(did = %did, key_id = %staged.key_id, "rotation cutover failed: staged key vanished before promotion");
                return Err(ApiError::new(
                    ErrorCode::InternalError,
                    "failed to promote the staged signing key",
                ));
            }
        }
    }

    // Announce the identity change so relays re-resolve the document. `None` handle =
    // "the identity changed, re-resolve" — the honest signal for a key rotation.
    if let Err(e) = state.firehose.emit_identity(did.clone(), None).await {
        tracing::warn!(
            error = %e,
            did = %did,
            "failed to sequence #identity firehose event after signing-key rotation (non-fatal)"
        );
    }

    tracing::info!(did = %did, key_id = %staged.key_id, "repo signing-key rotation complete");
    Ok(Json(CompleteRotationResponse {
        signing_key: staged.key_id,
    }))
}

/// Upsert the locally-cached DID document for `did`. Mirrors `submitPlcOperation`'s
/// cache refresh (routes may not import one another).
async fn upsert_cached_did_document(
    db: &sqlx::SqlitePool,
    did: &str,
    document: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO did_documents (did, document, created_at, updated_at) \
         VALUES (?, ?, datetime('now'), datetime('now')) \
         ON CONFLICT(did) DO UPDATE SET document = excluded.document, updated_at = datetime('now')",
    )
    .bind(did)
    .bind(document.to_string())
    .execute(db)
    .await?;
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use uuid::Uuid;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::app::{app, test_state_with_plc_url, AppState};
    use crate::auth::token::generate_token;
    use crate::db::repo_keys::{get_signing_key_by_did, get_staged_signing_key};
    use crate::routes::test_utils::{seed_account_with_signing_key, test_master_key};

    const DID: &str = "did:plc:rotation1111111111111111";
    const HEAD_CID: &str = "bafyreidmwn2nk3hb2ta2b3wgqzted5cixmwjjmpq2vt6potol7cke2ptoq";

    /// Test state: mock plc.directory + the signing-key master key configured.
    async fn rotation_state(plc_uri: String) -> AppState {
        let base = test_state_with_plc_url(plc_uri).await;
        let mut config = (*base.config).clone();
        config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(
            test_master_key(),
        )));
        AppState {
            config: std::sync::Arc::new(config),
            ..base
        }
    }

    /// Seed the rotating account (active signing key + handle) and a wallet session
    /// token for the owner guard. Returns (old active key id, session token).
    async fn seed_owner(state: &AppState) -> (String, String) {
        let old_key = seed_account_with_signing_key(&state.db, DID, "rotator.example.com").await;
        let token = generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(DID)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .unwrap();
        (old_key, token.plaintext)
    }

    fn services_json(endpoint: &str) -> serde_json::Value {
        serde_json::json!({
            "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": endpoint }
        })
    }

    fn services_map(endpoint: &str) -> BTreeMap<String, crypto::PlcService> {
        let mut m = BTreeMap::new();
        m.insert(
            "atproto_pds".to_string(),
            crypto::PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: endpoint.to_string(),
            },
        );
        m
    }

    /// Mount an audit log whose head has `rotationKeys` [device, old PDS key] and
    /// `verificationMethods.atproto` = the old PDS key.
    async fn mount_current_state(server: &MockServer, device_key: &str, old_pds_key: &str) {
        let log = serde_json::json!([{
            "did": DID,
            "cid": HEAD_CID,
            "createdAt": "2026-07-02T00:00:00Z",
            "nullified": false,
            "operation": {
                "type": "plc_operation",
                "prev": null,
                "rotationKeys": [device_key, old_pds_key],
                "verificationMethods": { "atproto": old_pds_key },
                "alsoKnownAs": ["at://rotator.example.com"],
                "services": services_json("https://test.example.com"),
            }
        }]);
        Mock::given(method("GET"))
            .and(path(format!("/{DID}/log/audit")))
            .respond_with(ResponseTemplate::new(200).set_body_json(log))
            .mount(server)
            .await;
    }

    /// Build a device-key-signed rotation op chaining on `prev`, installing
    /// `new_pds_key` as `verificationMethods.atproto` and `rotationKeys[1]`.
    fn build_rotation_op(
        device: &crypto::P256Keypair,
        prev: &str,
        new_pds_key: &str,
        endpoint: &str,
    ) -> crypto::SignedPlcOperation {
        let mut vms = BTreeMap::new();
        vms.insert("atproto".to_string(), new_pds_key.to_string());
        let pk: [u8; 32] = *device.private_key_bytes;
        let signer = repo_engine::CommitSigner::from_bytes(&pk).unwrap();
        crypto::build_did_plc_rotation_op(
            prev,
            vec![device.key_id.0.clone(), new_pds_key.to_string()],
            vms,
            vec!["at://rotator.example.com".to_string()],
            services_map(endpoint),
            |bytes| Ok(signer.sign(bytes)),
        )
        .unwrap()
    }

    fn begin_req(token: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/repo-keys/rotation");
        if let Some(token) = token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        builder.body(Body::empty()).unwrap()
    }

    fn complete_req(token: &str, operation: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/repo-keys/rotation/complete")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({ "operation": operation }).to_string(),
            ))
            .unwrap()
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn identity_events(db: &sqlx::SqlitePool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM repo_seq WHERE event_type = 'identity'")
            .fetch_one(db)
            .await
            .unwrap()
    }

    // ── begin ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn begin_requires_auth() {
        let plc = MockServer::start().await;
        let state = rotation_state(plc.uri()).await;
        let response = app(state).oneshot(begin_req(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn begin_stages_a_fresh_key_without_touching_the_active_one() {
        let plc = MockServer::start().await;
        let state = rotation_state(plc.uri()).await;
        let (old_key, token) = seed_owner(&state).await;
        let db = state.db.clone();

        let response = app(state.clone())
            .oneshot(begin_req(Some(&token)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let staged_id = body_json(response).await["signingKey"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(staged_id, old_key);

        // Active lookup still returns the old key; the staged key is parked.
        let active = get_signing_key_by_did(&db, DID).await.unwrap().unwrap();
        assert_eq!(active.key_id, old_key);
        let staged = get_staged_signing_key(&db, DID).await.unwrap().unwrap();
        assert_eq!(staged.key_id, staged_id);

        // A second begin mints a DIFFERENT fresh key, replacing the first.
        let response = app(state).oneshot(begin_req(Some(&token))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let second_id = body_json(response).await["signingKey"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(second_id, staged_id);
        let staged = get_staged_signing_key(&db, DID).await.unwrap().unwrap();
        assert_eq!(staged.key_id, second_id);
    }

    #[tokio::test]
    async fn begin_rejects_an_account_with_no_signing_key() {
        let plc = MockServer::start().await;
        let state = rotation_state(plc.uri()).await;
        // Account + session but no signing key.
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(DID)
        .bind("keyless@example.com")
        .execute(&state.db)
        .await
        .unwrap();
        let token = generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(DID)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .unwrap();

        let response = app(state)
            .oneshot(begin_req(Some(&token.plaintext)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ── complete ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn complete_submits_the_op_and_cuts_over() {
        let plc = MockServer::start().await;
        let state = rotation_state(plc.uri()).await;
        let (old_key, token) = seed_owner(&state).await;
        let db = state.db.clone();
        let device = crypto::generate_p256_keypair().unwrap();
        mount_current_state(&plc, &device.key_id.0, &old_key).await;
        Mock::given(method("POST"))
            .and(path(format!("/{DID}")))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&plc)
            .await;

        // Stage.
        let response = app(state.clone())
            .oneshot(begin_req(Some(&token)))
            .await
            .unwrap();
        let staged_id = body_json(response).await["signingKey"]
            .as_str()
            .unwrap()
            .to_string();

        // Complete with a device-signed op installing the staged key.
        let signed = build_rotation_op(&device, HEAD_CID, &staged_id, "https://test.example.com");
        let op: serde_json::Value = serde_json::from_str(&signed.signed_op_json).unwrap();
        let response = app(state).oneshot(complete_req(&token, op)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["signingKey"], staged_id);

        // The staged key is now the only key, and it is active.
        let active = get_signing_key_by_did(&db, DID).await.unwrap().unwrap();
        assert_eq!(active.key_id, staged_id);
        assert_eq!(get_staged_signing_key(&db, DID).await.unwrap(), None);
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM signing_keys WHERE did = ?")
            .bind(DID)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(total, 1);

        // The cached DID document reflects the new key, and relays were told.
        let doc: String = sqlx::query_scalar("SELECT document FROM did_documents WHERE did = ?")
            .bind(DID)
            .fetch_one(&db)
            .await
            .unwrap();
        assert!(doc.contains(staged_id.strip_prefix("did:key:").unwrap()));
        assert_eq!(identity_events(&db).await, 1);
        // plc mock's `.expect(1)` verifies the POST happened on drop.
    }

    #[tokio::test]
    async fn complete_rejects_an_op_installing_a_different_key() {
        let plc = MockServer::start().await;
        let state = rotation_state(plc.uri()).await;
        let (old_key, token) = seed_owner(&state).await;
        let db = state.db.clone();
        let device = crypto::generate_p256_keypair().unwrap();
        mount_current_state(&plc, &device.key_id.0, &old_key).await;
        // No POST mock: a submit attempt would 404 — the guard must reject first.

        app(state.clone())
            .oneshot(begin_req(Some(&token)))
            .await
            .unwrap();

        // The op installs a smuggled key instead of the staged one.
        let smuggled = crypto::generate_p256_keypair().unwrap();
        let signed = build_rotation_op(
            &device,
            HEAD_CID,
            &smuggled.key_id.0,
            "https://test.example.com",
        );
        let op: serde_json::Value = serde_json::from_str(&signed.signed_op_json).unwrap();
        let response = app(state).oneshot(complete_req(&token, op)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Nothing changed locally.
        let active = get_signing_key_by_did(&db, DID).await.unwrap().unwrap();
        assert_eq!(active.key_id, old_key);
        assert!(get_staged_signing_key(&db, DID).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn complete_rejects_an_op_that_moves_the_pds() {
        let plc = MockServer::start().await;
        let state = rotation_state(plc.uri()).await;
        let (old_key, token) = seed_owner(&state).await;
        let device = crypto::generate_p256_keypair().unwrap();
        mount_current_state(&plc, &device.key_id.0, &old_key).await;

        let response = app(state.clone())
            .oneshot(begin_req(Some(&token)))
            .await
            .unwrap();
        let staged_id = body_json(response).await["signingKey"]
            .as_str()
            .unwrap()
            .to_string();

        // Valid staged key, but the op relocates the account to another PDS.
        let signed = build_rotation_op(&device, HEAD_CID, &staged_id, "https://evil.example.com");
        let op: serde_json::Value = serde_json::from_str(&signed.signed_op_json).unwrap();
        let response = app(state).oneshot(complete_req(&token, op)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn complete_rejects_an_unauthorized_signer() {
        let plc = MockServer::start().await;
        let state = rotation_state(plc.uri()).await;
        let (old_key, token) = seed_owner(&state).await;
        let device = crypto::generate_p256_keypair().unwrap();
        mount_current_state(&plc, &device.key_id.0, &old_key).await;

        let response = app(state.clone())
            .oneshot(begin_req(Some(&token)))
            .await
            .unwrap();
        let staged_id = body_json(response).await["signingKey"]
            .as_str()
            .unwrap()
            .to_string();

        // Signed by a key that is NOT in the DID's current rotationKeys.
        let attacker = crypto::generate_p256_keypair().unwrap();
        let signed = build_rotation_op(&attacker, HEAD_CID, &staged_id, "https://test.example.com");
        let op: serde_json::Value = serde_json::from_str(&signed.signed_op_json).unwrap();
        let response = app(state).oneshot(complete_req(&token, op)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn complete_rejects_a_stale_prev() {
        let plc = MockServer::start().await;
        let state = rotation_state(plc.uri()).await;
        let (old_key, token) = seed_owner(&state).await;
        let device = crypto::generate_p256_keypair().unwrap();
        mount_current_state(&plc, &device.key_id.0, &old_key).await;

        let response = app(state.clone())
            .oneshot(begin_req(Some(&token)))
            .await
            .unwrap();
        let staged_id = body_json(response).await["signingKey"]
            .as_str()
            .unwrap()
            .to_string();

        let stale_prev = "bafyreib2rxk3rh6kzwq6nbrzws2hbrbqvq3g6dlvwvwkkbzbsvpj2vsxaa";
        let signed = build_rotation_op(&device, stale_prev, &staged_id, "https://test.example.com");
        let op: serde_json::Value = serde_json::from_str(&signed.signed_op_json).unwrap();
        let response = app(state).oneshot(complete_req(&token, op)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn complete_rejects_when_no_rotation_is_in_progress() {
        let plc = MockServer::start().await;
        let state = rotation_state(plc.uri()).await;
        let (old_key, token) = seed_owner(&state).await;
        let device = crypto::generate_p256_keypair().unwrap();
        mount_current_state(&plc, &device.key_id.0, &old_key).await;

        // No begin call — nothing staged.
        let fresh = crypto::generate_p256_keypair().unwrap();
        let signed = build_rotation_op(
            &device,
            HEAD_CID,
            &fresh.key_id.0,
            "https://test.example.com",
        );
        let op: serde_json::Value = serde_json::from_str(&signed.signed_op_json).unwrap();
        let response = app(state).oneshot(complete_req(&token, op)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// A retry after plc.directory accepted the op but the cutover didn't land: the op
    /// is now the audit-log head, so `complete` skips the submit and only promotes.
    #[tokio::test]
    async fn complete_reconciles_when_the_op_already_landed() {
        let plc = MockServer::start().await;
        let state = rotation_state(plc.uri()).await;
        let (_old_key, token) = seed_owner(&state).await;
        let db = state.db.clone();
        let device = crypto::generate_p256_keypair().unwrap();

        let response = app(state.clone())
            .oneshot(begin_req(Some(&token)))
            .await
            .unwrap();
        let staged_id = body_json(response).await["signingKey"]
            .as_str()
            .unwrap()
            .to_string();

        // The audit log's head IS the signed rotation op (prev attempt landed).
        let signed = build_rotation_op(&device, HEAD_CID, &staged_id, "https://test.example.com");
        let op: serde_json::Value = serde_json::from_str(&signed.signed_op_json).unwrap();
        let log = serde_json::json!([{
            "did": DID,
            "cid": signed.cid,
            "createdAt": "2026-07-02T01:00:00Z",
            "nullified": false,
            "operation": op,
        }]);
        Mock::given(method("GET"))
            .and(path(format!("/{DID}/log/audit")))
            .respond_with(ResponseTemplate::new(200).set_body_json(log))
            .mount(&plc)
            .await;
        // No POST mock: a re-submit would 404 and fail the flow — the landed op must
        // skip straight to promotion.

        let response = app(state).oneshot(complete_req(&token, op)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let active = get_signing_key_by_did(&db, DID).await.unwrap().unwrap();
        assert_eq!(active.key_id, staged_id);
        assert_eq!(get_staged_signing_key(&db, DID).await.unwrap(), None);
    }

    /// A repeat of a fully-completed rotation (promotion done, response lost) is a 200.
    #[tokio::test]
    async fn complete_is_idempotent_after_promotion() {
        let plc = MockServer::start().await;
        let state = rotation_state(plc.uri()).await;
        let (_old_key, token) = seed_owner(&state).await;
        let db = state.db.clone();
        let device = crypto::generate_p256_keypair().unwrap();

        let response = app(state.clone())
            .oneshot(begin_req(Some(&token)))
            .await
            .unwrap();
        let staged_id = body_json(response).await["signingKey"]
            .as_str()
            .unwrap()
            .to_string();
        let signed = build_rotation_op(&device, HEAD_CID, &staged_id, "https://test.example.com");
        let op: serde_json::Value = serde_json::from_str(&signed.signed_op_json).unwrap();
        let log = serde_json::json!([{
            "did": DID,
            "cid": signed.cid,
            "createdAt": "2026-07-02T01:00:00Z",
            "nullified": false,
            "operation": op,
        }]);
        Mock::given(method("GET"))
            .and(path(format!("/{DID}/log/audit")))
            .respond_with(ResponseTemplate::new(200).set_body_json(log))
            .mount(&plc)
            .await;

        // First complete promotes; second reconciles to success with nothing staged.
        let response = app(state.clone())
            .oneshot(complete_req(&token, op.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app(state).oneshot(complete_req(&token, op)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let active = get_signing_key_by_did(&db, DID).await.unwrap().unwrap();
        assert_eq!(active.key_id, staged_id);
    }

    #[tokio::test]
    async fn did_web_account_rejected() {
        let plc = MockServer::start().await;
        let state = rotation_state(plc.uri()).await;
        let did = "did:web:rotator.example.com";
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind("web@example.com")
        .execute(&state.db)
        .await
        .unwrap();
        let token = generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(did)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .unwrap();

        let response = app(state)
            .oneshot(begin_req(Some(&token.plaintext)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
