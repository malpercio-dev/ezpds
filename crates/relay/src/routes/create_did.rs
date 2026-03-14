// pattern: Imperative Shell
//
// POST /v1/dids — Device-signed DID ceremony and account promotion
//
// Inputs:
//   - Authorization: Bearer <pending_session_token>
//   - JSON body: {
//       "rotationKeyPublic": "did:key:z...",
//       "signedCreationOp": { ...genesis op fields... }
//     }
//
// Processing steps:
//   1. require_pending_session → PendingSessionInfo { account_id, device_id }
//   2. SELECT handle, pending_did, email FROM pending_accounts WHERE id = account_id
//   3. Validate rotationKeyPublic starts with "did:key:z" → DidKeyUri
//   4. serde_json::to_string(signedCreationOp) → signed_op_str
//   5. crypto::verify_genesis_op(signed_op_str, rotation_key) → VerifiedGenesisOp
//   6. Semantic validation:
//        verified.rotation_keys[0] == rotationKeyPublic
//        verified.also_known_as[0] == "at://{handle}"
//        verified.atproto_pds_endpoint  == config.public_url
//   7. If pending_did IS NULL: UPDATE pending_accounts SET pending_did = verified.did
//      If pending_did IS NOT NULL: verify match, set skip_plc_directory = true
//   8. SELECT EXISTS(SELECT 1 FROM accounts WHERE did = verified.did) → 409 if true
//   9. If !skip_plc_directory: POST {plc_directory_url}/{did} with signed_op_str
//  10. build_did_document(&verified) → serde_json::Value
//  11. Atomic transaction:
//        INSERT accounts (did, email, password_hash=NULL)
//        INSERT did_documents (did, document)
//        INSERT handles (handle, did)
//        DELETE pending_sessions WHERE account_id = ?
//        DELETE devices WHERE account_id = ?
//        DELETE pending_accounts WHERE id = ?
//  12. Return { "did": "did:plc:...", "did_document": {...}, "status": "active" }
//
// Outputs (success):  200 { "did": "did:plc:...", "did_document": {...}, "status": "active" }
// Outputs (error):    400 INVALID_CLAIM, 401 UNAUTHORIZED, 409 DID_ALREADY_EXISTS,
//                     502 PLC_DIRECTORY_ERROR, 500 INTERNAL_ERROR

use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::routes::auth::require_pending_session;
use common::{ApiError, ErrorCode};

/// Check if a sqlx::Error is a UNIQUE constraint violation.
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(
        e,
        sqlx::Error::Database(db_err)
            if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidRequest {
    pub rotation_key_public: String,
    pub signed_creation_op: serde_json::Value,
}

#[derive(Serialize)]
pub struct CreateDidResponse {
    pub did: String,
    pub did_document: serde_json::Value,
    pub status: &'static str,
}

pub async fn create_did_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateDidRequest>,
) -> Result<Json<CreateDidResponse>, ApiError> {
    // Step 1: Authenticate via pending_session Bearer token.
    let session = require_pending_session(&headers, &state.db).await?;

    // Step 2: Load pending account details.
    let (handle, pending_did, email): (String, Option<String>, String) =
        sqlx::query_as("SELECT handle, pending_did, email FROM pending_accounts WHERE id = ?")
            .bind(&session.account_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to query pending account");
                ApiError::new(ErrorCode::InternalError, "failed to load account")
            })?
            .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized, "account not found"))?;

    // Step 3: Validate rotationKeyPublic format.
    if !payload.rotation_key_public.starts_with("did:key:z") {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "rotationKeyPublic must be a did:key: URI starting with 'did:key:z'",
        ));
    }
    let rotation_key = crypto::DidKeyUri(payload.rotation_key_public.clone());

    // Step 4: Serialize the submitted signed op to a JSON string for crypto verification.
    let signed_op_str = serde_json::to_string(&payload.signed_creation_op).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize signedCreationOp");
        ApiError::new(ErrorCode::InternalError, "failed to process signed op")
    })?;

    // Step 5: Verify the ECDSA signature and derive the DID.
    let verified = crypto::verify_genesis_op(&signed_op_str, &rotation_key).map_err(|e| {
        tracing::warn!(error = %e, "genesis op verification failed");
        ApiError::new(ErrorCode::InvalidClaim, "signed genesis op is invalid")
    })?;

    // Step 6: Semantic validation — ensure op fields match account and server config.
    if verified.rotation_keys.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "op rotationKeys is empty",
        ));
    }
    if verified.rotation_keys.first().map(String::as_str) != Some(&payload.rotation_key_public) {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "rotationKeys[0] in op does not match rotationKeyPublic",
        ));
    }
    if verified.also_known_as.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "op alsoKnownAs is empty",
        ));
    }
    if verified.also_known_as.first().map(String::as_str) != Some(&format!("at://{handle}")) {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "alsoKnownAs[0] in op does not match account handle",
        ));
    }
    if verified.atproto_pds_endpoint.as_deref() != Some(&state.config.public_url) {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "services.atproto_pds.endpoint in op does not match server public URL",
        ));
    }

    let did = &verified.did;

    // Step 7: Pre-store the DID for retry resilience.
    let skip_plc_directory = if let Some(pre_stored_did) = &pending_did {
        if did != pre_stored_did {
            tracing::error!(
                derived_did = %did,
                stored_did = %pre_stored_did,
                "retry path: derived DID does not match pre-stored DID; inputs may have changed"
            );
            return Err(ApiError::new(
                ErrorCode::InternalError,
                "DID mismatch: derived DID does not match pre-stored value",
            ));
        }
        tracing::info!(did = %pre_stored_did, "retry detected: pending_did already set, skipping plc.directory");
        true
    } else {
        let result = sqlx::query("UPDATE pending_accounts SET pending_did = ? WHERE id = ?")
            .bind(did)
            .bind(&session.account_id)
            .execute(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to pre-store pending_did");
                ApiError::new(ErrorCode::InternalError, "failed to store pending DID")
            })?;
        if result.rows_affected() == 0 {
            tracing::error!(account_id = %session.account_id, "pending account row vanished during DID pre-store");
            return Err(ApiError::new(
                ErrorCode::InternalError,
                "account no longer exists",
            ));
        }
        false
    };

    // Step 8: Check if the account is already fully promoted (idempotency guard).
    let already_promoted: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE did = ?)")
            .bind(did)
            .fetch_one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to check accounts existence");
                ApiError::new(ErrorCode::InternalError, "database error")
            })?;

    if already_promoted {
        return Err(ApiError::new(
            ErrorCode::DidAlreadyExists,
            "DID is already fully promoted",
        ));
    }

    // Step 9: POST the signed genesis operation to plc.directory (skipped on retry).
    if !skip_plc_directory {
        let plc_url = format!("{}/{}", state.config.plc_directory_url, did);
        let response = state
            .http_client
            .post(&plc_url)
            .body(signed_op_str.clone())
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, plc_url = %plc_url, "failed to contact plc.directory");
                ApiError::new(
                    ErrorCode::PlcDirectoryError,
                    "failed to contact plc.directory",
                )
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read body>".to_string());
            tracing::error!(
                status = %status,
                body = %body_text,
                "plc.directory rejected genesis operation"
            );
            return Err(ApiError::new(
                ErrorCode::PlcDirectoryError,
                format!("plc.directory returned {status}"),
            ));
        }
    }

    // Step 10: Build the DID document from verified op fields.
    let did_document = build_did_document(&verified)?;
    let did_document_str = serde_json::to_string(&did_document).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize DID document");
        ApiError::new(ErrorCode::InternalError, "failed to serialize DID document")
    })?;

    // Step 11: Atomically promote the account.
    let mut tx = state
        .db
        .begin()
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to begin promotion transaction"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to begin transaction"))?;

    sqlx::query(
        "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
         VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
    )
    .bind(did)
    .bind(&email)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert account");
        if is_unique_violation(&e) {
            ApiError::new(ErrorCode::DidAlreadyExists, "DID is already fully promoted")
        } else {
            ApiError::new(ErrorCode::InternalError, "failed to create account")
        }
    })?;

    sqlx::query(
        "INSERT INTO did_documents (did, document, created_at, updated_at) \
         VALUES (?, ?, datetime('now'), datetime('now'))",
    )
    .bind(did)
    .bind(&did_document_str)
    .execute(&mut *tx)
    .await
    .inspect_err(|e| tracing::error!(error = %e, "failed to insert did_document"))
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store DID document"))?;

    sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
        .bind(&handle)
        .bind(did)
        .execute(&mut *tx)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to insert handle"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to register handle"))?;

    sqlx::query("DELETE FROM pending_sessions WHERE account_id = ?")
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to delete pending sessions"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to clean up sessions"))?;

    sqlx::query("DELETE FROM devices WHERE account_id = ?")
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to delete devices"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to clean up devices"))?;

    sqlx::query("DELETE FROM pending_accounts WHERE id = ?")
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to delete pending account"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to clean up account"))?;

    tx.commit()
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to commit promotion transaction"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to commit transaction"))?;

    // Step 12: Return the result.
    Ok(Json(CreateDidResponse {
        did: did.clone(),
        did_document,
        status: "active",
    }))
}

/// Construct a minimal DID Core document from a verified genesis operation.
///
/// No I/O — pure construction from [`crypto::VerifiedGenesisOp`] fields.
///
/// # Errors
/// Returns `InternalError` if `verificationMethods["atproto"]` is absent or is not a did:key: URI.
fn build_did_document(verified: &crypto::VerifiedGenesisOp) -> Result<serde_json::Value, ApiError> {
    let did = &verified.did;

    // Extract the multibase key from did:key URI for publicKeyMultibase.
    // did:key:zAbcDef... → publicKeyMultibase = "zAbcDef..."
    let atproto_did_key = verified
        .verification_methods
        .get("atproto")
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InternalError,
                "atproto verification method not found in op",
            )
        })?;
    let public_key_multibase = atproto_did_key.strip_prefix("did:key:").ok_or_else(|| {
        ApiError::new(
            ErrorCode::InternalError,
            "atproto key is not a did:key: URI",
        )
    })?;

    let service_endpoint = verified.atproto_pds_endpoint.as_deref().ok_or_else(|| {
        ApiError::new(
            ErrorCode::InternalError,
            "missing service endpoint in verified op",
        )
    })?;

    Ok(serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1"
        ],
        "id": did,
        "alsoKnownAs": &verified.also_known_as,
        "verificationMethod": [{
            "id": format!("{did}#atproto"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": public_key_multibase
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": service_endpoint
        }]
    }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state_with_plc_url;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use rand_core::{OsRng, RngCore};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt; // for `.oneshot()`
    use uuid::Uuid;
    use wiremock::{
        matchers::{method, path_regex},
        Mock, MockServer, ResponseTemplate,
    };

    // ── Test setup helpers ────────────────────────────────────────────────────

    struct TestSetup {
        session_token: String,
        account_id: String,
        handle: String,
    }

    /// Generate a signed genesis op verifiable by the returned rotation_key_public.
    ///
    /// Uses the same keypair for both rotation and signing: kp signs the op,
    /// AND kp.key_id appears at rotationKeys[0]. Calling verify_genesis_op with
    /// kp.key_id will succeed.
    fn make_signed_op(handle: &str, public_url: &str) -> (String, serde_json::Value) {
        use crypto::{build_did_plc_genesis_op, generate_p256_keypair};
        let kp = generate_p256_keypair().expect("keypair");
        let private_bytes = *kp.private_key_bytes;
        let genesis_op = build_did_plc_genesis_op(
            &kp.key_id, // rotation key — placed at rotationKeys[0]
            &kp.key_id, // signing key (same) — kp's private key performs the signing
            &private_bytes,
            handle,
            public_url,
        )
        .expect("genesis op");
        let signed_op_value: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).expect("valid JSON");
        (kp.key_id.0, signed_op_value)
    }

    /// Insert prerequisite rows for a DID-creation test.
    ///
    /// Inserts: claim_code, pending_account, device, pending_session.
    /// No relay signing key needed for MM-90.
    async fn insert_test_data(db: &sqlx::SqlitePool) -> TestSetup {
        let claim_code = format!("TEST-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(&claim_code)
        .execute(db)
        .await
        .expect("insert claim_code");

        let account_id = Uuid::new_v4().to_string();
        let handle = format!("alice{}.example.com", &account_id[..8]);
        sqlx::query(
            "INSERT INTO pending_accounts \
             (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, ?, ?, 'free', ?, datetime('now'))",
        )
        .bind(&account_id)
        .bind(format!("alice{}@example.com", &account_id[..8]))
        .bind(&handle)
        .bind(&claim_code)
        .execute(db)
        .await
        .expect("insert pending_account");

        let device_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices \
             (id, account_id, platform, public_key, device_token_hash, created_at, last_seen_at) \
             VALUES (?, ?, 'ios', 'test_pubkey', 'test_device_hash', datetime('now'), datetime('now'))",
        )
        .bind(&device_id)
        .bind(&account_id)
        .execute(db)
        .await
        .expect("insert device");

        let mut token_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        let session_token = URL_SAFE_NO_PAD.encode(token_bytes);
        let token_hash: String = Sha256::digest(token_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        sqlx::query(
            "INSERT INTO pending_sessions \
             (id, account_id, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '+1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(&device_id)
        .bind(&token_hash)
        .execute(db)
        .await
        .expect("insert pending_session");

        TestSetup {
            session_token,
            account_id,
            handle,
        }
    }

    /// Create an AppState with plc_directory_url pointing to the mock server.
    /// No signing_key_master_key needed for MM-90.
    async fn test_state_for_did(plc_url: String) -> AppState {
        test_state_with_plc_url(plc_url).await
    }

    /// Build a POST /v1/dids request with the MM-90 body shape.
    fn create_did_request(
        session_token: &str,
        rotation_key_public: &str,
        signed_creation_op: &serde_json::Value,
    ) -> Request<Body> {
        let body = serde_json::json!({
            "rotationKeyPublic": rotation_key_public,
            "signedCreationOp": signed_creation_op,
        });
        Request::builder()
            .method("POST")
            .uri("/v1/dids")
            .header("Authorization", format!("Bearer {session_token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    // ── AC2.1/2.2/2.3/2.4/2.5/4.1/4.2/4.3: Happy path ───────────────────────

    /// MM-90.AC2.1, AC2.2, AC2.3, AC2.4, AC2.5, AC4.1, AC4.2, AC4.3:
    /// Valid request promotes account and returns full DID response.
    #[tokio::test]
    async fn happy_path_promotes_account_and_returns_did() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:[a-z2-7]+$"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .named("plc.directory genesis op")
            .mount(&mock_server)
            .await;

        let state = test_state_for_did(mock_server.uri()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let (rotation_key_public, signed_op) =
            make_signed_op(&setup.handle, &state.config.public_url);

        let app = crate::app::app(state.clone());
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &rotation_key_public,
                &signed_op,
            ))
            .await
            .unwrap();

        // AC2.1: 200 OK with { did, did_document, status: "active" }
        assert_eq!(response.status(), StatusCode::OK, "expected 200 OK");
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(
            body["did"]
                .as_str()
                .map(|d| d.starts_with("did:plc:"))
                .unwrap_or(false),
            "did should start with did:plc:"
        );
        assert_eq!(body["status"], "active", "status should be active");
        assert!(
            body["did_document"].is_object(),
            "did_document should be a JSON object"
        );

        let did = body["did"].as_str().unwrap();
        let doc = &body["did_document"];

        // AC4.2: alsoKnownAs contains at://{handle}
        let also_known_as = doc["alsoKnownAs"].as_array().expect("alsoKnownAs is array");
        assert!(
            also_known_as
                .iter()
                .any(|e| e.as_str() == Some(&format!("at://{}", setup.handle))),
            "alsoKnownAs should contain at://{}",
            setup.handle
        );

        // AC4.1: verificationMethod has publicKeyMultibase starting with "z"
        let vm = &doc["verificationMethod"][0];
        let pkm = vm["publicKeyMultibase"]
            .as_str()
            .expect("publicKeyMultibase is string");
        assert!(
            pkm.starts_with('z'),
            "publicKeyMultibase should start with 'z'"
        );

        // AC4.3: service entry has serviceEndpoint matching public_url
        let service = &doc["service"][0];
        assert_eq!(
            service["serviceEndpoint"].as_str(),
            Some("https://test.example.com"),
            "serviceEndpoint should match config.public_url"
        );

        // AC2.2: accounts row with correct did, email; password_hash IS NULL
        let row: Option<(String, Option<String>)> =
            sqlx::query_as("SELECT email, password_hash FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_optional(&db)
                .await
                .unwrap();
        let (email, password_hash) = row.expect("accounts row should exist");
        assert!(email.contains("alice"), "email should match test account");
        assert!(
            password_hash.is_none(),
            "password_hash should be NULL for device-provisioned account"
        );

        // AC2.3: did_documents row exists with non-empty document
        let doc_row: Option<(String,)> =
            sqlx::query_as("SELECT document FROM did_documents WHERE did = ?")
                .bind(did)
                .fetch_optional(&db)
                .await
                .unwrap();
        let (document,) = doc_row.expect("did_documents row should exist");
        assert!(!document.is_empty(), "document should be non-empty");

        // AC2.4: handles row links handle to did
        let handle_row: Option<(String,)> =
            sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
                .bind(&setup.handle)
                .fetch_optional(&db)
                .await
                .unwrap();
        let (handle_did,) = handle_row.expect("handles row should exist");
        assert_eq!(handle_did, did, "handles.did should match response did");

        // AC2.5: pending_accounts and pending_sessions deleted
        let pending_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pending_accounts WHERE id = ?")
                .bind(&setup.account_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(pending_count, 0, "pending_accounts row should be deleted");

        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pending_sessions WHERE account_id = ?")
                .bind(&setup.account_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(session_count, 0, "pending_sessions rows should be deleted");

        // AC2.5: devices deleted
        let device_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE account_id = ?")
                .bind(&setup.account_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(device_count, 0, "devices rows should be deleted");
    }

    // ── AC2.6: Retry path skips plc.directory ─────────────────────────────────

    /// MM-90.AC2.6: When pending_did already set, plc.directory is not called.
    #[tokio::test]
    async fn retry_with_pending_did_skips_plc_directory() {
        let mock_server = MockServer::start().await;
        // plc.directory must NOT be called on retry
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .named("plc.directory should not be called")
            .mount(&mock_server)
            .await;

        let state = test_state_for_did(mock_server.uri()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let (rotation_key_public, signed_op) =
            make_signed_op(&setup.handle, &state.config.public_url);

        // Derive the DID from the signed op to pre-store it.
        let signed_op_str = serde_json::to_string(&signed_op).unwrap();
        let verified = crypto::verify_genesis_op(
            &signed_op_str,
            &crypto::DidKeyUri(rotation_key_public.clone()),
        )
        .expect("verify should succeed");

        // Pre-set pending_did to simulate a retry scenario.
        sqlx::query("UPDATE pending_accounts SET pending_did = ? WHERE id = ?")
            .bind(&verified.did)
            .bind(&setup.account_id)
            .execute(&db)
            .await
            .expect("pre-store pending_did");

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &rotation_key_public,
                &signed_op,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "retry should return 200");
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            body["did"].as_str(),
            Some(verified.did.as_str()),
            "did should match pre-computed DID"
        );
        // wiremock verifies expect(0) on mock_server drop
    }

    // ── Test Gap G2: Retry with mismatched pending_did ────────────────────────

    /// Retry path with a DIFFERENT signedCreationOp (tampered retry) should
    /// derive a different DID and return 500 INTERNAL_ERROR because the
    /// pre-stored pending_did doesn't match.
    #[tokio::test]
    async fn retry_with_mismatched_pending_did_returns_500() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let (rotation_key_public, signed_op) =
            make_signed_op(&setup.handle, &state.config.public_url);

        // Pre-set pending_did to a DIFFERENT value (tampered/corrupted retry).
        let tampered_did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        sqlx::query("UPDATE pending_accounts SET pending_did = ? WHERE id = ?")
            .bind(&tampered_did)
            .bind(&setup.account_id)
            .execute(&db)
            .await
            .expect("pre-store tampered pending_did");

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &rotation_key_public,
                &signed_op,
            ))
            .await
            .unwrap();

        // Derived DID != tampered pending_did → 500 INTERNAL_ERROR
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "expected 500"
        );
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["error"]["code"], "INTERNAL_ERROR");
    }

    // ── AC3.1: Invalid signature ───────────────────────────────────────────────

    /// MM-90.AC3.1: Corrupted signature returns 400 INVALID_CLAIM.
    #[tokio::test]
    async fn invalid_signature_returns_400() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let (rotation_key_public, mut signed_op) =
            make_signed_op(&setup.handle, &state.config.public_url);

        // Corrupt the sig: decode, flip one byte, re-encode.
        let sig_str = signed_op["sig"].as_str().unwrap().to_string();
        let mut sig_bytes = URL_SAFE_NO_PAD.decode(&sig_str).unwrap();
        sig_bytes[0] ^= 0xff;
        signed_op["sig"] = serde_json::json!(URL_SAFE_NO_PAD.encode(&sig_bytes));

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &rotation_key_public,
                &signed_op,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "expected 400");
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["error"]["code"], "INVALID_CLAIM");
    }

    // ── AC3.2: Wrong handle in alsoKnownAs ────────────────────────────────────

    /// MM-90.AC3.2: alsoKnownAs mismatch returns 400 INVALID_CLAIM.
    #[tokio::test]
    async fn wrong_handle_in_op_returns_400() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        // Build op with a different handle — pending_accounts has setup.handle.
        let (rotation_key_public, signed_op) =
            make_signed_op("different.handle.com", &state.config.public_url);

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &rotation_key_public,
                &signed_op,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "expected 400");
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["error"]["code"], "INVALID_CLAIM");
    }

    // ── AC3.3: Wrong service endpoint ─────────────────────────────────────────

    /// MM-90.AC3.3: services.atproto_pds.endpoint mismatch returns 400 INVALID_CLAIM.
    #[tokio::test]
    async fn wrong_service_endpoint_returns_400() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        // Build op with wrong service endpoint.
        let (rotation_key_public, signed_op) =
            make_signed_op(&setup.handle, "https://wrong.example.com");

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &rotation_key_public,
                &signed_op,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "expected 400");
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["error"]["code"], "INVALID_CLAIM");
    }

    // ── AC3.4: rotationKeys[0] mismatch ───────────────────────────────────────

    /// MM-90.AC3.4: rotationKeys[0] in op != rotationKeyPublic in request body → 400 INVALID_CLAIM.
    ///
    /// To isolate semantic validation (not crypto failure): use kp_x as the signer
    /// (signature verifies with kp_x), but put kp_y at rotationKeys[0]. Send kp_x
    /// as rotationKeyPublic — verify passes (kp_x signed), but rotation_keys[0] == kp_y ≠ kp_x.
    #[tokio::test]
    async fn wrong_rotation_key_in_op_returns_400() {
        use crypto::{build_did_plc_genesis_op, generate_p256_keypair};

        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;

        let kp_x = generate_p256_keypair().expect("signer keypair");
        let kp_y = generate_p256_keypair().expect("rotation keypair");
        let x_private = *kp_x.private_key_bytes;

        // Build op: rotationKeys[0] = kp_y, signing key = kp_x (signs with kp_x).
        let genesis_op = build_did_plc_genesis_op(
            &kp_y.key_id, // rotationKeys[0] = kp_y
            &kp_x.key_id, // signing key = kp_x, signs with kp_x's private key
            &x_private,
            &setup.handle,
            &state.config.public_url,
        )
        .expect("genesis op");
        let signed_op: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).unwrap();

        // Send request with rotationKeyPublic = kp_x (not kp_y).
        // verify_genesis_op(op, kp_x) passes (kp_x signed it),
        // but rotation_keys[0] == kp_y ≠ kp_x → semantic validation fails.
        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &kp_x.key_id.0,
                &signed_op,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "expected 400");
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["error"]["code"], "INVALID_CLAIM");
    }

    // ── Test Gap G4: Malformed rotationKeyPublic format ────────────────────────

    /// rotationKeyPublic that doesn't start with "did:key:z" returns 400 INVALID_CLAIM,
    /// even with a valid session token.
    #[tokio::test]
    async fn invalid_rotation_key_format_returns_400() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;

        let request_body = serde_json::json!({
            "rotationKeyPublic": "not-a-did-key",
            "signedCreationOp": serde_json::json!({})
        });

        let request = Request::builder()
            .method("POST")
            .uri("/v1/dids")
            .header("Authorization", format!("Bearer {}", setup.session_token))
            .header("Content-Type", "application/json")
            .body(Body::from(request_body.to_string()))
            .unwrap();

        let app = crate::app::app(state);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "expected 400");
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["error"]["code"], "INVALID_CLAIM");
    }

    // ── AC3.5: Already promoted ────────────────────────────────────────────────

    /// MM-90.AC3.5: Account already promoted returns 409 DID_ALREADY_EXISTS.
    #[tokio::test]
    async fn already_promoted_account_returns_409() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let (rotation_key_public, signed_op) =
            make_signed_op(&setup.handle, &state.config.public_url);

        // Derive the DID and pre-insert an accounts row.
        let signed_op_str = serde_json::to_string(&signed_op).unwrap();
        let verified = crypto::verify_genesis_op(
            &signed_op_str,
            &crypto::DidKeyUri(rotation_key_public.clone()),
        )
        .unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'other@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .bind(&verified.did)
        .execute(&db)
        .await
        .expect("pre-insert promoted account");

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &rotation_key_public,
                &signed_op,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT, "expected 409");
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["error"]["code"], "DID_ALREADY_EXISTS");
    }

    // ── AC3.6: Missing auth ────────────────────────────────────────────────────

    /// MM-90.AC3.6: Missing Authorization header returns 401 UNAUTHORIZED.
    #[tokio::test]
    async fn missing_auth_returns_401() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let signed_op = serde_json::json!({});
        let request = Request::builder()
            .method("POST")
            .uri("/v1/dids")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "rotationKeyPublic": "did:key:z123",
                    "signedCreationOp": signed_op
                })
                .to_string(),
            ))
            .unwrap();

        let app = crate::app::app(state);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "expected 401");
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["error"]["code"], "UNAUTHORIZED");
    }

    // ── AC3.7: plc.directory error ────────────────────────────────────────────

    /// MM-90.AC3.7: plc.directory non-2xx returns 502 PLC_DIRECTORY_ERROR.
    #[tokio::test]
    async fn plc_directory_error_returns_502() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:[a-z2-7]+$"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .named("plc.directory returns 500")
            .mount(&mock_server)
            .await;

        let state = test_state_for_did(mock_server.uri()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let (rotation_key_public, signed_op) =
            make_signed_op(&setup.handle, &state.config.public_url);

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &rotation_key_public,
                &signed_op,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "expected 502");
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["error"]["code"], "PLC_DIRECTORY_ERROR");
    }
}
