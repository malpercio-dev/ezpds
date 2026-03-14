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
    let verified =
        crypto::verify_genesis_op(&signed_op_str, &rotation_key).map_err(|e| {
            tracing::warn!(error = %e, "genesis op verification failed");
            ApiError::new(ErrorCode::InvalidClaim, format!("invalid signed genesis op: {e}"))
        })?;

    // Step 6: Semantic validation — ensure op fields match account and server config.
    if verified.rotation_keys.first().map(String::as_str) != Some(&payload.rotation_key_public) {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "rotationKeys[0] in op does not match rotationKeyPublic",
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
        sqlx::query("UPDATE pending_accounts SET pending_did = ? WHERE id = ?")
            .bind(did)
            .bind(&session.account_id)
            .execute(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to pre-store pending_did");
                ApiError::new(ErrorCode::InternalError, "failed to store pending DID")
            })?;
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
                ApiError::new(ErrorCode::PlcDirectoryError, "failed to contact plc.directory")
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
    .inspect_err(|e| tracing::error!(error = %e, "failed to insert account"))
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to create account"))?;

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
            ApiError::new(ErrorCode::InternalError, "atproto verification method not found in op")
        })?;
    let public_key_multibase = atproto_did_key.strip_prefix("did:key:").ok_or_else(|| {
        ApiError::new(ErrorCode::InternalError, "atproto key is not a did:key: URI")
    })?;

    let service_endpoint = verified.atproto_pds_endpoint.as_deref().unwrap_or_default();

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

    /// A test master key: 32 bytes of 0x01.
    const TEST_MASTER_KEY: [u8; 32] = [0x01u8; 32];

    /// All data needed to call POST /v1/dids in a test.
    struct TestSetup {
        session_token: String,
        signing_key_id: String,
        rotation_key_id: String,
        account_id: String,
        /// The handle stored in `pending_accounts`. Needed for AC2.10 to re-create
        /// a second pending account that derives the same DID (same keys + same handle).
        handle: String,
    }

    /// Insert all prerequisite rows for a DID-creation test.
    ///
    /// Inserts: relay_signing_key, pending_account (with claim code), device, pending_session.
    ///
    /// Pre-step: Read `crates/relay/src/routes/test_utils.rs` to see if helpers already
    /// exist for inserting claim codes, pending accounts, or pending sessions. Use them here
    /// if available. If not, use the raw SQL below.
    async fn insert_test_data(db: &sqlx::SqlitePool) -> TestSetup {
        use crypto::{encrypt_private_key, generate_p256_keypair};

        // Generate signing and rotation keypairs.
        let signing_kp = generate_p256_keypair().expect("signing keypair");
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");

        // Encrypt the signing private key with the test master key.
        let encrypted = encrypt_private_key(&signing_kp.private_key_bytes, &TEST_MASTER_KEY)
            .expect("encrypt key");

        // Insert relay_signing_key.
        sqlx::query(
            "INSERT INTO relay_signing_keys \
             (id, algorithm, public_key, private_key_encrypted, created_at) \
             VALUES (?, 'p256', ?, ?, datetime('now'))",
        )
        .bind(&signing_kp.key_id.0)
        .bind(&signing_kp.public_key)
        .bind(&encrypted)
        .execute(db)
        .await
        .expect("insert relay_signing_key");

        // Insert a claim_code row (required FK for pending_accounts).
        let claim_code = format!("TEST-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(&claim_code)
        .execute(db)
        .await
        .expect("insert claim_code");

        // Insert pending_account.
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

        // Insert a device (required FK for pending_sessions).
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

        // Generate pending session token.
        let mut token_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        let session_token = URL_SAFE_NO_PAD.encode(token_bytes);
        let token_hash: String = Sha256::digest(token_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        // Insert pending_session.
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
            signing_key_id: signing_kp.key_id.0,
            rotation_key_id: rotation_kp.key_id.0,
            account_id,
            handle,
        }
    }

    /// Create an AppState with TEST_MASTER_KEY set and plc_directory_url pointing to the mock.
    async fn test_state_for_did(plc_url: String) -> AppState {
        use common::Sensitive;
        use std::sync::Arc;
        use std::time::Duration;
        use zeroize::Zeroizing;

        let base = test_state_with_plc_url(plc_url).await;
        let mut config = (*base.config).clone();
        config.signing_key_master_key = Some(Sensitive(Zeroizing::new(TEST_MASTER_KEY)));

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("test http client");

        AppState {
            config: Arc::new(config),
            db: base.db,
            http_client,
        }
    }

    /// Build a POST /v1/dids request with the given session token and body.
    fn create_did_request(
        session_token: &str,
        signing_key: &str,
        rotation_key: &str,
    ) -> Request<Body> {
        let body = serde_json::json!({
            "signingKey": signing_key,
            "rotationKey": rotation_key,
        });
        Request::builder()
            .method("POST")
            .uri("/v1/dids")
            .header("Authorization", format!("Bearer {session_token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    // ── AC2.1: Valid request returns 200 with { did, status: "active" } ───────

    /// MM-89.AC2.1, AC2.2, AC2.3, AC2.4, AC2.5: Happy path — full promotion
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

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &setup.signing_key_id,
                &setup.rotation_key_id,
            ))
            .await
            .unwrap();

        // AC2.1: 200 OK with did + status
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let did = body["did"].as_str().expect("did field");
        assert!(
            did.starts_with("did:plc:"),
            "did should start with did:plc:"
        );
        assert_eq!(body["status"], "active");

        // AC2.2: accounts row with null password_hash
        let (stored_email, stored_hash): (String, Option<String>) =
            sqlx::query_as("SELECT email, password_hash FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .expect("accounts row should exist");
        assert!(stored_hash.is_none(), "password_hash should be NULL");
        assert!(stored_email.contains("alice"), "email should be set");

        // AC2.3: did_documents row with non-empty document
        let (doc,): (String,) = sqlx::query_as("SELECT document FROM did_documents WHERE did = ?")
            .bind(did)
            .fetch_one(&db)
            .await
            .expect("did_documents row should exist");
        assert!(!doc.is_empty(), "did_document should be non-empty");

        // AC2.4: handles row
        let (handle_did,): (String,) = sqlx::query_as("SELECT did FROM handles WHERE did = ?")
            .bind(did)
            .fetch_one(&db)
            .await
            .expect("handles row should exist");
        assert_eq!(handle_did, did);

        // AC2.5: pending_accounts and pending_sessions deleted
        let pending_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pending_accounts WHERE id = ?")
                .bind(&setup.account_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(pending_count, 0, "pending_account should be deleted");

        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pending_sessions WHERE account_id = ?")
                .bind(&setup.account_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(session_count, 0, "pending_sessions should be deleted");
    }

    /// MM-89.AC2.6: Retry path — pending_did pre-set, plc.directory NOT called
    #[tokio::test]
    async fn retry_with_pending_did_skips_plc_directory() {
        let mock_server = MockServer::start().await;
        // Expect zero calls to plc.directory on a retry.
        // MockServer auto-verifies .expect(0) on drop — if plc.directory is called,
        // the mock panics and the test fails.
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:.*$"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0) // Must NOT be called
            .named("plc.directory (should not be called on retry)")
            .mount(&mock_server)
            .await;

        let state = test_state_for_did(mock_server.uri()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;

        // Derive the DID from the same inputs that the handler will use.
        // This ensures the pre-stored pending_did matches what the handler will derive.
        let rotation_key = crypto::DidKeyUri(setup.rotation_key_id.clone());
        let signing_key = crypto::DidKeyUri(setup.signing_key_id.clone());

        // Look up the private key (same as handler does).
        let (private_key_encrypted,): (String,) =
            sqlx::query_as("SELECT private_key_encrypted FROM relay_signing_keys WHERE id = ?")
                .bind(&setup.signing_key_id)
                .fetch_one(&db)
                .await
                .expect("signing key must exist");

        let private_key_bytes =
            crypto::decrypt_private_key(&private_key_encrypted, &TEST_MASTER_KEY)
                .expect("decrypt key");

        // Build the genesis op to get the DID (same as handler does).
        let genesis = crypto::build_did_plc_genesis_op(
            &rotation_key,
            &signing_key,
            &private_key_bytes,
            &setup.handle,
            &state.config.public_url,
        )
        .expect("build genesis");

        let derived_did = genesis.did.clone();

        // Simulate a partial-failure retry: pre-store the same DID that will be derived.
        sqlx::query("UPDATE pending_accounts SET pending_did = ? WHERE id = ?")
            .bind(&derived_did)
            .bind(&setup.account_id)
            .execute(&db)
            .await
            .expect("pre-store pending_did");

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &setup.signing_key_id,
                &setup.rotation_key_id,
            ))
            .await
            .unwrap();

        // The route detects the pre-stored DID, verifies it matches the derived DID,
        // skips plc.directory (enforced by .expect(0) above), and proceeds
        // to promote the account using the crypto-derived DID. Returns 200.
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "retry should succeed with 200"
        );
    }

    /// MM-89.AC2.7: Missing Authorization header returns 401
    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let state = test_state_with_plc_url("https://plc.directory".to_string()).await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/dids")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"signingKey":"did:key:z...","rotationKey":"did:key:z..."}"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// MM-89.AC2.8: Expired session token returns 401
    #[tokio::test]
    async fn expired_session_returns_401() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;

        // Manually expire the session.
        sqlx::query("UPDATE pending_sessions SET expires_at = datetime('now', '-1 hour') WHERE account_id = ?")
            .bind(&setup.account_id)
            .execute(&db)
            .await
            .expect("expire session");

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &setup.signing_key_id,
                &setup.rotation_key_id,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// MM-89.AC2.9: signingKey not in relay_signing_keys returns 404
    #[tokio::test]
    async fn unknown_signing_key_returns_404() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                "did:key:zNONEXISTENT", // Not in relay_signing_keys
                &setup.rotation_key_id,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// MM-89.AC2.10: Account already promoted returns 409 DID_ALREADY_EXISTS
    ///
    /// The DID is deterministic from (rotation_key, signing_key, handle, service_endpoint).
    /// To reliably trigger 409, we:
    ///   1. First call promotes setup's account (deletes pending_accounts + pending_sessions).
    ///   2. Create a NEW pending account+session using the SAME signing key, rotation key,
    ///      and handle as setup. Same inputs → same crypto-derived DID.
    ///   3. Second call: handler derives the same DID, finds the existing `accounts` row,
    ///      returns 409 DID_ALREADY_EXISTS.
    #[tokio::test]
    async fn already_promoted_account_returns_409() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:.*$"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1) // Only first call should hit plc.directory
            .mount(&mock_server)
            .await;

        let state = test_state_for_did(mock_server.uri()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let signing_kp = crypto::generate_p256_keypair().expect("signing keypair");
        let encrypted =
            crypto::encrypt_private_key(&signing_kp.private_key_bytes, &TEST_MASTER_KEY)
                .expect("encrypt key");
        sqlx::query(
            "INSERT INTO relay_signing_keys \
             (id, algorithm, public_key, private_key_encrypted, created_at) \
             VALUES (?, 'p256', ?, ?, datetime('now'))",
        )
        .bind(&signing_kp.key_id.0)
        .bind(&signing_kp.public_key)
        .bind(&encrypted)
        .execute(&db)
        .await
        .expect("insert second signing key");

        // First call: promotes setup's account (deletes pending_accounts + pending_sessions).
        let app1 = crate::app::app(state);
        let resp1 = app1
            .oneshot(create_did_request(
                &setup.session_token,
                &setup.signing_key_id,
                &setup.rotation_key_id,
            ))
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::OK, "first call should succeed");

        // setup's pending_accounts row is now deleted. Create a NEW pending account
        // with the SAME handle and signing key. Since pending_accounts.handle has no
        // unique constraint, we can reuse setup.handle here.
        let claim_code2 = format!("TEST-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(&claim_code2)
        .execute(&db)
        .await
        .expect("claim_code2");

        let account_id2 = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO pending_accounts \
             (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, ?, ?, 'free', ?, datetime('now'))",
        )
        .bind(&account_id2)
        .bind(format!("retry{}@example.com", &account_id2[..8]))
        .bind(&setup.handle) // same handle → same DID with same signing/rotation keys
        .bind(&claim_code2)
        .execute(&db)
        .await
        .expect("pending_account2");

        let device_id2 = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices \
             (id, account_id, platform, public_key, device_token_hash, created_at, last_seen_at) \
             VALUES (?, ?, 'ios', 'retry_pubkey', 'retry_device_hash', datetime('now'), datetime('now'))",
        )
        .bind(&device_id2)
        .bind(&account_id2)
        .execute(&db)
        .await
        .expect("device2");

        let mut token_bytes2 = [0u8; 32];
        OsRng.fill_bytes(&mut token_bytes2);
        let session_token2 = URL_SAFE_NO_PAD.encode(token_bytes2);
        let token_hash2: String = Sha256::digest(token_bytes2)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        sqlx::query(
            "INSERT INTO pending_sessions \
             (id, account_id, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '+1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id2)
        .bind(&device_id2)
        .bind(&token_hash2)
        .execute(&db)
        .await
        .expect("session2");

        // Second call: same signing_key + rotation_key + handle → same DID.
        // accounts table already has this DID → handler returns 409.
        let state2 = test_state_for_did(mock_server.uri()).await;
        let app2 = crate::app::app(AppState {
            config: state2.config,
            db: db.clone(),
            http_client: state2.http_client,
        });
        let resp2 = app2
            .oneshot(create_did_request(
                &session_token2,
                &setup.signing_key_id,  // same signing key
                &setup.rotation_key_id, // same rotation key
            ))
            .await
            .unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::CONFLICT,
            "should return 409 DID_ALREADY_EXISTS"
        );
    }

    /// MM-89.AC2.11: plc.directory returns non-2xx → 502 PLC_DIRECTORY_ERROR
    #[tokio::test]
    async fn plc_directory_error_returns_502() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:.*$"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let state = test_state_for_did(mock_server.uri()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &setup.signing_key_id,
                &setup.rotation_key_id,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }
}
