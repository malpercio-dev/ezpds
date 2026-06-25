// pattern: Imperative Shell
//
// POST /v1/dids — Device-signed DID ceremony and account promotion
//
// Inputs:
//   - Authorization: Bearer <pending_session_token>
//   - JSON body: {
//       "rotationKeyPublic": "did:key:z...",
//       "signedCreationOp": { ...genesis op fields... },
//       "password": "<plaintext>"  // required; stored as argon2id PHC string
//     }
//
// Processing steps:
//   1. require_pending_session → PendingSessionInfo { account_id, device_id }
//   2. SELECT handle, pending_did, email, pending_share_{1,2,3} FROM pending_accounts WHERE id = account_id
//   2a. Reject if password is empty (400 INVALID_CLAIM) — argon2 hashes "" so guard is explicit
//   3. Validate rotationKeyPublic starts with "did:key:z" → DidKeyUri
//   4. serde_json::to_string(signedCreationOp) → signed_op_str
//   5. crypto::verify_genesis_op(signed_op_str, rotation_key) → VerifiedGenesisOp
//   6. Semantic validation:
//        verified.rotation_keys[0] == rotationKeyPublic
//        verified.also_known_as[0] == "at://{handle}"
//        verified.atproto_pds_endpoint  == config.public_url
//   7. If pending_did IS NULL: generate 3 Shamir shares; UPDATE pending_accounts SET
//        pending_did = verified.did, pending_share_{1,2,3} = <base32 shares>
//      If pending_did IS NOT NULL: verify match, reuse stored shares, set skip_plc = true
//   8. SELECT EXISTS(SELECT 1 FROM accounts WHERE did = verified.did) → 409 if true
//   9. If !skip_plc: POST {plc_directory_url}/{did} with signed_op_str
//  10. build_did_document(&verified) → serde_json::Value
//  11. Generate session token: 32 random bytes → base64url (returned) + SHA-256 hex (stored)
//  12. Hash password with argon2id → password_hash
//  13. Atomic transaction:
//        INSERT accounts (did, email, password_hash=argon2id(password), recovery_share=pending_share_2)
//        INSERT did_documents (did, document)
//        INSERT sessions (id, did, device_id=NULL, token_hash, expires_at=+1 year)
//        DELETE pending_sessions WHERE account_id = ?
//        DELETE devices WHERE account_id = ?
//        DELETE pending_accounts WHERE id = ?
//  14. Return { "did", "did_document", "status": "active", "session_token",
//               "shamir_share_1": <base32>, "shamir_share_3": <base32> }
//
// Note: handles are NOT inserted here. Handle creation is the caller's responsibility
// via POST /v1/handles, which validates format and optionally creates DNS records.
//
// Outputs (success):  200 { "did": "...", "did_document": {...}, "status": "active",
//                          "session_token": "...", "shamir_share_1": "...", "shamir_share_3": "..." }
// Outputs (error):    400 INVALID_CLAIM, 401 UNAUTHORIZED, 409 DID_ALREADY_EXISTS,
//                     502 PLC_DIRECTORY_ERROR, 500 INTERNAL_ERROR

use axum::{extract::State, http::HeaderMap, Json};
use data_encoding::BASE32_NOPAD;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::app::AppState;
use crate::auth::password::hash_password;
use crate::db::is_unique_violation;
use crate::routes::auth::require_pending_session;
use crate::routes::token::generate_token;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidRequest {
    pub rotation_key_public: String,
    pub signed_creation_op: serde_json::Value,
    /// Initial password, stored as an argon2id PHC string.
    /// Enables `createSession` for this account after promotion.
    pub password: String,
}

#[derive(Serialize)]
pub struct CreateDidResponse {
    pub did: String,
    pub did_document: serde_json::Value,
    pub status: &'static str,
    pub session_token: String,
    /// Share 1 of 3 — for storage in the user's iCloud Keychain.
    /// Base32-encoded (RFC 4648, no padding), 52 uppercase chars.
    pub shamir_share_1: String,
    /// Share 3 of 3 — for user-directed manual backup.
    /// Base32-encoded (RFC 4648, no padding), 52 uppercase chars.
    pub shamir_share_3: String,
}

pub async fn create_did_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateDidRequest>,
) -> Result<Json<CreateDidResponse>, ApiError> {
    // Phase 1: Authenticate and load pending account.
    let session = require_pending_session(&headers, &state.db).await?;
    let pending = load_pending_account(&state.db, &session.account_id).await?;

    // The per-account repo signing key must have been issued (GET /v1/repo-signing-key)
    // before the ceremony, because the op publishes it as #atproto and the relay signs
    // repo commits with the matching private key.
    let repo_key = crate::db::repo_keys::get_pending_repo_key(&state.db, &session.account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to load pending repo signing key");
            ApiError::new(ErrorCode::InternalError, "failed to load signing key")
        })?
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidClaim,
                "repo signing key not provisioned; call GET /v1/repo-signing-key before creating the DID",
            )
        })?;

    // Guard: reject empty passwords before doing any expensive work.
    // argon2 happily hashes "" — this ensures the relay never stores a zero-length password.
    if payload.password.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "password must not be empty",
        ));
    }

    // Phase 2: Verify the genesis op and validate it against account + server config.
    let (verified, signed_op_str) =
        verify_and_validate_genesis_op(&payload, &pending.handle, &state.config.public_url)?;
    let did = &verified.did;

    // The op must publish the issued per-account key as its #atproto verification method.
    // A mismatch means the relay could not sign this repo's commits, so reject it.
    if verified
        .verification_methods
        .get("atproto")
        .map(String::as_str)
        != Some(repo_key.key_id.as_str())
    {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "op verificationMethods.atproto does not match the issued repo signing key",
        ));
    }

    // Build the (empty) genesis repo in memory, signed with the per-account key, so its
    // blocks are persisted atomically inside the promotion transaction below. Doing this
    // before the plc.directory call means a build failure aborts the ceremony cleanly,
    // with no orphaned PLC registration and no account-without-a-repo.
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
    let genesis_private = crypto::decrypt_private_key(&repo_key.private_key_encrypted, master_key)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to decrypt repo signing key for genesis");
            ApiError::new(ErrorCode::InternalError, "failed to prepare genesis repo")
        })?;
    let genesis_signer = repo_engine::CommitSigner::from_bytes(&genesis_private).map_err(|e| {
        tracing::error!(error = %e, "invalid repo signing key for genesis");
        ApiError::new(ErrorCode::InternalError, "failed to prepare genesis repo")
    })?;
    let (genesis_root, genesis_rev, genesis_blocks) =
        repo_engine::build_genesis_repo(did, &genesis_signer)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to build genesis repo");
                ApiError::new(ErrorCode::InternalError, "failed to build genesis repo")
            })?;
    let genesis_root_str = genesis_root.to_string();

    // Phase 3: Pre-store DID and Shamir shares for retry resilience, then POST to plc.directory.
    // Shares are generated once and stored alongside pending_did so that retries return the
    // same shares — preventing Share 2 from being orphaned in accounts.recovery_share.
    let (skip_plc, share1, share2, share3) =
        pre_store_did_and_shares(&state.db, &session.account_id, did, &pending).await?;
    check_already_promoted(&state.db, did).await?;
    if !skip_plc {
        post_to_plc_directory(
            &state.http_client,
            &state.config.plc_directory_url,
            did,
            &signed_op_str,
        )
        .await?;
    }

    // Phase 4: Build DID document, generate session, hash password, atomically promote.
    let did_document = build_did_document(&verified)?;
    let session_token = generate_token();
    let password_hash = hash_password(&payload.password)?;
    promote_account(
        &state.db,
        did,
        &pending.email,
        &session.account_id,
        &did_document,
        &session_token.hash,
        &share2,
        &password_hash,
        &repo_key,
        &genesis_root_str,
        &genesis_rev,
        &genesis_blocks,
    )
    .await?;

    Ok(Json(CreateDidResponse {
        did: did.clone(),
        did_document,
        status: "active",
        session_token: session_token.plaintext,
        shamir_share_1: share1,
        shamir_share_3: share3,
    }))
}

// ── Private helpers ───────────────────────────────────────────────────────────

// ── Phase helpers ─────────────────────────────────────────────────────────────

struct PendingAccount {
    handle: String,
    pending_did: Option<String>,
    email: String,
    pending_share_1: Option<String>,
    pending_share_2: Option<String>,
    pending_share_3: Option<String>,
}

/// Load pending account details (Step 2).
async fn load_pending_account(
    db: &sqlx::SqlitePool,
    account_id: &str,
) -> Result<PendingAccount, ApiError> {
    let row: (
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT handle, pending_did, email, pending_share_1, pending_share_2, pending_share_3 \
             FROM pending_accounts WHERE id = ?",
    )
    .bind(account_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to query pending account");
        ApiError::new(ErrorCode::InternalError, "failed to load account")
    })?
    .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized, "account not found"))?;
    Ok(PendingAccount {
        handle: row.0,
        pending_did: row.1,
        email: row.2,
        pending_share_1: row.3,
        pending_share_2: row.4,
        pending_share_3: row.5,
    })
}

/// Validate the rotation key format, verify the genesis op signature, and check
/// that the op fields match the account handle and server config (Steps 3-6).
fn verify_and_validate_genesis_op(
    payload: &CreateDidRequest,
    handle: &str,
    public_url: &str,
) -> Result<(crypto::VerifiedGenesisOp, String), ApiError> {
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
    if verified.atproto_pds_endpoint.as_deref() != Some(public_url) {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "services.atproto_pds.endpoint in op does not match server public URL",
        ));
    }

    Ok((verified, signed_op_str))
}

/// Pre-store the DID and Shamir shares in pending_accounts for retry resilience (Step 7).
///
/// On first attempt: generates 3 Shamir shares, stores `pending_did` + all three shares
/// in a single UPDATE so they are available to any retry.
///
/// On retry (pending_did already set): reuses the stored shares and returns `skip_plc = true`
/// to skip the plc.directory call. This guarantees every attempt returns the same shares,
/// preventing Share 2 from being orphaned in accounts.recovery_share.
///
/// Returns `(skip_plc, share1, share2, share3)`.
async fn pre_store_did_and_shares(
    db: &sqlx::SqlitePool,
    account_id: &str,
    did: &str,
    pending: &PendingAccount,
) -> Result<(bool, String, String, String), ApiError> {
    if let Some(pre_stored_did) = &pending.pending_did {
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
        tracing::info!(did = %pre_stored_did, "retry detected: pending_did already set, reusing shares, skipping plc.directory");
        let s1 = pending.pending_share_1.clone().ok_or_else(|| {
            tracing::error!(
                "retry: pending_share_1 is NULL; shares were not stored on first attempt"
            );
            ApiError::new(
                ErrorCode::InternalError,
                "retry: missing shares from first attempt",
            )
        })?;
        let s2 = pending.pending_share_2.clone().ok_or_else(|| {
            tracing::error!(
                "retry: pending_share_2 is NULL; shares were not stored on first attempt"
            );
            ApiError::new(
                ErrorCode::InternalError,
                "retry: missing shares from first attempt",
            )
        })?;
        let s3 = pending.pending_share_3.clone().ok_or_else(|| {
            tracing::error!(
                "retry: pending_share_3 is NULL; shares were not stored on first attempt"
            );
            ApiError::new(
                ErrorCode::InternalError,
                "retry: missing shares from first attempt",
            )
        })?;
        return Ok((true, s1, s2, s3));
    }

    let (s1, s2, s3) = generate_recovery_shares()?;

    let result = sqlx::query(
        "UPDATE pending_accounts \
         SET pending_did = ?, pending_share_1 = ?, pending_share_2 = ?, pending_share_3 = ? \
         WHERE id = ?",
    )
    .bind(did)
    .bind(&s1)
    .bind(&s2)
    .bind(&s3)
    .bind(account_id)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to pre-store pending DID and shares");
        ApiError::new(ErrorCode::InternalError, "failed to store pending DID")
    })?;

    if result.rows_affected() == 0 {
        tracing::error!(account_id = %account_id, "pending account row vanished during DID pre-store");
        return Err(ApiError::new(
            ErrorCode::InternalError,
            "account no longer exists",
        ));
    }
    Ok((false, s1, s2, s3))
}

/// Check if the DID is already fully promoted (Step 8).
async fn check_already_promoted(db: &sqlx::SqlitePool, did: &str) -> Result<(), ApiError> {
    let already_promoted: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE did = ?)")
            .bind(did)
            .fetch_one(db)
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
    Ok(())
}

/// Generate a fresh 32-byte recovery secret, split it into 3 Shamir shares,
/// and return the shares base32-encoded as `(share1, share2, share3)`.
///
/// Share 1 → user's iCloud Keychain (returned to app).
/// Share 2 → relay DB custody (stored in accounts.recovery_share).
/// Share 3 → user-directed manual backup (returned to app).
///
/// Any 2 of the 3 shares can reconstruct the original secret.
fn generate_recovery_shares() -> Result<(String, String, String), ApiError> {
    let mut secret = Zeroizing::new([0u8; 32]);
    OsRng.try_fill_bytes(secret.as_mut()).map_err(|e| {
        tracing::error!(error = %e, "OS RNG unavailable during recovery share generation");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to generate recovery secret",
        )
    })?;

    let [s1, s2, s3] = crypto::split_secret(&secret).map_err(|e| {
        tracing::error!(error = %e, "shamir split failed");
        ApiError::new(ErrorCode::InternalError, "failed to split recovery secret")
    })?;

    // The raw 32-byte secret is cleared on drop via Zeroizing. The base32 String
    // outputs are plain heap allocations; String does not implement Zeroize.
    Ok((
        BASE32_NOPAD.encode(s1.data.as_ref()),
        BASE32_NOPAD.encode(s2.data.as_ref()),
        BASE32_NOPAD.encode(s3.data.as_ref()),
    ))
}

/// POST the signed genesis operation to plc.directory (Step 9).
async fn post_to_plc_directory(
    http_client: &reqwest::Client,
    plc_directory_url: &str,
    did: &str,
    signed_op_str: &str,
) -> Result<(), ApiError> {
    let plc_url = format!("{plc_directory_url}/{did}");
    let response = http_client
        .post(&plc_url)
        .body(signed_op_str.to_string())
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
    Ok(())
}

/// Atomically promote a pending account to a full account (Steps 10-13).
///
/// In a single transaction: INSERT accounts + did_documents + sessions,
/// then DELETE pending_sessions + devices + pending_accounts.
/// `recovery_share` is Share 2 of the Shamir split; stored for relay-side custody.
/// `password_hash` is the argon2id PHC string for the account's password set during the ceremony.
#[allow(clippy::too_many_arguments)]
async fn promote_account(
    db: &sqlx::SqlitePool,
    did: &str,
    email: &str,
    account_id: &str,
    did_document: &serde_json::Value,
    token_hash: &str,
    recovery_share: &str,
    password_hash: &str,
    repo_key: &crate::db::repo_keys::RepoSigningKey,
    genesis_root: &str,
    genesis_rev: &str,
    genesis_blocks: &[(repo_engine::Cid, Vec<u8>)],
) -> Result<(), ApiError> {
    let did_document_str = serde_json::to_string(did_document).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize DID document");
        ApiError::new(ErrorCode::InternalError, "failed to serialize DID document")
    })?;
    let session_id = uuid::Uuid::new_v4().to_string();

    let mut tx = db
        .begin()
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to begin promotion transaction"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to begin transaction"))?;

    sqlx::query(
        "INSERT INTO accounts \
         (did, email, password_hash, recovery_share, repo_root_cid, repo_rev, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
    )
    .bind(did)
    .bind(email)
    .bind(password_hash)
    .bind(recovery_share)
    .bind(genesis_root)
    .bind(genesis_rev)
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

    sqlx::query(
        "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
         VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
    )
    .bind(&session_id)
    .bind(did)
    .bind(token_hash)
    .execute(&mut *tx)
    .await
    .inspect_err(|e| tracing::error!(error = %e, "failed to insert session"))
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to create session"))?;

    // Move the per-account repo signing key from the pending account into signing_keys
    // (DID-keyed), atomically with promotion. The relay loads it to sign repo commits.
    crate::db::repo_keys::insert_did_signing_key(&mut *tx, did, repo_key)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to insert repo signing key"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store signing key"))?;

    // Persist the genesis repo blocks (built in memory before the PLC call) in the same
    // transaction, so account + signing key + a complete repo all commit together.
    for (cid, bytes) in genesis_blocks {
        sqlx::query(
            "INSERT INTO blocks (cid, account_did, bytes) VALUES (?, ?, ?) \
             ON CONFLICT(cid) DO NOTHING",
        )
        .bind(cid.to_string())
        .bind(did)
        .bind(bytes.as_slice())
        .execute(&mut *tx)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to insert genesis block"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store genesis repo"))?;
    }

    sqlx::query("DELETE FROM pending_sessions WHERE account_id = ?")
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to delete pending sessions"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to clean up sessions"))?;

    sqlx::query("DELETE FROM devices WHERE account_id = ?")
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to delete devices"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to clean up devices"))?;

    sqlx::query("DELETE FROM pending_accounts WHERE id = ?")
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to delete pending account"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to clean up account"))?;

    tx.commit()
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to commit promotion transaction"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to commit transaction"))?;

    Ok(())
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
    use crate::routes::token::generate_token;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
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
        /// did:key of the per-account repo signing key issued by GET /v1/repo-signing-key.
        /// The genesis op must publish this as its #atproto verification method.
        repo_signing_key_id: String,
    }

    /// Generate a signed genesis op verifiable by the returned rotation_key_public.
    ///
    /// Uses the same keypair for both rotation and signing: kp signs the op,
    /// AND kp.key_id appears at rotationKeys[0]. Calling verify_genesis_op with
    /// kp.key_id will succeed.
    fn make_signed_op(
        handle: &str,
        public_url: &str,
        atproto_key_did: &str,
    ) -> (String, serde_json::Value) {
        use crypto::{build_did_plc_genesis_op, generate_p256_keypair, DidKeyUri};
        // The device/rotation key signs the op; the per-account key (issued by the relay)
        // is published as rotationKeys[1] + verificationMethods.atproto.
        let device = generate_p256_keypair().expect("device keypair");
        let device_private = *device.private_key_bytes;
        let genesis_op = build_did_plc_genesis_op(
            &device.key_id,                          // rotationKeys[0] — signs the op
            &DidKeyUri(atproto_key_did.to_string()), // rotationKeys[1] + verificationMethods.atproto
            &device_private,                         // op is signed by the device/rotation key
            handle,
            public_url,
        )
        .expect("genesis op");
        let signed_op_value: serde_json::Value =
            serde_json::from_str(&genesis_op.signed_op_json).expect("valid JSON");
        (device.key_id.0, signed_op_value)
    }

    /// Insert prerequisite rows for a DID-creation test.
    ///
    /// Inserts: claim_code, pending_account, device, pending_session.
    /// No relay signing key needed.
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

        let token = generate_token();
        sqlx::query(
            "INSERT INTO pending_sessions \
             (id, account_id, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '+1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(&device_id)
        .bind(&token.hash)
        .execute(db)
        .await
        .expect("insert pending_session");

        // Provision the per-account repo signing key (as GET /v1/repo-signing-key would),
        // encrypted with the same master key configured by test_state_for_did.
        let repo_kp = crypto::generate_p256_keypair().expect("repo keypair");
        let private_key_encrypted = crypto::encrypt_private_key(
            &repo_kp.private_key_bytes,
            &crate::routes::test_utils::test_master_key(),
        )
        .expect("encrypt repo key");
        crate::db::repo_keys::set_pending_repo_key(
            db,
            &account_id,
            &crate::db::repo_keys::RepoSigningKey {
                key_id: repo_kp.key_id.to_string(),
                public_key: repo_kp.public_key.clone(),
                private_key_encrypted,
            },
        )
        .await
        .expect("set pending repo key");

        TestSetup {
            session_token: token.plaintext,
            account_id,
            handle,
            repo_signing_key_id: repo_kp.key_id.0,
        }
    }

    /// Create an AppState with plc_directory_url pointing to the mock server and the
    /// signing-key master key configured (so genesis-repo signing works in tests).
    async fn test_state_for_did(plc_url: String) -> AppState {
        let base = test_state_with_plc_url(plc_url).await;
        let mut config = (*base.config).clone();
        config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(
            crate::routes::test_utils::test_master_key(),
        )));
        AppState {
            config: std::sync::Arc::new(config),
            ..base
        }
    }

    /// Build a POST /v1/dids request with a default test password.
    fn create_did_request(
        session_token: &str,
        rotation_key_public: &str,
        signed_creation_op: &serde_json::Value,
    ) -> Request<Body> {
        let body = serde_json::json!({
            "rotationKeyPublic": rotation_key_public,
            "signedCreationOp": signed_creation_op,
            "password": "test-password",
        });
        Request::builder()
            .method("POST")
            .uri("/v1/dids")
            .header("Authorization", format!("Bearer {session_token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    // ── Happy path ────────────────────────────────────────────────────────────

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
        let (rotation_key_public, signed_op) = make_signed_op(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

        let app = crate::app::app(state.clone());
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &rotation_key_public,
                &signed_op,
            ))
            .await
            .unwrap();

        // 200 OK with { did, did_document, status: "active", session_token }
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
        assert!(
            body["session_token"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "response should include a non-empty session_token"
        );

        // End-to-end: the issued per-account key was moved into signing_keys (DID-keyed),
        // and the genesis repo was created and its root recorded on the account.
        let did = body["did"].as_str().unwrap();
        let stored_key_id: Option<String> =
            sqlx::query_scalar("SELECT id FROM signing_keys WHERE did = ?")
                .bind(did)
                .fetch_optional(&db)
                .await
                .unwrap();
        assert_eq!(
            stored_key_id.as_deref(),
            Some(setup.repo_signing_key_id.as_str()),
            "issued per-account key must be stored in signing_keys for the DID"
        );
        let repo_root: Option<String> =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            repo_root
                .as_deref()
                .map(|r| r.starts_with("baf"))
                .unwrap_or(false),
            "genesis repo root CID must be recorded on the account"
        );
        // The genesis blocks must have been persisted atomically in the promotion tx.
        let block_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM blocks WHERE account_did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            block_count >= 2,
            "genesis blocks must be persisted (commit + MST node); got {block_count}"
        );

        // shamir_share_1 and shamir_share_3 must be present, 52-char BASE32 (A-Z, 2-7).
        // Missing fields or wrong alphabet here means a rename or swap would go undetected.
        let share1 = body["shamir_share_1"]
            .as_str()
            .expect("shamir_share_1 missing from response");
        let share3 = body["shamir_share_3"]
            .as_str()
            .expect("shamir_share_3 missing from response");
        assert_eq!(share1.len(), 52, "shamir_share_1 should be 52 chars");
        assert_eq!(share3.len(), 52, "shamir_share_3 should be 52 chars");
        assert!(
            share1.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')),
            "shamir_share_1 should be valid BASE32 (A-Z, 2-7), got: {share1}"
        );
        assert!(
            share3.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')),
            "shamir_share_3 should be valid BASE32 (A-Z, 2-7), got: {share3}"
        );

        let did = body["did"].as_str().unwrap();
        let doc = &body["did_document"];

        // alsoKnownAs contains at://{handle}
        let also_known_as = doc["alsoKnownAs"].as_array().expect("alsoKnownAs is array");
        assert!(
            also_known_as
                .iter()
                .any(|e| e.as_str() == Some(&format!("at://{}", setup.handle))),
            "alsoKnownAs should contain at://{}",
            setup.handle
        );

        // verificationMethod has publicKeyMultibase starting with "z"
        let vm = &doc["verificationMethod"][0];
        let pkm = vm["publicKeyMultibase"]
            .as_str()
            .expect("publicKeyMultibase is string");
        assert!(
            pkm.starts_with('z'),
            "publicKeyMultibase should start with 'z'"
        );

        // service entry has serviceEndpoint matching public_url
        let service = &doc["service"][0];
        assert_eq!(
            service["serviceEndpoint"].as_str(),
            Some("https://test.example.com"),
            "serviceEndpoint should match config.public_url"
        );

        // accounts row with correct did, email; password_hash is a non-NULL argon2id PHC string;
        // recovery_share persisted.
        let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT email, password_hash, recovery_share FROM accounts WHERE did = ?",
        )
        .bind(did)
        .fetch_optional(&db)
        .await
        .unwrap();
        let (email, password_hash, recovery_share) = row.expect("accounts row should exist");
        assert!(email.contains("alice"), "email should match test account");
        let hash_str = password_hash.expect("password_hash should not be NULL after DID ceremony");
        assert!(
            hash_str.starts_with("$argon2id$"),
            "password_hash should be an argon2id PHC string, got: {hash_str}"
        );
        let rs = recovery_share
            .as_deref()
            .expect("recovery_share should not be NULL — Share 2 must be stored for relay custody");
        assert_eq!(rs.len(), 52, "recovery_share should be 52 chars");
        assert!(
            rs.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')),
            "recovery_share should be valid BASE32 (A-Z, 2-7), got: {rs}"
        );

        // did_documents row exists with non-empty document
        let doc_row: Option<(String,)> =
            sqlx::query_as("SELECT document FROM did_documents WHERE did = ?")
                .bind(did)
                .fetch_optional(&db)
                .await
                .unwrap();
        let (document,) = doc_row.expect("did_documents row should exist");
        assert!(!document.is_empty(), "document should be non-empty");

        // session row created with correct did and matching token_hash
        let session_token_str = body["session_token"].as_str().unwrap();
        let expected_hash = crate::routes::token::hash_bearer_token(session_token_str).unwrap();
        let session_row: Option<(String,)> =
            sqlx::query_as("SELECT did FROM sessions WHERE token_hash = ?")
                .bind(&expected_hash)
                .fetch_optional(&db)
                .await
                .unwrap();
        let (session_did,) = session_row.expect("sessions row should exist for token_hash");
        assert_eq!(session_did, did, "sessions.did should match response did");

        // handles table should NOT have a row yet (handle created via POST /v1/handles)
        let handle_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM handles WHERE did = ?")
            .bind(did)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(
            handle_count, 0,
            "handles table should be empty after DID ceremony"
        );

        // pending_accounts and pending_sessions deleted
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

        // devices deleted
        let device_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE account_id = ?")
                .bind(&setup.account_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(device_count, 0, "devices rows should be deleted");
    }

    // ── Retry path skips plc.directory ────────────────────────────────────────

    /// When pending_did already set, plc.directory is not called.
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
        let (rotation_key_public, signed_op) = make_signed_op(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

        // Derive the DID from the signed op to pre-store it.
        let signed_op_str = serde_json::to_string(&signed_op).unwrap();
        let verified = crypto::verify_genesis_op(
            &signed_op_str,
            &crypto::DidKeyUri(rotation_key_public.clone()),
        )
        .expect("verify should succeed");

        // Pre-set pending_did and all three shares to simulate a retry scenario.
        // The retry branch in pre_store_did_and_shares requires all share columns to be
        // non-NULL; leaving them NULL would cause a 500 instead of 200.
        let pre_share_1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let pre_share_2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let pre_share_3 = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        sqlx::query(
            "UPDATE pending_accounts \
             SET pending_did = ?, pending_share_1 = ?, pending_share_2 = ?, pending_share_3 = ? \
             WHERE id = ?",
        )
        .bind(&verified.did)
        .bind(pre_share_1)
        .bind(pre_share_2)
        .bind(pre_share_3)
        .bind(&setup.account_id)
        .execute(&db)
        .await
        .expect("pre-store pending_did and shares");

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
        // Shares returned must be the pre-stored ones, not freshly generated ones.
        // This is the core invariant of idempotent share storage: retrying the ceremony
        // must return the same shares so Share 2 in accounts.recovery_share stays consistent.
        assert_eq!(
            body["shamir_share_1"].as_str(),
            Some(pre_share_1),
            "retry should return pre-stored share 1, not a new one"
        );
        assert_eq!(
            body["shamir_share_3"].as_str(),
            Some(pre_share_3),
            "retry should return pre-stored share 3, not a new one"
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
        let (rotation_key_public, signed_op) = make_signed_op(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

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

    // ── Invalid signature ─────────────────────────────────────────────────────

    /// Corrupted signature returns 400 INVALID_CLAIM.
    #[tokio::test]
    async fn invalid_signature_returns_400() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let (rotation_key_public, mut signed_op) = make_signed_op(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

        // Corrupt the sig: decode, flip one byte, re-encode.
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
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

    // ── Wrong handle in alsoKnownAs ───────────────────────────────────────────

    /// alsoKnownAs mismatch returns 400 INVALID_CLAIM.
    #[tokio::test]
    async fn wrong_handle_in_op_returns_400() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        // Build op with a different handle — pending_accounts has setup.handle.
        let (rotation_key_public, signed_op) = make_signed_op(
            "different.handle.com",
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

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

    // ── Wrong service endpoint ────────────────────────────────────────────────

    /// services.atproto_pds.endpoint mismatch returns 400 INVALID_CLAIM.
    #[tokio::test]
    async fn wrong_service_endpoint_returns_400() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        // Build op with wrong service endpoint.
        let (rotation_key_public, signed_op) = make_signed_op(
            &setup.handle,
            "https://wrong.example.com",
            &setup.repo_signing_key_id,
        );

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

    // ── Per-account repo signing key checks ───────────────────────────────────

    /// An op publishing a different #atproto key than the one issued is rejected,
    /// before any plc.directory call (the relay could not sign that repo's commits).
    #[tokio::test]
    async fn mismatched_atproto_key_returns_400() {
        let mock_server = MockServer::start().await;
        // No PLC mock: rejection must happen before Phase 3.
        let state = test_state_for_did(mock_server.uri()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;

        let unrelated_key = crypto::generate_p256_keypair().unwrap().key_id.0;
        let (rotation_key_public, signed_op) =
            make_signed_op(&setup.handle, &state.config.public_url, &unrelated_key);

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
    }

    /// The ceremony is rejected if the repo signing key was never issued
    /// (GET /v1/repo-signing-key not called before /v1/dids).
    #[tokio::test]
    async fn missing_repo_signing_key_returns_400() {
        let mock_server = MockServer::start().await;
        let state = test_state_for_did(mock_server.uri()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        // Simulate a ceremony that skipped the key-issuance step.
        sqlx::query(
            "UPDATE pending_accounts \
             SET repo_signing_key_id = NULL, repo_signing_public_key = NULL, \
                 repo_signing_private_key_encrypted = NULL \
             WHERE id = ?",
        )
        .bind(&setup.account_id)
        .execute(&db)
        .await
        .unwrap();

        let (rotation_key_public, signed_op) = make_signed_op(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

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
    }

    // ── rotationKeys[0] mismatch ──────────────────────────────────────────────

    /// rotationKeys[0] in op != rotationKeyPublic in request body → 400 INVALID_CLAIM.
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
            "signedCreationOp": serde_json::json!({}),
            "password": "test-password",
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

    // ── Already promoted ──────────────────────────────────────────────────────

    /// Account already promoted returns 409 DID_ALREADY_EXISTS.
    #[tokio::test]
    async fn already_promoted_account_returns_409() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let (rotation_key_public, signed_op) = make_signed_op(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

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

    // ── Missing auth ──────────────────────────────────────────────────────────

    /// Missing Authorization header returns 401 UNAUTHORIZED.
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
                    "signedCreationOp": signed_op,
                    "password": "test-password",
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

    // ── Password provisioning ─────────────────────────────────────────────────

    /// Account promoted with a password can authenticate via createSession.
    ///
    /// Uses the retry path (pre-stored pending_did) so plc.directory is never called,
    /// making the test runnable without network access.
    #[tokio::test]
    async fn with_password_account_can_call_create_session() {
        // Use any URL — plc.directory will not be contacted on the retry path.
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let (rotation_key_public, signed_op) = make_signed_op(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

        // Derive DID and pre-store it with dummy shares to trigger the skip_plc path.
        let signed_op_str = serde_json::to_string(&signed_op).unwrap();
        let verified = crypto::verify_genesis_op(
            &signed_op_str,
            &crypto::DidKeyUri(rotation_key_public.clone()),
        )
        .expect("verify should succeed");
        sqlx::query(
            "UPDATE pending_accounts \
             SET pending_did = ?, pending_share_1 = ?, pending_share_2 = ?, pending_share_3 = ? \
             WHERE id = ?",
        )
        .bind(&verified.did)
        .bind("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .bind("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
        .bind("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
        .bind(&setup.account_id)
        .execute(&db)
        .await
        .expect("pre-store pending_did and shares");

        // POST /v1/dids with a password.
        let body = serde_json::json!({
            "rotationKeyPublic": rotation_key_public,
            "signedCreationOp": signed_op,
            "password": "mysecretpassword",
        });
        let request = Request::builder()
            .method("POST")
            .uri("/v1/dids")
            .header("Authorization", format!("Bearer {}", setup.session_token))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let did_response = crate::app::app(state.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(
            did_response.status(),
            StatusCode::OK,
            "DID ceremony should succeed"
        );
        let body_bytes = axum::body::to_bytes(did_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let did_body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let did = did_body["did"].as_str().unwrap().to_string();

        // password_hash should be a non-NULL argon2id PHC string.
        let stored_hash: Option<String> =
            sqlx::query_scalar("SELECT password_hash FROM accounts WHERE did = ?")
                .bind(&did)
                .fetch_one(&db)
                .await
                .unwrap();
        let hash_str =
            stored_hash.expect("password_hash should not be NULL when password provided");
        assert!(
            hash_str.starts_with("$argon2id$"),
            "password_hash should be an argon2id PHC string, got: {hash_str}"
        );

        // Directly verify the PHC string round-trip: parse the stored hash and verify
        // the ceremony password against it without going through createSession.
        {
            use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};
            let parsed = PasswordHash::new(&hash_str).expect("stored PHC string should parse");
            Argon2::default()
                .verify_password(b"mysecretpassword", &parsed)
                .expect("stored hash should verify against the ceremony password");
        }

        // createSession with the correct password should return 200.
        let cs_request = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.createSession")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"identifier":"{did}","password":"mysecretpassword"}}"#
            )))
            .unwrap();
        let cs_response = crate::app::app(state).oneshot(cs_request).await.unwrap();
        assert_eq!(
            cs_response.status(),
            StatusCode::OK,
            "createSession should return 200 after password-provisioned DID ceremony"
        );
    }

    /// Wrong password after ceremony returns 401 from createSession.
    ///
    /// Verifies that the stored argon2id hash correctly rejects a wrong password,
    /// confirming the PHC round-trip works end-to-end (store → verify).
    #[tokio::test]
    async fn wrong_password_returns_401_from_create_session() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let (rotation_key_public, signed_op) = make_signed_op(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

        // Pre-store pending_did to use the skip_plc path (no network required).
        let signed_op_str = serde_json::to_string(&signed_op).unwrap();
        let verified = crypto::verify_genesis_op(
            &signed_op_str,
            &crypto::DidKeyUri(rotation_key_public.clone()),
        )
        .expect("verify should succeed");
        sqlx::query(
            "UPDATE pending_accounts \
             SET pending_did = ?, pending_share_1 = ?, pending_share_2 = ?, pending_share_3 = ? \
             WHERE id = ?",
        )
        .bind(&verified.did)
        .bind("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .bind("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
        .bind("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
        .bind(&setup.account_id)
        .execute(&db)
        .await
        .expect("pre-store pending_did and shares");

        // Promote with password "correct-password".
        let body = serde_json::json!({
            "rotationKeyPublic": rotation_key_public,
            "signedCreationOp": signed_op,
            "password": "correct-password",
        });
        let did_response = crate::app::app(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/dids")
                    .header("Authorization", format!("Bearer {}", setup.session_token))
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            did_response.status(),
            StatusCode::OK,
            "DID ceremony should succeed"
        );
        let body_bytes = axum::body::to_bytes(did_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let did_body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let did = did_body["did"].as_str().unwrap().to_string();

        // createSession with the WRONG password should return 401.
        let cs_response = crate::app::app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.server.createSession")
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"identifier":"{did}","password":"wrong-password"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            cs_response.status(),
            StatusCode::UNAUTHORIZED,
            "createSession should return 401 for wrong password"
        );
    }

    /// Missing password field in request body returns 422 Unprocessable Entity.
    ///
    /// Axum rejects deserialization of `CreateDidRequest` when a required field is absent.
    #[tokio::test]
    async fn missing_password_field_returns_422() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;

        let request_body = serde_json::json!({
            "rotationKeyPublic": "did:key:z123",
            "signedCreationOp": serde_json::json!({}),
            // "password" field intentionally omitted
        });
        let request = Request::builder()
            .method("POST")
            .uri("/v1/dids")
            .header("Authorization", format!("Bearer {}", setup.session_token))
            .header("Content-Type", "application/json")
            .body(Body::from(request_body.to_string()))
            .unwrap();

        let response = crate::app::app(state).oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "missing password field should return 422"
        );
    }

    /// Empty password string returns 400 INVALID_CLAIM.
    ///
    /// Argon2 would happily hash "" — the server-side guard prevents this.
    #[tokio::test]
    async fn empty_password_returns_400() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let (rotation_key_public, signed_op) = make_signed_op(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

        let request_body = serde_json::json!({
            "rotationKeyPublic": rotation_key_public,
            "signedCreationOp": signed_op,
            "password": "",
        });
        let request = Request::builder()
            .method("POST")
            .uri("/v1/dids")
            .header("Authorization", format!("Bearer {}", setup.session_token))
            .header("Content-Type", "application/json")
            .body(Body::from(request_body.to_string()))
            .unwrap();

        let response = crate::app::app(state).oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "empty password should return 400"
        );
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["error"]["code"], "INVALID_CLAIM");
    }

    // ── plc.directory error ───────────────────────────────────────────────────

    /// plc.directory non-2xx returns 502 PLC_DIRECTORY_ERROR.
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
        let (rotation_key_public, signed_op) = make_signed_op(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

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
