// pattern: Imperative Shell
//
// POST /xrpc/com.atproto.server.createAccount — the standard ATProto onboarding + migration
// endpoint. Named `create_account_xrpc` to distinguish it from the native, admin-gated
// `create_account.rs` (POST /v1/accounts). Two modes, selected by whether `did` is present:
//
//   New-account mode (no `did`):
//     The client supplies a SELF-SIGNED did:plc genesis op (`plcOp`) — ezpds never mints a DID
//     whose top rotation key is PDS-held (ADR-0001/0002), so `plcOp` is required. The PDS verifies
//     the op, builds the genesis repo signed by the client's reserved per-account key, submits the
//     op to plc.directory, and returns an ACTIVE session — mirroring the `/v1/dids` ceremony
//     without its Shamir/pending-account machinery.
//
//   Migration mode (`did` present):
//     Authenticated by a service-auth JWT the OLD PDS minted (Bearer), verified against the
//     migrating DID's `#atproto` key. Creates the account DEACTIVATED with no repo yet — the repo
//     arrives later via `importRepo`, and `activateAccount` finalizes it.
//
// Invite codes are enforced (single-use, against `claim_codes`) when `config.invite_code_required`.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::HeaderMap, response::Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::jwt::{
    issue_access_jwt, issue_refresh_jwt, verify_service_auth_jwt, SCOPE_ACCESS,
};
use crate::auth::password::hash_password;
use crate::db::is_unique_violation;
use crate::db::repo_keys::{
    get_reserved_repo_key_by_did, get_reserved_repo_key_by_id, insert_did_signing_key,
    RepoSigningKey,
};
use crate::identity_resolution::{atproto_verification_key, resolve_did_document};
use crate::uniqueness::{email_taken, handle_taken};

/// The lexicon method a migration service-auth token must authorize (when it carries an `lxm`).
const CREATE_ACCOUNT_LXM: &str = "com.atproto.server.createAccount";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountRequest {
    handle: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    password: Option<String>,
    /// Existing DID to migrate in. Its presence selects migration mode.
    #[serde(default)]
    did: Option<String>,
    /// Self-signed did:plc genesis operation. Required for new-account mode.
    #[serde(default)]
    plc_op: Option<serde_json::Value>,
    #[serde(default)]
    invite_code: Option<String>,
    // Accepted for lexicon compatibility; not used by ezpds (the client bakes any recovery key
    // into its self-signed `plcOp`, and ezpds does no phone verification).
    #[serde(default)]
    #[allow(dead_code)]
    recovery_key: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    verification_code: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    verification_phone: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResponse {
    access_jwt: String,
    refresh_jwt: String,
    handle: String,
    did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    did_doc: Option<serde_json::Value>,
}

/// POST /xrpc/com.atproto.server.createAccount
pub async fn create_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateAccountRequest>,
) -> Result<Json<CreateAccountResponse>, ApiError> {
    match payload
        .did
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
    {
        Some(did) => create_account_migration(&state, &headers, &payload, did).await,
        None => create_account_new(&state, &payload).await,
    }
}

// ── New-account mode ───────────────────────────────────────────────────────────

async fn create_account_new(
    state: &AppState,
    payload: &CreateAccountRequest,
) -> Result<Json<CreateAccountResponse>, ApiError> {
    // New-account mode creates a fresh identity on this server: require email + password and a
    // handle on a served domain.
    let email = require_email(payload)?;
    let password = payload
        .password
        .as_deref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidClaim, "password must not be empty"))?;
    if let Err(msg) =
        crate::handle::validate_handle(&payload.handle, &state.config.available_user_domains)
    {
        return Err(ApiError::new(ErrorCode::InvalidHandle, msg));
    }

    // ezpds never mints a server-custodied DID: the client must supply a self-signed genesis op.
    let plc_op = payload.plc_op.as_ref().ok_or_else(|| {
        ApiError::new(
            ErrorCode::InvalidClaim,
            "plcOp is required: this server does not create server-custodied identities; \
             supply a self-signed did:plc genesis operation (or migrate an existing DID)",
        )
    })?;
    // The op is self-signed by rotationKeys[0]; pull that key out to verify the signature against.
    let rotation_key_public = plc_op
        .get("rotationKeys")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidClaim,
                "plcOp.rotationKeys[0] is missing or not a string",
            )
        })?;

    let (verified, signed_op_str) = crate::genesis::verify_and_validate_genesis_op(
        rotation_key_public,
        plc_op,
        &payload.handle,
        &state.config.public_url,
    )?;
    let did = verified.did.clone();

    // The op must publish a per-account signing key this server actually holds (reserved earlier
    // via `reserveSigningKey`), because the PDS signs this repo's commits with it.
    let atproto_key_id = verified
        .verification_methods
        .get("atproto")
        .map(String::as_str)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidClaim,
                "op verificationMethods.atproto is missing",
            )
        })?;
    let repo_key = get_reserved_repo_key_by_id(&state.db, atproto_key_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to load reserved signing key");
            ApiError::new(ErrorCode::InternalError, "failed to load signing key")
        })?
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidClaim,
                "op verificationMethods.atproto does not match a reserved signing key; \
                 call reserveSigningKey first",
            )
        })?;

    // Uniqueness pre-flight (fast rejection before expensive genesis work) and invite pre-check.
    ensure_email_and_handle_free(state, email, &payload.handle).await?;
    precheck_invite_code(state, payload.invite_code.as_deref()).await?;

    // Build the (empty) genesis repo in memory, signed with the reserved per-account key, so its
    // blocks commit atomically inside the promotion transaction. Building before the plc.directory
    // call means a build failure aborts cleanly with no orphaned PLC registration.
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
            tracing::error!(error = %e, "failed to decrypt reserved signing key for genesis");
            ApiError::new(ErrorCode::InternalError, "failed to prepare genesis repo")
        })?;
    let genesis_signer = repo_engine::CommitSigner::from_bytes(&genesis_private).map_err(|e| {
        tracing::error!(error = %e, "invalid reserved signing key for genesis");
        ApiError::new(ErrorCode::InternalError, "failed to prepare genesis repo")
    })?;
    let (genesis_root, genesis_rev, genesis_blocks) =
        repo_engine::build_genesis_repo(&did, &genesis_signer)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to build genesis repo");
                ApiError::new(ErrorCode::InternalError, "failed to build genesis repo")
            })?;
    let genesis_root_str = genesis_root.to_string();
    let genesis_car = crate::genesis::build_genesis_car(genesis_root, &genesis_blocks);
    let genesis_sync_car = crate::genesis::build_commit_block_car(genesis_root, &genesis_blocks)
        .ok_or_else(|| {
            tracing::error!(did = %did, "genesis commit block missing from built blocks");
            ApiError::new(ErrorCode::InternalError, "failed to build genesis repo")
        })?;

    check_did_not_promoted(state, &did).await?;
    crate::genesis::post_to_plc_directory(
        &state.http_client,
        &state.config.plc_directory_url,
        &did,
        &signed_op_str,
    )
    .await?;

    let did_document = crate::genesis::build_did_document(&verified)?;
    let password_hash = hash_password(password)?;

    let session = promote_new_account(
        state,
        NewAccountPromotion {
            did: &did,
            email,
            handle: &payload.handle,
            password_hash: &password_hash,
            did_document: &did_document,
            repo_key: &repo_key,
            genesis_root: &genesis_root_str,
            genesis_rev: &genesis_rev,
            genesis_blocks: &genesis_blocks,
            genesis_car,
            genesis_sync_car,
            invite_code: payload.invite_code.as_deref(),
        },
    )
    .await?;

    Ok(Json(CreateAccountResponse {
        access_jwt: session.access_jwt,
        refresh_jwt: session.refresh_jwt,
        handle: payload.handle.clone(),
        did,
        did_doc: Some(did_document),
    }))
}

/// Owned/borrowed inputs to the new-account promotion transaction, grouped to avoid a
/// `too_many_arguments` signature.
struct NewAccountPromotion<'a> {
    did: &'a str,
    email: &'a str,
    handle: &'a str,
    password_hash: &'a str,
    did_document: &'a serde_json::Value,
    repo_key: &'a RepoSigningKey,
    genesis_root: &'a str,
    genesis_rev: &'a str,
    genesis_blocks: &'a [(repo_engine::Cid, Vec<u8>)],
    genesis_car: Vec<u8>,
    genesis_sync_car: Vec<u8>,
    invite_code: Option<&'a str>,
}

/// Atomically create the active account, its genesis repo, and a session, then sequence the
/// genesis `#commit` + `#sync` + `#account` to the firehose (mirrors `create_did::promote_account`).
async fn promote_new_account(
    state: &AppState,
    p: NewAccountPromotion<'_>,
) -> Result<IssuedSession, ApiError> {
    let did_document_str = serde_json::to_string(p.did_document).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize DID document");
        ApiError::new(ErrorCode::InternalError, "failed to serialize DID document")
    })?;

    // Acquire the firehose lock *before* opening the transaction — see the firehose section of
    // crates/pds/CLAUDE.md for why that order matters on the single-connection pool.
    let emit_guard = state.firehose.lock_emit().await;
    let mut tx = state
        .db
        .begin()
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to begin createAccount transaction"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to begin transaction"))?;

    // Redeem the invite code first: a bad code rolls the whole transaction back before any work.
    redeem_invite_code(&mut tx, state, p.invite_code).await?;

    sqlx::query(
        "INSERT INTO accounts \
         (did, email, password_hash, repo_root_cid, repo_rev, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
    )
    .bind(p.did)
    .bind(p.email)
    .bind(p.password_hash)
    .bind(p.genesis_root)
    .bind(p.genesis_rev)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert account");
        if is_unique_violation(&e) {
            ApiError::new(ErrorCode::DidAlreadyExists, "account already exists")
        } else {
            ApiError::new(ErrorCode::InternalError, "failed to create account")
        }
    })?;

    insert_did_document(&mut tx, p.did, &did_document_str).await?;
    insert_handle(&mut tx, p.handle, p.did).await?;

    insert_did_signing_key(&mut *tx, p.did, p.repo_key)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to insert repo signing key"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store signing key"))?;

    for (cid, bytes) in p.genesis_blocks {
        sqlx::query(
            "INSERT INTO blocks (cid, account_did, bytes, rev) VALUES (?, ?, ?, ?) \
             ON CONFLICT(cid) DO NOTHING",
        )
        .bind(cid.to_string())
        .bind(p.did)
        .bind(bytes.as_slice())
        .bind(p.genesis_rev)
        .execute(&mut *tx)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to insert genesis block"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store genesis repo"))?;
    }

    // Stage the genesis `#commit` and a chained Sync v1.1 `#sync` head assertion in this same
    // transaction, so a fresh host self-announces to the relay atomically with the repo it describes.
    let pending_commit = emit_guard
        .stage_commit(
            &mut tx,
            crate::firehose::CommitInput {
                repo: p.did.to_string(),
                commit: p.genesis_root.to_string(),
                rev: p.genesis_rev.to_string(),
                since: None,
                prev_data: None,
                ops: Vec::new(),
                blocks: p.genesis_car,
            },
        )
        .await
        .inspect_err(|e| tracing::error!(error = %e, did = %p.did, "failed to stage genesis firehose commit event"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to sequence genesis repo"))?
        .stage_sync(
            &mut tx,
            crate::firehose::SyncInput {
                did: p.did.to_string(),
                rev: p.genesis_rev.to_string(),
                blocks: p.genesis_sync_car,
            },
        )
        .await
        .inspect_err(|e| tracing::error!(error = %e, did = %p.did, "failed to stage genesis firehose sync event"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to sequence genesis repo"))?;

    let session = issue_session(&mut tx, state, p.did).await?;

    tx.commit()
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to commit createAccount transaction"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to commit transaction"))?;

    pending_commit.finish();

    if let Err(e) = state
        .firehose
        .emit_account(p.did.to_string(), true, None)
        .await
    {
        tracing::warn!(error = %e, did = %p.did, "failed to sequence #account firehose event after account creation (non-fatal)");
    }
    state.crawlers.notify();

    Ok(session)
}

// ── Migration mode ─────────────────────────────────────────────────────────────

async fn create_account_migration(
    state: &AppState,
    headers: &HeaderMap,
    payload: &CreateAccountRequest,
    did: &str,
) -> Result<Json<CreateAccountResponse>, ApiError> {
    // Migration is authenticated by a service-auth JWT the OLD PDS minted for the migrating DID.
    let service_auth = bearer_token(headers).ok_or_else(|| {
        ApiError::new(
            ErrorCode::AuthenticationRequired,
            "migration requires a service-auth token from the current PDS",
        )
    })?;

    // Resolve the incoming DID's document and pull out its #atproto signing key to verify against.
    let did_document = resolve_did_document(state, did).await?;
    let atproto_key = atproto_verification_key(&did_document).ok_or_else(|| {
        ApiError::new(
            ErrorCode::InvalidRequest,
            "the DID document has no #atproto verification method",
        )
    })?;

    let server_did = state.config.resolve_server_did();
    verify_service_auth_jwt(
        service_auth,
        did,
        &server_did,
        CREATE_ACCOUNT_LXM,
        &atproto_key,
        unix_now()?,
    )?;

    // The migrating identity's handle is foreign (e.g. its old domain), so only structural
    // validity is required — not this server's served-domain policy.
    if let Err(msg) = crate::handle::validate_handle_structure(&payload.handle) {
        return Err(ApiError::new(ErrorCode::InvalidHandle, msg));
    }
    let email = require_email(payload)?;

    // A repo signing key must have been reserved for this DID (via reserveSigningKey) so the PDS
    // can sign commits once the repo is imported.
    let repo_key = get_reserved_repo_key_by_did(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to load reserved signing key");
            ApiError::new(ErrorCode::InternalError, "failed to load signing key")
        })?
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidClaim,
                "no reserved signing key for this DID; call reserveSigningKey first",
            )
        })?;

    ensure_email_and_handle_free(state, email, &payload.handle).await?;
    precheck_invite_code(state, payload.invite_code.as_deref()).await?;

    let did_document_str = serde_json::to_string(&did_document).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize resolved DID document");
        ApiError::new(ErrorCode::InternalError, "failed to store DID document")
    })?;
    // A migration account may carry no password (OAuth-only); store NULL then.
    let password_hash = match payload.password.as_deref().filter(|p| !p.is_empty()) {
        Some(p) => Some(hash_password(p)?),
        None => None,
    };

    let mut tx = state
        .db
        .begin()
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to begin migration transaction"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to begin transaction"))?;

    redeem_invite_code(&mut tx, state, payload.invite_code.as_deref()).await?;

    // Deactivated, repo-less: repo root/rev stay NULL until importRepo lands, and the account is
    // deactivated until activateAccount is called.
    sqlx::query(
        "INSERT INTO accounts \
         (did, email, password_hash, deactivated_at, created_at, updated_at) \
         VALUES (?, ?, ?, datetime('now'), datetime('now'), datetime('now'))",
    )
    .bind(did)
    .bind(email)
    .bind(password_hash.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert migration account");
        if is_unique_violation(&e) {
            ApiError::new(ErrorCode::DidAlreadyExists, "account already exists")
        } else {
            ApiError::new(ErrorCode::InternalError, "failed to create account")
        }
    })?;

    insert_did_document(&mut tx, did, &did_document_str).await?;
    insert_handle(&mut tx, &payload.handle, did).await?;
    insert_did_signing_key(&mut *tx, did, &repo_key)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to insert repo signing key"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store signing key"))?;

    let session = issue_session(&mut tx, state, did).await?;

    tx.commit()
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to commit migration transaction"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to commit transaction"))?;

    Ok(Json(CreateAccountResponse {
        access_jwt: session.access_jwt,
        refresh_jwt: session.refresh_jwt,
        handle: payload.handle.clone(),
        did: did.to_string(),
        did_doc: Some(did_document),
    }))
}

// ── Shared helpers ───────────────────────────────────────────────────────────

struct IssuedSession {
    access_jwt: String,
    refresh_jwt: String,
}

/// Issue an access + refresh JWT pair and persist the `sessions` + `refresh_tokens` rows inside
/// the caller's transaction — the standard `createSession` shape (full access scope, no app
/// password), so the returned account can immediately act as itself.
async fn issue_session(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    state: &AppState,
    did: &str,
) -> Result<IssuedSession, ApiError> {
    let now = unix_now()?;
    let aud = state
        .config
        .server_did
        .as_deref()
        .unwrap_or(&state.config.public_url)
        .to_string();

    let access_jwt = issue_access_jwt(&state.jwt_secret, did, &aud, now, SCOPE_ACCESS)?;
    let refresh_jti = Uuid::new_v4().to_string();
    let refresh_jwt = issue_refresh_jwt(&state.jwt_secret, did, &aud, &refresh_jti, now)?;
    let session_id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
         VALUES (?, ?, NULL, NULL, datetime('now'), datetime('now', '+90 days'))",
    )
    .bind(&session_id)
    .bind(did)
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert session");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;

    sqlx::query(
        "INSERT INTO refresh_tokens (jti, did, session_id, expires_at, app_password_name, created_at) \
         VALUES (?, ?, ?, datetime('now', '+90 days'), NULL, datetime('now'))",
    )
    .bind(&refresh_jti)
    .bind(did)
    .bind(&session_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert refresh token");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;

    Ok(IssuedSession {
        access_jwt,
        refresh_jwt,
    })
}

async fn insert_did_document(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    did: &str,
    document: &str,
) -> Result<(), ApiError> {
    // Upsert: in migration mode the DID document is already cached locally by the resolver, so a
    // plain INSERT would conflict on the `did` primary key. New-account mode has no prior row, so
    // the ON CONFLICT branch simply never fires.
    sqlx::query(
        "INSERT INTO did_documents (did, document, created_at, updated_at) \
         VALUES (?, ?, datetime('now'), datetime('now')) \
         ON CONFLICT(did) DO UPDATE SET document = excluded.document, updated_at = datetime('now')",
    )
    .bind(did)
    .bind(document)
    .execute(&mut **tx)
    .await
    .inspect_err(|e| tracing::error!(error = %e, "failed to insert did_document"))
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store DID document"))?;
    Ok(())
}

async fn insert_handle(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    handle: &str,
    did: &str,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
        .bind(handle)
        .bind(did)
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to insert handle");
            if is_unique_violation(&e) {
                ApiError::new(ErrorCode::HandleTaken, "this handle is already claimed")
            } else {
                ApiError::new(ErrorCode::InternalError, "failed to bind handle")
            }
        })?;
    Ok(())
}

/// Require a non-empty email (accounts.email is NOT NULL).
fn require_email(payload: &CreateAccountRequest) -> Result<&str, ApiError> {
    payload
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidClaim, "email is required"))
}

/// Fast-path uniqueness rejection before expensive work; the DB constraints are the authoritative
/// guard inside the transaction.
async fn ensure_email_and_handle_free(
    state: &AppState,
    email: &str,
    handle: &str,
) -> Result<(), ApiError> {
    if email_taken(&state.db, email).await.map_err(|e| {
        tracing::error!(error = %e, "failed to check email uniqueness");
        ApiError::new(ErrorCode::InternalError, "failed to create account")
    })? {
        return Err(ApiError::new(
            ErrorCode::AccountExists,
            "an account with this email already exists",
        ));
    }
    if handle_taken(&state.db, handle).await.map_err(|e| {
        tracing::error!(error = %e, "failed to check handle uniqueness");
        ApiError::new(ErrorCode::InternalError, "failed to create account")
    })? {
        return Err(ApiError::new(
            ErrorCode::HandleTaken,
            "this handle is already claimed",
        ));
    }
    Ok(())
}

/// Confirm the DID is not already a fully-provisioned account.
async fn check_did_not_promoted(state: &AppState, did: &str) -> Result<(), ApiError> {
    if crate::db::accounts::account_exists(&state.db, did).await? {
        return Err(ApiError::new(
            ErrorCode::DidAlreadyExists,
            "an account for this DID already exists",
        ));
    }
    Ok(())
}

/// Pre-flight invite-code validation (no consumption) so obviously-invalid codes are rejected
/// before any genesis/plc work. The authoritative single-use consumption is `redeem_invite_code`.
async fn precheck_invite_code(state: &AppState, code: Option<&str>) -> Result<(), ApiError> {
    if !state.config.invite_code_required {
        return Ok(());
    }
    let code = code
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "an invite code is required"))?;
    let valid = crate::db::claim_codes::claim_code_valid(&state.db, code).await?;
    if !valid {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "invalid or expired invite code",
        ));
    }
    Ok(())
}

/// Redeem the invite code inside the account-creation transaction — the atomic single-use gate.
/// The WHERE guard rejects invalid/expired/already-redeemed codes in one step; 0 rows → reject.
async fn redeem_invite_code(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    state: &AppState,
    code: Option<&str>,
) -> Result<(), ApiError> {
    if !state.config.invite_code_required {
        return Ok(());
    }
    let code = code
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "an invite code is required"))?;
    let result = sqlx::query(
        "UPDATE claim_codes SET redeemed_at = datetime('now') \
         WHERE code = ? AND redeemed_at IS NULL AND expires_at > datetime('now')",
    )
    .bind(code)
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to redeem invite code");
        ApiError::new(ErrorCode::InternalError, "failed to redeem invite code")
    })?;
    if result.rows_affected() == 0 {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "invalid or expired invite code",
        ));
    }
    Ok(())
}

/// Extract a `Bearer` token from the `Authorization` header.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

fn unix_now() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| {
            tracing::error!(error = %e, "system clock is before Unix epoch");
            ApiError::new(ErrorCode::InternalError, "system clock error")
        })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use wiremock::{
        matchers::{method, path_regex},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::app::{app, test_state_with_plc_url, AppState};
    use crate::routes::test_utils::{seed_did_document, test_master_key};

    const CREATE_ACCOUNT_URI: &str = "/xrpc/com.atproto.server.createAccount";

    // ── State builders ────────────────────────────────────────────────────────

    /// AppState with the signing-key master key configured, a plc.directory mock URL, and an
    /// explicit `invite_code_required` toggle.
    async fn test_state(plc_url: String, invite_required: bool) -> AppState {
        let base = test_state_with_plc_url(plc_url).await;
        let mut config = (*base.config).clone();
        config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(
            test_master_key(),
        )));
        config.invite_code_required = invite_required;
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn post(body: serde_json::Value, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(CREATE_ACCOUNT_URI)
            .header("Content-Type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    /// Mount a plc.directory mock that accepts any genesis op with 200.
    async fn plc_mock() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:[a-z2-7]+$"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        server
    }

    // ── New-account fixtures ──────────────────────────────────────────────────

    /// Reserve a per-account signing key (as `reserveSigningKey` would) and return its did:key id.
    async fn reserve_key(db: &sqlx::SqlitePool, did: Option<&str>) -> crypto::P256Keypair {
        let kp = crypto::generate_p256_keypair().expect("keypair");
        let private_key_encrypted =
            crypto::encrypt_private_key(&kp.private_key_bytes, &test_master_key())
                .expect("encrypt");
        crate::db::repo_keys::insert_reserved_repo_key(
            db,
            did,
            &crate::db::repo_keys::RepoSigningKey {
                key_id: kp.key_id.to_string(),
                public_key: kp.public_key.clone(),
                private_key_encrypted,
            },
        )
        .await
        .expect("reserve key");
        kp
    }

    /// Build a self-signed genesis op: rotationKeys[0] = a fresh device key (signs the op),
    /// rotationKeys[1] + verificationMethods.atproto = `atproto_key_did`.
    fn signed_genesis_op(
        handle: &str,
        public_url: &str,
        atproto_key_did: &str,
    ) -> serde_json::Value {
        use crypto::{build_did_plc_genesis_op, generate_p256_keypair, DidKeyUri};
        let device = generate_p256_keypair().expect("device keypair");
        let device_private = *device.private_key_bytes;
        let op = build_did_plc_genesis_op(
            &device.key_id,
            &DidKeyUri(atproto_key_did.to_string()),
            &device_private,
            handle,
            public_url,
        )
        .expect("genesis op");
        serde_json::from_str(&op.signed_op_json).expect("valid op JSON")
    }

    // ── New-account mode ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn new_account_happy_path_returns_active_session_and_announces() {
        let plc = plc_mock().await;
        let state = test_state(plc.uri(), false).await;
        let db = state.db.clone();
        let reserved = reserve_key(&db, None).await;
        let op = signed_genesis_op(
            "alice.example.com",
            &state.config.public_url,
            &reserved.key_id.0,
        );

        let mut fh_rx = state.firehose.subscribe();
        let response = app(state.clone())
            .oneshot(post(
                serde_json::json!({
                    "handle": "alice.example.com",
                    "email": "alice@example.com",
                    "password": "hunter2hunter2",
                    "plcOp": op,
                }),
                None,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert!(json["accessJwt"].as_str().is_some(), "accessJwt required");
        assert!(json["refreshJwt"].as_str().is_some(), "refreshJwt required");
        assert_eq!(json["handle"], "alice.example.com");
        let did = json["did"].as_str().expect("did present");
        assert!(did.starts_with("did:plc:"));
        assert!(json["didDoc"].is_object(), "didDoc must be returned");

        // Active account with a genesis repo root recorded, signing key promoted, handle bound.
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
            "genesis repo root must be recorded"
        );
        let deactivated: Option<String> =
            sqlx::query_scalar("SELECT deactivated_at FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(deactivated.is_none(), "new account must be active");
        let signing_key: Option<String> =
            sqlx::query_scalar("SELECT id FROM signing_keys WHERE did = ?")
                .bind(did)
                .fetch_optional(&db)
                .await
                .unwrap();
        assert_eq!(signing_key.as_deref(), Some(reserved.key_id.0.as_str()));
        let handle_did: Option<String> =
            sqlx::query_scalar("SELECT did FROM handles WHERE handle = 'alice.example.com'")
                .fetch_optional(&db)
                .await
                .unwrap();
        assert_eq!(handle_did.as_deref(), Some(did));

        // Session persisted.
        let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE did = ?")
            .bind(did)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(sessions, 1);

        // Self-announce: genesis #commit, #sync, then #account (active).
        use crate::firehose::FirehoseEvent;
        assert!(
            matches!(fh_rx.try_recv(), Ok(FirehoseEvent::Commit(c)) if c.repo == did),
            "expected a genesis #commit"
        );
        assert!(
            matches!(fh_rx.try_recv(), Ok(FirehoseEvent::Sync(s)) if s.did == did),
            "expected a genesis #sync"
        );
        assert!(
            matches!(fh_rx.try_recv(), Ok(FirehoseEvent::Account(a)) if a.did == did && a.active),
            "expected an #account (active)"
        );
    }

    #[tokio::test]
    async fn new_account_without_plc_op_returns_400() {
        let plc = plc_mock().await;
        let state = test_state(plc.uri(), false).await;
        let response = app(state)
            .oneshot(post(
                serde_json::json!({
                    "handle": "bob.example.com",
                    "email": "bob@example.com",
                    "password": "hunter2hunter2",
                }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_CLAIM");
    }

    #[tokio::test]
    async fn new_account_with_unreserved_atproto_key_returns_400() {
        // The op names an #atproto key the server never reserved — reject.
        let plc = plc_mock().await;
        let state = test_state(plc.uri(), false).await;
        let stranger = crypto::generate_p256_keypair().expect("keypair");
        let op = signed_genesis_op(
            "carol.example.com",
            &state.config.public_url,
            &stranger.key_id.0,
        );

        let response = app(state)
            .oneshot(post(
                serde_json::json!({
                    "handle": "carol.example.com",
                    "email": "carol@example.com",
                    "password": "hunter2hunter2",
                    "plcOp": op,
                }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn new_account_unserved_handle_domain_returns_400() {
        let plc = plc_mock().await;
        let state = test_state(plc.uri(), false).await;
        let db = state.db.clone();
        let reserved = reserve_key(&db, None).await;
        let op = signed_genesis_op(
            "dave.other.com",
            &state.config.public_url,
            &reserved.key_id.0,
        );

        let response = app(state)
            .oneshot(post(
                serde_json::json!({
                    "handle": "dave.other.com",
                    "email": "dave@example.com",
                    "password": "hunter2hunter2",
                    "plcOp": op,
                }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_HANDLE");
    }

    // ── Invite codes ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn invite_required_but_missing_returns_400() {
        let plc = plc_mock().await;
        let state = test_state(plc.uri(), true).await;
        let db = state.db.clone();
        let reserved = reserve_key(&db, None).await;
        let op = signed_genesis_op(
            "eve.example.com",
            &state.config.public_url,
            &reserved.key_id.0,
        );

        let response = app(state)
            .oneshot(post(
                serde_json::json!({
                    "handle": "eve.example.com",
                    "email": "eve@example.com",
                    "password": "hunter2hunter2",
                    "plcOp": op,
                }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn invite_required_and_valid_succeeds_and_consumes_code() {
        let plc = plc_mock().await;
        let state = test_state(plc.uri(), true).await;
        let db = state.db.clone();
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES ('GOOD01', datetime('now', '+1 hour'), datetime('now'))",
        )
        .execute(&db)
        .await
        .unwrap();
        let reserved = reserve_key(&db, None).await;
        let op = signed_genesis_op(
            "frank.example.com",
            &state.config.public_url,
            &reserved.key_id.0,
        );

        let response = app(state)
            .oneshot(post(
                serde_json::json!({
                    "handle": "frank.example.com",
                    "email": "frank@example.com",
                    "password": "hunter2hunter2",
                    "plcOp": op,
                    "inviteCode": "GOOD01",
                }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let redeemed: Option<String> =
            sqlx::query_scalar("SELECT redeemed_at FROM claim_codes WHERE code = 'GOOD01'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(redeemed.is_some(), "invite code must be consumed");
    }

    // ── Migration mode ────────────────────────────────────────────────────────

    /// Seed a resolvable DID document whose #atproto key is `kp`, and reserve a signing key for it.
    async fn seed_migration_did(
        db: &sqlx::SqlitePool,
        did: &str,
        handle: &str,
    ) -> crypto::P256Keypair {
        let kp = crypto::generate_p256_keypair().expect("atproto keypair");
        let multibase = kp.key_id.0.strip_prefix("did:key:").unwrap().to_string();
        seed_did_document(
            db,
            did,
            serde_json::json!({
                "id": did,
                "alsoKnownAs": [format!("at://{handle}")],
                "verificationMethod": [{
                    "id": format!("{did}#atproto"),
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": multibase,
                }],
                "service": [{
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://old.example.com",
                }],
            }),
        )
        .await;
        reserve_key(db, Some(did)).await;
        kp
    }

    /// Mint a service-auth JWT signed by `kp` (the DID's #atproto key), for this server.
    fn service_auth_jwt(
        kp: &crypto::P256Keypair,
        iss: &str,
        aud: &str,
        lxm: Option<&str>,
    ) -> String {
        let key = *kp.private_key_bytes;
        let signer = repo_engine::CommitSigner::from_bytes(&key).expect("signer");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        crate::auth::jwt::mint_service_auth_jwt(|b| signer.sign(b), iss, aud, lxm, now, now + 300)
    }

    #[tokio::test]
    async fn migration_happy_path_creates_deactivated_repoless_account() {
        let state = test_state("http://unused.invalid".to_string(), false).await;
        let db = state.db.clone();
        let did = "did:plc:migrator22222222222222";
        let kp = seed_migration_did(&db, did, "alice.migrated.example").await;
        let aud = state.config.resolve_server_did();
        let token = service_auth_jwt(&kp, did, &aud, Some("com.atproto.server.createAccount"));

        let response = app(state)
            .oneshot(post(
                serde_json::json!({
                    "handle": "alice.migrated.example",
                    "email": "migrant@example.com",
                    "did": did,
                }),
                Some(&token),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["did"], did);
        assert!(json["accessJwt"].as_str().is_some());
        assert!(json["didDoc"].is_object());

        // Deactivated, repo-less account, with the reserved key promoted for later imports.
        let row: (Option<String>, Option<String>) =
            sqlx::query_as("SELECT deactivated_at, repo_root_cid FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(row.0.is_some(), "migration account must be deactivated");
        assert!(row.1.is_none(), "migration account must have no repo yet");
        let signing_key: Option<String> =
            sqlx::query_scalar("SELECT id FROM signing_keys WHERE did = ?")
                .bind(did)
                .fetch_optional(&db)
                .await
                .unwrap();
        assert!(
            signing_key.is_some(),
            "reserved signing key must be promoted"
        );
    }

    #[tokio::test]
    async fn migration_without_service_auth_returns_401() {
        let state = test_state("http://unused.invalid".to_string(), false).await;
        let db = state.db.clone();
        let did = "did:plc:migrator33333333333333";
        seed_migration_did(&db, did, "bob.migrated.example").await;

        let response = app(state)
            .oneshot(post(
                serde_json::json!({
                    "handle": "bob.migrated.example",
                    "email": "bob@example.com",
                    "did": did,
                }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn migration_with_forged_service_auth_returns_401() {
        let state = test_state("http://unused.invalid".to_string(), false).await;
        let db = state.db.clone();
        let did = "did:plc:migrator44444444444444";
        seed_migration_did(&db, did, "carol.migrated.example").await;
        let aud = state.config.resolve_server_did();
        // Signed by a DIFFERENT key than the DID's #atproto key.
        let attacker = crypto::generate_p256_keypair().expect("keypair");
        let token = service_auth_jwt(
            &attacker,
            did,
            &aud,
            Some("com.atproto.server.createAccount"),
        );

        let response = app(state)
            .oneshot(post(
                serde_json::json!({
                    "handle": "carol.migrated.example",
                    "email": "carol@example.com",
                    "did": did,
                }),
                Some(&token),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn migration_with_wrong_audience_returns_401() {
        let state = test_state("http://unused.invalid".to_string(), false).await;
        let db = state.db.clone();
        let did = "did:plc:migrator55555555555555";
        let kp = seed_migration_did(&db, did, "dave.migrated.example").await;
        // aud is some other service, not this server.
        let token = service_auth_jwt(
            &kp,
            did,
            "did:web:other.example.com",
            Some("com.atproto.server.createAccount"),
        );

        let response = app(state)
            .oneshot(post(
                serde_json::json!({
                    "handle": "dave.migrated.example",
                    "email": "dave@example.com",
                    "did": did,
                }),
                Some(&token),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
