// pattern: Imperative Shell
//
// POST /v1/dids — Device-signed DID ceremony and account promotion
//
// Verifies the client-signed did:plc genesis op against the previously issued per-account
// repo signing key and server config, then builds the genesis repo in memory before the
// plc.directory POST — so a build failure aborts cleanly, with no orphaned PLC registration
// and no account without a repo.
//
// The ceremony runs in one of two share-custody modes, inferred from the request shape:
//
// - **Client-share** (`recoveryKey` + `escrowShare` present, did:plc only): the wallet
//   generated the recovery seed, derived the recovery rotation key, and split the seed
//   client-side. The server receives exactly one share — the Share 2 envelope — verifies the
//   declared recovery key appears in the op's `rotationKeys` (so the escrow deposit and the
//   DID's public state cannot diverge), and stores the KEK-wrapped envelope in
//   `recovery_escrow` atomically with promotion. No share material is returned and nothing
//   lands in `pending_share_*`, so no DB snapshot or backup can ever hold two shares.
// - **Legacy server-side** (neither field present): the pre-inversion path for wallet builds
//   that predate client-side generation, kept for the fleet-update transition window and
//   flagged in logs for adoption tracking. The derived DID and its 3 Shamir shares are
//   pre-stored on the pending account before the plc.directory POST: a retry (pending_did
//   already set) reuses the stored shares and skips plc.directory instead of re-splitting
//   the secret, which would orphan Share 2 from a prior attempt in accounts.recovery_share.
//
// On the client-share path only the DID is pre-stored; retry idempotency of the share set is
// the wallet's job (it stages the set locally until the ceremony is confirmed).
//
// Handles are NOT inserted here — that is POST /v1/handles' job (format validation +
// optional DNS record creation), so a handle failure never has to unwind an already-
// promoted account.
//
// Account, DID document, session, and genesis repo blocks are promoted in one transaction
// that also stages the genesis #commit + #sync firehose events; only after it commits does
// the handler best-effort emit a separate #account (active) frame and request a crawl, so a
// never-crawled host self-announces to the relay instead of staying invisible until its
// first record write.

use axum::{extract::State, http::HeaderMap, Json};
use data_encoding::BASE32_NOPAD;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::app::AppState;
use crate::auth::guards::require_pending_session;
use crate::auth::password::hash_password;
use crate::auth::token::generate_token;
use crate::db::is_unique_violation;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidRequest {
    pub rotation_key_public: String,
    /// Signed PLC genesis operation. Exactly one of this and `did_web_document` is required.
    pub signed_creation_op: Option<serde_json::Value>,
    /// Already-published did:web document for a user-owned domain. The server resolves the
    /// authoritative URL and requires the parsed document to match before promotion.
    pub did_web_document: Option<String>,
    /// Initial password, stored as an argon2id PHC string.
    /// Enables `createSession` for this account after promotion.
    pub password: String,
    /// did:key of the wallet-derived recovery rotation key (client-share ceremony).
    /// Must be present together with `escrow_share`, and must appear in the op's
    /// `rotationKeys`.
    pub recovery_key: Option<String>,
    /// Share 2 of the wallet's client-side split, as a base32 v2 share envelope
    /// (client-share ceremony). Must be present together with `recovery_key`.
    pub escrow_share: Option<String>,
}

#[derive(Serialize)]
pub struct CreateDidResponse {
    pub did: String,
    pub did_document: serde_json::Value,
    pub status: &'static str,
    pub session_token: String,
    /// Share 1 of 3 — for storage in the user's iCloud Keychain.
    /// Base32-encoded (RFC 4648, no padding), 52 uppercase chars.
    /// Legacy server-side ceremony only; absent on the client-share path
    /// (the wallet already holds every share it needs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shamir_share_1: Option<String>,
    /// Share 3 of 3 — for user-directed manual backup.
    /// Base32-encoded (RFC 4648, no padding), 52 uppercase chars.
    /// Legacy server-side ceremony only; absent on the client-share path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shamir_share_3: Option<String>,
}

/// How the promoted account's escrowed share material is sourced and stored —
/// resolved from the request shape before any state is written.
enum ShareCustody {
    /// Client-share ceremony: the wallet split the seed; the server stores only the
    /// deposited Share 2 envelope (already validated) in `recovery_escrow`.
    ClientEscrow { envelope: crypto::ShareEnvelope },
    /// Legacy pre-inversion ceremony: the server generates and splits the secret,
    /// returning Shares 1 and 3 and keeping Share 2 in `accounts.recovery_share`.
    ServerLegacy,
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
    // before the ceremony, because the op publishes it as #atproto and the PDS signs
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
    // argon2 happily hashes "" — this ensures the PDS never stores a zero-length password.
    if payload.password.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "password must not be empty",
        ));
    }

    // Resolve the share-custody mode from the request shape before any state is written.
    // The two client-share fields travel together: a half-shaped request is a client bug
    // and must fail loudly rather than silently falling back to server-side generation,
    // which would strand the wallet's client-generated share set.
    let custody = match (
        payload.recovery_key.as_deref(),
        payload.escrow_share.as_deref(),
    ) {
        (Some(_), Some(escrow_share)) => {
            if payload.did_web_document.is_some() {
                // A did:web document has no PLC rotationKeys for the recovery key to bind
                // to; the recovery model for did:web identities is deliberately unscoped.
                return Err(ApiError::new(
                    ErrorCode::InvalidClaim,
                    "the client-share ceremony applies to did:plc accounts only",
                ));
            }
            // Structural validation before anything is stored — a malformed or corrupted
            // share fails now, not at recovery time. Errors are reported by kind but never
            // echo the submitted material.
            let envelope = crypto::ShareEnvelope::decode_share(escrow_share).map_err(|e| {
                ApiError::new(
                    ErrorCode::InvalidClaim,
                    format!("invalid escrow share: {e}"),
                )
            })?;
            if envelope.index() != 2 {
                return Err(ApiError::new(
                    ErrorCode::InvalidClaim,
                    "escrow holds Share 2 only; refusing a share with a different index",
                ));
            }
            ShareCustody::ClientEscrow { envelope }
        }
        (None, None) => ShareCustody::ServerLegacy,
        _ => {
            return Err(ApiError::new(
                ErrorCode::InvalidClaim,
                "recoveryKey and escrowShare must be provided together",
            ))
        }
    };

    // Phase 2: validate one method-specific ceremony, yielding the same method-agnostic
    // promotion inputs. did:web has no PLC operation: its already-published document is the
    // authority, so we resolve it externally and compare the JSON value before creating anything.
    let (did, did_document, signed_op_str) = match (
        payload.signed_creation_op.as_ref(),
        payload.did_web_document.as_ref(),
    ) {
        (Some(signed_op), None) => {
            let (verified, signed_op_str) =
                crate::identity::genesis::verify_and_validate_genesis_op(
                    &payload.rotation_key_public,
                    signed_op,
                    &pending.handle,
                    &state.config.public_url,
                )?;
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
            // Client-share ceremony: the declared recovery key must actually appear in the
            // op's rotationKeys, so the escrow deposit can never diverge from the DID's
            // public state (an escrowed share whose derived key controls nothing would be a
            // silent recovery dead end). Key count and ordering stay the wallet's choice —
            // validation is deliberately permissive beyond membership.
            if let Some(recovery_key) = payload.recovery_key.as_deref() {
                if !verified.rotation_keys.iter().any(|key| key == recovery_key) {
                    return Err(ApiError::new(
                        ErrorCode::InvalidClaim,
                        "declared recovery key does not appear in the op's rotationKeys",
                    ));
                }
            }
            let document = crate::identity::genesis::build_did_document(&verified)?;
            (verified.did, document, Some(signed_op_str))
        }
        (None, Some(document_bytes)) => {
            let document: serde_json::Value =
                serde_json::from_str(document_bytes).map_err(|_| {
                    ApiError::new(
                        ErrorCode::InvalidClaim,
                        "did:web document is not valid JSON",
                    )
                })?;
            let did = validate_did_web_document(
                &document,
                &pending.handle,
                &payload.rotation_key_public,
                &repo_key.key_id,
                &state.config.public_url,
            )?;
            let resolved =
                crate::identity::resolution::resolve_web_did_document_bytes(&state, &did).await?;
            if resolved.as_bytes() != document_bytes.as_bytes() {
                return Err(ApiError::new(
                    ErrorCode::InvalidClaim,
                    "published did:web document does not match the reviewed document",
                ));
            }
            (did, document, None)
        }
        _ => {
            return Err(ApiError::new(
                ErrorCode::InvalidClaim,
                "provide exactly one DID ceremony document",
            ))
        }
    };

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
        repo_engine::build_genesis_repo(&did, &genesis_signer)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to build genesis repo");
                ApiError::new(ErrorCode::InternalError, "failed to build genesis repo")
            })?;
    let genesis_root_str = genesis_root.to_string();
    // Every block `build_genesis_repo` wrote is reachable from `genesis_root` (there is no
    // previous commit to diff against), so the genesis `#commit` frame's CARv1 payload can be
    // built directly from these in-memory blocks — no block-store round trip needed.
    let genesis_car = crate::identity::genesis::build_genesis_car(genesis_root, &genesis_blocks);
    // A `#sync` state assertion carrying just the signed genesis commit block, staged atomically
    // with the account so a relay can anchor to this fresh host's head (Sync v1.1). The commit
    // block is always in the freshly-built genesis blocks, so `None` is an internal invariant break.
    let genesis_sync_car =
        crate::identity::genesis::build_commit_block_car(genesis_root, &genesis_blocks)
            .ok_or_else(|| {
                tracing::error!(did = %did, "genesis commit block missing from built blocks");
                ApiError::new(ErrorCode::InternalError, "failed to build genesis repo")
            })?;

    // Phase 3: Pre-store the DID (and, on the legacy path, the Shamir shares) for retry
    // resilience, then POST to plc.directory. Legacy shares are generated once and stored
    // alongside pending_did so retries return the same shares — preventing Share 2 from
    // being orphaned in accounts.recovery_share. The client-share path stores only the DID:
    // the wallet stages its share set locally, so nothing share-shaped may touch the DB
    // outside the escrow deposit at promotion.
    let (skip_plc, legacy_shares) = match &custody {
        ShareCustody::ClientEscrow { .. } => {
            let skip_plc = pre_store_did(&state.db, &session.account_id, &did, &pending).await?;
            (skip_plc, None)
        }
        ShareCustody::ServerLegacy => {
            // Adoption tracking for the transition window: once this line goes quiet across
            // the fleet, the legacy path (and pending_share_*) can be retired.
            tracing::info!(
                account_id = %session.account_id,
                "legacy server-side share ceremony used (pre-client-share wallet build)"
            );
            let (skip_plc, s1, s2, s3) =
                pre_store_did_and_shares(&state.db, &session.account_id, &did, &pending).await?;
            (skip_plc, Some((s1, s2, s3)))
        }
    };
    check_already_promoted(&state.db, &did).await?;
    if !skip_plc && signed_op_str.is_some() {
        crate::identity::genesis::post_to_plc_directory(
            &state.http_client,
            &state.config.plc_directory_url,
            &did,
            signed_op_str.as_deref().expect("checked above"),
        )
        .await?;
    }

    // Phase 4: Build DID document, generate session, hash password, atomically promote.
    let session_token = generate_token();
    let password_hash = hash_password(&payload.password)?;
    let deposit = match &custody {
        ShareCustody::ClientEscrow { envelope } => {
            // KEK-wrap the deposited envelope exactly as PUT /v1/recovery/escrow-share
            // does — the shared SecretFamily ciphertext format, so rewrap-master-key
            // covers this row like every other wrapped column.
            let wrapped = crypto::encrypt_secret_bytes(envelope.to_bytes().as_slice(), master_key)
                .map_err(|e| {
                    tracing::error!(error = %e, "failed to wrap escrow share for promotion");
                    ApiError::new(ErrorCode::InternalError, "failed to protect escrow share")
                })?;
            EscrowDeposit::ClientShare {
                wrapped_envelope: wrapped,
                set_id: envelope.set_id(),
                version: envelope.version(),
            }
        }
        ShareCustody::ServerLegacy => {
            let (_, share2, _) = legacy_shares
                .as_ref()
                .expect("legacy path always carries its shares");
            let wrapped = crate::recovery_share::wrap(share2, master_key).map_err(|e| {
                tracing::error!(error = %e, "failed to wrap PDS recovery share");
                ApiError::new(ErrorCode::InternalError, "failed to protect recovery share")
            })?;
            EscrowDeposit::Legacy {
                recovery_share_encrypted: wrapped,
            }
        }
    };
    promote_account(
        &state,
        &did,
        &pending.email,
        &session.account_id,
        &did_document,
        &session_token.hash,
        &deposit,
        &password_hash,
        &repo_key,
        &genesis_root_str,
        &genesis_rev,
        &genesis_blocks,
        genesis_car,
        genesis_sync_car,
    )
    .await?;

    let (shamir_share_1, shamir_share_3) = match legacy_shares {
        Some((share1, _, share3)) => (Some(share1), Some(share3)),
        None => (None, None),
    };
    Ok(Json(CreateDidResponse {
        did,
        did_document,
        status: "active",
        session_token: session_token.plaintext,
        shamir_share_1,
        shamir_share_3,
    }))
}

/// The escrow write `promote_account` performs inside the promotion transaction, resolved
/// from [`ShareCustody`] once the master key is in hand.
enum EscrowDeposit {
    /// Legacy path: KEK-wrapped Share 2 lands in `accounts.recovery_share`.
    Legacy { recovery_share_encrypted: String },
    /// Client-share path: the KEK-wrapped Share 2 envelope lands in `recovery_escrow`
    /// with a `deposited` audit event; `accounts.recovery_share` stays NULL.
    ClientShare {
        wrapped_envelope: String,
        set_id: u32,
        version: u8,
    },
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn validate_did_web_document(
    document: &serde_json::Value,
    handle: &str,
    device_key: &str,
    repo_key: &str,
    pds_url: &str,
) -> Result<String, ApiError> {
    let did = document
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|did| did.starts_with("did:web:"))
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidClaim, "document id must be did:web"))?;
    let expected_handle = format!("at://{handle}");
    if !document
        .get("alsoKnownAs")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|values| {
            values
                .iter()
                .any(|value| value.as_str() == Some(&expected_handle))
        })
    {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "did:web document does not contain the pending account handle",
        ));
    }

    let device_multibase = device_key.strip_prefix("did:key:").unwrap_or(device_key);
    let repo_multibase = repo_key.strip_prefix("did:key:").unwrap_or(repo_key);
    let methods = document
        .get("verificationMethod")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidClaim, "verificationMethod is required"))?;
    let has_key = |fragment: &str, multibase: &str| {
        let id = format!("{did}#{fragment}");
        methods.iter().any(|method| {
            method.get("id").and_then(serde_json::Value::as_str) == Some(&id)
                && method.get("type").and_then(serde_json::Value::as_str) == Some("Multikey")
                && method.get("controller").and_then(serde_json::Value::as_str) == Some(did)
                && method
                    .get("publicKeyMultibase")
                    .and_then(serde_json::Value::as_str)
                    == Some(multibase)
        })
    };
    if !has_key("device", device_multibase) {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "did:web document does not publish the device key as #device",
        ));
    }
    if !has_key("atproto", repo_multibase) {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "did:web #atproto key does not match the issued repo signing key",
        ));
    }

    let expected_endpoint = pds_url.trim_end_matches('/');
    let expected_service = format!("{did}#atproto_pds");
    let has_service = document
        .get("service")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|services| {
            services.iter().any(|service| {
                service.get("id").and_then(serde_json::Value::as_str) == Some(&expected_service)
                    && service.get("type").and_then(serde_json::Value::as_str)
                        == Some("AtprotoPersonalDataServer")
                    && service
                        .get("serviceEndpoint")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|endpoint| endpoint.trim_end_matches('/') == expected_endpoint)
            })
        });
    if !has_service {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "did:web #atproto_pds does not point at this server",
        ));
    }

    Ok(did.to_string())
}

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

/// Pre-store the DID alone for the client-share ceremony's retry resilience.
///
/// The client-share path never writes share material to the DB — the wallet stages its
/// share set locally until the ceremony is confirmed — so only `pending_did` is recorded.
/// A retry (pending_did already set) returns `skip_plc = true` after the same DID-mismatch
/// guard as the legacy path; any `pending_share_*` values left by an earlier legacy-shaped
/// attempt are simply ignored (they are deleted with the pending row at promotion).
async fn pre_store_did(
    db: &sqlx::SqlitePool,
    account_id: &str,
    did: &str,
    pending: &PendingAccount,
) -> Result<bool, ApiError> {
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
        tracing::info!(did = %pre_stored_did, "retry detected: pending_did already set, skipping plc.directory");
        return Ok(true);
    }

    let result = sqlx::query("UPDATE pending_accounts SET pending_did = ? WHERE id = ?")
        .bind(did)
        .bind(account_id)
        .execute(db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to pre-store pending DID");
            ApiError::new(ErrorCode::InternalError, "failed to store pending DID")
        })?;

    if result.rows_affected() == 0 {
        tracing::error!(account_id = %account_id, "pending account row vanished during DID pre-store");
        return Err(ApiError::new(
            ErrorCode::InternalError,
            "account no longer exists",
        ));
    }
    Ok(false)
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
    if crate::db::accounts::account_exists(db, did).await? {
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
/// Share 2 → PDS DB custody (stored in accounts.recovery_share).
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

/// Atomically promote a pending account to a full account (Steps 10-13), and sequence the
/// account's genesis repo to the firehose so a never-crawled host self-announces instead of
/// staying invisible until its first record write.
///
/// In a single transaction: INSERT accounts + did_documents + sessions, stage the genesis
/// `#commit` firehose event, then DELETE pending_sessions + devices + pending_accounts.
/// `deposit` decides where the escrowed share material lands: the legacy path binds
/// KEK-wrapped Share 2 into `accounts.recovery_share`; the client-share path leaves that
/// column NULL and inserts the wrapped Share 2 envelope into `recovery_escrow` (with its
/// `deposited` audit event) in the same transaction.
/// `password_hash` is the argon2id PHC string for the account's password set during the ceremony.
#[allow(clippy::too_many_arguments)]
async fn promote_account(
    state: &AppState,
    did: &str,
    email: &str,
    account_id: &str,
    did_document: &serde_json::Value,
    token_hash: &str,
    deposit: &EscrowDeposit,
    password_hash: &str,
    repo_key: &crate::db::repo_keys::RepoSigningKey,
    genesis_root: &str,
    genesis_rev: &str,
    genesis_blocks: &[(repo_engine::Cid, Vec<u8>)],
    genesis_car: Vec<u8>,
    genesis_sync_car: Vec<u8>,
) -> Result<(), ApiError> {
    let did_document_str = serde_json::to_string(did_document).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize DID document");
        ApiError::new(ErrorCode::InternalError, "failed to serialize DID document")
    })?;
    let session_id = uuid::Uuid::new_v4().to_string();

    // Acquired *before* opening the transaction below — see `Firehose::lock_emit`'s docs
    // (crates/pds/AGENTS.md's firehose section) for why that order matters on this crate's
    // single-connection pool.
    let emit_guard = state.firehose.lock_emit().await;
    let mut tx = state
        .db
        .begin()
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to begin promotion transaction"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to begin transaction"))?;

    let recovery_share_column = match deposit {
        EscrowDeposit::Legacy {
            recovery_share_encrypted,
        } => Some(recovery_share_encrypted.as_str()),
        EscrowDeposit::ClientShare { .. } => None,
    };
    sqlx::query(
        "INSERT INTO accounts \
         (did, email, password_hash, recovery_share, repo_root_cid, repo_rev, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
    )
    .bind(did)
    .bind(email)
    .bind(password_hash)
    .bind(recovery_share_column)
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

    // Client-share ceremony: land the escrow deposit (and its audit event) atomically with
    // the account it belongs to — the same rows PUT /v1/recovery/escrow-share would write,
    // minus the possibility of the account existing shareless in between.
    if let EscrowDeposit::ClientShare {
        wrapped_envelope,
        set_id,
        version,
    } = deposit
    {
        crate::db::recovery_escrow::insert_escrow_share(&mut *tx, did, wrapped_envelope)
            .await
            .inspect_err(|e| tracing::error!(error = %e, "failed to insert escrow share"))
            .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store escrow share"))?;
        let detail = serde_json::json!({ "set_id": set_id, "version": version });
        crate::db::recovery_audit::insert_recovery_audit_event(
            &mut *tx,
            &uuid::Uuid::new_v4().to_string(),
            did,
            crate::db::recovery_audit::RecoveryAuditEventType::Deposited,
            Some(&detail.to_string()),
        )
        .await?;
    }

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
    // (DID-keyed), atomically with promotion. The PDS loads it to sign repo commits.
    crate::db::repo_keys::insert_did_signing_key(&mut *tx, did, repo_key)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to insert repo signing key"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store signing key"))?;

    // Persist the genesis repo blocks (built in memory before the PLC call) in the same
    // transaction, so account + signing key + a complete repo all commit together.
    for (cid, bytes) in genesis_blocks {
        let cid = cid.to_string();
        crate::db::blocks::put_block_with_rev(
            &mut tx,
            &cid,
            did,
            bytes.as_slice(),
            Some(genesis_rev),
        )
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to insert genesis block"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store genesis repo"))?;
    }

    // Stage the genesis `#commit` event in the same transaction as the repo it describes: a
    // repo root recorded on `accounts` with no corresponding firehose row would be the same
    // "durable write, silently dropped event" hazard `record_write::commit_repo_write` avoids
    // for ordinary record writes.
    // Stage the genesis `#commit` and, chained after it in the same transaction and under the same
    // sequencer lock, a Sync v1.1 `#sync` state assertion (carrying just the signed commit block).
    // The reference PDS emits `#sync` on account activation; for a fresh account, genesis *is* that
    // activation, so a relay learns this host's authoritative head atomically with the repo it
    // describes. `prev_data` is `None` — the genesis commit has no predecessor.
    let pending_commit = emit_guard
        .stage_commit(
            &mut tx,
            crate::firehose::CommitInput {
                repo: did.to_string(),
                commit: genesis_root.to_string(),
                rev: genesis_rev.to_string(),
                since: None,
                prev_data: None,
                ops: Vec::new(),
                blocks: genesis_car,
            },
        )
        .await
        .inspect_err(|e| tracing::error!(error = %e, did = %did, "failed to stage genesis firehose commit event"))
        .map_err(|_| {
            ApiError::new(ErrorCode::InternalError, "failed to sequence genesis repo")
        })?
        .stage_sync(
            &mut tx,
            crate::firehose::SyncInput {
                did: did.to_string(),
                rev: genesis_rev.to_string(),
                blocks: genesis_sync_car,
            },
        )
        .await
        .inspect_err(|e| tracing::error!(error = %e, did = %did, "failed to stage genesis firehose sync event"))
        .map_err(|_| {
            ApiError::new(ErrorCode::InternalError, "failed to sequence genesis repo")
        })?;

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

    // Only now that the transaction (which already carries the genesis commit's and the `#sync`'s
    // `repo_seq` rows) has committed successfully: advance the sequence counter past both and
    // broadcast the `#commit` then the `#sync`.
    pending_commit.finish();

    // Emit the `#account` (active) frame separately, best-effort, once the account and its
    // genesis commit are both durable — mirrors `create_handle.rs`'s post-write `#identity`
    // emission: a sequencer write failure here is logged and dropped rather than failing an
    // otherwise-successful account creation. A relay that misses it still learns the account is
    // active from the genesis commit above or a later one.
    if let Err(e) = state
        .firehose
        .emit_account(did.to_string(), true, None)
        .await
    {
        tracing::warn!(
            error = %e,
            did = %did,
            "failed to sequence #account firehose event after account promotion (non-fatal)"
        );
    }

    // A fresh account may be the first thing this host has ever announced: request crawl so a
    // relay that has never seen this PDS discovers it now rather than waiting on some future
    // commit to trigger the notification.
    state.crawlers.notify();

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state_with_plc_url;
    use crate::auth::token::generate_token;
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

    #[test]
    fn did_web_document_requires_device_repo_service_and_handle() {
        let did = "did:web:alice.example.com";
        let document = serde_json::json!({
            "id": did,
            "alsoKnownAs": ["at://alice.example.com"],
            "verificationMethod": [
                {"id": format!("{did}#device"), "type": "Multikey", "controller": did, "publicKeyMultibase": "zdevice"},
                {"id": format!("{did}#atproto"), "type": "Multikey", "controller": did, "publicKeyMultibase": "zrepo"}
            ],
            "service": [{"id": format!("{did}#atproto_pds"), "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://pds.example.com"}]
        });
        assert_eq!(
            validate_did_web_document(
                &document,
                "alice.example.com",
                "did:key:zdevice",
                "did:key:zrepo",
                "https://pds.example.com/",
            )
            .unwrap(),
            did
        );

        let mut wrong = document;
        wrong["verificationMethod"][0]["publicKeyMultibase"] = serde_json::json!("zattacker");
        assert!(validate_did_web_document(
            &wrong,
            "alice.example.com",
            "did:key:zdevice",
            "did:key:zrepo",
            "https://pds.example.com",
        )
        .is_err());

        wrong["verificationMethod"][0]["publicKeyMultibase"] = serde_json::json!("zdevice");
        wrong["service"][0]["type"] = serde_json::json!("WrongServiceType");
        assert!(validate_did_web_document(
            &wrong,
            "alice.example.com",
            "did:key:zdevice",
            "did:key:zrepo",
            "https://pds.example.com",
        )
        .is_err());

        wrong["service"][0]["type"] = serde_json::json!("AtprotoPersonalDataServer");
        wrong["verificationMethod"][0]["type"] = serde_json::json!("JsonWebKey2020");
        assert!(validate_did_web_document(
            &wrong,
            "alice.example.com",
            "did:key:zdevice",
            "did:key:zrepo",
            "https://pds.example.com",
        )
        .is_err());
    }

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
        // The device/rotation key signs the op; the per-account key (issued by the PDS)
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
    /// No PDS signing key needed.
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

        // Subscribe before issuing the request so the genesis firehose events are captured.
        let mut fh_rx = state.firehose.subscribe();
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
            sqlx::query_scalar("SELECT COUNT(*) FROM block_owners WHERE account_did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            block_count >= 2,
            "genesis blocks must be persisted (commit + MST node); got {block_count}"
        );

        // A fresh account must self-announce — genesis #commit, a Sync v1.1 #sync head assertion,
        // then #account (active) sequenced to the firehose, so a never-crawled host doesn't stay
        // invisible to the relay until its first record write.
        use crate::firehose::FirehoseEvent;
        let FirehoseEvent::Commit(commit_event) = fh_rx
            .try_recv()
            .expect("a genesis #commit event must be emitted")
        else {
            panic!("expected a #commit event first");
        };
        assert_eq!(commit_event.repo, did);
        assert_eq!(commit_event.commit, repo_root.clone().unwrap());
        assert!(commit_event.since.is_none(), "genesis commit has no since");
        assert!(
            commit_event.prev_data.is_none(),
            "genesis commit has no prevData"
        );
        assert!(
            commit_event.ops.is_empty(),
            "genesis commit carries no record ops"
        );
        let car =
            atrium_repo::blockstore::CarStore::open(std::io::Cursor::new(&commit_event.blocks))
                .await
                .expect("genesis commit blocks must be a valid CAR");
        let roots: Vec<_> = car.roots().collect();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].to_string(), commit_event.commit);

        // The genesis #sync asserts the same head, carrying a CAR whose sole root is the commit.
        let FirehoseEvent::Sync(sync_event) = fh_rx
            .try_recv()
            .expect("a genesis #sync event must follow the commit")
        else {
            panic!("expected a #sync event second");
        };
        assert_eq!(sync_event.did, did);
        assert_eq!(sync_event.rev, commit_event.rev);
        let sync_car =
            atrium_repo::blockstore::CarStore::open(std::io::Cursor::new(&sync_event.blocks))
                .await
                .expect("#sync blocks must be a valid CAR");
        let sync_roots: Vec<_> = sync_car.roots().collect();
        assert_eq!(sync_roots.len(), 1);
        assert_eq!(sync_roots[0].to_string(), commit_event.commit);

        let FirehoseEvent::Account(account_event) = fh_rx
            .try_recv()
            .expect("an #account event must follow the genesis #sync")
        else {
            panic!("expected an #account event third");
        };
        assert_eq!(account_event.did, did);
        assert!(account_event.active, "fresh account should be active");
        assert!(account_event.status.is_none());

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
            .expect("recovery_share should not be NULL — Share 2 must be stored for PDS custody");
        assert_eq!(rs.len(), 80, "recovery_share should be KEK-wrapped");
        let plaintext =
            crate::recovery_share::unwrap(rs, &crate::routes::test_utils::test_master_key())
                .expect("recovery_share should decrypt under the configured KEK");
        let decode_share = |index, encoded: &str| {
            let bytes = BASE32_NOPAD.decode(encoded.as_bytes()).unwrap();
            crypto::ShamirShare {
                index,
                data: Zeroizing::new(bytes.try_into().unwrap()),
            }
        };
        let share_1 = decode_share(1, share1);
        let share_2 = decode_share(2, &plaintext);
        let share_3 = decode_share(3, share3);
        assert_eq!(
            *crypto::combine_shares(&share_1, &share_2).unwrap(),
            *crypto::combine_shares(&share_1, &share_3).unwrap(),
            "the decrypted escrow share must reconstruct the ceremony secret"
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
        let expected_hash = crate::auth::token::hash_bearer_token(session_token_str).unwrap();
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
        let pre_share_1 = BASE32_NOPAD.encode(&[0x11; 32]);
        let pre_share_2 = BASE32_NOPAD.encode(&[0x22; 32]);
        let pre_share_3 = BASE32_NOPAD.encode(&[0x33; 32]);
        sqlx::query(
            "UPDATE pending_accounts \
             SET pending_did = ?, pending_share_1 = ?, pending_share_2 = ?, pending_share_3 = ? \
             WHERE id = ?",
        )
        .bind(&verified.did)
        .bind(&pre_share_1)
        .bind(&pre_share_2)
        .bind(&pre_share_3)
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
            Some(pre_share_1.as_str()),
            "retry should return pre-stored share 1, not a new one"
        );
        assert_eq!(
            body["shamir_share_3"].as_str(),
            Some(pre_share_3.as_str()),
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
    /// before any plc.directory call (the PDS could not sign that repo's commits).
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
        .bind(BASE32_NOPAD.encode(&[0x11; 32]))
        .bind(BASE32_NOPAD.encode(&[0x22; 32]))
        .bind(BASE32_NOPAD.encode(&[0x33; 32]))
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
        .bind(BASE32_NOPAD.encode(&[0x11; 32]))
        .bind(BASE32_NOPAD.encode(&[0x22; 32]))
        .bind(BASE32_NOPAD.encode(&[0x33; 32]))
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

    // ── Client-share ceremony (wallet-generated shares, single-share escrow) ──

    /// Everything the wallet contributes to a client-share ceremony, generated the same
    /// way the wallet does it: seed → envelope split → derived recovery key → a 3-key
    /// genesis op `[device, recovery, PDS]` signed by the device key.
    struct ClientShareCeremony {
        rotation_key_public: String,
        recovery_key_id: String,
        signed_op: serde_json::Value,
        envelopes: [crypto::ShareEnvelope; 3],
    }

    fn make_client_share_ceremony(
        handle: &str,
        public_url: &str,
        atproto_key_did: &str,
    ) -> ClientShareCeremony {
        use crypto::{
            build_did_plc_genesis_op_multi_rotation, derive_recovery_keypair,
            generate_p256_keypair, split_secret_into_envelopes, DidKeyUri,
        };
        let seed: [u8; 32] = core::array::from_fn(|i| (i * 7 + 13) as u8);
        let envelopes = split_secret_into_envelopes(&seed, 0xC0FFEE).expect("split");
        let recovery = derive_recovery_keypair(&seed).expect("derive recovery keypair");

        let device = generate_p256_keypair().expect("device keypair");
        let device_private = *device.private_key_bytes;
        let genesis_op = build_did_plc_genesis_op_multi_rotation(
            &[
                device.key_id.clone(),
                recovery.key_id.clone(),
                DidKeyUri(atproto_key_did.to_string()),
            ],
            &DidKeyUri(atproto_key_did.to_string()),
            &device_private,
            handle,
            public_url,
        )
        .expect("multi-rotation genesis op");
        ClientShareCeremony {
            rotation_key_public: device.key_id.0,
            recovery_key_id: recovery.key_id.0,
            signed_op: serde_json::from_str(&genesis_op.signed_op_json).expect("valid JSON"),
            envelopes,
        }
    }

    /// Build a POST /v1/dids request carrying the client-share fields.
    fn client_share_request(
        session_token: &str,
        ceremony: &ClientShareCeremony,
        recovery_key: &str,
        escrow_share: &str,
    ) -> Request<Body> {
        let body = serde_json::json!({
            "rotationKeyPublic": ceremony.rotation_key_public,
            "signedCreationOp": ceremony.signed_op,
            "password": "test-password",
            "recoveryKey": recovery_key,
            "escrowShare": escrow_share,
        });
        Request::builder()
            .method("POST")
            .uri("/v1/dids")
            .header("Authorization", format!("Bearer {session_token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// The full client-share happy path: promotion succeeds, the response carries no share
    /// material, the DB holds exactly one share (the wrapped Share 2 envelope) and zero
    /// pending_share_* data, and the escrowed envelope reconstructs to the seed whose
    /// derived key sits at rotationKeys[1].
    #[tokio::test]
    async fn client_share_ceremony_promotes_without_returning_shares() {
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
        let ceremony = make_client_share_ceremony(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );
        let escrow_share = ceremony.envelopes[1].encode_share();

        let app = crate::app::app(state.clone());
        let response = app
            .oneshot(client_share_request(
                &setup.session_token,
                &ceremony,
                &ceremony.recovery_key_id,
                &escrow_share,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "expected 200 OK");
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let did = body["did"].as_str().expect("did present").to_string();

        // The response must not return any share material on this path.
        assert!(
            body.get("shamir_share_1").is_none(),
            "client-share response must not carry shamir_share_1"
        );
        assert!(
            body.get("shamir_share_3").is_none(),
            "client-share response must not carry shamir_share_3"
        );

        // The op's rotationKeys are [device, recovery, PDS], in that order.
        let verified = crypto::verify_genesis_op(
            &serde_json::to_string(&ceremony.signed_op).unwrap(),
            &crypto::DidKeyUri(ceremony.rotation_key_public.clone()),
        )
        .unwrap();
        assert_eq!(
            verified.rotation_keys,
            vec![
                ceremony.rotation_key_public.clone(),
                ceremony.recovery_key_id.clone(),
                setup.repo_signing_key_id.clone(),
            ],
            "rotationKeys must be [device, recovery, PDS] in order"
        );

        // Server DB: exactly one share — the wrapped Share 2 envelope — and nothing legacy.
        let recovery_share: Option<String> =
            sqlx::query_scalar("SELECT recovery_share FROM accounts WHERE did = ?")
                .bind(&did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            recovery_share.is_none(),
            "accounts.recovery_share must stay NULL on the client-share path"
        );
        let escrow_encrypted: String =
            sqlx::query_scalar("SELECT share_encrypted FROM recovery_escrow WHERE did = ?")
                .bind(&did)
                .fetch_one(&db)
                .await
                .expect("escrow row must exist");
        let unwrapped = crypto::decrypt_secret_bytes(
            &escrow_encrypted,
            &crate::routes::test_utils::test_master_key(),
        )
        .expect("escrow ciphertext must unwrap under the configured KEK");
        let stored_envelope = crypto::ShareEnvelope::from_bytes(&unwrapped).unwrap();
        assert_eq!(stored_envelope.index(), 2);
        assert_eq!(stored_envelope.set_id(), ceremony.envelopes[1].set_id());

        // The pending row (and any pending_share_* columns with it) is gone.
        let pending_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pending_accounts WHERE id = ?")
                .bind(&setup.account_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(pending_count, 0, "pending_accounts row should be deleted");

        // The deposit is audited atomically with promotion.
        let events: Vec<String> = sqlx::query_scalar(
            "SELECT event_type FROM recovery_audit_events WHERE did = ? ORDER BY rowid",
        )
        .bind(&did)
        .fetch_all(&db)
        .await
        .unwrap();
        assert_eq!(events, vec!["deposited"]);

        // Recovery harness check: Shares 1 + 3 (the wallet's + the user's) reconstruct a
        // seed whose derived public key is exactly rotationKeys[1].
        let seed =
            crypto::combine_envelopes(&ceremony.envelopes[0], &ceremony.envelopes[2]).unwrap();
        let rederived = crypto::derive_recovery_keypair(&seed).unwrap();
        assert_eq!(
            rederived.key_id.0, verified.rotation_keys[1],
            "derived recovery pubkey must match rotationKeys[1]"
        );
        // And the escrowed Share 2 combines with Share 1 to the same seed.
        let stored_seed =
            crypto::combine_envelopes(&ceremony.envelopes[0], &stored_envelope).unwrap();
        assert_eq!(*stored_seed, *seed);
    }

    /// A client-share retry (pending_did already set, no pending shares) skips
    /// plc.directory and still lands the escrow deposit at promotion.
    #[tokio::test]
    async fn client_share_retry_skips_plc_and_deposits_escrow() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .named("plc.directory should not be called")
            .mount(&mock_server)
            .await;

        let state = test_state_for_did(mock_server.uri()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let ceremony = make_client_share_ceremony(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

        // Simulate a first attempt that reached the pre-store but died before promotion:
        // pending_did set, pending_share_* untouched (the client-share path never writes them).
        let verified = crypto::verify_genesis_op(
            &serde_json::to_string(&ceremony.signed_op).unwrap(),
            &crypto::DidKeyUri(ceremony.rotation_key_public.clone()),
        )
        .unwrap();
        sqlx::query("UPDATE pending_accounts SET pending_did = ? WHERE id = ?")
            .bind(&verified.did)
            .bind(&setup.account_id)
            .execute(&db)
            .await
            .unwrap();

        let escrow_share = ceremony.envelopes[1].encode_share();
        let response = crate::app::app(state)
            .oneshot(client_share_request(
                &setup.session_token,
                &ceremony,
                &ceremony.recovery_key_id,
                &escrow_share,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "retry should return 200");

        let escrow_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM recovery_escrow WHERE did = ?")
                .bind(&verified.did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(escrow_count, 1, "the retry deposits exactly one escrow row");
        // wiremock verifies expect(0) on drop
    }

    /// A declared recovery key that does not appear in the op's rotationKeys is refused —
    /// the escrow deposit and the DID's public state must never diverge.
    #[tokio::test]
    async fn client_share_recovery_key_not_in_op_returns_400() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let ceremony = make_client_share_ceremony(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

        // Declare a different (validly-formatted) recovery key than the op carries.
        let unrelated = crypto::generate_p256_keypair().unwrap().key_id.0;
        let escrow_share = ceremony.envelopes[1].encode_share();
        let response = crate::app::app(state)
            .oneshot(client_share_request(
                &setup.session_token,
                &ceremony,
                &unrelated,
                &escrow_share,
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

    /// The escrow slot holds Share 2 only — depositing Share 1 or 3 is refused before any
    /// state is written.
    #[tokio::test]
    async fn client_share_wrong_index_escrow_share_returns_400() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let ceremony = make_client_share_ceremony(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

        // Share 3 (the user's copy) must be refused by the escrow.
        let share_3 = ceremony.envelopes[2].encode_share();
        let response = crate::app::app(state)
            .oneshot(client_share_request(
                &setup.session_token,
                &ceremony,
                &ceremony.recovery_key_id,
                &share_3,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "expected 400");
    }

    /// A malformed escrow share fails structural validation loudly.
    #[tokio::test]
    async fn client_share_malformed_escrow_share_returns_400() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let ceremony = make_client_share_ceremony(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

        let response = crate::app::app(state)
            .oneshot(client_share_request(
                &setup.session_token,
                &ceremony,
                &ceremony.recovery_key_id,
                "NOT-A-SHARE",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "expected 400");
    }

    /// The client-share fields travel together: a half-shaped request (either field alone)
    /// is a client bug and must not silently fall back to server-side generation.
    #[tokio::test]
    async fn client_share_half_shaped_request_returns_400() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let ceremony = make_client_share_ceremony(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );
        let escrow_share = ceremony.envelopes[1].encode_share().to_string();

        for (recovery_key, escrow) in [
            (Some(ceremony.recovery_key_id.clone()), None::<String>),
            (None, Some(escrow_share)),
        ] {
            let mut body = serde_json::json!({
                "rotationKeyPublic": ceremony.rotation_key_public,
                "signedCreationOp": ceremony.signed_op,
                "password": "test-password",
            });
            if let Some(rk) = recovery_key {
                body["recoveryKey"] = serde_json::json!(rk);
            }
            if let Some(es) = escrow {
                body["escrowShare"] = serde_json::json!(es);
            }
            let request = Request::builder()
                .method("POST")
                .uri("/v1/dids")
                .header("Authorization", format!("Bearer {}", setup.session_token))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            let response = crate::app::app(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "half-shaped client-share request must be rejected"
            );
        }
    }

    /// The client-share ceremony is did:plc only — a did:web document alongside the new
    /// fields is refused before any state is written.
    #[tokio::test]
    async fn client_share_with_did_web_document_returns_400() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;
        let ceremony = make_client_share_ceremony(
            &setup.handle,
            &state.config.public_url,
            &setup.repo_signing_key_id,
        );

        let body = serde_json::json!({
            "rotationKeyPublic": ceremony.rotation_key_public,
            "didWebDocument": "{}",
            "password": "test-password",
            "recoveryKey": ceremony.recovery_key_id,
            "escrowShare": ceremony.envelopes[1].encode_share().to_string(),
        });
        let request = Request::builder()
            .method("POST")
            .uri("/v1/dids")
            .header("Authorization", format!("Bearer {}", setup.session_token))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = crate::app::app(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "expected 400");
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
