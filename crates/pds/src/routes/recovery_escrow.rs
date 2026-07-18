// pattern: Imperative Shell
//
// Owner endpoints for the PDS-held Shamir Share 2 (the escrow half of share-based recovery):
//
//   PUT    /v1/recovery/escrow-share — deposit or replace the account's Share 2 envelope
//   DELETE /v1/recovery/escrow-share — opt out of escrow entirely (idempotent)
//
// The share arrives as the v2 base32 share envelope the wallet produced client-side; the server
// validates it structurally (well-formed envelope, index 2 — Custos never holds any other share)
// and stores only the AES-256-GCM master-KEK wrapping of its 42 envelope bytes
// (`crypto::encrypt_secret_bytes`, the shared `SecretFamily` ciphertext format — the base
// envelope deliberately, with no per-row AAD divergence from the other wrapped columns). One
// share is information-theoretically worthless alone, so the wrapping is defense-in-depth: a raw
// DB dump or backup never exposes even that.
//
// Each state change appends its `recovery_audit_events` row in the same transaction
// (`deposited` / `rotated` / `deleted` — mechanical facts only, never share material). The
// repeat DELETE is a 200 no-op with no duplicate event.
//
// Auth is `auth::guards::authenticate_account_owner` (wallet session token or full-access
// OAuth/XRPC token; agent-derived and app-password credentials refused) — the ceremony deposit,
// the rotation epilogue, and the old-account re-key all act as the owner. These live on the
// same-origin `/v1/*` surface (no permissive CORS).

use axum::{
    extract::State,
    http::{HeaderMap, Method, Uri},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::guards::{authenticate_account_owner, OwnerAuthError};
use crate::db::recovery_audit::{insert_recovery_audit_event, RecoveryAuditEventType};
use crate::db::recovery_escrow::{
    delete_escrow_share, escrow_share_exists, insert_escrow_share, null_legacy_recovery_share,
    replace_escrow_share,
};
use common::{ApiError, ErrorCode};

/// Authenticate the account owner and map the neutral rejection into this surface's vocabulary.
/// Mirrors `agents.rs`'s wrapper (routes may not import one another).
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

/// The escrow slot always holds Share 2 — the index reserved for Custos in the 2-of-3 split.
const ESCROW_SHARE_INDEX: u8 = 2;

// ── PUT /v1/recovery/escrow-share ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PutEscrowShareRequest {
    /// The base32-encoded v2 share envelope (as produced by the wallet's client-side split).
    pub share: String,
}

#[derive(Serialize)]
pub struct PutEscrowShareResponse {
    /// `"deposited"` for an account's first escrow, `"rotated"` for a replacement.
    pub status: &'static str,
}

pub async fn put_escrow_share(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Json(payload): Json<PutEscrowShareRequest>,
) -> Result<Json<PutEscrowShareResponse>, ApiError> {
    let did = authenticate_owner(&headers, &method, &uri, &state).await?;

    // Structural validation before anything is stored: a malformed or corrupted share fails
    // loudly now, not at recovery time. Decode errors are reported by kind (version / checksum /
    // format — `decode_share` distinguishes them) but never echo the submitted material.
    let envelope = crypto::ShareEnvelope::decode_share(&payload.share)
        .map_err(|e| ApiError::new(ErrorCode::InvalidRequest, format!("invalid share: {e}")))?;
    if envelope.index() != ESCROW_SHARE_INDEX {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "escrow holds Share 2 only; refusing a share with a different index",
        ));
    }

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
    let wrapped = crypto::encrypt_secret_bytes(envelope.to_bytes().as_slice(), master_key)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to wrap escrow share");
            ApiError::new(ErrorCode::InternalError, "failed to store escrow share")
        })?;

    let map_err = |e: sqlx::Error| {
        tracing::error!(did = %did, error = %e, "DB error storing escrow share");
        ApiError::new(ErrorCode::InternalError, "failed to store escrow share")
    };

    // Replace-or-insert plus its audit event, atomically. `detail` records the envelope's
    // non-secret metadata so a rotation is auditable against the share generation it installed.
    let mut tx = state.db.begin().await.map_err(map_err)?;
    let event = if escrow_share_exists(&mut *tx, &did).await.map_err(map_err)? {
        replace_escrow_share(&mut *tx, &did, &wrapped)
            .await
            .map_err(map_err)?;
        RecoveryAuditEventType::Rotated
    } else {
        insert_escrow_share(&mut *tx, &did, &wrapped)
            .await
            .map_err(map_err)?;
        RecoveryAuditEventType::Deposited
    };
    // A re-key of an old-model account (MM-411) voids the dead legacy Share 2
    // (`accounts.recovery_share`, V010) in the same transaction: once a client-generated Share 2
    // is escrowed, the server-generated legacy split protects nothing and must not survive in
    // backups. Idempotent for accounts that never had one, so it is safe on every deposit path.
    let legacy_voided = null_legacy_recovery_share(&mut *tx, &did)
        .await
        .map_err(map_err)?;
    let detail = serde_json::json!({
        "set_id": envelope.set_id(),
        "version": envelope.version(),
        "legacy_voided": legacy_voided,
    });
    insert_recovery_audit_event(
        &mut *tx,
        &Uuid::new_v4().to_string(),
        &did,
        event,
        Some(&detail.to_string()),
    )
    .await?;
    tx.commit().await.map_err(map_err)?;

    Ok(Json(PutEscrowShareResponse {
        status: event.as_str(),
    }))
}

// ── DELETE /v1/recovery/escrow-share ──────────────────────────────────────────

#[derive(Serialize)]
pub struct DeleteEscrowShareResponse {
    /// Always `"deleted"` — the terminal state holds whether or not a share existed.
    pub status: &'static str,
}

pub async fn delete_escrow_share_handler(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<DeleteEscrowShareResponse>, ApiError> {
    let did = authenticate_owner(&headers, &method, &uri, &state).await?;

    let map_err = |e: sqlx::Error| {
        tracing::error!(did = %did, error = %e, "DB error deleting escrow share");
        ApiError::new(ErrorCode::InternalError, "failed to delete escrow share")
    };

    // Delete plus its audit event, atomically — but only a real deletion is audited, so the
    // idempotent repeat call leaves no duplicate event.
    let mut tx = state.db.begin().await.map_err(map_err)?;
    let deleted = delete_escrow_share(&mut *tx, &did).await.map_err(map_err)?;
    if deleted {
        insert_recovery_audit_event(
            &mut *tx,
            &Uuid::new_v4().to_string(),
            &did,
            RecoveryAuditEventType::Deleted,
            None,
        )
        .await?;
    }
    tx.commit().await.map_err(map_err)?;

    Ok(Json(DeleteEscrowShareResponse { status: "deleted" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{test_state, AppState};
    use crate::routes::test_utils::test_master_key;
    use axum::http::HeaderValue;
    use std::sync::Arc;

    /// Test state with the master key configured (wrapping requires it).
    async fn escrow_state() -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(
            test_master_key(),
        )));
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    async fn seed_account(db: &sqlx::SqlitePool, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(db)
        .await
        .expect("seed account");
    }

    /// Insert a wallet session for the DID and return headers bearing its token.
    async fn session_headers(db: &sqlx::SqlitePool, did: &str) -> HeaderMap {
        let token = crate::auth::token::generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(did)
        .bind(&token.hash)
        .execute(db)
        .await
        .expect("seed session");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token.plaintext)).unwrap(),
        );
        headers
    }

    fn share_envelope(set_id: u32, index: usize) -> String {
        let seed = [0x5a_u8; 32];
        let envelopes = crypto::split_secret_into_envelopes(&seed, set_id).unwrap();
        envelopes[index].encode_share().to_string()
    }

    async fn put_share(
        state: &AppState,
        headers: &HeaderMap,
        share: &str,
    ) -> Result<String, ApiError> {
        let response = put_escrow_share(
            State(state.clone()),
            Method::PUT,
            Uri::from_static("/v1/recovery/escrow-share"),
            headers.clone(),
            Json(PutEscrowShareRequest {
                share: share.to_string(),
            }),
        )
        .await?;
        Ok(response.0.status.to_string())
    }

    async fn delete_share(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
        let response = delete_escrow_share_handler(
            State(state.clone()),
            Method::DELETE,
            Uri::from_static("/v1/recovery/escrow-share"),
            headers.clone(),
        )
        .await?;
        Ok(response.0.status.to_string())
    }

    async fn audit_events(db: &sqlx::SqlitePool, did: &str) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT event_type FROM recovery_audit_events WHERE did = ? ORDER BY rowid",
        )
        .bind(did)
        .fetch_all(db)
        .await
        .unwrap()
    }

    async fn stored_row(db: &sqlx::SqlitePool, did: &str) -> Option<(String, Option<String>)> {
        sqlx::query_as("SELECT share_encrypted, rotated_at FROM recovery_escrow WHERE did = ?")
            .bind(did)
            .fetch_optional(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn deposit_replace_delete_lifecycle_with_audit_trail() {
        let state = escrow_state().await;
        let did = "did:plc:escrowroute";
        seed_account(&state.db, did).await;
        let headers = session_headers(&state.db, did).await;

        // Deposit.
        let share_a = share_envelope(1, 1);
        assert_eq!(
            put_share(&state, &headers, &share_a).await.unwrap(),
            "deposited"
        );

        // The stored ciphertext is wrapped — the raw row never contains the share, and it
        // unwraps back to the exact envelope bytes under the master key.
        let (stored_share, _) = stored_row(&state.db, did).await.unwrap();
        assert!(!stored_share.contains(&share_a));
        let unwrapped = crypto::decrypt_secret_bytes(&stored_share, &test_master_key()).unwrap();
        let envelope = crypto::ShareEnvelope::from_bytes(&unwrapped).unwrap();
        assert_eq!(envelope.set_id(), 1);
        assert_eq!(envelope.index(), 2);

        // Replace (rotation epilogue / re-key).
        let share_b = share_envelope(2, 1);
        assert_eq!(
            put_share(&state, &headers, &share_b).await.unwrap(),
            "rotated"
        );
        let (stored_share, rotated_at) = stored_row(&state.db, did).await.unwrap();
        let unwrapped = crypto::decrypt_secret_bytes(&stored_share, &test_master_key()).unwrap();
        assert_eq!(
            crypto::ShareEnvelope::from_bytes(&unwrapped)
                .unwrap()
                .set_id(),
            2,
            "the replacement generation must be stored"
        );
        assert!(rotated_at.is_some());

        // Delete (opt-out), then the idempotent repeat.
        assert_eq!(delete_share(&state, &headers).await.unwrap(), "deleted");
        assert!(stored_row(&state.db, did).await.is_none());
        assert_eq!(delete_share(&state, &headers).await.unwrap(), "deleted");

        assert_eq!(
            audit_events(&state.db, did).await,
            vec!["deposited", "rotated", "deleted"],
            "one event per real state change; the repeat delete adds none"
        );
    }

    async fn audit_details(db: &sqlx::SqlitePool, did: &str) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT COALESCE(detail, '') FROM recovery_audit_events WHERE did = ? ORDER BY rowid",
        )
        .bind(did)
        .fetch_all(db)
        .await
        .unwrap()
    }

    async fn legacy_recovery_share(db: &sqlx::SqlitePool, did: &str) -> Option<String> {
        sqlx::query_scalar("SELECT recovery_share FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn rekey_deposit_voids_legacy_recovery_share() {
        let state = escrow_state().await;
        let did = "did:plc:legacyrekeydeposit";
        seed_account(&state.db, did).await;
        // Old-model account: a server-generated legacy Share 2 sits in accounts.recovery_share.
        sqlx::query("UPDATE accounts SET recovery_share = ? WHERE did = ?")
            .bind("LEGACYSHARE2")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let headers = session_headers(&state.db, did).await;

        // The re-key deposits its client-generated Share 2 through the standalone PUT.
        assert_eq!(
            put_share(&state, &headers, &share_envelope(7, 1))
                .await
                .unwrap(),
            "deposited"
        );

        // The legacy column is voided in the same transaction, and the audit event records it.
        assert_eq!(
            legacy_recovery_share(&state.db, did).await,
            None,
            "the dead legacy share is nulled on the re-key deposit"
        );
        let details = audit_details(&state.db, did).await;
        assert_eq!(details.len(), 1);
        assert!(
            details[0].contains("\"legacy_voided\":true"),
            "the deposit event records that it voided legacy material: {}",
            details[0]
        );

        // A subsequent rotation deposit has no legacy material left to void.
        assert_eq!(
            put_share(&state, &headers, &share_envelope(8, 1))
                .await
                .unwrap(),
            "rotated"
        );
        let details = audit_details(&state.db, did).await;
        assert!(
            details[1].contains("\"legacy_voided\":false"),
            "a later rotation voids nothing: {}",
            details[1]
        );
    }

    #[tokio::test]
    async fn deposit_without_legacy_material_records_no_void() {
        let state = escrow_state().await;
        let did = "did:plc:cleandeposit";
        seed_account(&state.db, did).await; // no legacy recovery_share
        let headers = session_headers(&state.db, did).await;

        assert_eq!(
            put_share(&state, &headers, &share_envelope(1, 1))
                .await
                .unwrap(),
            "deposited"
        );
        let details = audit_details(&state.db, did).await;
        assert!(
            details[0].contains("\"legacy_voided\":false"),
            "a post-inversion account has nothing to void: {}",
            details[0]
        );
    }

    #[tokio::test]
    async fn malformed_and_wrong_index_shares_are_refused() {
        let state = escrow_state().await;
        let did = "did:plc:escrowbadshare";
        seed_account(&state.db, did).await;
        let headers = session_headers(&state.db, did).await;

        let err = put_share(&state, &headers, "NOT-A-SHARE")
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 400);

        // Share 3 (index 3) is the user's copy — the escrow refuses it.
        let share_3 = share_envelope(1, 2);
        let err = put_share(&state, &headers, &share_3).await.unwrap_err();
        assert_eq!(err.status_code(), 400);

        assert!(
            audit_events(&state.db, did).await.is_empty(),
            "refused deposits leave no state and no audit rows"
        );
    }

    #[tokio::test]
    async fn unauthenticated_requests_are_rejected() {
        let state = escrow_state().await;
        let headers = HeaderMap::new();

        let err = put_share(&state, &headers, &share_envelope(1, 1))
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
        let err = delete_share(&state, &headers).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn missing_master_key_is_service_unavailable() {
        let state = test_state().await; // no master key configured
        let did = "did:plc:escrownokey";
        seed_account(&state.db, did).await;
        let headers = session_headers(&state.db, did).await;

        let err = put_share(&state, &headers, &share_envelope(1, 1))
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 503);
    }
}
