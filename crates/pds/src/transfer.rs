// pattern: Imperative Shell
//
// Higher-level planned-transfer workflows that compose multiple DB tables inside
// request-sized transactions. The `db::transfers` module owns the SQL statements;
// this module owns the cross-table ordering needed to accept and complete a transfer.

use sqlx::SqlitePool;
use uuid::Uuid;

/// Outcome of accepting a transfer code from the new device.
#[derive(Debug, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// The code was valid and the new device credentials were durably registered.
    Accepted { transfer_id: String },
    /// No pending, unexpired transfer matches this code.
    InvalidOrExpired,
    /// The code belongs to a transfer that has already advanced past `pending`.
    NotPending,
}

/// Outcome of completing a transfer handoff.
#[derive(Debug, PartialEq, Eq)]
pub enum CompleteOutcome {
    /// The accepted transfer is now terminal, or was already terminal for this target.
    Completed { transfer_id: String },
    /// No transfer with this id exists, or it is terminal without a valid accepted target.
    Invalid,
    /// The transfer exists but has not been accepted by a target device yet.
    NotAccepted,
    /// The bearer token belongs to neither the source account session nor the accepted target.
    Unauthorized,
}

/// Accept a pending transfer code and atomically register the new device credentials.
///
/// The code is a bearer credential, so acceptance is a single transaction: stale pending
/// rows for this code are first swept to `expired`, then the still-pending row is observed
/// inside the write transaction, the new device token hash is stored, and the transfer
/// advances to `accepted`. A second accept attempt observes `accepted` and does not mint
/// another device.
pub async fn accept_transfer(
    db: &SqlitePool,
    code: &str,
    device_id: &str,
    platform: &str,
    public_key: &str,
    device_token_hash: &str,
) -> Result<AcceptOutcome, sqlx::Error> {
    let mut tx = db.begin().await?;

    // Materialise expiry before lookup so an expired code is indistinguishable from an
    // unknown code to the caller and the active-code partial index slot is released.
    crate::db::transfers::expire_pending_code(&mut tx, code).await?;

    let Some(row) = crate::db::transfers::active_transfer_for_code(&mut tx, code).await? else {
        tx.commit().await?;
        return Ok(AcceptOutcome::InvalidOrExpired);
    };

    if row.status != "pending" {
        tx.commit().await?;
        return Ok(AcceptOutcome::NotPending);
    }

    crate::db::transfers::insert_transfer_device(
        &mut tx,
        device_id,
        &row.did,
        platform,
        public_key,
        device_token_hash,
    )
    .await?;

    let updated = crate::db::transfers::mark_transfer_accepted(&mut tx, &row.id, device_id).await?;

    if updated != 1 {
        crate::db::transfers::delete_transfer_device(&mut tx, device_id).await?;
        crate::db::transfers::expire_pending_transfer_if_elapsed(&mut tx, &row.id).await?;
        tx.commit().await?;
        return Ok(AcceptOutcome::InvalidOrExpired);
    }

    tx.commit().await?;
    Ok(AcceptOutcome::Accepted {
        transfer_id: row.id,
    })
}

/// Complete an accepted transfer and revoke superseded credentials atomically.
///
/// The caller supplies the SHA-256 hash of the Bearer token from the request. The token
/// authorizes completion if it is either an unexpired source session for the transfer DID
/// or the accepted target device token. On the first successful completion, all promoted
/// sessions for the DID are deleted (including the source session used for this request),
/// prior transfer-device credentials are revoked, the accepted target credential is kept,
/// the transfer moves to `complete`, and an audit row is inserted. A repeat call from the
/// accepted target is idempotent and returns `Completed` without duplicating audit rows.
pub async fn complete_transfer(
    db: &SqlitePool,
    transfer_id: &str,
    token_hash: &str,
) -> Result<CompleteOutcome, sqlx::Error> {
    let mut tx = db.begin().await?;

    let Some(row) = crate::db::transfers::transfer_by_id(&mut tx, transfer_id).await? else {
        tx.commit().await?;
        return Ok(CompleteOutcome::Invalid);
    };

    let source_session =
        crate::db::transfers::session_token_matches_did(&mut tx, &row.did, token_hash).await?;

    let Some(accepted_device_id) = row.accepted_device_id.clone() else {
        tx.commit().await?;
        return Ok(match (row.status.as_str(), source_session) {
            ("pending", true) => CompleteOutcome::NotAccepted,
            (_, false) => CompleteOutcome::Unauthorized,
            _ => CompleteOutcome::Invalid,
        });
    };

    let target_device = crate::db::transfers::transfer_device_token_matches(
        &mut tx,
        &accepted_device_id,
        token_hash,
    )
    .await?;

    if !source_session && !target_device {
        tx.commit().await?;
        return Ok(CompleteOutcome::Unauthorized);
    }

    match row.status.as_str() {
        "accepted" | "completing" => {
            let updated = crate::db::transfers::mark_transfer_complete(&mut tx, &row.id).await?;
            if updated != 1 {
                tx.commit().await?;
                return Ok(CompleteOutcome::Invalid);
            }

            crate::db::transfers::delete_refresh_tokens_for_did(&mut tx, &row.did).await?;
            crate::db::transfers::delete_sessions_for_did(&mut tx, &row.did).await?;
            crate::db::transfers::revoke_other_transfer_devices(
                &mut tx,
                &row.did,
                &accepted_device_id,
            )
            .await?;
            crate::db::transfers::insert_transfer_audit_event(
                &mut tx,
                &Uuid::new_v4().to_string(),
                &row.id,
                &row.did,
                "transfer.complete",
                Some(&accepted_device_id),
            )
            .await?;
        }
        "complete" => {
            // Idempotent for the surviving target credential; source sessions were revoked
            // by the first completion and therefore cannot authorize a repeat call.
        }
        "pending" => {
            tx.commit().await?;
            return Ok(CompleteOutcome::NotAccepted);
        }
        _ => {
            tx.commit().await?;
            return Ok(CompleteOutcome::Invalid);
        }
    }

    tx.commit().await?;
    Ok(CompleteOutcome::Completed {
        transfer_id: row.id,
    })
}
