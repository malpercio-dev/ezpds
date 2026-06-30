// pattern: Imperative Shell
//
// Higher-level planned-transfer workflows that compose multiple DB tables inside
// request-sized transactions. The `db::transfers` module owns the SQL statements;
// this module owns the cross-table ordering needed to accept a transfer code.

use sqlx::SqlitePool;

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
