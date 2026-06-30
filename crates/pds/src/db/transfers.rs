// pattern: Imperative Shell
//
// Query functions for the V027 `transfers` table and V029 transfer-accepted
// device credentials — planned device-swap sessions. One active transfer per
// account is enforced by the partial unique index `idx_transfers_active_did`;
// see V027__transfers.sql for the schema rationale.

use sqlx::SqlitePool;

use crate::db::{is_unique_violation, unique_violation_column};

/// Outcome of attempting to open a transfer session for an account.
///
/// `DuplicateActive` is a normal domain outcome (the caller maps it to HTTP 409),
/// not an error — keeping the success/expected-conflict split out of `sqlx::Error`.
#[derive(Debug, PartialEq, Eq)]
pub enum InitiateOutcome {
    /// A new `pending` transfer row was created. Carries the stored `expires_at`
    /// (computed by SQLite) so the handler can echo it back to the client verbatim.
    Created { expires_at: String },
    /// An unexpired active transfer already exists for this DID; none was created.
    DuplicateActive,
    /// The supplied `code` collides with another account's active transfer. None was
    /// created; the caller should regenerate the code and retry.
    CodeCollision,
}

/// Open a new transfer session for `did`, enforcing one active transfer per account.
///
/// This is a single-table atomic operation, so it owns its transaction. It first sweeps
/// any expired-but-still-active row for this DID to `expired` (clearing the partial
/// unique index slot), then inserts the new `pending` row with an `expires_at` of
/// `now + ttl_minutes`. A surviving *unexpired* active row makes the INSERT violate
/// `idx_transfers_active_did`, reported as [`InitiateOutcome::DuplicateActive`]; a `code`
/// already held by another account's active transfer violates `idx_transfers_active_code`,
/// reported as [`InitiateOutcome::CodeCollision`] so the caller can regenerate and retry.
///
/// `id` and `code` are caller-generated (a UUID and a 6-char code, respectively).
pub async fn insert_transfer(
    db: &SqlitePool,
    id: &str,
    did: &str,
    code: &str,
    ttl_minutes: i64,
) -> Result<InitiateOutcome, sqlx::Error> {
    let mut tx = db.begin().await?;

    // Sweep stale active transfers so an expired one never blocks a fresh request.
    // (Only rows already past `expires_at` are touched; a still-valid active transfer
    // is left intact so the INSERT below trips the unique index and reports 409.)
    sqlx::query(
        "UPDATE transfers SET status = 'expired' \
         WHERE did = ? AND status IN ('pending', 'accepted', 'completing') \
           AND expires_at <= datetime('now')",
    )
    .bind(did)
    .execute(&mut *tx)
    .await?;

    // Insert the new pending transfer, letting SQLite compute and return `expires_at`.
    // The `+N minutes` modifier is built as a bound string so the TTL stays a parameter.
    let inserted = sqlx::query_scalar::<_, String>(
        "INSERT INTO transfers (id, did, code, status, expires_at, created_at) \
         VALUES (?, ?, ?, 'pending', datetime('now', ?), datetime('now')) \
         RETURNING expires_at",
    )
    .bind(id)
    .bind(did)
    .bind(code)
    .bind(format!("+{ttl_minutes} minutes"))
    .fetch_one(&mut *tx)
    .await;

    match inserted {
        Ok(expires_at) => {
            tx.commit().await?;
            Ok(InitiateOutcome::Created { expires_at })
        }
        // A partial unique index rejected the row. Dropping `tx` rolls back the
        // (harmless) sweep too; no row was created. Which index fired decides the
        // outcome: a `did` clash means this account already has an active transfer
        // (the 409 path); a `code` clash with another account's active transfer is a
        // regenerate-and-retry. Any other uniqueness failure (e.g. a `id` PK clash, or
        // a column we couldn't classify) is an unexpected insert bug — bubble it rather
        // than masking it as a misleading 409.
        Err(e) if is_unique_violation(&e) => match unique_violation_column(&e, "transfers") {
            Some("did") => Ok(InitiateOutcome::DuplicateActive),
            Some("code") => Ok(InitiateOutcome::CodeCollision),
            _ => Err(e),
        },
        Err(e) => Err(e),
    }
}

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
/// rows for this code are first swept to `expired`, then the still-pending row is locked by
/// the write transaction, the new device token hash is stored, and the transfer advances to
/// `accepted`. A second accept attempt observes `accepted` and does not mint another device.
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
    sqlx::query(
        "UPDATE transfers SET status = 'expired' \
         WHERE code = ? AND status = 'pending' AND expires_at <= datetime('now')",
    )
    .bind(code)
    .execute(&mut *tx)
    .await?;

    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, did, status FROM transfers \
         WHERE code = ? AND status IN ('pending', 'accepted', 'completing')",
    )
    .bind(code)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((transfer_id, did, status)) = row else {
        tx.commit().await?;
        return Ok(AcceptOutcome::InvalidOrExpired);
    };

    if status != "pending" {
        tx.commit().await?;
        return Ok(AcceptOutcome::NotPending);
    }

    sqlx::query(
        "INSERT INTO transfer_devices \
         (id, did, platform, public_key, device_token_hash, created_at, last_seen_at) \
         VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
    )
    .bind(device_id)
    .bind(&did)
    .bind(platform)
    .bind(public_key)
    .bind(device_token_hash)
    .execute(&mut *tx)
    .await?;

    let updated = sqlx::query(
        "UPDATE transfers \
         SET status = 'accepted', accepted_device_id = ?, accepted_at = datetime('now') \
         WHERE id = ? AND status = 'pending' AND expires_at > datetime('now')",
    )
    .bind(device_id)
    .bind(&transfer_id)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() != 1 {
        sqlx::query("DELETE FROM transfer_devices WHERE id = ?")
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE transfers SET status = 'expired' \
             WHERE id = ? AND status = 'pending' AND expires_at <= datetime('now')",
        )
        .bind(&transfer_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(AcceptOutcome::InvalidOrExpired);
    }

    tx.commit().await?;
    Ok(AcceptOutcome::Accepted { transfer_id })
}

/// Check whether a promoted-account transfer device matches the supplied token hash.
pub async fn transfer_device_token_exists(
    db: &SqlitePool,
    device_id: &str,
    token_hash: &str,
) -> Result<bool, sqlx::Error> {
    let found: Option<(String,)> =
        sqlx::query_as("SELECT id FROM transfer_devices WHERE id = ? AND device_token_hash = ?")
            .bind(device_id)
            .bind(token_hash)
            .fetch_optional(db)
            .await?;

    Ok(found.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;

    async fn seed_account(db: &SqlitePool, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn first_transfer_is_created() {
        let state = test_state().await;
        seed_account(&state.db, "did:plc:initiate1").await;

        let outcome = insert_transfer(&state.db, "t1", "did:plc:initiate1", "ABC123", 15)
            .await
            .unwrap();

        assert!(matches!(outcome, InitiateOutcome::Created { .. }));
    }

    #[tokio::test]
    async fn second_active_transfer_is_rejected() {
        let state = test_state().await;
        seed_account(&state.db, "did:plc:initiate2").await;

        insert_transfer(&state.db, "t1", "did:plc:initiate2", "ABC123", 15)
            .await
            .unwrap();
        let outcome = insert_transfer(&state.db, "t2", "did:plc:initiate2", "DEF456", 15)
            .await
            .unwrap();

        assert_eq!(outcome, InitiateOutcome::DuplicateActive);
    }

    #[tokio::test]
    async fn expired_transfer_does_not_block_new_one() {
        let state = test_state().await;
        seed_account(&state.db, "did:plc:initiate3").await;

        // A pending transfer that has already expired.
        sqlx::query(
            "INSERT INTO transfers (id, did, code, status, expires_at, created_at) \
             VALUES ('old', 'did:plc:initiate3', 'OLD000', 'pending', \
                     datetime('now', '-1 minute'), datetime('now', '-16 minutes'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let outcome = insert_transfer(&state.db, "new", "did:plc:initiate3", "NEW111", 15)
            .await
            .unwrap();

        assert!(
            matches!(outcome, InitiateOutcome::Created { .. }),
            "an expired transfer must be swept aside, not block a new one"
        );

        // The stale row was swept to `expired`, and exactly one active row remains.
        let active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM transfers WHERE did = 'did:plc:initiate3' \
             AND status IN ('pending', 'accepted', 'completing')",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(active, 1);
    }

    #[tokio::test]
    async fn duplicate_active_code_reports_collision() {
        let state = test_state().await;
        seed_account(&state.db, "did:plc:codea").await;
        seed_account(&state.db, "did:plc:codeb").await;

        // Account A holds an active transfer with a known code.
        let a = insert_transfer(&state.db, "ta", "did:plc:codea", "DUP123", 15)
            .await
            .unwrap();
        assert!(matches!(a, InitiateOutcome::Created { .. }));

        // A *different* account taking the same active code is a collision (caller
        // retries with a new code), distinct from the per-account DuplicateActive 409.
        let b = insert_transfer(&state.db, "tb", "did:plc:codeb", "DUP123", 15)
            .await
            .unwrap();
        assert_eq!(b, InitiateOutcome::CodeCollision);
    }
}
