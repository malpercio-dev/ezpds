// pattern: Imperative Shell

use common::{ApiError, ErrorCode};
use sqlx::SqlitePool;

use crate::code_gen::generate_code;

/// Whether `code` is a currently-redeemable invite code (exists, unredeemed, unexpired). A
/// preflight check only — the authoritative single-use redemption is an atomic UPDATE inside the
/// account-creation transaction.
pub async fn claim_code_valid(db: &SqlitePool, code: &str) -> Result<bool, ApiError> {
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM claim_codes \
         WHERE code = ? AND redeemed_at IS NULL AND revoked_at IS NULL \
           AND expires_at > datetime('now'))",
    )
    .bind(code)
    .fetch_one(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to validate invite code");
        ApiError::new(ErrorCode::InternalError, "failed to validate invite code")
    })?;

    Ok(valid)
}

/// One claim code's stored lifecycle, plus the rowid pagination cursor. Status is derived,
/// not stored (V004/V041): `redeemed_at`/`revoked_at` are NULL until that transition happens,
/// and expiry is a comparison against the clock — `is_expired` carries that comparison out of
/// SQL so callers never re-derive "now" inconsistently.
pub struct ClaimCodeRow {
    /// Insertion-order sequence (the table's rowid) — the pagination cursor. Rows are never
    /// deleted (revocation is a tombstone), so rowid order is exactly mint order.
    pub row_seq: i64,
    pub code: String,
    pub created_at: String,
    pub expires_at: String,
    pub redeemed_at: Option<String>,
    pub revoked_at: Option<String>,
    /// Whether `expires_at` has passed, evaluated by SQLite at query time.
    pub is_expired: bool,
}

/// Page the claim-code inventory newest-first. `cursor` is the `row_seq` of the last row of
/// the previous page (exclusive); `None` starts from the newest mint.
pub async fn list_claim_codes(
    db: &SqlitePool,
    cursor: Option<i64>,
    limit: u32,
) -> Result<Vec<ClaimCodeRow>, sqlx::Error> {
    let rows = sqlx::query_as::<
        _,
        (
            i64,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            bool,
        ),
    >(
        "SELECT rowid, code, created_at, expires_at, redeemed_at, revoked_at, \
                (expires_at <= datetime('now')) \
         FROM claim_codes \
         WHERE (? IS NULL OR rowid < ?) \
         ORDER BY rowid DESC LIMIT ?",
    )
    .bind(cursor)
    .bind(cursor)
    .bind(limit)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(row_seq, code, created_at, expires_at, redeemed_at, revoked_at, is_expired)| {
                ClaimCodeRow {
                    row_seq,
                    code,
                    created_at,
                    expires_at,
                    redeemed_at,
                    revoked_at,
                    is_expired,
                }
            },
        )
        .collect())
}

/// What a revocation attempt found. Only a never-redeemed, never-revoked code transitions;
/// the other cases let the route report honestly instead of pretending a spent code was killed.
#[derive(Debug, PartialEq, Eq)]
pub enum RevokeClaimCodeOutcome {
    /// This call set `revoked_at`. An expired-but-pending code still revokes (harmless, and
    /// the tombstone records the operator's intent).
    Revoked,
    /// The code was already revoked — idempotent success for the caller.
    AlreadyRevoked,
    /// The code was already redeemed: there is nothing live to kill.
    Redeemed,
    NotFound,
}

/// Revoke a claim code: atomically set `revoked_at` iff the code is unredeemed and not
/// already revoked. The guarded UPDATE is the authoritative transition (mirroring the
/// single-use redemption UPDATEs); the follow-up SELECT only classifies a failed attempt,
/// which is race-free because all three non-transition states are terminal.
pub async fn revoke_claim_code(
    db: &SqlitePool,
    code: &str,
) -> Result<RevokeClaimCodeOutcome, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE claim_codes SET revoked_at = datetime('now') \
         WHERE code = ? AND redeemed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(code)
    .execute(db)
    .await?;
    if result.rows_affected() == 1 {
        return Ok(RevokeClaimCodeOutcome::Revoked);
    }

    let row = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "SELECT redeemed_at, revoked_at FROM claim_codes WHERE code = ?",
    )
    .bind(code)
    .fetch_optional(db)
    .await?;
    Ok(match row {
        Some((Some(_), _)) => RevokeClaimCodeOutcome::Redeemed,
        Some((None, Some(_))) => RevokeClaimCodeOutcome::AlreadyRevoked,
        // The UPDATE matched nothing yet the row is unredeemed and unrevoked: impossible
        // (those states never un-set), so treat it as the closest honest answer.
        Some((None, None)) => RevokeClaimCodeOutcome::NotFound,
        None => RevokeClaimCodeOutcome::NotFound,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum MintClaimCodesError {
    #[error("failed to store claim codes: {0}")]
    Store(sqlx::Error),
    #[error("failed to generate unique claim codes after retries")]
    Exhausted,
}

/// Mint and persist a batch of single-use claim codes.
///
/// Retries on rare code-collision unique violations; any other storage failure is returned
/// immediately so the route can map it to its wire error shape.
pub async fn mint_claim_codes(
    db: &SqlitePool,
    count: u32,
    expires_in_hours: u32,
) -> Result<Vec<String>, MintClaimCodesError> {
    mint_claim_codes_with_generator(db, count, expires_in_hours, generate_code).await
}

async fn mint_claim_codes_with_generator(
    db: &SqlitePool,
    count: u32,
    expires_in_hours: u32,
    mut generate: impl FnMut() -> String,
) -> Result<Vec<String>, MintClaimCodesError> {
    for attempt in 0..3_usize {
        let codes = generate_unique_codes(count as usize, &mut generate);
        match insert_claim_codes(db, &codes, expires_in_hours).await {
            Ok(()) => return Ok(codes),
            Err(e) if super::is_unique_violation(&e) => {
                tracing::warn!(attempt, "claim code uniqueness conflict; retrying");
            }
            Err(e) => return Err(MintClaimCodesError::Store(e)),
        }
    }

    Err(MintClaimCodesError::Exhausted)
}

fn generate_unique_codes(count: usize, generate: &mut impl FnMut() -> String) -> Vec<String> {
    let mut codes = std::collections::HashSet::with_capacity(count);
    while codes.len() < count {
        codes.insert(generate());
    }
    codes.into_iter().collect()
}

async fn insert_claim_codes(
    db: &SqlitePool,
    codes: &[String],
    expires_in_hours: u32,
) -> Result<(), sqlx::Error> {
    let offset = format!("+{expires_in_hours} hours");
    let mut tx = db.begin().await?;
    for code in codes {
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', ?), datetime('now'))",
        )
        .bind(code)
        .bind(&offset)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_pool, run_migrations};

    async fn test_db() -> SqlitePool {
        let db = open_pool("sqlite::memory:").await.expect("test pool");
        run_migrations(&db).await.expect("test migrations");
        db
    }

    #[tokio::test]
    async fn mint_claim_codes_persists_generated_code() {
        let db = test_db().await;

        let codes = mint_claim_codes_with_generator(&db, 1, 24, || "OKCODE".to_string())
            .await
            .expect("mint succeeds");

        assert_eq!(codes, vec!["OKCODE".to_string()]);
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM claim_codes WHERE code = 'OKCODE'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn mint_claim_codes_retries_unique_conflicts_then_exhausts() {
        let db = test_db().await;
        insert_claim_codes(&db, &["DUP123".to_string()], 24)
            .await
            .expect("seed duplicate code");

        let err = mint_claim_codes_with_generator(&db, 1, 24, || "DUP123".to_string())
            .await
            .expect_err("constant duplicate generator exhausts retries");

        assert!(matches!(err, MintClaimCodesError::Exhausted));
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM claim_codes WHERE code = 'DUP123'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(
            count, 1,
            "failed retry attempts must not add duplicate rows"
        );
    }

    #[tokio::test]
    async fn mint_claim_codes_returns_store_error() {
        let db = test_db().await;
        db.close().await;

        let err = mint_claim_codes_with_generator(&db, 1, 24, || "ERR123".to_string())
            .await
            .expect_err("closed pool returns storage error");

        assert!(matches!(err, MintClaimCodesError::Store(_)));
    }

    // ── Inventory: list ───────────────────────────────────────────────────────

    /// Insert one code directly with explicit lifecycle timestamps.
    async fn seed_code(
        db: &SqlitePool,
        code: &str,
        expires_offset: &str,
        redeemed: bool,
        revoked: bool,
    ) {
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at, redeemed_at, revoked_at) \
             VALUES (?, datetime('now', ?), datetime('now'), \
                     CASE WHEN ? THEN datetime('now') END, \
                     CASE WHEN ? THEN datetime('now') END)",
        )
        .bind(code)
        .bind(expires_offset)
        .bind(redeemed)
        .bind(revoked)
        .execute(db)
        .await
        .expect("seed claim code");
    }

    #[tokio::test]
    async fn list_returns_newest_first_with_lifecycle_fields() {
        let db = test_db().await;
        seed_code(&db, "OLDEST", "+24 hours", false, false).await;
        seed_code(&db, "SPENT1", "+24 hours", true, false).await;
        seed_code(&db, "KILLED", "+24 hours", false, true).await;
        seed_code(&db, "LAPSED", "-1 hours", false, false).await;

        let rows = list_claim_codes(&db, None, 10).await.expect("list");

        let codes: Vec<&str> = rows.iter().map(|r| r.code.as_str()).collect();
        assert_eq!(codes, vec!["LAPSED", "KILLED", "SPENT1", "OLDEST"]);
        assert!(rows[0].is_expired, "LAPSED is past its expiry");
        assert!(rows[1].revoked_at.is_some(), "KILLED carries its tombstone");
        assert!(rows[2].redeemed_at.is_some(), "SPENT1 carries redeemed_at");
        assert!(
            !rows[3].is_expired && rows[3].redeemed_at.is_none() && rows[3].revoked_at.is_none(),
            "OLDEST is still pending"
        );
    }

    #[tokio::test]
    async fn list_pages_by_rowid_cursor() {
        let db = test_db().await;
        for code in ["CODE01", "CODE02", "CODE03"] {
            seed_code(&db, code, "+24 hours", false, false).await;
        }

        let first = list_claim_codes(&db, None, 2).await.expect("first page");
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].code, "CODE03");

        let second = list_claim_codes(&db, Some(first[1].row_seq), 2)
            .await
            .expect("second page");
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].code, "CODE01");
    }

    // ── Inventory: revoke ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn revoke_pending_code_sets_tombstone_and_closes_redemption() {
        let db = test_db().await;
        seed_code(&db, "LIVE01", "+24 hours", false, false).await;

        let outcome = revoke_claim_code(&db, "LIVE01").await.expect("revoke");
        assert_eq!(outcome, RevokeClaimCodeOutcome::Revoked);

        assert!(
            !claim_code_valid(&db, "LIVE01").await.expect("preflight"),
            "a revoked code must no longer pass the redemption preflight"
        );
    }

    #[tokio::test]
    async fn revoke_is_idempotent_and_reports_terminal_states() {
        let db = test_db().await;
        seed_code(&db, "LIVE01", "+24 hours", false, false).await;
        seed_code(&db, "SPENT1", "+24 hours", true, false).await;

        revoke_claim_code(&db, "LIVE01").await.expect("first");
        assert_eq!(
            revoke_claim_code(&db, "LIVE01").await.expect("repeat"),
            RevokeClaimCodeOutcome::AlreadyRevoked
        );
        assert_eq!(
            revoke_claim_code(&db, "SPENT1").await.expect("redeemed"),
            RevokeClaimCodeOutcome::Redeemed
        );
        assert_eq!(
            revoke_claim_code(&db, "GHOST1").await.expect("unknown"),
            RevokeClaimCodeOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn revoke_works_on_expired_pending_code() {
        let db = test_db().await;
        seed_code(&db, "LAPSED", "-1 hours", false, false).await;

        assert_eq!(
            revoke_claim_code(&db, "LAPSED").await.expect("revoke"),
            RevokeClaimCodeOutcome::Revoked
        );
    }
}
