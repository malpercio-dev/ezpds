// pattern: Imperative Shell

//! The syncer-notice queue (`space_syncer_notice_retries`, V082): the `spaceDeleted` and
//! `registrationExpired` notices a space host owes its registered syncers, one row per
//! registration, plus the registration-row edits that go with them. The schedule and the guards
//! are `space_notify_retry`'s; this is SQL only.
//!
//! Every time is unix seconds, bound by the caller, so the statements that claim a lapse and
//! queue its notice agree on what "lapsed" means.

use sqlx::{SqliteConnection, SqlitePool};

/// One queued notice. The `retry_at` read with it is the row's version: [`clear`] and
/// [`reschedule`] match it, so a row re-queued since (a deletion replacing an expiry) is left
/// alone.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct NoticeRow {
    pub space_uri: String,
    pub endpoint: String,
    pub token: String,
    /// The `update` JSON the syncer is sent.
    pub notice: String,
    pub attempts: i64,
    pub retry_at: i64,
    pub expires_at: i64,
}

/// Queue `notice` (a `spaceDeleted`) for every registration of the space, lapsed included,
/// replacing whatever is pending for each. Run inside the deletion's transaction, before its
/// registrations are dropped.
pub async fn queue_space_deleted(
    conn: &mut SqliteConnection,
    space_uri: &str,
    notice: &str,
    retry_at: i64,
    expires_at: i64,
) -> Result<u64, sqlx::Error> {
    let queued = sqlx::query(
        "INSERT INTO space_syncer_notice_retries \
         (space_uri, endpoint, token, notice, attempts, retry_at, expires_at) \
         SELECT space_uri, endpoint, token, ?1, 0, ?2, ?3 FROM space_notify_registrations \
         WHERE space_uri = ?4 \
         ON CONFLICT (space_uri, endpoint, token) DO UPDATE SET \
           notice = excluded.notice, attempts = 0, \
           retry_at = excluded.retry_at, expires_at = excluded.expires_at",
    )
    .bind(notice)
    .bind(retry_at)
    .bind(expires_at)
    .bind(space_uri)
    .execute(&mut *conn)
    .await?;
    Ok(queued.rows_affected())
}

/// Claim every registration of the space that lapsed by `now` and has not been claimed yet, and
/// queue `notice` (a `registrationExpired`) for each, in one transaction. A pending notice is
/// never replaced, so a deletion notice is never lost to an expiry. Each lapse is claimed once,
/// so a syncer is owed a single expiry notice however many updates follow.
pub async fn claim_lapsed(
    pool: &SqlitePool,
    space_uri: &str,
    notice: &str,
    now: i64,
    retry_at: i64,
    expires_at: i64,
) -> Result<u64, sqlx::Error> {
    const LAPSED: &str = "space_uri = ?1 AND expiry_notified = 0 \
                          AND expires_at <= datetime(?2, 'unixepoch')";
    let mut tx = pool.begin().await?;
    sqlx::query(&format!(
        "INSERT INTO space_syncer_notice_retries \
         (space_uri, endpoint, token, notice, attempts, retry_at, expires_at) \
         SELECT space_uri, endpoint, token, ?3, 0, ?4, ?5 FROM space_notify_registrations \
         WHERE {LAPSED} ON CONFLICT (space_uri, endpoint, token) DO NOTHING"
    ))
    .bind(space_uri)
    .bind(now)
    .bind(notice)
    .bind(retry_at)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    let claimed = sqlx::query(&format!(
        "UPDATE space_notify_registrations SET expiry_notified = 1 WHERE {LAPSED}"
    ))
    .bind(space_uri)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(claimed.rows_affected())
}

/// The space's notices no one has tried yet: what the transaction that queued them hands to
/// its immediate attempt.
pub async fn untried(pool: &SqlitePool, space_uri: &str) -> Result<Vec<NoticeRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT * FROM space_syncer_notice_retries WHERE space_uri = ? AND attempts = 0 \
         ORDER BY endpoint, token",
    )
    .bind(space_uri)
    .fetch_all(pool)
    .await
}

/// Up to `limit` notices due by `now`, oldest first.
pub async fn due(pool: &SqlitePool, now: i64, limit: i64) -> Result<Vec<NoticeRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT * FROM space_syncer_notice_retries WHERE retry_at <= ? \
         ORDER BY retry_at LIMIT ?",
    )
    .bind(now)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Drop a notice: delivered, abandoned, or no longer owed.
pub async fn clear(pool: &SqlitePool, row: &NoticeRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM space_syncer_notice_retries \
         WHERE space_uri = ? AND endpoint = ? AND token = ? AND retry_at = ?",
    )
    .bind(&row.space_uri)
    .bind(&row.endpoint)
    .bind(&row.token)
    .bind(row.retry_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Record a failed try and when to try next.
pub async fn reschedule(
    pool: &SqlitePool,
    row: &NoticeRow,
    attempts: i64,
    retry_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE space_syncer_notice_retries SET attempts = ?, retry_at = ? \
         WHERE space_uri = ? AND endpoint = ? AND token = ? AND retry_at = ?",
    )
    .bind(attempts)
    .bind(retry_at)
    .bind(&row.space_uri)
    .bind(&row.endpoint)
    .bind(&row.token)
    .bind(row.retry_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Whether the row's registration exists and is still lapsed at `now`: an expiry notice is owed
/// only then, never once the syncer has renewed.
pub async fn registration_lapsed(
    pool: &SqlitePool,
    row: &NoticeRow,
    now: i64,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM space_notify_registrations \
         WHERE space_uri = ? AND endpoint = ? AND token = ? \
         AND expires_at <= datetime(?, 'unixepoch'))",
    )
    .bind(&row.space_uri)
    .bind(&row.endpoint)
    .bind(&row.token)
    .bind(now)
    .fetch_one(pool)
    .await
}

/// Delete the row's registration if it is still lapsed at `now`, once its expiry notice is
/// delivered or abandoned. A registration renewed since is left alone.
pub async fn remove_lapsed_registration(
    pool: &SqlitePool,
    row: &NoticeRow,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM space_notify_registrations \
         WHERE space_uri = ? AND endpoint = ? AND token = ? \
         AND expires_at <= datetime(?, 'unixepoch')",
    )
    .bind(&row.space_uri)
    .bind(&row.endpoint)
    .bind(&row.token)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete every space's registrations that lapsed before `before` without their expiry notice
/// being claimed. Returns how many went.
pub async fn prune_unnotified_lapses(pool: &SqlitePool, before: i64) -> Result<u64, sqlx::Error> {
    let pruned = sqlx::query(
        "DELETE FROM space_notify_registrations \
         WHERE expiry_notified = 0 AND expires_at <= datetime(?, 'unixepoch')",
    )
    .bind(before)
    .execute(pool)
    .await?;
    Ok(pruned.rows_affected())
}
