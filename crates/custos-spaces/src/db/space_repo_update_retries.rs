// pattern: Imperative Shell

//! The repo-update queue (`space_repo_update_retries`, V084): the `notifyRepoUpdate` a repo host
//! owes a foreign space host, one row per `(repo, space)`, coalesced to the newest rev. The
//! schedule and the guards are `space_notify_retry`'s; this is SQL only. Times are unix seconds.

use sqlx::{SqliteConnection, SqlitePool};

/// One queued update. `repo_rev` and `attempts` read with it are the row's version:
/// [`reschedule`] matches both, so a row a newer commit has replaced since is left alone.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct RepoUpdateRow {
    pub repo_did: String,
    pub space_uri: String,
    pub repo_rev: String,
    /// The repo's set hash at `repo_rev`.
    pub data: Vec<u8>,
    pub attempts: i64,
    pub retry_at: i64,
    pub expires_at: i64,
}

/// Queue the update for `(repo, space)` at `repo_rev`, inside the commit's transaction. A newer
/// rev replaces what is pending and restarts its schedule and window; an older one changes nothing.
pub async fn queue(
    conn: &mut SqliteConnection,
    repo_did: &str,
    space_uri: &str,
    repo_rev: &str,
    data: &[u8],
    retry_at: i64,
    expires_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO space_repo_update_retries \
         (repo_did, space_uri, repo_rev, data, attempts, retry_at, expires_at) \
         VALUES (?, ?, ?, ?, 0, ?, ?) \
         ON CONFLICT (repo_did, space_uri) DO UPDATE SET \
           repo_rev = excluded.repo_rev, data = excluded.data, attempts = 0, \
           retry_at = excluded.retry_at, expires_at = excluded.expires_at \
         WHERE space_repo_update_retries.repo_rev < excluded.repo_rev",
    )
    .bind(repo_did)
    .bind(space_uri)
    .bind(repo_rev)
    .bind(data)
    .bind(retry_at)
    .bind(expires_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The pending update for `(repo, space)`, if any: what the commit hands its immediate attempt.
pub async fn pending(
    pool: &SqlitePool,
    repo_did: &str,
    space_uri: &str,
) -> Result<Option<RepoUpdateRow>, sqlx::Error> {
    sqlx::query_as("SELECT * FROM space_repo_update_retries WHERE repo_did = ? AND space_uri = ?")
        .bind(repo_did)
        .bind(space_uri)
        .fetch_optional(pool)
        .await
}

/// Up to `limit` updates due by `now`, oldest first.
pub async fn due(
    pool: &SqlitePool,
    now: i64,
    limit: i64,
) -> Result<Vec<RepoUpdateRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT * FROM space_repo_update_retries WHERE retry_at <= ? ORDER BY retry_at LIMIT ?",
    )
    .bind(now)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Drop the update once `row`'s rev is delivered, abandoned or no longer owed. A newer rev queued
/// since stays.
pub async fn clear(pool: &SqlitePool, row: &RepoUpdateRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM space_repo_update_retries \
         WHERE repo_did = ? AND space_uri = ? AND repo_rev <= ?",
    )
    .bind(&row.repo_did)
    .bind(&row.space_uri)
    .bind(&row.repo_rev)
    .execute(pool)
    .await?;
    Ok(())
}

/// Drop the update for `(repo, space)` if its window has closed by `now`. Whether one was dropped.
pub async fn expire(pool: &SqlitePool, row: &RepoUpdateRow, now: i64) -> Result<bool, sqlx::Error> {
    let dropped = sqlx::query(
        "DELETE FROM space_repo_update_retries \
         WHERE repo_did = ? AND space_uri = ? AND expires_at <= ?",
    )
    .bind(&row.repo_did)
    .bind(&row.space_uri)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(dropped.rows_affected() > 0)
}

/// Record a failed or paused try and when to try next.
pub async fn reschedule(
    pool: &SqlitePool,
    row: &RepoUpdateRow,
    attempts: i64,
    retry_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE space_repo_update_retries SET attempts = ?, retry_at = ? \
         WHERE repo_did = ? AND space_uri = ? AND repo_rev = ? AND attempts = ?",
    )
    .bind(attempts)
    .bind(retry_at)
    .bind(&row.repo_did)
    .bind(&row.space_uri)
    .bind(&row.repo_rev)
    .bind(row.attempts)
    .execute(pool)
    .await?;
    Ok(())
}
