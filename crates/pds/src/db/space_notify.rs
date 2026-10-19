// pattern: Imperative Shell

//! The space-host notification tables: write-notification registrations
//! (`space_notify_registrations`, V065) and the writer set (`space_writers`, V067).
//!
//! One registration table serves both roles the notification flow gives a host, discriminated by
//! `repo_did`:
//!
//! * **Space host** — `registerNotify` stores a whole-space row (`repo_did = ''`, the sentinel
//!   the V065 primary key is built around): notify this subscriber about *any* repo in the space.
//! * **Repo host** — a first write into a space whose authority lives elsewhere stores a per-repo
//!   row naming the authority's `#atproto_space_host`, so the authority learns of the write. The
//!   spec's auto-registration.
//!
//! `subscriber_did` holds the full **service identifier** the wire carries — a DID with an
//! optional `#fragment` naming the DID-document entry to deliver to. The bare DID (the service
//! auth `aud`) is the part before the fragment.
//!
//! Expiry is enforced by the read query, not by a sweep: re-registering refreshes the existing
//! row through the primary key, so the table grows with the *distinct subscriber* count — its
//! live set — rather than accumulating dead rows.

use sqlx::{Sqlite, SqlitePool};

/// The `repo_did` sentinel for a registration covering every repo in a space. Empty rather than
/// NULL so the primary key can span both shapes (NULLs never compare equal, so a nullable column
/// would admit duplicate rows).
pub const WHOLE_SPACE: &str = "";

/// Record (or renew) a write-notification registration, returning its new expiry.
///
/// Re-registering an existing `(space, service, repo)` replaces it and extends the expiry, which
/// is what `registerNotify` promises and what makes the repo-host auto-registration self-healing:
/// every write renews the authority's subscription rather than letting it lapse mid-conversation.
pub async fn upsert_registration<'e, E>(
    executor: E,
    space_uri: &str,
    service: &str,
    repo_did: &str,
    ttl_secs: i64,
) -> Result<String, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query_scalar(
        "INSERT INTO space_notify_registrations \
         (space_uri, subscriber_did, repo_did, created_at, expires_at) \
         VALUES (?, ?, ?, datetime('now'), datetime('now', '+' || ? || ' seconds')) \
         ON CONFLICT (space_uri, subscriber_did, repo_did) \
         DO UPDATE SET expires_at = excluded.expires_at \
         RETURNING expires_at",
    )
    .bind(space_uri)
    .bind(service)
    .bind(repo_did)
    .bind(ttl_secs)
    .fetch_one(executor)
    .await
}

/// Withdraw a whole-space registration. Idempotent — `unregisterNotify` succeeds either way.
pub async fn delete_registration<'e, E>(
    executor: E,
    space_uri: &str,
    service: &str,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "DELETE FROM space_notify_registrations \
         WHERE space_uri = ? AND subscriber_did = ? AND repo_did = ?",
    )
    .bind(space_uri)
    .bind(service)
    .bind(WHOLE_SPACE)
    .execute(executor)
    .await?;
    Ok(())
}

/// The unexpired subscribers to notify about a write to `repo_did` in `space_uri`: the
/// whole-space registrations plus the ones naming this repo. Ordered so a fan-out is
/// deterministic; capped by `limit` so one space can never spawn an unbounded delivery burst.
pub async fn subscribers_for_write(
    pool: &SqlitePool,
    space_uri: &str,
    repo_did: &str,
    limit: i64,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT subscriber_did FROM space_notify_registrations \
         WHERE space_uri = ? AND (repo_did = ? OR repo_did = ?) AND expires_at > datetime('now') \
         ORDER BY subscriber_did LIMIT ?",
    )
    .bind(space_uri)
    .bind(WHOLE_SPACE)
    .bind(repo_did)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Every unexpired subscriber to a space, whatever repo they registered for — the recipients of
/// `notifySpaceDeleted`.
pub async fn subscribers_for_space(
    pool: &SqlitePool,
    space_uri: &str,
    limit: i64,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT DISTINCT subscriber_did FROM space_notify_registrations \
         WHERE space_uri = ? AND expires_at > datetime('now') \
         ORDER BY subscriber_did LIMIT ?",
    )
    .bind(space_uri)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Record a repo's latest reported head in the writer set — but only when this host is the
/// space's **authority**, which is exactly `spaces.policy IS NOT NULL` (a row with no simplespace
/// config is a space this host only keeps repos in; its authority lives elsewhere and answers
/// `listRepos` itself).
///
/// The guard is in SQL rather than a preceding `SELECT` so the check and the write are one
/// statement, and so a caller inside the write transaction cannot observe a space that stopped
/// being ours between the two.
pub async fn upsert_writer<'e, E>(
    executor: E,
    space_uri: &str,
    repo_did: &str,
    rev: &str,
    hash: &[u8],
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO space_writers (space_uri, repo_did, rev, hash, updated_at) \
         SELECT ?, ?, ?, ?, datetime('now') \
         WHERE EXISTS (SELECT 1 FROM spaces WHERE uri = ? AND policy IS NOT NULL) \
         ON CONFLICT (space_uri, repo_did) \
         DO UPDATE SET rev = excluded.rev, hash = excluded.hash, updated_at = excluded.updated_at",
    )
    .bind(space_uri)
    .bind(repo_did)
    .bind(rev)
    .bind(hash)
    .bind(space_uri)
    .execute(executor)
    .await?;
    Ok(())
}

/// One `listRepos` row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SpaceWriterRow {
    pub repo_did: String,
    pub rev: String,
    pub hash: Vec<u8>,
}

/// One page of a space's writer set, by DID ascending, after `after` when given.
pub async fn list_writers(
    pool: &SqlitePool,
    space_uri: &str,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<SpaceWriterRow>, sqlx::Error> {
    sqlx::query_as::<_, SpaceWriterRow>(
        "SELECT repo_did, rev, hash FROM space_writers \
         WHERE space_uri = ? AND (? IS NULL OR repo_did > ?) \
         ORDER BY repo_did ASC LIMIT ?",
    )
    .bind(space_uri)
    .bind(after)
    .bind(after)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Drop a space's whole writer set (space deletion), alongside its members and registrations.
pub async fn delete_writers<'e, E>(executor: E, space_uri: &str) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query("DELETE FROM space_writers WHERE space_uri = ?")
        .bind(space_uri)
        .execute(executor)
        .await?;
    Ok(())
}
