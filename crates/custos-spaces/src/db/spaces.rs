// pattern: Imperative Shell

//! Space rows (V065; the policy is V079's): every space this PDS interacts with, keyed by
//! canonical space URI, plus the memberspace member list. `policy` is the normalized space policy
//! JSON (`crate::policy`): non-NULL means a local account created the space through
//! `createSpace` and this host answers for it; NULL means the row was recorded by a member's
//! write and the policy lives with a foreign authority (or the space was deleted — deletion
//! clears the policy, so the URI can be created again). Lifecycle is derived (`deleted_at` set =
//! deleted).

use sqlx::{Sqlite, SqlitePool};

/// One `spaces` row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SpaceRow {
    pub uri: String,
    pub authority_did: String,
    /// The normalized space policy JSON; read through [`SpaceRow::space_policy`].
    pub policy: Option<String>,
    pub deleted_at: Option<String>,
    /// When the operator took this space down (V070). Independent of `deleted_at`: the
    /// authority's tombstone is durable and clears the policy, this is a reversible refusal to
    /// serve that leaves everything else in place.
    pub takendown_at: Option<String>,
    /// The space revision of the latest writer-set change (V074), `None` before the first.
    pub last_space_rev: Option<String>,
}

impl SpaceRow {
    /// The stored policy, or `None` for a space whose authority is elsewhere.
    pub fn space_policy(&self) -> Result<Option<crate::policy::SpacePolicy>, common::ApiError> {
        self.policy
            .as_deref()
            .map(crate::policy::SpacePolicy::from_stored)
            .transpose()
    }
}

/// A space's identity: what a new row is keyed and filtered by.
pub struct NewSpace<'a> {
    pub uri: &'a str,
    pub authority_did: &'a str,
    pub space_type: &'a str,
    pub skey: &'a str,
}

/// Record a foreign authority's space (no policy) on a member's first write. Returns `false`
/// when the URI (or the equivalent authority/type/skey triple) already exists.
pub async fn insert_space<'e, E>(executor: E, space: &NewSpace<'_>) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "INSERT INTO spaces (uri, authority_did, space_type, skey, created_at) \
         VALUES (?, ?, ?, ?, datetime('now')) \
         ON CONFLICT DO NOTHING",
    )
    .bind(space.uri)
    .bind(space.authority_did)
    .bind(space.space_type)
    .bind(space.skey)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Fetch a space by canonical URI, deleted or not — callers decide what a set
/// `deleted_at` means for their surface.
pub async fn get_space<'e, E>(executor: E, uri: &str) -> Result<Option<SpaceRow>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query_as::<_, SpaceRow>(
        "SELECT uri, authority_did, policy, deleted_at, takendown_at, last_space_rev FROM spaces \
         WHERE uri = ?",
    )
    .bind(uri)
    .fetch_optional(executor)
    .await
}

/// `member_did`'s entry on the member list of the space at `uri`, if any.
pub async fn get_member<'e, E>(
    executor: E,
    uri: &str,
    member_did: &str,
) -> Result<Option<crate::policy::Access>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let row: Option<(bool, bool)> = sqlx::query_as(
        "SELECT can_read, can_write FROM space_members WHERE space_uri = ? AND member_did = ?",
    )
    .bind(uri)
    .bind(member_did)
    .fetch_optional(executor)
    .await?;
    Ok(row.map(|(read, write)| crate::policy::Access { read, write }))
}

/// Create a space this host is the authority for, or claim/revive the row at that URI when it
/// carries no policy (recorded by a member's write, or deleted). Returns `false` when an active
/// space already exists there — the caller's `SpaceAlreadyExists` — or when the operator has
/// taken the URI down: the row is occupied by a refusal, and re-creating over it would let the
/// authority undo the takedown by deleting and creating the same URI.
///
/// Distinct from [`insert_space`], which records a foreign space on a member's write and must
/// never touch an existing row: reviving a tombstone is only ever the authority's decision.
pub async fn create_space<'e, E>(
    executor: E,
    space: &NewSpace<'_>,
    policy: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "INSERT INTO spaces (uri, authority_did, space_type, skey, policy, created_at) \
         VALUES (?, ?, ?, ?, ?, datetime('now')) \
         ON CONFLICT (uri) DO UPDATE SET \
           policy = excluded.policy, created_at = excluded.created_at, deleted_at = NULL \
         WHERE spaces.policy IS NULL AND spaces.takendown_at IS NULL",
    )
    .bind(space.uri)
    .bind(space.authority_did)
    .bind(space.space_type)
    .bind(space.skey)
    .bind(policy)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Replace a space's policy wholesale.
pub async fn set_space_policy<'e, E>(
    executor: E,
    uri: &str,
    policy: &str,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query("UPDATE spaces SET policy = ? WHERE uri = ?")
        .bind(policy)
        .bind(uri)
        .execute(executor)
        .await?;
    Ok(())
}

/// Tombstone a space: set `deleted_at` and drop its policy. The row stays so
/// `authorizeSpaceSync` keeps answering `SpaceDeleted`; with no policy left, `createSpace`
/// may claim the URI again.
pub async fn mark_space_deleted<'e, E>(executor: E, uri: &str) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query("UPDATE spaces SET deleted_at = datetime('now'), policy = NULL WHERE uri = ?")
        .bind(uri)
        .execute(executor)
        .await?;
    Ok(())
}

/// Add a DID to a space's member list, or replace its read/write access (idempotent).
pub async fn put_member<'e, E>(
    executor: E,
    uri: &str,
    member_did: &str,
    read: bool,
    write: bool,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO space_members (space_uri, member_did, added_at, can_read, can_write) \
         VALUES (?, ?, datetime('now'), ?, ?) \
         ON CONFLICT (space_uri, member_did) \
         DO UPDATE SET can_read = excluded.can_read, can_write = excluded.can_write",
    )
    .bind(uri)
    .bind(member_did)
    .bind(read)
    .bind(write)
    .execute(executor)
    .await?;
    Ok(())
}

/// Remove a DID from a space's member list. Returns whether it was a member.
pub async fn remove_member<'e, E>(
    executor: E,
    uri: &str,
    member_did: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query("DELETE FROM space_members WHERE space_uri = ? AND member_did = ?")
        .bind(uri)
        .bind(member_did)
        .execute(executor)
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Drop a space's whole member list (space deletion, or a policy `$type` change).
pub async fn delete_members<'e, E>(executor: E, uri: &str) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query("DELETE FROM space_members WHERE space_uri = ?")
        .bind(uri)
        .execute(executor)
        .await?;
    Ok(())
}

/// Drop every write-notification registration on a space (space deletion).
pub async fn delete_notify_registrations<'e, E>(executor: E, uri: &str) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query("DELETE FROM space_notify_registrations WHERE space_uri = ?")
        .bind(uri)
        .execute(executor)
        .await?;
    Ok(())
}

/// One member list entry.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MemberRow {
    pub member_did: String,
    pub can_read: bool,
    pub can_write: bool,
}

/// A space's whole member list, by DID ascending (publishing or withdrawing it at once).
pub async fn all_members<'e, E>(executor: E, uri: &str) -> Result<Vec<MemberRow>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query_as::<_, MemberRow>(
        "SELECT member_did, can_read, can_write FROM space_members \
         WHERE space_uri = ? ORDER BY member_did ASC",
    )
    .bind(uri)
    .fetch_all(executor)
    .await
}

/// One page of a space's member list, by DID ascending, after `after` (the previous page's
/// last DID) when given.
pub async fn list_members(
    pool: &SqlitePool,
    uri: &str,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<MemberRow>, sqlx::Error> {
    sqlx::query_as::<_, MemberRow>(
        "SELECT member_did, can_read, can_write FROM space_members \
         WHERE space_uri = ? AND (? IS NULL OR member_did > ?) \
         ORDER BY member_did ASC LIMIT ?",
    )
    .bind(uri)
    .bind(after)
    .bind(after)
    .bind(limit)
    .fetch_all(pool)
    .await
}

// ── Operator takedown (V070) ─────────────────────────────────────────────────

/// Apply or clear the operator takedown on a space. A no-op for a URI with no row — the
/// caller checks existence (it needs the row to report the resulting state anyway), so this
/// stays a single statement that can join the audit write's transaction.
///
/// Deliberately only this column: unlike [`mark_space_deleted`], a takedown leaves the
/// policy, members, notify registrations, and every stored repo untouched, because it is
/// reversible and a restore has to put the space back exactly as it was. Re-applying an
/// existing takedown keeps the original timestamp, so the audit log and the listing agree on
/// when the refusal started.
pub async fn set_space_takedown<'e, E>(
    executor: E,
    uri: &str,
    applied: bool,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    if applied {
        sqlx::query(
            "UPDATE spaces SET takendown_at = datetime('now') \
             WHERE uri = ? AND takendown_at IS NULL",
        )
    } else {
        sqlx::query("UPDATE spaces SET takendown_at = NULL WHERE uri = ?")
    }
    .bind(uri)
    .execute(executor)
    .await?;
    Ok(())
}

/// One row of the operator space listing.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HostedSpaceRow {
    pub uri: String,
    pub authority_did: String,
    /// The policy's `$type` (the generated `policy_type` column). Non-NULL: this host is the
    /// space's authority. NULL means the authority is a foreign server and this host only
    /// stores members' repos — the case with no authority-side lever, and the reason this
    /// listing exists.
    pub policy_type: Option<String>,
    pub created_at: String,
    pub deleted_at: Option<String>,
    pub takendown_at: Option<String>,
    /// Repos this host stores in the space.
    pub repo_count: i64,
    /// Records across those repos — what the operator is actually serving.
    pub record_count: i64,
}

/// One page of every space this host stores anything about, by URI ascending, after `after`
/// (the previous page's last URI). `takendown_only` narrows to the operator's refusal list.
///
/// Both counts are prefix scans of a `WITHOUT ROWID` primary key (`space_repos` /
/// `space_records` both lead with `space_uri`), so they cost a range walk per row rather
/// than a table scan.
pub async fn list_hosted_spaces(
    pool: &SqlitePool,
    after: Option<&str>,
    takendown_only: bool,
    limit: i64,
) -> Result<Vec<HostedSpaceRow>, sqlx::Error> {
    sqlx::query_as::<_, HostedSpaceRow>(
        "SELECT s.uri, s.authority_did, s.policy_type, s.created_at, s.deleted_at, s.takendown_at, \
                (SELECT COUNT(*) FROM space_repos r WHERE r.space_uri = s.uri) AS repo_count, \
                (SELECT COUNT(*) FROM space_records c WHERE c.space_uri = s.uri) AS record_count \
         FROM spaces s \
         WHERE (? IS NULL OR s.uri > ?) \
           AND (? = 0 OR s.takendown_at IS NOT NULL) \
         ORDER BY s.uri ASC LIMIT ?",
    )
    .bind(after)
    .bind(after)
    .bind(i64::from(takendown_only))
    .bind(limit)
    .fetch_all(pool)
    .await
}
