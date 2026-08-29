// pattern: Imperative Shell

//! Space rows (V065; the `app_access`/`app_allowed` allowList columns are V069):
//! every space this PDS interacts with, keyed by canonical space URI, plus the
//! simplespace member list. `policy`/`app_access` are the
//! simplespace config: non-NULL means a local account created the space through
//! `createSpace` and this host answers for it; NULL means the row was recorded
//! by a member's write and the config lives with a foreign authority (or the
//! space was deleted — deletion clears the config, so the URI can be created
//! again). Lifecycle is derived (`deleted_at` set = deleted). The
//! notify-registration queries land with the space-host notification surface.

use sqlx::{Sqlite, SqlitePool};

/// One `spaces` row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SpaceRow {
    pub uri: String,
    pub authority_did: String,
    pub policy: Option<String>,
    pub app_access: Option<String>,
    /// JSON array of the `allowList` app-access policy's client IDs; meaningful only when
    /// `app_access = 'allowList'`. Read through [`SpaceRow::allowed_client_ids`].
    pub app_allowed: Option<String>,
    pub managing_app: Option<String>,
    pub deleted_at: Option<String>,
}

impl SpaceRow {
    /// The `allowList` policy's client IDs. An absent or unparseable column reads as empty,
    /// which refuses every app — the safe direction for a config this host cannot read.
    pub fn allowed_client_ids(&self) -> Vec<String> {
        self.app_allowed
            .as_deref()
            .and_then(|json| serde_json::from_str::<Vec<String>>(json).ok())
            .unwrap_or_default()
    }
}

/// A new space to insert.
pub struct NewSpace<'a> {
    pub uri: &'a str,
    pub authority_did: &'a str,
    pub space_type: &'a str,
    pub skey: &'a str,
    pub policy: Option<&'a str>,
    pub app_access: Option<&'a str>,
    /// JSON array of allow-listed client IDs (see [`SpaceRow::app_allowed`]).
    pub app_allowed: Option<&'a str>,
    pub managing_app: Option<&'a str>,
}

/// Insert a space. Returns `false` when the URI (or the equivalent
/// authority/type/skey triple) already exists.
pub async fn insert_space<'e, E>(executor: E, space: &NewSpace<'_>) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "INSERT INTO spaces \
         (uri, authority_did, space_type, skey, policy, app_access, app_allowed, managing_app, \
          created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now')) \
         ON CONFLICT DO NOTHING",
    )
    .bind(space.uri)
    .bind(space.authority_did)
    .bind(space.space_type)
    .bind(space.skey)
    .bind(space.policy)
    .bind(space.app_access)
    .bind(space.app_allowed)
    .bind(space.managing_app)
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
        "SELECT uri, authority_did, policy, app_access, app_allowed, managing_app, deleted_at \
         FROM spaces WHERE uri = ?",
    )
    .bind(uri)
    .fetch_optional(executor)
    .await
}

/// Whether `member_did` is on the simplespace member list of the space at `uri`. The
/// `member-list` policy check behind `getSpaceCredential`.
pub async fn is_member<'e, E>(executor: E, uri: &str, member_did: &str) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let found: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM space_members WHERE space_uri = ? AND member_did = ?")
            .bind(uri)
            .bind(member_did)
            .fetch_optional(executor)
            .await?;
    Ok(found.is_some())
}

/// Create a simplespace-managed space, or claim/revive the row at that URI when it carries no
/// config (recorded by a member's write, or deleted). Returns `false` when an active
/// simplespace already exists there — the caller's `SpaceAlreadyExists`.
///
/// Distinct from [`insert_space`], which records a foreign space on a member's write and must
/// never touch an existing row: reviving a tombstone is only ever the authority's decision.
pub async fn create_space<'e, E>(executor: E, space: &NewSpace<'_>) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "INSERT INTO spaces \
         (uri, authority_did, space_type, skey, policy, app_access, app_allowed, managing_app, \
          created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now')) \
         ON CONFLICT (uri) DO UPDATE SET \
           policy = excluded.policy, app_access = excluded.app_access, \
           app_allowed = excluded.app_allowed, managing_app = excluded.managing_app, \
           created_at = excluded.created_at, deleted_at = NULL \
         WHERE spaces.policy IS NULL",
    )
    .bind(space.uri)
    .bind(space.authority_did)
    .bind(space.space_type)
    .bind(space.skey)
    .bind(space.policy)
    .bind(space.app_access)
    .bind(space.app_allowed)
    .bind(space.managing_app)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Replace a space's simplespace config wholesale.
pub async fn set_space_config<'e, E>(
    executor: E,
    uri: &str,
    policy: &str,
    app_access: &str,
    app_allowed: Option<&str>,
    managing_app: Option<&str>,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "UPDATE spaces SET policy = ?, app_access = ?, app_allowed = ?, managing_app = ? \
         WHERE uri = ?",
    )
    .bind(policy)
    .bind(app_access)
    .bind(app_allowed)
    .bind(managing_app)
    .bind(uri)
    .execute(executor)
    .await?;
    Ok(())
}

/// Tombstone a space: set `deleted_at` and drop its simplespace config. The row stays so
/// `getSpaceCredential` keeps answering `SpaceDeleted`; with no config left, `createSpace`
/// may claim the URI again.
pub async fn mark_space_deleted<'e, E>(executor: E, uri: &str) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "UPDATE spaces SET deleted_at = datetime('now'), \
           policy = NULL, app_access = NULL, app_allowed = NULL, managing_app = NULL \
         WHERE uri = ?",
    )
    .bind(uri)
    .execute(executor)
    .await?;
    Ok(())
}

/// Add a DID to a space's member list (idempotent).
pub async fn add_member<'e, E>(executor: E, uri: &str, member_did: &str) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO space_members (space_uri, member_did, added_at) \
         VALUES (?, ?, datetime('now')) ON CONFLICT DO NOTHING",
    )
    .bind(uri)
    .bind(member_did)
    .execute(executor)
    .await?;
    Ok(())
}

/// Remove a DID from a space's member list (idempotent).
pub async fn remove_member<'e, E>(
    executor: E,
    uri: &str,
    member_did: &str,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query("DELETE FROM space_members WHERE space_uri = ? AND member_did = ?")
        .bind(uri)
        .bind(member_did)
        .execute(executor)
        .await?;
    Ok(())
}

/// Drop a space's whole member list (space deletion).
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

/// One page of a space's member list, by DID ascending, after `after` (the previous page's
/// last DID) when given.
pub async fn list_members(
    pool: &SqlitePool,
    uri: &str,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT member_did FROM space_members \
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
