// pattern: Imperative Shell

//! Space rows (V065): every space this PDS interacts with, keyed by canonical
//! space URI. `policy`/`app_access` are the simplespace config, meaningful only
//! when a local account is the authority; lifecycle is derived (`deleted_at`
//! set = deleted). The member and notify-registration tables from the same
//! migration get their query functions with the surfaces that consume them
//! (simplespace management, space-host notifications).

// The management surface that creates spaces over HTTP lands with the
// simplespace routes; until then these functions are exercised by the write
// choke point's tests only.
#![allow(dead_code)]

use sqlx::Sqlite;

/// One `spaces` row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SpaceRow {
    pub uri: String,
    pub authority_did: String,
    pub space_type: String,
    pub skey: String,
    pub policy: Option<String>,
    pub app_access: Option<String>,
    pub managing_app: Option<String>,
    pub created_at: String,
    pub deleted_at: Option<String>,
}

/// A new space to insert.
pub struct NewSpace<'a> {
    pub uri: &'a str,
    pub authority_did: &'a str,
    pub space_type: &'a str,
    pub skey: &'a str,
    pub policy: Option<&'a str>,
    pub app_access: Option<&'a str>,
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
         (uri, authority_did, space_type, skey, policy, app_access, managing_app, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now')) \
         ON CONFLICT DO NOTHING",
    )
    .bind(space.uri)
    .bind(space.authority_did)
    .bind(space.space_type)
    .bind(space.skey)
    .bind(space.policy)
    .bind(space.app_access)
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
        "SELECT uri, authority_did, space_type, skey, policy, app_access, managing_app, \
                created_at, deleted_at \
         FROM spaces WHERE uri = ?",
    )
    .bind(uri)
    .fetch_optional(executor)
    .await
}
