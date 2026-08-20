// pattern: Imperative Shell

//! Permissioned repo store queries (V065): `space_repos` (rev + LtHash state),
//! `space_records` (path → current record block), and `space_repo_ops` (the
//! listRepoOps oplog). Single-statement queries only — the write transaction
//! that strings them together is `space_record_write.rs`, the one write choke
//! point.

// Consumed today by the write choke point and blob GC; the read/sync routes
// that widen usage land with the record CRUD surface.
#![allow(dead_code)]

use sqlx::{Sqlite, SqlitePool};

/// One `space_repos` row: the repo head.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SpaceRepoRow {
    pub rev: String,
    pub lthash_state: Vec<u8>,
}

/// One `space_records` row's content half.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SpaceRecordRow {
    pub cid: String,
    pub value: Vec<u8>,
}

/// Fetch a repo head (rev + LtHash state).
pub async fn get_repo<'e, E>(
    executor: E,
    space_uri: &str,
    account_did: &str,
) -> Result<Option<SpaceRepoRow>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query_as::<_, SpaceRepoRow>(
        "SELECT rev, lthash_state FROM space_repos WHERE space_uri = ? AND account_did = ?",
    )
    .bind(space_uri)
    .bind(account_did)
    .fetch_optional(executor)
    .await
}

/// Create a repo at its first commit. Returns `false` when the repo already
/// exists (a concurrent first write won).
pub async fn insert_repo<'e, E>(
    executor: E,
    space_uri: &str,
    account_did: &str,
    rev: &str,
    lthash_state: &[u8],
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "INSERT OR IGNORE INTO space_repos \
         (space_uri, account_did, rev, lthash_state, created_at, updated_at) \
         VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))",
    )
    .bind(space_uri)
    .bind(account_did)
    .bind(rev)
    .bind(lthash_state)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Advance a repo head with a compare-and-swap on `rev`. Returns `false` when
/// the head moved since the caller read `expected_rev` — nothing is written.
pub async fn advance_repo_rev<'e, E>(
    executor: E,
    space_uri: &str,
    account_did: &str,
    new_rev: &str,
    lthash_state: &[u8],
    expected_rev: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "UPDATE space_repos SET rev = ?, lthash_state = ?, updated_at = datetime('now') \
         WHERE space_uri = ? AND account_did = ? AND rev = ?",
    )
    .bind(new_rev)
    .bind(lthash_state)
    .bind(space_uri)
    .bind(account_did)
    .bind(expected_rev)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Fetch the current record block at a path.
pub async fn get_record<'e, E>(
    executor: E,
    space_uri: &str,
    account_did: &str,
    collection: &str,
    rkey: &str,
) -> Result<Option<SpaceRecordRow>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query_as::<_, SpaceRecordRow>(
        "SELECT cid, value FROM space_records \
         WHERE space_uri = ? AND account_did = ? AND collection = ? AND rkey = ?",
    )
    .bind(space_uri)
    .bind(account_did)
    .bind(collection)
    .bind(rkey)
    .fetch_optional(executor)
    .await
}

/// Insert or replace the record block at a path.
pub async fn upsert_record<'e, E>(
    executor: E,
    space_uri: &str,
    account_did: &str,
    collection: &str,
    rkey: &str,
    cid: &str,
    value: &[u8],
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO space_records \
         (space_uri, account_did, collection, rkey, cid, value, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now')) \
         ON CONFLICT (space_uri, account_did, collection, rkey) \
         DO UPDATE SET cid = excluded.cid, value = excluded.value, \
                       updated_at = datetime('now')",
    )
    .bind(space_uri)
    .bind(account_did)
    .bind(collection)
    .bind(rkey)
    .bind(cid)
    .bind(value)
    .execute(executor)
    .await?;
    Ok(())
}

/// Delete the record at a path. Returns `false` when no row existed.
pub async fn delete_record<'e, E>(
    executor: E,
    space_uri: &str,
    account_did: &str,
    collection: &str,
    rkey: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "DELETE FROM space_records \
         WHERE space_uri = ? AND account_did = ? AND collection = ? AND rkey = ?",
    )
    .bind(space_uri)
    .bind(account_did)
    .bind(collection)
    .bind(rkey)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Append one oplog entry. `cid` `None` = delete, `prev` `None` = create; ops
/// of one atomic batch share `rev`.
#[allow(clippy::too_many_arguments)]
pub async fn insert_repo_op<'e, E>(
    executor: E,
    space_uri: &str,
    account_did: &str,
    rev: &str,
    collection: &str,
    rkey: &str,
    cid: Option<&str>,
    prev: Option<&str>,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO space_repo_ops \
         (space_uri, account_did, rev, collection, rkey, cid, prev, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))",
    )
    .bind(space_uri)
    .bind(account_did)
    .bind(rev)
    .bind(collection)
    .bind(rkey)
    .bind(cid)
    .bind(prev)
    .execute(executor)
    .await?;
    Ok(())
}

/// Every stored record block for one account, across all of its space repos —
/// the blob GC's input for unioning space blob references with the public
/// repo's.
// ponytail: one unpaged read per account per GC pass; switch to PK-keyset
// paging if space stores grow beyond what one result set should hold.
pub async fn list_record_values_for_account(
    pool: &SqlitePool,
    account_did: &str,
) -> Result<Vec<Vec<u8>>, sqlx::Error> {
    sqlx::query_scalar::<_, Vec<u8>>("SELECT value FROM space_records WHERE account_did = ?")
        .bind(account_did)
        .fetch_all(pool)
        .await
}
