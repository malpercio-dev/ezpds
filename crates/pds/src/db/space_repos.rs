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
        "INSERT INTO space_repos \
         (space_uri, account_did, rev, lthash_state, created_at, updated_at) \
         VALUES (?, ?, ?, ?, datetime('now'), datetime('now')) \
         ON CONFLICT DO NOTHING",
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

/// Insert or replace the record block at a path. `rev` is the commit rev that wrote it —
/// the durable "changed since" fact `listBlobs?since` filters on (V066).
#[allow(clippy::too_many_arguments)]
pub async fn upsert_record<'e, E>(
    executor: E,
    space_uri: &str,
    account_did: &str,
    collection: &str,
    rkey: &str,
    cid: &str,
    value: &[u8],
    rev: &str,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO space_records \
         (space_uri, account_did, collection, rkey, cid, value, rev, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now')) \
         ON CONFLICT (space_uri, account_did, collection, rkey) \
         DO UPDATE SET cid = excluded.cid, value = excluded.value, rev = excluded.rev, \
                       updated_at = datetime('now')",
    )
    .bind(space_uri)
    .bind(account_did)
    .bind(collection)
    .bind(rkey)
    .bind(cid)
    .bind(value)
    .bind(rev)
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

/// The keyset cursor for [`list_record_blocks_for_account`]: the primary-key
/// tail of the last row seen (`space_uri`, `collection`, `rkey`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceRecordCursor {
    pub space_uri: String,
    pub collection: String,
    pub rkey: String,
}

/// One page of an account's stored record blocks across all of its space
/// repos, in primary-key order — the blob GC's input for unioning space blob
/// references with the public repo's. Pass the last row's cursor to continue;
/// a page shorter than `limit` is the last one.
pub async fn list_record_blocks_for_account(
    pool: &SqlitePool,
    account_did: &str,
    after: Option<&SpaceRecordCursor>,
    limit: i64,
) -> Result<Vec<(SpaceRecordCursor, Vec<u8>)>, sqlx::Error> {
    // Row-value comparison keysets on the PK tail; the empty-string triple
    // sorts before every real key, so it doubles as "from the start".
    let (space_uri, collection, rkey) = match after {
        Some(c) => (c.space_uri.as_str(), c.collection.as_str(), c.rkey.as_str()),
        None => ("", "", ""),
    };
    let rows: Vec<(String, String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT space_uri, collection, rkey, value FROM space_records \
         WHERE account_did = ? AND (space_uri, collection, rkey) > (?, ?, ?) \
         ORDER BY space_uri, collection, rkey \
         LIMIT ?",
    )
    .bind(account_did)
    .bind(space_uri)
    .bind(collection)
    .bind(rkey)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(space_uri, collection, rkey, value)| {
            (
                SpaceRecordCursor {
                    space_uri,
                    collection,
                    rkey,
                },
                value,
            )
        })
        .collect())
}

/// One row of a `listRecords` page. `value` is the stored DAG-CBOR block, absent when the
/// caller asked for a metadata-only listing (`excludeValues`).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SpaceRecordListRow {
    pub collection: String,
    pub rkey: String,
    pub cid: String,
    pub value: Option<Vec<u8>>,
}

/// One page of an account's records in one space repo, ordered by `(collection, rkey)` — the
/// `space_records` primary key, so the page walk is an index scan.
///
/// `after` is the last row of the previous page. `reverse` selects ascending order; the default
/// (and so the reference's) is descending, newest rkey first.
// Every argument is one independent axis of the lexicon's query — bundling them into a struct
// would only move the same list one call frame up.
#[allow(clippy::too_many_arguments)]
pub async fn list_repo_records(
    pool: &SqlitePool,
    space_uri: &str,
    account_did: &str,
    collection: Option<&str>,
    after: Option<(&str, &str)>,
    reverse: bool,
    exclude_values: bool,
    limit: i64,
) -> Result<Vec<SpaceRecordListRow>, sqlx::Error> {
    // `value` is selected as a literal NULL rather than omitted so both shapes decode into one
    // `FromRow` struct; SQLite never reads the (potentially large) blob in that branch.
    let value_column = if exclude_values { "NULL" } else { "value" };
    // Row-value comparison against the primary key: SQLite uses the index for both the seek and
    // the ordering, so a deep page costs the same as a shallow one.
    let (order, keyset) = if reverse {
        ("ASC", "(collection, rkey) > (?, ?)")
    } else {
        ("DESC", "(collection, rkey) < (?, ?)")
    };
    // Every placeholder is a plain positional `?`: mixing `?` with `?N` makes SQLite number the
    // bare ones from "one past the largest index seen so far", which silently shifts the binds
    // that follow. The two cursor columns are each bound twice — once for the NULL test, once
    // for the comparison — rather than reusing an index.
    let sql = format!(
        "SELECT collection, rkey, cid, {value_column} AS value FROM space_records \
         WHERE space_uri = ? AND account_did = ? \
           AND (? IS NULL OR collection = ?) \
           AND (? IS NULL OR {keyset}) \
         ORDER BY collection {order}, rkey {order} LIMIT ?"
    );
    sqlx::query_as::<_, SpaceRecordListRow>(&sql)
        .bind(space_uri)
        .bind(account_did)
        .bind(collection)
        .bind(collection)
        .bind(after.map(|(c, _)| c))
        .bind(after.map(|(c, _)| c))
        .bind(after.map(|(_, r)| r))
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// One page of the spaces an account holds a repo in — spaces it has *written to*, which is
/// what `listSpaces` reports (a repo host tracks writers, never a member list). Ordered by URI,
/// deleted spaces omitted.
pub async fn list_spaces_for_account(
    pool: &SqlitePool,
    account_did: &str,
    space_type: Option<&str>,
    authority: Option<&str>,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT s.uri FROM space_repos r JOIN spaces s ON s.uri = r.space_uri \
         WHERE r.account_did = ? AND s.deleted_at IS NULL \
           AND (? IS NULL OR s.space_type = ?) \
           AND (? IS NULL OR s.authority_did = ?) \
           AND (? IS NULL OR s.uri > ?) \
         ORDER BY s.uri ASC LIMIT ?",
    )
    .bind(account_did)
    .bind(space_type)
    .bind(space_type)
    .bind(authority)
    .bind(authority)
    .bind(after)
    .bind(after)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// One oplog entry of a `listRepoOps` page. `idx` is the row's rowid — the tiebreak within a
/// batch (ops of one commit share `rev` and were inserted in request order) and the second half
/// of the page cursor. `value` is the record's *current* block, present only when this op is
/// its latest write (the join below misses for deletes and superseded ops).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SpaceRepoOpRow {
    pub idx: i64,
    pub rev: String,
    pub collection: String,
    pub rkey: String,
    pub cid: Option<String>,
    pub prev: Option<String>,
    pub value: Option<Vec<u8>>,
}

/// One page of a repo's oplog, ordered `(rev, rowid)` — commit order, then request order
/// within a batch.
///
/// Joining `space_records` on the op's *cid* as well as its path means only a record's current
/// value comes back: an op a later write superseded joins to nothing, so its stale value is
/// left off rather than served (the reference reader does exactly this). `since` keeps ops
/// strictly after that rev; `after` is the previous page's last `(rev, rowid)`.
pub async fn list_repo_ops(
    pool: &SqlitePool,
    space_uri: &str,
    account_did: &str,
    since: Option<&str>,
    after: Option<(&str, i64)>,
    exclude_values: bool,
    limit: i64,
) -> Result<Vec<SpaceRepoOpRow>, sqlx::Error> {
    // `value` selected as a literal NULL when excluded, so both shapes decode into one struct
    // and SQLite never reads the blob (the `list_repo_records` pattern).
    let value_column = if exclude_values { "NULL" } else { "r.value" };
    let sql = format!(
        "SELECT o.rowid AS idx, o.rev, o.collection, o.rkey, o.cid, o.prev, \
                {value_column} AS value \
         FROM space_repo_ops o \
         LEFT JOIN space_records r \
           ON r.space_uri = o.space_uri AND r.account_did = o.account_did \
          AND r.collection = o.collection AND r.rkey = o.rkey AND r.cid = o.cid \
         WHERE o.space_uri = ? AND o.account_did = ? \
           AND (? IS NULL OR o.rev > ?) \
           AND (? IS NULL OR o.rev > ? OR (o.rev = ? AND o.rowid > ?)) \
         ORDER BY o.rev, o.rowid LIMIT ?"
    );
    sqlx::query_as::<_, SpaceRepoOpRow>(&sql)
        .bind(space_uri)
        .bind(account_did)
        .bind(since)
        .bind(since)
        .bind(after.map(|(rev, _)| rev))
        .bind(after.map(|(rev, _)| rev))
        .bind(after.map(|(rev, _)| rev))
        .bind(after.map(|(_, idx)| idx))
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// Every record path and CID in one repo — the raw material for `getRepo`'s DRISL index. The
/// route re-sorts into canonical DAG-CBOR key order (length-first), which SQL cannot express;
/// unordered here, and unpaged because the index must be materialized whole anyway.
pub async fn list_record_index(
    pool: &SqlitePool,
    space_uri: &str,
    account_did: &str,
) -> Result<Vec<(String, String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT collection, rkey, cid FROM space_records \
         WHERE space_uri = ? AND account_did = ?",
    )
    .bind(space_uri)
    .bind(account_did)
    .fetch_all(pool)
    .await
}

/// One page of a repo's stored record blocks, optionally only records written after `since` —
/// the input for deriving a repo's blob references (`listBlobs`, `getBlob`'s membership check).
/// PK-keyset paged like [`list_record_blocks_for_account`]; a page shorter than `limit` is the
/// last. A pre-V066 row whose backfilled `rev` is NULL never matches a `since` filter, which is
/// the safe direction only because the backfill leaves none behind.
pub async fn list_record_blocks_for_repo(
    pool: &SqlitePool,
    space_uri: &str,
    account_did: &str,
    since: Option<&str>,
    after: Option<(&str, &str)>,
    limit: i64,
) -> Result<Vec<(String, String, Vec<u8>)>, sqlx::Error> {
    let (collection, rkey) = after.unwrap_or(("", ""));
    sqlx::query_as(
        "SELECT collection, rkey, value FROM space_records \
         WHERE space_uri = ? AND account_did = ? \
           AND (? IS NULL OR rev > ?) \
           AND (collection, rkey) > (?, ?) \
         ORDER BY collection, rkey LIMIT ?",
    )
    .bind(space_uri)
    .bind(account_did)
    .bind(since)
    .bind(since)
    .bind(collection)
    .bind(rkey)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Prune oplog entries older than `max_age_secs` — the retention half of the spec's "a host may
/// compact or drop the oplog". Returns the rows reclaimed. A syncer whose `since` predates the
/// retained window gets a short page whose head commit hash won't match its own fold, which is
/// its signal to heal via `getRepo`.
pub async fn sweep_old_repo_ops(pool: &SqlitePool, max_age_secs: u64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM space_repo_ops WHERE created_at < datetime('now', '-' || ? || ' seconds')",
    )
    .bind(max_age_secs as i64)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Delete one account's repo in a space outright — oplog, records, then the head (FK order).
/// The space-host side of `deleteSpace`: the authority's own repo goes with its space. Takes a
/// connection rather than a generic executor because it is three statements.
pub async fn delete_repo(
    conn: &mut sqlx::SqliteConnection,
    space_uri: &str,
    account_did: &str,
) -> Result<(), sqlx::Error> {
    for sql in [
        "DELETE FROM space_repo_ops WHERE space_uri = ? AND account_did = ?",
        "DELETE FROM space_records WHERE space_uri = ? AND account_did = ?",
        "DELETE FROM space_repos WHERE space_uri = ? AND account_did = ?",
    ] {
        sqlx::query(sql)
            .bind(space_uri)
            .bind(account_did)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}
