// pattern: Imperative Shell

//! The blob GC's read of permissioned space records: every record block an account stores across
//! its space repos, so space blob references are unioned with the public repo's. The
//! `space_records` table is `custos-spaces`' to write; this module only reads it.

use sqlx::SqlitePool;

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
