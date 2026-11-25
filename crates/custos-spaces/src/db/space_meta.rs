// pattern: Imperative Shell

//! The writer-set half of a space meta archive (`crate::space_migration`): reading the whole set
//! out for `exportSpaceMeta`, and replacing it wholesale for `importSpaceMeta`. The member and
//! policy halves reuse `db::spaces`.

use sqlx::Sqlite;

/// One writer-set entry as a space meta archive carries it.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct MetaWriterRow {
    pub repo_did: String,
    pub rev: String,
    pub hash: Vec<u8>,
    pub space_rev: String,
}

/// A space's whole writer set, by DID ascending.
pub async fn all_writers<'e, E>(
    executor: E,
    space_uri: &str,
) -> Result<Vec<MetaWriterRow>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query_as::<_, MetaWriterRow>(
        "SELECT repo_did, rev, hash, space_rev FROM space_writers \
         WHERE space_uri = ? ORDER BY repo_did ASC",
    )
    .bind(space_uri)
    .fetch_all(executor)
    .await
}

/// Replace a space's writer set with `writers`, and move its space revision to the newest one
/// they carry, so the next writer-set change follows them. Never backwards: a return migration can
/// land on a host whose own `last_space_rev` is already ahead.
pub async fn replace_writers(
    conn: &mut sqlx::SqliteConnection,
    space_uri: &str,
    writers: &[MetaWriterRow],
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM space_writers WHERE space_uri = ?")
        .bind(space_uri)
        .execute(&mut *conn)
        .await?;
    for writer in writers {
        sqlx::query(
            "INSERT INTO space_writers (space_uri, repo_did, rev, hash, space_rev, updated_at) \
             VALUES (?, ?, ?, ?, ?, datetime('now'))",
        )
        .bind(space_uri)
        .bind(&writer.repo_did)
        .bind(&writer.rev)
        .bind(&writer.hash)
        .bind(&writer.space_rev)
        .execute(&mut *conn)
        .await?;
    }
    if let Some(newest) = writers.iter().map(|w| w.space_rev.as_str()).max() {
        sqlx::query(
            "UPDATE spaces SET last_space_rev = ? \
             WHERE uri = ? AND (last_space_rev IS NULL OR last_space_rev < ?)",
        )
        .bind(newest)
        .bind(space_uri)
        .bind(newest)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}
