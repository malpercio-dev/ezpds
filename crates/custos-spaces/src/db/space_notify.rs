// pattern: Imperative Shell

//! The space-host notification tables: write-notification registrations
//! (`space_notify_registrations`, V065) and the writer set (`space_writers`, V067).
//!
//! Registrations are whole-space syncer subscriptions a space host stores for `registerNotify`
//! (`repo_did = ''`, the sentinel the V065 primary key is built around). A repo host keeps no
//! registration: it pushes `notifyWrite` straight to the authority (V074 removed the old
//! per-repo auto-registration rows).
//!
//! `subscriber_did` holds the full **service identifier** the wire carries — a DID with an
//! optional `#fragment` naming the DID-document entry to deliver to. The bare DID (the service
//! auth `aud`) is the part before the fragment.
//!
//! Expiry is enforced by the read query, not by a sweep: re-registering refreshes the existing
//! row through the primary key, so the table grows with the *distinct subscriber* count — its
//! live set — rather than accumulating dead rows.

use sqlx::{Sqlite, SqlitePool};

/// The `repo_did` every registration carries: the whole space. Empty rather than NULL because the
/// column is part of the V065 primary key, and NULLs never compare equal, so a NULL would admit
/// duplicate rows.
const WHOLE_SPACE: &str = "";

/// Record (or renew) a whole-space registration, returning its new expiry. Re-registering an
/// existing `(space, service)` extends the expiry, which is what `registerNotify` promises.
pub async fn upsert_registration<'e, E>(
    executor: E,
    space_uri: &str,
    service: &str,
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
    .bind(WHOLE_SPACE)
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

/// Every unexpired subscriber to a space — the recipients of a forwarded `notifyWrite` and of
/// `notifySpaceDeleted`. Ordered so a fan-out is deterministic; capped by `limit` so one space can
/// never spawn an unbounded delivery burst.
pub async fn subscribers_for_space(
    pool: &SqlitePool,
    space_uri: &str,
    limit: i64,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT subscriber_did FROM space_notify_registrations \
         WHERE space_uri = ? AND repo_did = ? AND expires_at > datetime('now') \
         ORDER BY subscriber_did LIMIT ?",
    )
    .bind(space_uri)
    .bind(WHOLE_SPACE)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// The space revisions assigned to a recorded write: the new one, and the one it follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterRevs {
    pub space_rev: String,
    /// `None` on the first update in a space.
    pub prev_space_rev: Option<String>,
}

/// What [`upsert_writer`] did with a reported write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriterUpdate {
    /// Recorded, and assigned the next space revision: forward it to the space's syncers.
    Accepted(WriterRevs),
    /// `rev` does not advance the repo's stored one. Nothing changed and nothing is forwarded.
    Stale,
    /// This host is not the space's authority, so it keeps no writer set for it.
    NotAuthority,
}

/// Record (or advance) a repo in a space's writer set, assigning the update the next space
/// revision. Only the space's authority (`spaces.policy IS NOT NULL`) keeps a writer set, and only
/// a `rev` that advances the stored one is recorded: a replayed or reordered report must not move
/// a writer backwards or use up a space revision.
///
/// The space revision is a TID strictly after the space's `last_space_rev` (V074), a per-space
/// high-water mark rather than the maximum over writer rows, because account purge deletes rows
/// and the maximum would then step backwards. Monotonic revisions are what make `spaceRev` a
/// usable `listRepos` cursor and let a syncer spot a missed notification from a `prevSpaceRev`
/// that is not the one it last saw.
///
/// The reads and the writes share the caller's connection; inside a transaction they are atomic,
/// and outside one the single-connection pool serializes them.
pub async fn upsert_writer(
    conn: &mut sqlx::SqliteConnection,
    space_uri: &str,
    repo_did: &str,
    rev: &str,
    hash: &[u8],
) -> Result<WriterUpdate, sqlx::Error> {
    let Some(prev) = sqlx::query_scalar::<_, Option<String>>(
        "SELECT last_space_rev FROM spaces WHERE uri = ? AND policy IS NOT NULL",
    )
    .bind(space_uri)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(WriterUpdate::NotAuthority);
    };
    let stored: Option<String> =
        sqlx::query_scalar("SELECT rev FROM space_writers WHERE space_uri = ? AND repo_did = ?")
            .bind(space_uri)
            .bind(repo_did)
            .fetch_optional(&mut *conn)
            .await?;
    // TIDs sort lexicographically in time order.
    if stored.is_some_and(|stored| rev <= stored.as_str()) {
        return Ok(WriterUpdate::Stale);
    }
    let space_rev = repo_engine::next_record_rev(prev.as_deref().unwrap_or(""))
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    // An empty repo is a nonexistent one, so a report carrying the empty-set hash takes the repo
    // out of the writer set. It still uses up a space revision and is forwarded, which is how
    // syncers learn the repo is gone.
    // ponytail: once the row is gone, a reordered older report for the same repo re-adds it;
    // keep a tombstone rev per repo if that window matters.
    if hash == crypto::LtHash::new().digest() {
        sqlx::query("DELETE FROM space_writers WHERE space_uri = ? AND repo_did = ?")
            .bind(space_uri)
            .bind(repo_did)
            .execute(&mut *conn)
            .await?;
    } else {
        sqlx::query(
            "INSERT INTO space_writers (space_uri, repo_did, rev, hash, space_rev, updated_at) \
             VALUES (?, ?, ?, ?, ?, datetime('now')) \
             ON CONFLICT (space_uri, repo_did) \
             DO UPDATE SET rev = excluded.rev, hash = excluded.hash, \
                           space_rev = excluded.space_rev, updated_at = excluded.updated_at",
        )
        .bind(space_uri)
        .bind(repo_did)
        .bind(rev)
        .bind(hash)
        .bind(&space_rev)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query("UPDATE spaces SET last_space_rev = ? WHERE uri = ?")
        .bind(&space_rev)
        .bind(space_uri)
        .execute(&mut *conn)
        .await?;
    Ok(WriterUpdate::Accepted(WriterRevs {
        space_rev,
        prev_space_rev: prev,
    }))
}

/// One writer-set row, as `listRepos` reports it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SpaceWriterRow {
    pub repo_did: String,
    pub rev: String,
    pub hash: Vec<u8>,
    pub space_rev: String,
}

/// One page of the writer set in ascending space-revision order, after `after_space_rev`
/// (exclusive) when given.
pub async fn list_writers(
    pool: &SqlitePool,
    space_uri: &str,
    after_space_rev: Option<&str>,
    limit: i64,
) -> Result<Vec<SpaceWriterRow>, sqlx::Error> {
    sqlx::query_as::<_, SpaceWriterRow>(
        "SELECT repo_did, rev, hash, space_rev FROM space_writers \
         WHERE space_uri = ? AND (? IS NULL OR space_rev > ?) \
         ORDER BY space_rev ASC, repo_did ASC LIMIT ?",
    )
    .bind(space_uri)
    .bind(after_space_rev)
    .bind(after_space_rev)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::spaces::{insert_space, NewSpace};
    use crate::test_support::test_state;

    const SPACE: &str = "at://did:plc:authoritywritersaaaaaaaa/space/org.example.bucket/main";
    const ALICE: &str = "did:plc:alicewritersaaaaaaaaaaaa";
    const BOB: &str = "did:plc:bobwritersaaaaaaaaaaaaaa";

    async fn record(pool: &SqlitePool, repo: &str, rev: &str) -> WriterUpdate {
        let mut conn = pool.acquire().await.unwrap();
        upsert_writer(&mut conn, SPACE, repo, rev, &[7; 32])
            .await
            .unwrap()
    }

    fn accepted(update: WriterUpdate) -> WriterRevs {
        match update {
            WriterUpdate::Accepted(revs) => revs,
            other => panic!("expected an accepted update, got {other:?}"),
        }
    }

    /// Each accepted update's `prevSpaceRev` is the previous one's `spaceRev`, even after the
    /// writer row holding the latest revision is deleted (account purge): the syncer's chain
    /// never shows a gap that is not there, and revisions never step backwards.
    #[tokio::test]
    async fn space_revs_chain_across_writers_and_survive_a_purged_writer() {
        let state = test_state().await;
        insert_space(
            &state.db,
            &NewSpace {
                uri: SPACE,
                authority_did: "did:plc:authoritywritersaaaaaaaa",
                space_type: "org.example.bucket",
                skey: "main",
                policy: Some("public"),
                app_access: Some("open"),
                app_allowed: None,
                managing_app: None,
                write_policy: None,
                write_managing_app: None,
            },
        )
        .await
        .unwrap();

        let first = accepted(record(&state.db, ALICE, "3kaaaaaaaaaa2").await);
        assert_eq!(first.prev_space_rev, None);
        let second = accepted(record(&state.db, BOB, "3kaaaaaaaaaa2").await);
        assert_eq!(second.prev_space_rev.as_ref(), Some(&first.space_rev));
        assert!(second.space_rev > first.space_rev);

        // Bob holds the latest revision; purge him.
        for sql in crate::PURGE_ACCOUNT_SQL {
            sqlx::query(sql).bind(BOB).execute(&state.db).await.unwrap();
        }
        let third = accepted(record(&state.db, ALICE, "3kaaaaaaaaaa3").await);
        assert_eq!(third.prev_space_rev.as_ref(), Some(&second.space_rev));
        assert!(third.space_rev > second.space_rev);

        assert_eq!(
            record(&state.db, ALICE, "3kaaaaaaaaaa3").await,
            WriterUpdate::Stale
        );
    }

    #[tokio::test]
    async fn a_space_without_simplespace_config_keeps_no_writer_set() {
        let state = test_state().await;
        assert_eq!(
            record(&state.db, ALICE, "3kaaaaaaaaaa2").await,
            WriterUpdate::NotAuthority
        );
    }
}
