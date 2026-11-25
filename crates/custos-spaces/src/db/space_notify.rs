// pattern: Imperative Shell

//! The space-host notification tables: notification registrations
//! (`space_notify_registrations`, V081) and the writer set (`space_writers`, V067).
//!
//! A registration is a syncer's `(endpoint, token)` for one space, made through
//! `authorizeSpaceSync` and expiring with the credential it came with. A repo host keeps no
//! registration: it pushes `notifyRepoUpdate` straight to the authority.
//!
//! Expiry is enforced by the read query. Re-registering refreshes the row through its primary
//! key. The token is stored as given, because every notice carries it; it is never logged.

use sqlx::{Sqlite, SqlitePool};

/// One syncer's registration for a space: where to deliver, and the token to present there.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Registration {
    pub endpoint: String,
    pub token: String,
}

/// Whether `(endpoint, token)` is registered for the space, lapsed or not. A known registration
/// is renewed without being confirmed again.
pub async fn registration_exists(
    pool: &SqlitePool,
    space_uri: &str,
    registration: &Registration,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM space_notify_registrations \
         WHERE space_uri = ? AND endpoint = ? AND token = ?)",
    )
    .bind(space_uri)
    .bind(&registration.endpoint)
    .bind(&registration.token)
    .fetch_one(pool)
    .await
}

/// How many of a space's registrations are still active.
pub async fn count_active_registrations(
    pool: &SqlitePool,
    space_uri: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM space_notify_registrations \
         WHERE space_uri = ? AND expires_at > datetime('now')",
    )
    .bind(space_uri)
    .fetch_one(pool)
    .await
}

/// How long a lapsed registration that was never sent its expiry notice is kept. Within it, the
/// next update still owes the syncer that notice; past it, the row is pruned (the same 72 h the
/// syncer-notice retries run for).
const UNNOTIFIED_LAPSE_RETENTION: &str = "-72 hours";

/// Delete a space's registrations that lapsed more than 72 h ago without their expiry notice
/// being claimed. A claimed one is removed when its notice is delivered or abandoned, never here.
/// Run before each new registration, so a space's dead rows stay bounded by the 72 h window.
pub async fn prune_lapsed_registrations(
    pool: &SqlitePool,
    space_uri: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM space_notify_registrations \
         WHERE space_uri = ? AND expiry_notified = 0 AND expires_at <= datetime('now', ?)",
    )
    .bind(space_uri)
    .bind(UNNOTIFIED_LAPSE_RETENTION)
    .execute(pool)
    .await?;
    Ok(())
}

/// What [`put_registration`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutRegistration {
    /// Recorded, or renewed.
    Written,
    /// A new registration, refused: the space already holds `cap` active ones.
    Full,
    /// Nothing written: the space is unknown or deleted.
    SpaceGone,
}

/// Record or renew a registration, expiring at `expires_at` (unix seconds). Renewal clears
/// `expiry_notified`, so a later lapse is owed its own notice.
///
/// One statement, so its checks are atomic with the write: the space must exist undeleted (a
/// registration can't outlive a concurrent deletion), and a *new* registration is written only
/// while the space holds fewer than `cap` active ones. Renewing a held registration always
/// succeeds. A caller's earlier count is only a cheap pre-check; this is the cap.
pub async fn put_registration(
    pool: &SqlitePool,
    space_uri: &str,
    registration: &Registration,
    expires_at: u64,
    cap: i64,
) -> Result<PutRegistration, sqlx::Error> {
    let expires_at = i64::try_from(expires_at).map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
    let written = sqlx::query(
        "INSERT INTO space_notify_registrations \
         (space_uri, endpoint, token, expires_at, expiry_notified) \
         SELECT uri, ?1, ?2, datetime(?3, 'unixepoch'), 0 FROM spaces \
         WHERE uri = ?4 AND deleted_at IS NULL AND ( \
             EXISTS (SELECT 1 FROM space_notify_registrations \
                     WHERE space_uri = ?4 AND endpoint = ?1 AND token = ?2) \
             OR (SELECT COUNT(*) FROM space_notify_registrations \
                 WHERE space_uri = ?4 AND expires_at > datetime('now')) < ?5) \
         ON CONFLICT (space_uri, endpoint, token) \
         DO UPDATE SET expires_at = excluded.expires_at, expiry_notified = 0",
    )
    .bind(&registration.endpoint)
    .bind(&registration.token)
    .bind(expires_at)
    .bind(space_uri)
    .bind(cap)
    .execute(pool)
    .await?;
    if written.rows_affected() > 0 {
        return Ok(PutRegistration::Written);
    }
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM spaces WHERE uri = ? AND deleted_at IS NULL)",
    )
    .bind(space_uri)
    .fetch_one(pool)
    .await?;
    Ok(if live {
        PutRegistration::Full
    } else {
        PutRegistration::SpaceGone
    })
}

/// Withdraw a registration. Idempotent.
pub async fn remove_registration(
    pool: &SqlitePool,
    space_uri: &str,
    registration: &Registration,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM space_notify_registrations \
         WHERE space_uri = ? AND endpoint = ? AND token = ?",
    )
    .bind(space_uri)
    .bind(&registration.endpoint)
    .bind(&registration.token)
    .execute(pool)
    .await?;
    Ok(())
}

/// A space's registrations, the recipients of a write fan-out (`active`) or of a deletion notice
/// (every one, lapsed included: a lapsed syncer is still told its space is gone). Ordered so a
/// fan-out is deterministic, freshest first, and capped by `limit`.
pub async fn registrations_for_space(
    pool: &SqlitePool,
    space_uri: &str,
    active: bool,
    limit: i64,
) -> Result<Vec<Registration>, sqlx::Error> {
    sqlx::query_as(
        "SELECT endpoint, token FROM space_notify_registrations \
         WHERE space_uri = ? AND (NOT ? OR expires_at > datetime('now')) \
         ORDER BY expires_at DESC, endpoint, token LIMIT ?",
    )
    .bind(space_uri)
    .bind(active)
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
        crate::test_support::seed_authority_space(
            &state.db,
            SPACE,
            &crate::test_support::memberspace_policy(true),
        )
        .await;

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
    async fn a_space_without_a_policy_keeps_no_writer_set() {
        let state = test_state().await;
        assert_eq!(
            record(&state.db, ALICE, "3kaaaaaaaaaa2").await,
            WriterUpdate::NotAuthority
        );
    }
}
