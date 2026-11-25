// pattern: Imperative Shell

//! The Atproto Spaces feature: the `com.atproto.space.*` and `com.atproto.memberspace.*` routes,
//! the operator's `/v1/admin/spaces` pair, the space authorization
//! seam, the space query modules, the space sweeps, and the `spaces` capability entry.
//!
//! `pds` is the composition root and consumes only what this file exports: [`router`] / [`internal_router`],
//! [`spawn_sweeps`], [`CAPABILITY`], [`purge_account_rows`], the [`space_record_write`] choke point, and (behind `test-support`)
//! [`test_support`]. See `AGENTS.md`.

use axum::extract::FromRef;
use common::SpacesConfig;
use custos_core::sweep::Scheduler;
use custos_core::CoreState;
use sqlx::SqliteConnection;

mod auth;
mod capability;
mod db;
mod kem_gate;
mod policy;
mod router;
mod routes;
mod space_jti_sweep;
mod space_mac;
mod space_migration;
mod space_notify;
mod space_notify_retry;
mod space_oplog_sweep;
pub mod space_record_write;
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used, clippy::expect_used)] // fixtures: a failed request panics the test
pub mod test_support;
mod views;

pub use capability::CAPABILITY;
pub use router::{internal_router, router};

/// Register the space sweeps (two retention sweeps and the notification retry sweep) on `pds`'s
/// scheduler, only while the surface is enabled.
/// Disabled, no route can write the tables they reclaim or retry from, and their `null` slots in
/// the health readout read as "not configured", like the blob mirror's. Rows already stored keep
/// their data; only reclamation and retrying pause with the surface.
pub fn spawn_sweeps<St>(scheduler: &mut Scheduler<St>, config: &SpacesConfig)
where
    St: Clone + Send + Sync + 'static,
    CoreState: FromRef<St>,
{
    if !config.enabled {
        return;
    }
    // The (scope, jti) primary key enforces anti-replay; each row's expires_at carries its own
    // token's acceptance horizon, so the sweep only bounds storage growth.
    scheduler.spawn(space_jti_sweep::SpaceJtiSweep);
    tracing::info!(
        interval_secs = space_jti_sweep::SWEEP_INTERVAL.as_secs(),
        "space jti retention sweep started"
    );
    // The oplog is droppable by spec; this bounds it to a backfill window, and a syncer further
    // behind heals via getRepo.
    scheduler.spawn(space_oplog_sweep::SpaceOplogSweep);
    tracing::info!(
        interval_secs = space_oplog_sweep::SWEEP_INTERVAL.as_secs(),
        retention_secs = space_oplog_sweep::OPLOG_RETENTION_SECS,
        "space oplog compaction sweep started"
    );
    // Retries the syncer notices that must arrive, written durably by the transaction that
    // owes them.
    scheduler.spawn(space_notify_retry::SpaceNotifyRetrySweep);
    tracing::info!(
        interval_secs = space_notify_retry::SWEEP_INTERVAL.as_secs(),
        "space notify retry sweep started"
    );
}

/// The statements [`purge_account_rows`] runs, in FK order (ops and records reference the repo
/// row); this crate's own schema-walking test checks it covers every space table's account FK.
///
/// The account's own rows go: its space repos, its memberships, and its rows in any locally
/// hosted writer set (`space_writers` has no FK to `accounts`, since most writers are foreign
/// repos, and a purged account left there advertises a repo every reader then gets
/// `RepoNotFound` for).
///
/// The spaces it is the authority for are deleted as `deleteSpace` deletes them, but without a
/// `spaceDeleted` notice (the `#account` event carries the news): every space-keyed row goes,
/// pending notices included, and the `spaces` row stays as the tombstone, since members' records
/// are their own and an unanswerable space is the spec's deletion semantics.
pub const PURGE_ACCOUNT_SQL: &[&str] = &[
    "DELETE FROM space_repo_ops WHERE account_did = ?",
    "DELETE FROM space_records WHERE account_did = ?",
    "DELETE FROM space_repos WHERE account_did = ?",
    "DELETE FROM space_members WHERE member_did = ?",
    "DELETE FROM space_writers WHERE repo_did = ?",
    "DELETE FROM space_syncer_notice_retries \
     WHERE space_uri IN (SELECT uri FROM spaces WHERE authority_did = ?)",
    "DELETE FROM space_notify_registrations \
     WHERE space_uri IN (SELECT uri FROM spaces WHERE authority_did = ?)",
    "DELETE FROM space_members WHERE space_uri IN (SELECT uri FROM spaces WHERE authority_did = ?)",
    "DELETE FROM space_writers WHERE space_uri IN (SELECT uri FROM spaces WHERE authority_did = ?)",
    "UPDATE spaces SET deleted_at = datetime('now'), policy = NULL \
     WHERE authority_did = ? AND deleted_at IS NULL",
];

/// Delete every space-owned row of `did` inside the caller's account-purge transaction.
pub async fn purge_account_rows(tx: &mut SqliteConnection, did: &str) -> Result<(), sqlx::Error> {
    for sql in PURGE_ACCOUNT_SQL {
        sqlx::query(sql).bind(did).execute(&mut *tx).await?;
    }
    Ok(())
}

#[cfg(test)]
mod purge_tests {
    use super::*;
    use crate::space_record_write::{apply_space_writes, SpaceWriteAction, SpaceWriteOp};
    use crate::test_support::{
        memberspace_policy, seed_account_with_repo, seed_authority_space, state_with_master_key,
    };

    /// Every account FK on a space table is scoped by [`PURGE_ACCOUNT_SQL`], so a `space*` table
    /// added without extending the purge fails here rather than FK-failing the reaper.
    #[tokio::test]
    async fn purge_covers_every_space_account_foreign_key() {
        let pool = custos_db::test_pool().await;
        let checked = custos_db::purge_coverage::assert_purge_covers(
            &pool,
            |t| t.starts_with("space"), // `spaces` and every `space_*` table
            PURGE_ACCOUNT_SQL,
        )
        .await;
        assert!(checked >= 1, "sanity: found {checked} space account FKs");
    }

    /// The purge takes the account's own space repo, its membership, and its row
    /// in a locally-hosted space's writer set (`listRepos` must stop advertising it). The space
    /// it is authority for is deleted without a notice: no space-keyed row of it survives, a
    /// pending syncer notice included, and the `spaces` row stays as the tombstone that makes the
    /// space unanswerable (members' own records are theirs; the space simply stops answering).
    #[tokio::test]
    async fn purge_removes_space_rows_and_keeps_authority_space_tombstone() {
        let state = state_with_master_key().await;
        let did = "did:plc:purgespaces";
        seed_account_with_repo(&state.db, did).await;
        let space = "at://did:plc:purgespaces/space/org.example.bucket/self";
        seed_authority_space(&state.db, space, &memberspace_policy(false)).await;
        apply_space_writes(
            &state,
            &custos_core::space_uri::parse_space_ref(space).unwrap(),
            did,
            &[SpaceWriteOp {
                action: SpaceWriteAction::Put,
                collection: "org.example.note".to_string(),
                rkey: "one".to_string(),
                value: Some(serde_json::json!({"text": "purge me"})),
            }],
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO space_members (space_uri, member_did, added_at) \
             VALUES (?, ?, datetime('now'))",
        )
        .bind(space)
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
        // Someone else's rows keyed by the authority's space: a member, a writer, a syncer's
        // registration, and the notice that registration is owed.
        let other = "did:plc:purgespacesmember";
        sqlx::query(
            "INSERT INTO space_members (space_uri, member_did, added_at) \
             VALUES (?, ?, datetime('now'))",
        )
        .bind(space)
        .bind(other)
        .execute(&state.db)
        .await
        .unwrap();
        let mut conn = state.db.acquire().await.unwrap();
        crate::db::space_notify::upsert_writer(&mut conn, space, other, "3kaaaaaaaaaa2", &[7; 32])
            .await
            .unwrap();
        drop(conn);
        crate::db::space_notify::put_registration(
            &state.db,
            space,
            &crate::db::space_notify::Registration {
                endpoint: "https://syncer.example".to_string(),
                token: "t".to_string(),
            },
            1,
            100,
        )
        .await
        .unwrap();
        let claimed = crate::db::space_notice_retries::claim_lapsed(
            &state.db,
            space,
            "{}",
            custos_core::time::unix_now_secs(),
            i64::MAX,
            i64::MAX,
        )
        .await
        .unwrap();
        assert_eq!(claimed, 1);

        let mut tx = state.db.begin().await.unwrap();
        purge_account_rows(&mut tx, did).await.unwrap();
        tx.commit().await.unwrap();

        for (table, column) in [
            ("space_repo_ops", "account_did"),
            ("space_records", "account_did"),
            ("space_repos", "account_did"),
            ("space_members", "member_did"),
            ("space_writers", "repo_did"),
        ] {
            let n: i64 =
                sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?"))
                    .bind(did)
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            assert_eq!(n, 0, "{table} rows survived the purge");
        }
        // Every space-keyed table, walked from the schema so a new one can't be missed. Another
        // local member's repo would survive, as with `deleteSpace`; none is seeded here.
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT m.name FROM sqlite_master m, pragma_table_info(m.name) c \
             WHERE m.type = 'table' AND m.name LIKE 'space%' AND c.name = 'space_uri'",
        )
        .fetch_all(&state.db)
        .await
        .unwrap();
        assert!(tables.len() >= 7, "sanity: {tables:?}");
        for table in tables {
            let n: i64 =
                sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE space_uri = ?"))
                    .bind(space)
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            assert_eq!(
                n, 0,
                "{table} rows of the authority's space survived the purge"
            );
        }
        let (policy, deleted_at): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT policy, deleted_at FROM spaces WHERE uri = ?")
                .bind(space)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert!(
            policy.is_none() && deleted_at.is_some(),
            "the authority's space row survives as the deletion tombstone"
        );
    }
}
