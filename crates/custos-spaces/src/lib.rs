// pattern: Imperative Shell

//! The Atproto Spaces feature: the `com.atproto.space.*` and `com.atproto.simplespace.*` routes,
//! `/v1/space/import-repo` and the operator's `/v1/admin/spaces` pair, the space authorization
//! seam, the space query modules, both space sweeps, and the `spaces` capability entry.
//!
//! `pds` is the composition root and consumes only what this file exports: [`SpacesState`],
//! [`router`] / [`internal_router`], [`spawn_sweeps`], [`CAPABILITY`], [`purge_account_rows`],
//! the [`space_record_write`] choke point, and (behind `test-support`)
//! [`test_support`]. See `AGENTS.md`.

use axum::extract::FromRef;
use common::SpacesConfig;
use custos_core::sweep::Scheduler;
use custos_core::CoreState;
use sqlx::SqliteConnection;

// Modules custos-core owns, aliased at the crate root so `crate::identity::…` and its siblings
// resolve as they did in `pds`.
use custos_core::{
    blob_store, identity, lexicon, metrics, rate_limit, space_uri, sweep, sweep_status, time,
};

mod auth;
mod capability;
mod db;
mod router;
mod routes;
mod space_jti_sweep;
mod space_notify;
mod space_oplog_sweep;
pub mod space_record_write;
mod state;
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used, clippy::expect_used)] // fixtures: a failed request panics the test
pub mod test_support;
mod views;

pub use capability::CAPABILITY;
pub use router::{internal_router, router};
pub use state::SpacesState;

/// Register both space retention sweeps on `pds`'s scheduler, only while the surface is enabled.
/// Disabled, no route can write the tables they reclaim, and their `null` slots in the health
/// readout read as "not configured", like the blob mirror's. Rows already stored keep their data;
/// only reclamation pauses with the surface.
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
}

/// The statements [`purge_account_rows`] runs, in FK order (ops and records reference the repo
/// row); this crate's own schema-walking test checks it covers every space table's account FK.
///
/// `spaces` rows deliberately survive even when the account is the authority: members' records are
/// their own, and an unanswerable space is exactly the spec's deletion semantics. `space_writers`
/// has no FK to `accounts` (most writers are foreign repos), so nothing removes those rows
/// implicitly, and a purged account left in `listRepos` advertises a repo every reader then gets
/// `RepoNotFound` for.
pub const PURGE_ACCOUNT_SQL: &[&str] = &[
    "DELETE FROM space_repo_ops WHERE account_did = ?",
    "DELETE FROM space_records WHERE account_did = ?",
    "DELETE FROM space_repos WHERE account_did = ?",
    "DELETE FROM space_members WHERE member_did = ?",
    "DELETE FROM space_notify_registrations WHERE subscriber_did = ?",
    "DELETE FROM space_writers WHERE repo_did = ?",
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
    use crate::db::spaces::{insert_space, NewSpace};
    use crate::space_record_write::{
        apply_space_writes, SpaceWriteAction, SpaceWriteAdmission, SpaceWriteOp,
    };
    use crate::test_support::{seed_account_with_repo, state_with_master_key};

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

    /// The purge takes the account's own space repo, its membership and notify rows, and its row
    /// in a locally-hosted space's writer set (`listRepos` must stop advertising it), while the
    /// `spaces` row it is authority for survives as the tombstone that makes the space
    /// unanswerable (members' own records are theirs; the space simply stops answering).
    #[tokio::test]
    async fn purge_removes_space_rows_and_keeps_authority_space_tombstone() {
        let state = state_with_master_key().await;
        let did = "did:plc:purgespaces";
        seed_account_with_repo(&state.db, did).await;
        let space = "at://did:plc:purgespaces/space/org.example.bucket/self";
        insert_space(
            &state.db,
            &NewSpace {
                uri: space,
                authority_did: did,
                space_type: "org.example.bucket",
                skey: "self",
                policy: Some("member-list"),
                app_access: Some("open"),
                app_allowed: None,
                managing_app: None,
                write_policy: None,
                write_managing_app: None,
            },
        )
        .await
        .unwrap();
        apply_space_writes(
            &state,
            &space_uri::parse_space_ref(space).unwrap(),
            did,
            &[SpaceWriteOp {
                action: SpaceWriteAction::Put,
                collection: "org.example.note".to_string(),
                rkey: "one".to_string(),
                value: Some(serde_json::json!({"text": "purge me"})),
            }],
            SpaceWriteAdmission::Active,
        )
        .await
        .unwrap();
        for sql in [
            "INSERT INTO space_members (space_uri, member_did, added_at) \
             VALUES (?, ?, datetime('now'))",
            "INSERT INTO space_notify_registrations \
             (space_uri, subscriber_did, repo_did, created_at, expires_at) \
             VALUES (?, ?, '', datetime('now'), datetime('now', '+1 hour'))",
        ] {
            sqlx::query(sql)
                .bind(space)
                .bind(did)
                .execute(&state.db)
                .await
                .unwrap();
        }

        let mut tx = state.db.begin().await.unwrap();
        purge_account_rows(&mut tx, did).await.unwrap();
        tx.commit().await.unwrap();

        for (table, column) in [
            ("space_repo_ops", "account_did"),
            ("space_records", "account_did"),
            ("space_repos", "account_did"),
            ("space_members", "member_did"),
            ("space_notify_registrations", "subscriber_did"),
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
        let spaces: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM spaces WHERE uri = ?")
            .bind(space)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(
            spaces, 1,
            "the authority's space row survives as the unanswerable-space tombstone"
        );
    }
}
