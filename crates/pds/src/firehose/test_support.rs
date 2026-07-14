// pattern: Functional Core

//! Shared test fixtures for the firehose module's test suites, split across `mod.rs`,
//! `events.rs`, and `replay.rs` test modules — this file holds what's common to more than one
//! of them.

use sqlx::SqlitePool;

use crate::db::{open_pool, run_migrations};

use super::{CommitInput, Firehose, OpAction, RepoOp, SyncInput};

/// A firehose backed by a fresh migrated in-memory database.
pub(crate) async fn test_firehose() -> Firehose {
    let db = open_pool("sqlite::memory:").await.expect("test pool");
    run_migrations(&db).await.expect("test migrations");
    Firehose::new(db).await.expect("firehose")
}

/// A firehose with a tiny broadcast buffer for exercising slow-consumer lag.
pub(crate) async fn test_firehose_with_capacity(capacity: usize) -> Firehose {
    let db = open_pool("sqlite::memory:").await.expect("test pool");
    run_migrations(&db).await.expect("test migrations");
    Firehose::with_capacity(db, capacity)
        .await
        .expect("firehose")
}

/// A valid CIDv1 (dag-cbor, sha2-256) — `emit_commit` validates wire CIDs before persisting, so
/// test commits must carry real CIDs rather than placeholder strings.
pub(crate) const VALID_CID: &str = "bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uwrf3e2o6cw3djmprrm";

pub(crate) fn commit_input(repo: &str) -> CommitInput {
    CommitInput {
        repo: repo.to_string(),
        commit: VALID_CID.to_string(),
        rev: "3krev".to_string(),
        since: None,
        prev_data: None,
        ops: vec![RepoOp {
            action: OpAction::Create,
            collection: "app.bsky.feed.post".to_string(),
            rkey: "abc".to_string(),
            cid: Some(VALID_CID.to_string()),
            prev: None,
            value: Some(serde_json::json!({ "text": "hi" })),
        }],
        blocks: vec![1, 2, 3],
    }
}

pub(crate) fn sync_input(did: &str) -> SyncInput {
    SyncInput {
        did: did.to_string(),
        rev: "3ksync".to_string(),
        blocks: vec![0xCA, 0xFE, 0xBA, 0xBE],
    }
}

/// Seed a minimal `accounts` row so a test can mutate it inside the same transaction as a staged
/// event, to observe whether that write survives a commit or a rollback.
pub(crate) async fn insert_account(db: &SqlitePool, did: &str, repo_root_cid: &str) {
    sqlx::query(
        "INSERT INTO accounts (did, email, password_hash, repo_root_cid, created_at, updated_at) \
         VALUES (?, ?, NULL, ?, datetime('now'), datetime('now'))",
    )
    .bind(did)
    .bind(format!("{did}@example.com"))
    .bind(repo_root_cid)
    .execute(db)
    .await
    .unwrap();
}
