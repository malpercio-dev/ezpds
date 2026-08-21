// pattern: Imperative Shell

//! The single write choke point for permissioned space repos — the
//! `record_write.rs` analog for the DB-backed, MST-less store (V065).
//!
//! Every mutation of a space repo flows through [`apply_space_writes`]:
//! validate → CAS rev → update LtHash state → append oplog — all inside one
//! SQLite transaction, so a space commit is atomic by construction. That is
//! the structural difference from the public path: the public repo's write
//! spans a non-transactional block store and needs per-DID locks plus a
//! post-commit GC; here the record rows, the oplog, and the repo head commit
//! or roll back together, and the rev compare-and-swap alone serializes
//! writers.
//!
//! Two accounting concerns deliberately do *not* live here:
//!
//! * **Blob references** — like the public path, nothing is bookkept at write
//!   time. Blob GC is authoritative: each pass decodes the account's stored
//!   space records and unions their blob references with the public repo's
//!   (`blob_gc::collect_referenced_blob_cids`), so a blob referenced from a
//!   space record is pinned exactly like one referenced from the MST.
//! * **Notification dispatch** — a successful commit returns the new `rev`
//!   and set hash (what `notifyWrite` carries on the wire); the fan-out to
//!   registered syncers is the space-host role's worker, which attaches to
//!   this seam. The store's job ends at the durable commit.
//!
//! Authentication and `space:` scope enforcement happen above this layer (the
//! space auth seam); callers pass an already-authorized `(space, did)`.

// Consumed by the space record CRUD routes, which land next; until then the
// module is exercised by its own tests.
#![allow(dead_code)]

use crate::app::AppState;
use common::{ApiError, ErrorCode};
use crypto::{format_set_hash_element, LtHash};

/// What one op does to its record path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceWriteAction {
    /// Fail with a conflict when the record already exists (`createRecord`).
    Create,
    /// Upsert (`putRecord`).
    Put,
    /// Remove the record; deleting an absent record is an idempotent no-op.
    Delete,
}

/// One record mutation in a space commit. `value` is required for
/// `Create`/`Put` and ignored for `Delete`.
pub struct SpaceWriteOp {
    pub action: SpaceWriteAction,
    pub collection: String,
    pub rkey: String,
    pub value: Option<serde_json::Value>,
}

/// What one op did, for the caller's response body and oplog mirroring.
#[derive(Debug, Clone)]
pub struct SpaceWriteResult {
    pub collection: String,
    pub rkey: String,
    /// The new record CID; `None` for a delete.
    pub cid: Option<String>,
    /// The previous record CID; `None` for a create.
    pub prev: Option<String>,
}

/// A committed space write: the repo's new head and per-op results.
#[derive(Debug, Clone)]
pub struct SpaceCommitOutcome {
    /// The repo's rev after this commit (unchanged if every op was an
    /// idempotent delete-of-absent no-op).
    pub rev: String,
    /// sha256 of the repo's LtHash state — the commit `hash` the wire carries.
    pub hash: [u8; 32],
    /// One entry per *effective* op (idempotent delete no-ops are omitted).
    pub results: Vec<SpaceWriteResult>,
}

/// Apply a batch of record writes to one space repo as a single atomic commit.
///
/// The repo is created on first write (fresh TID rev, empty LtHash state).
/// Returns [`ErrorCode::Conflict`] when the rev CAS loses to a concurrent
/// commit — nothing lands, the client retries against the new head.
pub async fn apply_space_writes(
    state: &AppState,
    space_uri: &str,
    did: &str,
    ops: &[SpaceWriteOp],
) -> Result<SpaceCommitOutcome, ApiError> {
    if ops.is_empty() {
        return Err(ApiError::new(ErrorCode::InvalidRequest, "no writes given"));
    }

    // Validate every op before touching the database: record path shape, the
    // schema-free record-format gate, and value presence. (The lexicon
    // `validate`-flag check is a route-layer concern, layered on by the CRUD
    // surface exactly as the public routes do.)
    for op in ops {
        repo_engine::validate_record_path(&op.collection, &op.rkey)
            .map_err(|e| ApiError::new(ErrorCode::InvalidRequest, e.to_string()))?;
        match op.action {
            SpaceWriteAction::Create | SpaceWriteAction::Put => {
                let value = op.value.as_ref().ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::InvalidRequest,
                        "write op is missing a record value",
                    )
                })?;
                crate::auth::validation::validate_record_formats(value)
                    .map_err(|message| ApiError::new(ErrorCode::InvalidRequest, message))?;
            }
            SpaceWriteAction::Delete => {}
        }
    }

    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open space write transaction");
        internal_error()
    })?;

    // A deactivated, suspended, or taken-down account is read-only, exactly as
    // on the public write path. Checked *inside* the transaction: the public
    // path folds this guard into its root CAS, but the space head's CAS is on
    // `space_repos`, not `accounts`, so a pre-transaction check would leave a
    // window for a concurrent deactivation to land between check and commit.
    match crate::db::accounts::account_lifecycle(&mut *tx, did).await? {
        Some(crate::db::accounts::AccountLifecycle::Active) => {}
        Some(_) => {
            tx.rollback().await.ok();
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "account is deactivated",
            ));
        }
        None => {
            tx.rollback().await.ok();
            return Err(ApiError::new(ErrorCode::NotFound, "account not found"));
        }
    }

    // The space must exist and be alive. A deleted space refuses writes — its
    // members' existing records stay put (spec deletion semantics), they just
    // stop changing.
    let space = crate::db::spaces::get_space(&mut *tx, space_uri)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space_uri, "failed to load space");
            internal_error()
        })?;
    let Some(space) = space else {
        tx.rollback().await.ok();
        return Err(ApiError::new(ErrorCode::NotFound, "space not found"));
    };
    if space.deleted_at.is_some() {
        tx.rollback().await.ok();
        return Err(ApiError::new(ErrorCode::NotFound, "space has been deleted"));
    }

    // Load the repo head, or start a fresh one on first write.
    let existing_repo = crate::db::space_repos::get_repo(&mut *tx, space_uri, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space_uri, did = %did, "failed to load space repo");
            internal_error()
        })?;
    let (prev_rev, mut lthash) = match &existing_repo {
        Some(repo) => {
            let lthash = LtHash::from_state(&repo.lthash_state).map_err(|e| {
                tracing::error!(error = %e, space = %space_uri, did = %did, "stored LtHash state is malformed");
                internal_error()
            })?;
            (Some(repo.rev.clone()), lthash)
        }
        None => (None, LtHash::new()),
    };
    let new_rev = match &prev_rev {
        Some(prev) => repo_engine::next_record_rev(prev).map_err(|e| {
            tracing::error!(error = %e, space = %space_uri, did = %did, "failed to derive commit rev");
            internal_error()
        })?,
        None => repo_engine::generate_tid(),
    };

    // Create or advance the head before touching any child row. Two distinct
    // reasons share this spot: on a first write, `insert_repo` is what
    // satisfies the record/oplog rows' `(space_uri, account_did)` foreign key
    // (SQLite enforces FKs immediately); on every later write,
    // `advance_repo_rev` is the rev compare-and-swap that serializes
    // concurrent writers — a commit that moved the head since our read makes
    // it a zero-row update, so we bail before doing any child-row work. The
    // folded LtHash state is finalized after the ops loop, same transaction.
    let advanced = match &prev_rev {
        Some(prev) => {
            crate::db::space_repos::advance_repo_rev(
                &mut *tx,
                space_uri,
                did,
                &new_rev,
                &lthash.state(),
                prev,
            )
            .await
        }
        None => {
            crate::db::space_repos::insert_repo(&mut *tx, space_uri, did, &new_rev, &lthash.state())
                .await
        }
    }
    .map_err(|e| {
        tracing::error!(error = %e, space = %space_uri, did = %did, "failed to advance space repo head");
        internal_error()
    })?;
    if !advanced {
        tx.rollback().await.ok();
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "space repo was modified concurrently; retry against the current head",
        ));
    }

    // Fold each op into the record set (reads see earlier ops in the same
    // batch — the rows are written as we go), the LtHash, and the oplog.
    // Deleting an absent record is skipped rather than an error, matching the
    // reference's idempotent deleteRecord.
    let mut results: Vec<SpaceWriteResult> = Vec::new();
    let mut write_cost: u64 = 0;
    for op in ops {
        let existing = crate::db::space_repos::get_record(
            &mut *tx,
            space_uri,
            did,
            &op.collection,
            &op.rkey,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space_uri, did = %did, "failed to read space record");
            internal_error()
        })?;
        let prev_cid = existing.map(|r| r.cid);

        match op.action {
            SpaceWriteAction::Create | SpaceWriteAction::Put => {
                if op.action == SpaceWriteAction::Create && prev_cid.is_some() {
                    tx.rollback().await.ok();
                    return Err(ApiError::new(
                        ErrorCode::Conflict,
                        "record already exists; use putRecord to update",
                    ));
                }
                let value = op.value.as_ref().expect("validated above");
                let ipld = repo_engine::json_to_record_value(value)
                    .map_err(|e| ApiError::new(ErrorCode::InvalidRequest, e.to_string()))?;
                let (cid, bytes) = repo_engine::encode_record_block(&ipld)
                    .map_err(|e| ApiError::new(ErrorCode::InvalidRequest, e.to_string()))?;
                let cid = cid.to_string();

                if let Some(prev) = &prev_cid {
                    lthash.remove(&format_set_hash_element(&op.collection, &op.rkey, prev));
                    write_cost += crate::rate_limit::WRITE_COST_UPDATE;
                } else {
                    write_cost += crate::rate_limit::WRITE_COST_CREATE;
                }
                lthash.add(&format_set_hash_element(&op.collection, &op.rkey, &cid));

                crate::db::space_repos::upsert_record(
                    &mut *tx,
                    space_uri,
                    did,
                    &op.collection,
                    &op.rkey,
                    &cid,
                    &bytes,
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, space = %space_uri, did = %did, "failed to write space record");
                    internal_error()
                })?;
                crate::db::space_repos::insert_repo_op(
                    &mut *tx,
                    space_uri,
                    did,
                    &new_rev,
                    &op.collection,
                    &op.rkey,
                    Some(&cid),
                    prev_cid.as_deref(),
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, space = %space_uri, did = %did, "failed to append space oplog entry");
                    internal_error()
                })?;
                results.push(SpaceWriteResult {
                    collection: op.collection.clone(),
                    rkey: op.rkey.clone(),
                    cid: Some(cid),
                    prev: prev_cid,
                });
            }
            SpaceWriteAction::Delete => {
                let Some(prev) = prev_cid else {
                    continue; // idempotent: deleting an absent record is a no-op
                };
                lthash.remove(&format_set_hash_element(&op.collection, &op.rkey, &prev));
                write_cost += crate::rate_limit::WRITE_COST_DELETE;
                crate::db::space_repos::delete_record(
                    &mut *tx,
                    space_uri,
                    did,
                    &op.collection,
                    &op.rkey,
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, space = %space_uri, did = %did, "failed to delete space record");
                    internal_error()
                })?;
                crate::db::space_repos::insert_repo_op(
                    &mut *tx,
                    space_uri,
                    did,
                    &new_rev,
                    &op.collection,
                    &op.rkey,
                    None,
                    Some(&prev),
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, space = %space_uri, did = %did, "failed to append space oplog entry");
                    internal_error()
                })?;
                results.push(SpaceWriteResult {
                    collection: op.collection.clone(),
                    rkey: op.rkey.clone(),
                    cid: None,
                    prev: Some(prev),
                });
            }
        }
    }

    // Every op was an idempotent no-op: roll back the head advance — the
    // existing head stands, and a repo is never brought into existence by a
    // batch that wrote nothing.
    if results.is_empty() {
        tx.rollback().await.ok();
        let Some(repo) = existing_repo else {
            return Err(ApiError::new(ErrorCode::NotFound, "space repo not found"));
        };
        return Ok(SpaceCommitOutcome {
            rev: repo.rev,
            hash: lthash.digest(),
            results,
        });
    }

    // Charge the commit against the account's write budget (same costs as the
    // public path, keyed by the already-authenticated DID).
    state
        .rate_limiter
        .check_write_points(did, write_cost)
        .inspect_err(|_| {
            state.metrics.rate_limit_rejections.add(
                1,
                &[crate::metrics::label(
                    crate::metrics::names::LABEL_LIMITER,
                    "account_writes",
                )],
            );
        })?;

    // Finalize the folded LtHash state. The rev was already advanced (and
    // CAS-guarded) before the fold; inside the same transaction this update
    // trivially matches its own rev.
    let finalized = crate::db::space_repos::advance_repo_rev(
        &mut *tx,
        space_uri,
        did,
        &new_rev,
        &lthash.state(),
        &new_rev,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, space = %space_uri, did = %did, "failed to store space repo state");
        internal_error()
    })?;
    if !finalized {
        tx.rollback().await.ok();
        tracing::error!(space = %space_uri, did = %did, "space repo head vanished mid-transaction");
        return Err(internal_error());
    }

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, space = %space_uri, did = %did, "failed to commit space write transaction");
        internal_error()
    })?;

    Ok(SpaceCommitOutcome {
        rev: new_rev,
        hash: lthash.digest(),
        results,
    })
}

fn internal_error() -> ApiError {
    ApiError::new(ErrorCode::InternalError, "failed to write space record")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use crate::db::spaces::NewSpace;

    const SPACE: &str = "at://did:plc:author/space/org.example.bucket/self";
    const DID: &str = "did:plc:spacewriter";

    async fn seed(state: &crate::app::AppState) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(DID)
        .bind(format!("{DID}@example.com"))
        .execute(&state.db)
        .await
        .unwrap();
        crate::db::spaces::insert_space(
            &state.db,
            &NewSpace {
                uri: SPACE,
                authority_did: DID,
                space_type: "org.example.bucket",
                skey: "self",
                policy: Some("member-list"),
                app_access: Some("open"),
                managing_app: None,
            },
        )
        .await
        .unwrap();
    }

    fn put(collection: &str, rkey: &str, text: &str) -> SpaceWriteOp {
        SpaceWriteOp {
            action: SpaceWriteAction::Put,
            collection: collection.to_string(),
            rkey: rkey.to_string(),
            value: Some(serde_json::json!({"text": text})),
        }
    }

    /// The full life of a repo through the choke point: first write creates
    /// the head, every commit advances `rev` strictly, the oplog mirrors each
    /// op, and — the invariant everything else hangs off — the incrementally
    /// maintained LtHash state always equals the state recomputed from scratch
    /// over the current record set.
    #[tokio::test]
    async fn write_flow_maintains_lthash_oplog_and_rev() {
        let state = test_state().await;
        seed(&state).await;

        let first = apply_space_writes(
            &state,
            SPACE,
            DID,
            &[
                put("org.example.note", "aaa", "one"),
                put("org.example.note", "bbb", "two"),
            ],
        )
        .await
        .unwrap();
        assert_eq!(first.results.len(), 2);
        assert!(first.results.iter().all(|r| r.prev.is_none()));

        // Update one record, then delete the other, in one commit.
        let second = apply_space_writes(
            &state,
            SPACE,
            DID,
            &[
                put("org.example.note", "aaa", "one revised"),
                SpaceWriteOp {
                    action: SpaceWriteAction::Delete,
                    collection: "org.example.note".to_string(),
                    rkey: "bbb".to_string(),
                    value: None,
                },
            ],
        )
        .await
        .unwrap();
        assert!(second.rev > first.rev, "rev must be strictly increasing");
        assert_eq!(second.results[0].prev, first.results[0].cid);
        assert_eq!(second.results[1].cid, None);

        // The stored state must equal a from-scratch fold of the live records.
        let repo = crate::db::space_repos::get_repo(&state.db, SPACE, DID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(repo.rev, second.rev);
        let rows: Vec<(String, String, String)> =
            sqlx::query_as("SELECT collection, rkey, cid FROM space_records WHERE account_did = ?")
                .bind(DID)
                .fetch_all(&state.db)
                .await
                .unwrap();
        assert_eq!(rows.len(), 1, "bbb was deleted");
        let mut recomputed = LtHash::new();
        for (collection, rkey, cid) in &rows {
            recomputed.add(&format_set_hash_element(collection, rkey, cid));
        }
        assert_eq!(recomputed.state().as_slice(), repo.lthash_state.as_slice());
        assert_eq!(recomputed.digest(), second.hash);

        // The oplog carries every op: two creates, one update (prev set), one
        // delete (cid NULL), batch ops sharing their commit's rev.
        let ops: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT rev, cid, prev FROM space_repo_ops WHERE account_did = ? ORDER BY rowid",
        )
        .bind(DID)
        .fetch_all(&state.db)
        .await
        .unwrap();
        assert_eq!(ops.len(), 4);
        assert_eq!(ops[0].0, first.rev);
        assert_eq!(ops[1].0, first.rev);
        assert_eq!(ops[2].0, second.rev);
        assert!(ops[2].1.is_some() && ops[2].2.is_some(), "update op");
        assert!(ops[3].1.is_none() && ops[3].2.is_some(), "delete op");
    }

    /// `Create` refuses an existing path; `Put` upserts it.
    #[tokio::test]
    async fn create_conflicts_on_existing_record() {
        let state = test_state().await;
        seed(&state).await;
        let first =
            apply_space_writes(&state, SPACE, DID, &[put("org.example.note", "aaa", "one")])
                .await
                .unwrap();

        let create = SpaceWriteOp {
            action: SpaceWriteAction::Create,
            collection: "org.example.note".to_string(),
            rkey: "aaa".to_string(),
            value: Some(serde_json::json!({"text": "clobber"})),
        };
        let err = apply_space_writes(&state, SPACE, DID, &[create])
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 409);

        // The failed batch must not have advanced the head or left oplog rows.
        let repo = crate::db::space_repos::get_repo(&state.db, SPACE, DID)
            .await
            .unwrap()
            .unwrap();
        let ops: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM space_repo_ops WHERE account_did = ?")
                .bind(DID)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(ops, 1);
        assert_eq!(
            repo.rev, first.rev,
            "the failed batch must not advance the head"
        );
    }

    /// Deleting an absent record is an idempotent no-op: the head stands and
    /// no oplog entry is appended.
    #[tokio::test]
    async fn delete_of_absent_record_is_a_noop() {
        let state = test_state().await;
        seed(&state).await;
        let first = apply_space_writes(&state, SPACE, DID, &[put("org.example.note", "aaa", "x")])
            .await
            .unwrap();

        let outcome = apply_space_writes(
            &state,
            SPACE,
            DID,
            &[SpaceWriteOp {
                action: SpaceWriteAction::Delete,
                collection: "org.example.note".to_string(),
                rkey: "missing".to_string(),
                value: None,
            }],
        )
        .await
        .unwrap();
        assert_eq!(outcome.rev, first.rev);
        assert!(outcome.results.is_empty());
    }

    /// The lifecycle gate: a deactivated account's space repos are read-only,
    /// and a write into an unknown or deleted space is refused.
    #[tokio::test]
    async fn lifecycle_gates_refuse_writes() {
        let state = test_state().await;
        seed(&state).await;

        let err = apply_space_writes(
            &state,
            "at://did:plc:author/space/org.example.bucket/nosuch",
            DID,
            &[put("org.example.note", "aaa", "x")],
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), 404);

        sqlx::query("UPDATE spaces SET deleted_at = datetime('now') WHERE uri = ?")
            .bind(SPACE)
            .execute(&state.db)
            .await
            .unwrap();
        let err = apply_space_writes(&state, SPACE, DID, &[put("org.example.note", "a", "x")])
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 404);

        sqlx::query("UPDATE spaces SET deleted_at = NULL WHERE uri = ?")
            .bind(SPACE)
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind(DID)
            .execute(&state.db)
            .await
            .unwrap();
        let err = apply_space_writes(&state, SPACE, DID, &[put("org.example.note", "a", "x")])
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 403);
    }
}
