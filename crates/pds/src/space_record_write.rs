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
//! * **Notification dispatch** — the network fan-out is
//!   `space_notify::fan_out_write`, spawned detached *after* the commit, so
//!   the store's blocking job still ends at the durable commit. It is
//!   triggered from here rather than from each record route because a write
//!   path that forgot to notify would look correct and silently strand every
//!   syncer. What stays inside the transaction is the writer-set row
//!   `listRepos` answers — our own durable claim about our own repo, not a
//!   network effect.
//!
//! Authentication and `space:` scope enforcement happen above this layer (the
//! space auth seam); callers pass an already-authorized `(space, did)`.

use crate::app::AppState;
use crate::space_uri::SpaceRef;
use common::{ApiError, ErrorCode};
use crypto::{format_set_hash_element, LtHash};

/// What one op does to its record path.
///
/// `Create`, `Update` and `Delete` each state a precondition on the path and fail when it does
/// not hold — the reference's space store does the same, and the batch lexicon declares
/// `RecordAlreadyExists`/`RecordNotFound` for exactly these. `Put` is the one action with no
/// precondition, which is why `putRecord` (an upsert by definition) is its only caller. The
/// idempotence `deleteRecord`'s lexicon promises is the *route's* — it checks for the record and
/// skips the commit entirely — not this layer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceWriteAction {
    /// Fail with `RecordAlreadyExists` when the record already exists (`createRecord`).
    Create,
    /// Upsert, with no precondition (`putRecord`).
    Put,
    /// Fail with `RecordNotFound` when the record is absent (`applyWrites`' `#update`).
    Update,
    /// Remove the record, failing with `RecordNotFound` when it is absent.
    Delete,
}

/// One record mutation in a space commit. `value` is required for
/// `Create`/`Put`/`Update` and ignored for `Delete`.
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
    /// The previous record CID; `None` for a create. The sync surface reads this from the oplog
    /// row this commit wrote, not from here, and the record routes label a write by the verb asked
    /// for — so nothing in production reads the field. It stays because the tests below assert the
    /// supersede chain through it (`Update` carries the CID it replaced).
    #[allow(dead_code)]
    pub prev: Option<String>,
}

/// Which account states a space commit may land on, and whether it is charged.
///
/// The split exists because migration has to write into a repo the account cannot otherwise
/// write to: `com.atproto.repo.importRepo` lands the public repo on a *deactivated* account,
/// and the permissioned repos have to arrive through the same window or they cannot follow
/// their account to a new host at all. Moderation states are refused either way — a takedown
/// is not a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceWriteAdmission {
    /// Ordinary writes: the account must be fully active, and the commit is charged against
    /// its write budget.
    Active,
    /// The migration import leg: a self-service-deactivated account may land a commit, and no
    /// write points are charged — an import is one bulk transfer of records the account
    /// already owns, not new authorship.
    Import,
}

/// A committed space write: the repo's new head and per-op results.
#[derive(Debug, Clone)]
pub struct SpaceCommitOutcome {
    /// The repo's rev after this commit.
    ///
    /// `rev` and `hash` together are what `notifyWrite` carries on the wire, but the fan-out is
    /// spawned from inside this module off the local values, before this struct exists — so the
    /// wire does not read them from here. `rev` is read by the import route's response; `hash`
    /// only by tests.
    pub rev: String,
    /// sha256 of the repo's LtHash state — the commit `hash` the wire carries. Read only by the
    /// tests below, which recompute the LtHash digest and check the commit agrees.
    #[allow(dead_code)]
    pub hash: [u8; 32],
    /// One entry per op, in request order.
    pub results: Vec<SpaceWriteResult>,
}

/// Apply a batch of record writes to one space repo as a single atomic commit.
///
/// The space row and the repo are both created on first write (fresh TID rev, empty LtHash
/// state) — a repo host records a space the first time its user writes into one, so a member
/// can join a foreign authority's space without this host having been told about it in advance.
/// Returns [`ErrorCode::Conflict`] when the rev CAS loses to a concurrent
/// commit — nothing lands, the client retries against the new head.
pub async fn apply_space_writes(
    state: &AppState,
    space: &SpaceRef,
    did: &str,
    ops: &[SpaceWriteOp],
    admission: SpaceWriteAdmission,
) -> Result<SpaceCommitOutcome, ApiError> {
    let space_uri = space.uri.as_str();
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
            SpaceWriteAction::Create | SpaceWriteAction::Put | SpaceWriteAction::Update => {
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
    // on the public write path — except on the import leg, which admits the
    // deactivated state the migration window runs in (see
    // [`SpaceWriteAdmission`]). Checked *inside* the transaction: the public
    // path folds this guard into its root CAS, but the space head's CAS is on
    // `space_repos`, not `accounts`, so a pre-transaction check would leave a
    // window for a concurrent deactivation to land between check and commit.
    use crate::db::accounts::AccountLifecycle;
    let admitted = match crate::db::accounts::account_lifecycle(&mut *tx, did).await? {
        Some(AccountLifecycle::Active) => true,
        Some(AccountLifecycle::Deactivated) => admission == SpaceWriteAdmission::Import,
        Some(_) => false,
        None => {
            tx.rollback().await.ok();
            return Err(ApiError::new(ErrorCode::NotFound, "account not found"));
        }
    };
    if !admitted {
        tx.rollback().await.ok();
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "account is deactivated",
        ));
    }

    // Record the space if this host has not seen it before. The reference does the same on
    // every space write, and it is what makes a foreign authority's space usable: nothing else
    // in the protocol tells a repo host that its user has joined one. The row carries no
    // simplespace config — that belongs to the authority, and stays NULL unless this host is it.
    //
    // Divergence from the reference, which additionally *clears* `deleted_at` here: a tombstone
    // is only ever written for a space this host is the authority for, and resurrecting one on a
    // member's write would undo the deletion the operator performed. So a deleted space refuses
    // writes instead — its members' existing records stay put (spec deletion semantics), they
    // just stop changing.
    crate::db::spaces::insert_space(
        &mut *tx,
        &crate::db::spaces::NewSpace {
            uri: space_uri,
            authority_did: &space.authority,
            space_type: &space.space_type,
            skey: &space.skey,
            policy: None,
            app_access: None,
            app_allowed: None,
            managing_app: None,
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, space = %space_uri, "failed to record space");
        internal_error()
    })?;
    let deleted = crate::db::spaces::get_space(&mut *tx, space_uri)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space_uri, "failed to load space");
            internal_error()
        })?
        .is_none_or(|row| row.deleted_at.is_some());
    if deleted {
        tx.rollback().await.ok();
        return Err(ApiError::new(
            ErrorCode::SpaceNotFound,
            "space has been deleted",
        ));
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
            SpaceWriteAction::Create | SpaceWriteAction::Put | SpaceWriteAction::Update => {
                if op.action == SpaceWriteAction::Create && prev_cid.is_some() {
                    tx.rollback().await.ok();
                    return Err(ApiError::new(
                        ErrorCode::RecordAlreadyExists,
                        "record already exists; use putRecord to update",
                    ));
                }
                if op.action == SpaceWriteAction::Update && prev_cid.is_none() {
                    tx.rollback().await.ok();
                    return Err(ApiError::new(
                        ErrorCode::RecordNotFound,
                        "record does not exist; use createRecord or putRecord to create it",
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
                    &new_rev,
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
                    tx.rollback().await.ok();
                    return Err(ApiError::new(
                        ErrorCode::RecordNotFound,
                        "record does not exist",
                    ));
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

    // Charge the commit against the account's write budget (same costs as the
    // public path, keyed by the already-authenticated DID). An import is not
    // charged: it moves records the account already owns, and a repo large
    // enough to be worth migrating would exhaust any sane budget on arrival.
    if admission == SpaceWriteAdmission::Active {
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
    }

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

    // The writer set `listRepos` answers, kept durable with the commit rather than derived
    // afterwards: for a space this host is the authority for, our own account's write is one of
    // the facts the authority reports. The query no-ops for a space whose authority is
    // elsewhere.
    let hash = lthash.digest();
    crate::db::space_notify::upsert_writer(&mut *tx, space_uri, did, &new_rev, &hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space_uri, did = %did, "failed to record space writer");
            internal_error()
        })?;

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, space = %space_uri, did = %did, "failed to commit space write transaction");
        internal_error()
    })?;

    // Best-effort, post-commit and non-blocking: tell the space host (or, when that is us, the
    // registered syncers) that this repo advanced. Placed here rather than in each record route
    // so no write path can be added that silently skips it.
    drop(crate::space_notify::fan_out_write(
        state, space, did, &new_rev, &hash,
    ));

    Ok(SpaceCommitOutcome {
        rev: new_rev,
        hash,
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

    const SPACE: &str = "at://did:plc:author/space/org.example.bucket/self";
    const DID: &str = "did:plc:spacewriter";

    fn space() -> SpaceRef {
        crate::space_uri::parse_space_ref(SPACE).expect("test space ref is well-formed")
    }

    /// Only the account: the space row is the write path's own responsibility.
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
            &space(),
            DID,
            &[
                put("org.example.note", "aaa", "one"),
                put("org.example.note", "bbb", "two"),
            ],
            SpaceWriteAdmission::Active,
        )
        .await
        .unwrap();
        assert_eq!(first.results.len(), 2);
        assert!(first.results.iter().all(|r| r.prev.is_none()));

        // Update one record, then delete the other, in one commit.
        let second = apply_space_writes(
            &state,
            &space(),
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
            SpaceWriteAdmission::Active,
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

    /// `Create` refuses an existing path; `Put` upserts it. The refusal is
    /// `RecordAlreadyExists`, the name the batch lexicon declares — distinct
    /// from the generic `Conflict` a lost CAS race reports.
    #[tokio::test]
    async fn create_conflicts_on_existing_record() {
        let state = test_state().await;
        seed(&state).await;
        let first = apply_space_writes(
            &state,
            &space(),
            DID,
            &[put("org.example.note", "aaa", "one")],
            SpaceWriteAdmission::Active,
        )
        .await
        .unwrap();

        let create = SpaceWriteOp {
            action: SpaceWriteAction::Create,
            collection: "org.example.note".to_string(),
            rkey: "aaa".to_string(),
            value: Some(serde_json::json!({"text": "clobber"})),
        };
        let err = apply_space_writes(
            &state,
            &space(),
            DID,
            &[create],
            SpaceWriteAdmission::Active,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), &ErrorCode::RecordAlreadyExists);

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

    /// `Update` and `Delete` both state that the record is there, and both
    /// answer `RecordNotFound` when it is not — the preconditions
    /// `applyWrites`' lexicon declares. (`deleteRecord`'s promised idempotence
    /// is the route's: it skips the commit rather than relaxing this.) A
    /// failed precondition leaves the head exactly where it was.
    #[tokio::test]
    async fn update_and_delete_require_an_existing_record() {
        let state = test_state().await;
        seed(&state).await;
        let first = apply_space_writes(
            &state,
            &space(),
            DID,
            &[put("org.example.note", "aaa", "x")],
            SpaceWriteAdmission::Active,
        )
        .await
        .unwrap();

        for op in [
            SpaceWriteOp {
                action: SpaceWriteAction::Delete,
                collection: "org.example.note".to_string(),
                rkey: "missing".to_string(),
                value: None,
            },
            SpaceWriteOp {
                action: SpaceWriteAction::Update,
                collection: "org.example.note".to_string(),
                rkey: "missing".to_string(),
                value: Some(serde_json::json!({"text": "revised"})),
            },
        ] {
            let err = apply_space_writes(&state, &space(), DID, &[op], SpaceWriteAdmission::Active)
                .await
                .unwrap_err();
            assert_eq!(err.code(), &ErrorCode::RecordNotFound);
        }

        // `Update` on a record that *is* there supersedes it, carrying `prev`.
        let second = apply_space_writes(
            &state,
            &space(),
            DID,
            &[SpaceWriteOp {
                action: SpaceWriteAction::Update,
                collection: "org.example.note".to_string(),
                rkey: "aaa".to_string(),
                value: Some(serde_json::json!({"text": "revised"})),
            }],
            SpaceWriteAdmission::Active,
        )
        .await
        .unwrap();
        assert_eq!(second.results[0].prev, first.results[0].cid);

        let repo = crate::db::space_repos::get_repo(&state.db, SPACE, DID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            repo.rev, second.rev,
            "only the satisfied op advanced the head"
        );
    }

    /// A first write into a space this host has never seen records it, so a
    /// member can join a foreign authority's space with no prior setup — and
    /// the row it writes claims no simplespace config, which belongs to the
    /// authority.
    #[tokio::test]
    async fn first_write_records_an_unknown_space() {
        let state = test_state().await;
        seed(&state).await;
        let unknown = crate::space_uri::parse_space_ref(
            "at://did:plc:someoneelse/space/org.example.bucket/shared",
        )
        .unwrap();

        apply_space_writes(
            &state,
            &unknown,
            DID,
            &[put("org.example.note", "aaa", "x")],
            SpaceWriteAdmission::Active,
        )
        .await
        .unwrap();

        let row = crate::db::spaces::get_space(&state.db, &unknown.uri)
            .await
            .unwrap()
            .expect("the write recorded the space");
        assert_eq!(row.authority_did, "did:plc:someoneelse");
        assert!(row.policy.is_none() && row.app_access.is_none());
        let (space_type, skey): (String, String) =
            sqlx::query_as("SELECT space_type, skey FROM spaces WHERE uri = ?")
                .bind(&unknown.uri)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(space_type, "org.example.bucket");
        assert_eq!(skey, "shared");
    }

    /// The lifecycle gates: a deactivated account's space repos are read-only,
    /// and a deleted space refuses writes rather than being resurrected by one.
    #[tokio::test]
    async fn lifecycle_gates_refuse_writes() {
        let state = test_state().await;
        seed(&state).await;

        apply_space_writes(
            &state,
            &space(),
            DID,
            &[put("org.example.note", "seed", "x")],
            SpaceWriteAdmission::Active,
        )
        .await
        .unwrap();
        sqlx::query("UPDATE spaces SET deleted_at = datetime('now') WHERE uri = ?")
            .bind(SPACE)
            .execute(&state.db)
            .await
            .unwrap();
        let err = apply_space_writes(
            &state,
            &space(),
            DID,
            &[put("org.example.note", "a", "x")],
            SpaceWriteAdmission::Active,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), &ErrorCode::SpaceNotFound);
        let still_deleted: Option<String> =
            sqlx::query_scalar("SELECT deleted_at FROM spaces WHERE uri = ?")
                .bind(SPACE)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert!(
            still_deleted.is_some(),
            "a member write must not undelete a space"
        );

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
        let err = apply_space_writes(
            &state,
            &space(),
            DID,
            &[put("org.example.note", "a", "x")],
            SpaceWriteAdmission::Active,
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), 403);
    }
}
