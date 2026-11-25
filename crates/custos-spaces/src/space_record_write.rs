// pattern: Imperative Shell

//! The single write choke point for permissioned space repos — the
//! `record_write.rs` analog for the DB-backed, MST-less store (V065).
//!
//! Every mutation of a space repo flows through [`apply_space_writes`] (or, for
//! the policy module's published records, [`apply_space_writes_in_tx`] on the
//! caller's transaction): validate → CAS rev → update LtHash state → append
//! oplog — all inside one SQLite transaction, so a space commit is atomic by
//! construction. The one exception is the migration import,
//! [`import_space_repo`], which replaces a repo outright. That is
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
//!   `space_notify::{forward_write, report_write}`, spawned detached *after* the commit, so
//!   the store's blocking job still ends at the durable commit. It is
//!   triggered from here rather than from each record route because a write
//!   path that forgot to notify would look correct and silently strand every
//!   syncer. What stays inside the transaction is the writer-set row
//!   `listWriters` answers — our own durable claim about our own repo, not a
//!   network effect.
//!
//! **The writer set is gated on the space's write policy; the write is not.** In a space this
//! host governs, a commit joins (or rejoins) the writer set only when the policy admits the
//! writer, the same check an inbound `notifyRepoUpdate` gets
//! (`auth::space::authorize_write_notification`: member `write` bit, `publicWrite`, a
//! managedspace's `checkAccess`). The record itself always commits, since the repo is the
//! writer's own, as in the reference, where a local write reaches its own authority through
//! `notifyRepoUpdate` too. A refused write records no writer row and fans nothing out. The
//! decision is made *before* the transaction ([`writer_may_join`]), because `checkAccess` is a
//! network call and the single SQLite connection must not wait on it. It fails closed: no
//! answer from a managing app means no join. A space governed elsewhere is unchanged: its
//! authority checks the policy on our outbound `notifyRepoUpdate`.
//!
//! Authentication and `space:` scope enforcement happen above this layer (the
//! space auth seam); callers pass an already-authorized `(space, did)`.

use common::{ApiError, ErrorCode};
use crypto::{format_set_hash_element, LtHash};
use custos_core::space_uri::SpaceRef;
use custos_core::CoreState;

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

/// A committed space write: the repo's new head and per-op results.
#[derive(Debug, Clone)]
pub struct SpaceCommitOutcome {
    /// The repo's rev after this commit.
    ///
    /// `rev` and `hash` together are what `notifyRepoUpdate` carries on the wire (as `repoRev`
    /// and `data`), but the fan-out is spawned from inside this module off the local values,
    /// before this struct exists — so the wire does not read them from here. Both are read only
    /// by tests.
    #[allow(dead_code)]
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
/// The repo is created on first write (fresh TID rev, empty LtHash state), and a commit that
/// empties it leaves it in place at the empty-set digest. A foreign authority's space row is recorded on first write too, so a
/// member can join it without this host having been told in advance; a space anchored on `did`
/// itself must already exist ([`ErrorCode::SpaceNotFound`] otherwise).
/// Returns [`ErrorCode::Conflict`] when the rev CAS loses to a concurrent
/// commit — nothing lands, the client retries against the new head.
///
/// The published policy and member collections (`crate::policy::PUBLISHED_COLLECTIONS`) are
/// refused here in any repo: only the policy module writes them, through
/// [`apply_space_writes_in_tx`], from the space's configuration. [`import_space_repo`] accepts
/// them as they arrive, as the reference's import does.
pub async fn apply_space_writes(
    state: &CoreState,
    space: &SpaceRef,
    did: &str,
    ops: &[SpaceWriteOp],
) -> Result<SpaceCommitOutcome, ApiError> {
    validate_ops(ops)?;
    if let Some(op) = ops
        .iter()
        .find(|op| crate::policy::PUBLISHED_COLLECTIONS.contains(&op.collection.as_str()))
    {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            format!(
                "{} records are published by the PDS from a space's configuration and cannot be written directly",
                op.collection
            ),
        ));
    }
    let join = writer_may_join(state, space, did).await?;
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open space write transaction");
        internal_error()
    })?;
    let commit = commit_ops(state, &mut tx, space, did, ops, join).await?;
    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, space = %space.uri, did = %did, "failed to commit space write transaction");
        internal_error()
    })?;
    Ok(commit.announce(state))
}

/// Apply `ops` to `did`'s repo inside the caller's transaction — the policy module's publish
/// entry, so a policy or member record lands or is withdrawn atomically with the configuration
/// change it mirrors. Skips the published-collection refusal [`apply_space_writes`] applies.
///
/// `None` when there is nothing to write. Otherwise the caller commits its transaction and then
/// calls [`PendingSpaceCommit::announce`], which fires the post-commit notification fan-out.
///
/// The only writer here is the space's authority, whom every policy admits, so the commit always
/// joins the writer set.
pub(crate) async fn apply_space_writes_in_tx(
    state: &CoreState,
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    space: &SpaceRef,
    did: &str,
    ops: &[SpaceWriteOp],
) -> Result<Option<PendingSpaceCommit>, ApiError> {
    if ops.is_empty() {
        return Ok(None);
    }
    validate_ops(ops)?;
    let join = did == space.authority;
    commit_ops(state, tx, space, did, ops, join).await.map(Some)
}

/// Whether a commit by `did` into `space` may join the writer set, decided before the commit's
/// transaction (see the module doc). `true` for the authority and for a space this host doesn't
/// govern (there the writer-set query records nothing and the commit is reported to the
/// authority, which decides); otherwise the space's write policy, failing closed.
async fn writer_may_join(state: &CoreState, space: &SpaceRef, did: &str) -> Result<bool, ApiError> {
    if space.authority == did {
        return Ok(true);
    }
    let row = crate::db::spaces::get_space(&state.db, &space.uri)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, "failed to load space");
            internal_error()
        })?;
    let Some(row) = row else {
        return Ok(true);
    };
    let Some(policy) = row.space_policy()? else {
        return Ok(true);
    };
    // ponytail: decided before the transaction, so a member change that lands between this check
    // and the commit is not seen by it; re-check inside the transaction for the local policies if
    // that window matters.
    crate::auth::space::authorize_write_notification(state, &row, &policy, did).await
}

/// A space commit written inside a transaction that has not committed yet.
pub(crate) struct PendingSpaceCommit {
    space: SpaceRef,
    did: String,
    /// `None` when the write policy kept the commit out of the writer set: nothing is announced.
    update: Option<crate::db::space_notify::WriterUpdate>,
    outcome: SpaceCommitOutcome,
}

impl PendingSpaceCommit {
    /// Best-effort, post-commit and non-blocking: tell the space host (or, when that is us, the
    /// registered syncers) that this repo advanced. Called once the transaction has committed;
    /// every write path ends here, so none can silently skip it.
    pub(crate) fn announce(self, state: &CoreState) -> SpaceCommitOutcome {
        use crate::db::space_notify::WriterUpdate;
        let (space, did, outcome) = (&self.space, self.did.as_str(), &self.outcome);
        let Some(update) = self.update else {
            return self.outcome;
        };
        match update {
            WriterUpdate::Accepted(revs) => drop(crate::space_notify::forward_write(
                state,
                space,
                did,
                &outcome.rev,
                &outcome.hash,
                revs,
            )),
            WriterUpdate::NotAuthority => drop(crate::space_notify::report_write(
                state,
                space,
                did,
                &outcome.rev,
                &outcome.hash,
            )),
            // Our own commit's rev always advances; nothing to announce if it somehow did not.
            WriterUpdate::Stale => {}
        }
        self.outcome
    }
}

/// Validate every op before touching the database: record path shape, the schema-free
/// record-format gate, and value presence. (The lexicon `validate`-flag check is a route-layer
/// concern, layered on by the CRUD surface exactly as the public routes do.)
fn validate_ops(ops: &[SpaceWriteOp]) -> Result<(), ApiError> {
    if ops.is_empty() {
        return Err(ApiError::new(ErrorCode::InvalidRequest, "no writes given"));
    }
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
                custos_core::auth::validation::validate_record_formats(value)
                    .map_err(|message| ApiError::new(ErrorCode::InvalidRequest, message))?;
            }
            SpaceWriteAction::Delete => {}
        }
    }

    Ok(())
}

/// The commit itself, on the caller's transaction. Any error leaves the transaction to be
/// dropped, which rolls it back. `join` is [`writer_may_join`]'s decision.
async fn commit_ops(
    state: &CoreState,
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    space: &SpaceRef,
    did: &str,
    ops: &[SpaceWriteOp],
    join: bool,
) -> Result<PendingSpaceCommit, ApiError> {
    let space_uri = space.uri.as_str();

    // A deactivated, suspended, or taken-down account is read-only, exactly as on the public
    // write path.
    require_writable_account(tx, did).await?;

    admit_space(tx, space, did).await?;

    // Load the repo head, or start a fresh one on first write.
    let existing_repo = crate::db::space_repos::get_repo(&mut **tx, space_uri, did)
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
                &mut **tx,
                space_uri,
                did,
                &new_rev,
                &lthash.state(),
                prev,
            )
            .await
        }
        None => {
            crate::db::space_repos::insert_repo(&mut **tx, space_uri, did, &new_rev, &lthash.state())
                .await
        }
    }
    .map_err(|e| {
        tracing::error!(error = %e, space = %space_uri, did = %did, "failed to advance space repo head");
        internal_error()
    })?;
    if !advanced {
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
            &mut **tx,
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
                    return Err(ApiError::new(
                        ErrorCode::RecordAlreadyExists,
                        "record already exists; use putRecord to update",
                    ));
                }
                if op.action == SpaceWriteAction::Update && prev_cid.is_none() {
                    return Err(ApiError::new(
                        ErrorCode::RecordNotFound,
                        "record does not exist; use createRecord or putRecord to create it",
                    ));
                }
                #[allow(clippy::expect_used, reason = "the value was validated present above")]
                let value = op.value.as_ref().expect("validated above");
                let ipld = repo_engine::json_to_record_value(value)
                    .map_err(|e| ApiError::new(ErrorCode::InvalidRequest, e.to_string()))?;
                let (cid, bytes) = repo_engine::encode_record_block(&ipld)
                    .map_err(|e| ApiError::new(ErrorCode::InvalidRequest, e.to_string()))?;
                let cid = cid.to_string();

                if let Some(prev) = &prev_cid {
                    lthash.remove(&format_set_hash_element(&op.collection, &op.rkey, prev));
                    write_cost += custos_core::rate_limit::WRITE_COST_UPDATE;
                } else {
                    write_cost += custos_core::rate_limit::WRITE_COST_CREATE;
                }
                lthash.add(&format_set_hash_element(&op.collection, &op.rkey, &cid));

                crate::db::space_repos::upsert_record(
                    &mut **tx,
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
                    &mut **tx,
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
                    return Err(ApiError::new(
                        ErrorCode::RecordNotFound,
                        "record does not exist",
                    ));
                };
                lthash.remove(&format_set_hash_element(&op.collection, &op.rkey, &prev));
                write_cost += custos_core::rate_limit::WRITE_COST_DELETE;
                crate::db::space_repos::delete_record(
                    &mut **tx,
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
                    &mut **tx,
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
    // public path, keyed by the already-authenticated DID).
    state
        .rate_limiter
        .check_write_points(did, write_cost)
        .inspect_err(|_| {
            state.metrics.rate_limit_rejections.add(
                1,
                &[custos_core::metrics::label(
                    custos_core::metrics::names::LABEL_LIMITER,
                    "account_writes",
                )],
            );
        })?;

    // A commit that removes the last record leaves an empty repo, not a missing one: the head
    // stays at the empty-set digest, its rev keeps advancing, and reads answer as for any empty
    // repo. Nothing collects it.
    finish_commit(tx, space, did, new_rev, &lthash, results, join).await
}

/// Store the folded LtHash state on the head the commit already advanced to `new_rev`, and,
/// when `join` allows, record the commit in the writer set, inside the commit's transaction.
async fn finish_commit(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    space: &SpaceRef,
    did: &str,
    new_rev: String,
    lthash: &LtHash,
    results: Vec<SpaceWriteResult>,
    join: bool,
) -> Result<PendingSpaceCommit, ApiError> {
    let space_uri = space.uri.as_str();
    // The rev was already advanced (and CAS-guarded) before the fold; inside the same
    // transaction this update trivially matches its own rev.
    let finalized = crate::db::space_repos::advance_repo_rev(
        &mut **tx,
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
        tracing::error!(space = %space_uri, did = %did, "space repo head vanished mid-transaction");
        return Err(internal_error());
    }

    // The writer set `listWriters` answers, kept durable with the commit rather than derived
    // afterwards: for a space this host is the authority for, our own account's write is one of
    // the facts the authority reports. The query no-ops for a space whose authority is
    // elsewhere. Skipped entirely when the write policy refused the writer (`join`).
    let hash = lthash.digest();
    let update = if join {
        Some(
            crate::db::space_notify::upsert_writer(tx, space_uri, did, &new_rev, &hash)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, space = %space_uri, did = %did, "failed to record space writer");
                    internal_error()
                })?,
        )
    } else {
        None
    };

    Ok(PendingSpaceCommit {
        space: space.clone(),
        did: did.to_string(),
        update,
        outcome: SpaceCommitOutcome {
            rev: new_rev,
            hash,
            results,
        },
    })
}

/// Delete every record in `did`'s repo in `space` except those in `keep`, as one commit:
/// `clearRecords`. The repo takes a new rev with the kept records' set hash, its oplog is cleared
/// (kept records' entries too, as the reference clears it), and the commit is announced like any
/// other. `None`, with nothing changed, when the repo doesn't exist or holds nothing to delete.
///
/// `granted` is the set of collections the caller's grant was checked against before the
/// transaction. A collection that appeared since then answers `Conflict`, so a concurrent write
/// can't slip a collection past the check; the client retries. One delete's write cost is charged,
/// not one per record, so a repo too large for the write budget can still be cleared.
pub async fn clear_space_records(
    state: &CoreState,
    space: &SpaceRef,
    did: &str,
    keep: &[&str],
    granted: &[String],
) -> Result<Option<SpaceCommitOutcome>, ApiError> {
    let space_uri = space.uri.as_str();
    let db_error = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space_uri, did = %did, "failed to clear space records");
        internal_error()
    };
    let join = writer_may_join(state, space, did).await?;
    let mut tx = state.db.begin().await.map_err(db_error)?;
    require_writable_account(&mut tx, did).await?;
    let Some(repo) = crate::db::space_repos::get_repo(&mut *tx, space_uri, did)
        .await
        .map_err(db_error)?
    else {
        return Ok(None);
    };
    // The repo exists, so its space row does too; this applies the write path's refusals
    // (deleted, taken down) without recording anything.
    admit_space(&mut tx, space, did).await?;

    let records = crate::db::space_repos::list_record_index(&mut *tx, space_uri, did)
        .await
        .map_err(db_error)?;
    if let Some((collection, _, _)) = records.iter().find(|(collection, _, _)| {
        !keep.contains(&collection.as_str()) && !granted.contains(collection)
    }) {
        tracing::debug!(space = %space_uri, did = %did, %collection, "clearRecords raced a new collection");
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "space repo was modified concurrently; retry",
        ));
    }
    let mut lthash = LtHash::new();
    let mut cleared = false;
    for (collection, rkey, cid) in &records {
        if keep.contains(&collection.as_str()) {
            lthash.add(&format_set_hash_element(collection, rkey, cid));
        } else {
            cleared = true;
        }
    }
    if !cleared {
        return Ok(None);
    }

    let new_rev = repo_engine::next_record_rev(&repo.rev).map_err(|e| {
        tracing::error!(error = %e, space = %space_uri, did = %did, "failed to derive commit rev");
        internal_error()
    })?;
    if !crate::db::space_repos::advance_repo_rev(
        &mut *tx,
        space_uri,
        did,
        &new_rev,
        &repo.lthash_state,
        &repo.rev,
    )
    .await
    .map_err(db_error)?
    {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "space repo was modified concurrently; retry against the current head",
        ));
    }
    crate::db::space_repos::clear_records(&mut tx, space_uri, did, keep)
        .await
        .map_err(db_error)?;

    state
        .rate_limiter
        .check_write_points(did, custos_core::rate_limit::WRITE_COST_DELETE)
        .inspect_err(|_| {
            state.metrics.rate_limit_rejections.add(
                1,
                &[custos_core::metrics::label(
                    custos_core::metrics::names::LABEL_LIMITER,
                    "account_writes",
                )],
            );
        })?;

    let pending = finish_commit(&mut tx, space, did, new_rev, &lthash, Vec::new(), join).await?;
    tx.commit().await.map_err(db_error)?;
    Ok(Some(pending.announce(state)))
}

/// Refuse a commit by an account that isn't active: deactivated, suspended, taken down or gone.
///
/// Read inside the commit's transaction: the public path folds this guard into its root CAS, but
/// the space head's CAS is on `space_repos`, not `accounts`, so a pre-transaction check would
/// leave a window for a concurrent deactivation to land between check and commit. The migration
/// import is [`import_space_repo`]'s own path.
async fn require_writable_account(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    did: &str,
) -> Result<(), ApiError> {
    use custos_db::accounts::AccountLifecycle;
    match custos_db::accounts::account_lifecycle(&mut **tx, did).await? {
        Some(AccountLifecycle::Active) => Ok(()),
        Some(AccountLifecycle::Deactivated) => Err(ApiError::new(
            ErrorCode::AccountDeactivated,
            "account is deactivated",
        )),
        Some(AccountLifecycle::TakenDown | AccountLifecycle::Suspended) => Err(ApiError::new(
            ErrorCode::AccountTakedown,
            "account has been taken down",
        )),
        None => Err(ApiError::new(ErrorCode::NotFound, "account not found")),
    }
}

/// Replace `did`'s repo in `archive.space` with the archive's records: the migration import
/// (`crate::space_migration`). `did` must be a deactivated account.
///
/// Not a commit of ops: the records and oplog are replaced outright, the repo takes a fresh rev
/// after whatever this host held for it with an empty oplog, and no notification fires and no
/// writer-set row moves, as in the reference. A syncer still holding the old host's `since` finds
/// its set hash no longer matches and heals with `getRepo`. Write points are not charged: the
/// records are the account's own, arriving in one bulk transfer. An archive with no records
/// leaves an empty repo, as the reference's import does.
///
/// The space is admitted as any commit's is, so the authority's own space has to be imported
/// with `importSpaceMeta` first (`SpaceNotFound` otherwise).
pub(crate) async fn import_space_repo(
    state: &CoreState,
    did: &common::Did,
    archive: &crate::space_migration::RepoArchive,
) -> Result<String, ApiError> {
    let space = &archive.space;
    let space_uri = space.uri.as_str();
    let db_error = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space_uri, did = %did, "space repo import failed");
        internal_error()
    };
    let mut tx = state.db.begin().await.map_err(db_error)?;
    // Inside the transaction, against a concurrent `activateAccount`.
    crate::space_migration::require_deactivated(&mut *tx, did).await?;
    admit_space(&mut tx, space, did).await?;

    let rev = match crate::db::space_repos::get_repo(&mut *tx, space_uri, did)
        .await
        .map_err(db_error)?
    {
        Some(repo) => repo_engine::next_record_rev(&repo.rev).map_err(|e| {
            tracing::error!(error = %e, space = %space_uri, did = %did, "failed to derive import rev");
            internal_error()
        })?,
        None => repo_engine::generate_tid(),
    };
    crate::db::space_repos::delete_repo(&mut tx, space_uri, did)
        .await
        .map_err(db_error)?;
    crate::db::space_repos::insert_repo(&mut *tx, space_uri, did, &rev, &archive.lthash.state())
        .await
        .map_err(db_error)?;
    for record in &archive.records {
        crate::db::space_repos::upsert_record(
            &mut *tx,
            space_uri,
            did,
            &record.collection,
            &record.rkey,
            &record.cid,
            &record.bytes,
            &rev,
        )
        .await
        .map_err(db_error)?;
    }
    tx.commit().await.map_err(db_error)?;
    Ok(rev)
}

/// Admit a commit to `space`, inside its transaction: record a foreign authority's space on
/// first sight, and refuse a deleted, uncreated or taken-down one.
async fn admit_space(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    space: &SpaceRef,
    did: &str,
) -> Result<(), ApiError> {
    let space_uri = space.uri.as_str();
    // Record a foreign authority's space if this host has not seen it before. The reference does
    // the same on every space write, and it is what makes a foreign authority's space usable:
    // nothing else in the protocol tells a repo host that its user has joined one. The row
    // carries no policy — that belongs to the authority.
    //
    // A space anchored on the writer's own DID is never recorded here: the spec requires it to
    // exist already, so it must have been made by `createSpace` (which is what writes the policy).
    //
    // Divergence from the reference, which additionally *clears* `deleted_at` here: a tombstone
    // is only ever written for a space this host is the authority for, and resurrecting one on a
    // member's write would undo the deletion the operator performed. So a deleted space refuses
    // writes instead — its members' existing records stay put (spec deletion semantics), they
    // just stop changing.
    let own_space = space.authority == did;
    if !own_space {
        crate::db::spaces::insert_space(
            &mut **tx,
            &crate::db::spaces::NewSpace {
                uri: space_uri,
                authority_did: &space.authority,
                space_type: &space.space_type,
                skey: &space.skey,
            },
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space_uri, "failed to record space");
            internal_error()
        })?;
    }
    let row = crate::db::spaces::get_space(&mut **tx, space_uri)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space_uri, "failed to load space");
            internal_error()
        })?;
    // All three refusals are read here rather than at the auth seam because the head CAS is on
    // `space_repos`, not `spaces`: outside this transaction a concurrent deleteSpace or
    // operator takedown could land between check and commit. `SpaceNotFound` for the
    // takedown, never `SpaceDeleted` — see `auth::space::require_space_servable`.
    if row.as_ref().is_some_and(|row| row.deleted_at.is_some()) {
        return Err(ApiError::new(
            ErrorCode::SpaceNotFound,
            "space has been deleted",
        ));
    }
    // An own space that was never created (no row, or a policy-less row recorded before this
    // rule) is refused rather than silently made.
    if row
        .as_ref()
        .is_none_or(|row| own_space && row.policy.is_none())
    {
        return Err(ApiError::new(ErrorCode::SpaceNotFound, "space not found"));
    }
    if row.is_some_and(|row| row.takendown_at.is_some()) {
        return Err(ApiError::new(ErrorCode::SpaceNotFound, "space not found"));
    }
    Ok(())
}

fn internal_error() -> ApiError {
    ApiError::new(ErrorCode::InternalError, "failed to write space record")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_state;

    const SPACE: &str = "at://did:plc:author/space/org.example.bucket/self";
    const DID: &str = "did:plc:spacewriter";

    fn space() -> SpaceRef {
        custos_core::space_uri::parse_space_ref(SPACE).expect("test space ref is well-formed")
    }

    /// Only the account: the space row is the write path's own responsibility.
    async fn seed(state: &CoreState) {
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
        )
        .await
        .unwrap();

        let create = SpaceWriteOp {
            action: SpaceWriteAction::Create,
            collection: "org.example.note".to_string(),
            rkey: "aaa".to_string(),
            value: Some(serde_json::json!({"text": "clobber"})),
        };
        let err = apply_space_writes(&state, &space(), DID, &[create])
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
            let err = apply_space_writes(&state, &space(), DID, &[op])
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
    /// the row it writes claims no policy, which belongs to the
    /// authority.
    #[tokio::test]
    async fn first_write_records_an_unknown_space() {
        let state = test_state().await;
        seed(&state).await;
        let unknown = custos_core::space_uri::parse_space_ref(
            "at://did:plc:someoneelse/space/org.example.bucket/shared",
        )
        .unwrap();

        apply_space_writes(
            &state,
            &unknown,
            DID,
            &[put("org.example.note", "aaa", "x")],
        )
        .await
        .unwrap();

        let row = crate::db::spaces::get_space(&state.db, &unknown.uri)
            .await
            .unwrap()
            .expect("the write recorded the space");
        assert_eq!(row.authority_did, "did:plc:someoneelse");
        assert!(row.policy.is_none());
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
        )
        .await
        .unwrap();
        sqlx::query("UPDATE spaces SET deleted_at = datetime('now') WHERE uri = ?")
            .bind(SPACE)
            .execute(&state.db)
            .await
            .unwrap();
        let err = apply_space_writes(&state, &space(), DID, &[put("org.example.note", "a", "x")])
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
        let err = apply_space_writes(&state, &space(), DID, &[put("org.example.note", "a", "x")])
            .await
            .unwrap_err();
        assert_eq!(err.code(), &ErrorCode::AccountDeactivated);

        // A moderation state is `AccountTakedown` here too, should one land between the route's
        // own gate and the commit.
        sqlx::query(
            "UPDATE accounts SET deactivated_at = NULL, taken_down_at = datetime('now') \
             WHERE did = ?",
        )
        .bind(DID)
        .execute(&state.db)
        .await
        .unwrap();
        let err = apply_space_writes(&state, &space(), DID, &[put("org.example.note", "a", "x")])
            .await
            .unwrap_err();
        assert_eq!(err.code(), &ErrorCode::AccountTakedown);
    }
}
