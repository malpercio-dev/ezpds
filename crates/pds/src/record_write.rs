// pattern: Imperative Shell

//! Shared record write operations for com.atproto.repo.{create,put,delete}Record.
//!
//! This module consolidates the common write flow (auth, repo open, signer load,
//! optimistic concurrency, GC) so that individual route handlers remain thin
//! gatherers that delegate to a single authoritative write path.
//!
//! The `create_only` flag distinguishes `createRecord` (must reject pre-existing rkeys)
//! from `putRecord` (upsert semantics) and `deleteRecord` (always removes).

use axum::http::HeaderMap;
use sqlx::SqlitePool;

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::Repository;

/// Result of a successful record write operation.
///
/// `new_root` has no reader yet (hence `#[allow(dead_code)]`); it is retained to feed
/// the ATProto `commit` field of the create/put responses and future sequencer emission.
#[allow(dead_code)]
pub struct WriteRecordResult {
    /// The new repo root CID after the write.
    pub new_root: String,
}

/// Optimistic-concurrency preconditions parsed from the ATProto `swapCommit` / `swapRecord`
/// request parameters. An all-`None` value (the [`Default`]) imposes no preconditions, so the
/// only guard is the existing commit-level compare-and-swap on the repo root.
#[derive(Default)]
pub struct SwapCheck {
    /// `swapCommit`: when set, the repo head must equal this commit CID before the write.
    pub commit: Option<String>,
    /// `swapRecord`: when set, the record at the target key must satisfy this precondition —
    /// `Some(cid)` requires the current record block to have exactly `cid`; `None` requires the
    /// record to be absent (create-only semantics, i.e. the client passed `swapRecord: null`).
    pub record: Option<Option<String>>,
}

/// Enforce the `swapCommit` / `swapRecord` preconditions against the current repo state.
///
/// `current_root` is the persisted repo head CID (string form) and `repo` is the already-opened
/// repository. Returns [`ErrorCode::InvalidSwap`] (409) on any mismatch — distinct from the
/// generic concurrent-write [`ErrorCode::Conflict`] raised by the root compare-and-swap.
pub(crate) async fn enforce_swap<S>(
    swap: &SwapCheck,
    current_root: &str,
    repo: &mut Repository<S>,
    mst_key: &str,
) -> Result<(), ApiError>
where
    S: repo_engine::AsyncBlockStoreRead + repo_engine::AsyncBlockStoreWrite,
{
    if let Some(expected_commit) = &swap.commit {
        if expected_commit != current_root {
            return Err(ApiError::new(
                ErrorCode::InvalidSwap,
                "swapCommit did not match the current repo head",
            ));
        }
    }

    if let Some(expected_record) = &swap.record {
        let current = repo_engine::get_record_cid(repo, mst_key)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, key = %mst_key, "failed to read record CID for swap check");
                ApiError::new(ErrorCode::InternalError, "failed to evaluate swapRecord")
            })?
            .map(|c| c.to_string());
        match expected_record {
            // swapRecord: <cid> — the record must currently exist with exactly this CID.
            Some(expected_cid) => {
                if current.as_deref() != Some(expected_cid.as_str()) {
                    return Err(ApiError::new(
                        ErrorCode::InvalidSwap,
                        "swapRecord did not match the current record",
                    ));
                }
            }
            // swapRecord: null — the record must be absent (create-only semantics).
            None => {
                if current.is_some() {
                    return Err(ApiError::new(
                        ErrorCode::InvalidSwap,
                        "swapRecord was null but the record already exists",
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Shared write flow: authenticate → open repo → load signer → write record →
/// optimistic-concurrency CAS → GC.
///
/// # Arguments
/// * `state` - Application state (DB pool, config, etc.)
/// * `headers` - Request headers (for Bearer token extraction)
/// * `did` - The DID of the repo owner
/// * `mst_key` - The MST key (collection/rkey)
/// * `record` - The record data as JSON
/// * `create_only` - If true, reject writes when the key already exists (createRecord
///   semantics). If false, upsert (putRecord semantics).
/// * `swap` - Optional `swapCommit`/`swapRecord` optimistic-concurrency preconditions
///   enforced before the write; pass [`SwapCheck::default`] for none.
///
/// # Precondition
/// `mst_key` must already be validated via `repo_engine::validate_record_path`; this
/// helper trusts it and does not re-check the collection/rkey format.
pub async fn write_record(
    state: &AppState,
    headers: &HeaderMap,
    did: &str,
    mst_key: &str,
    record: &serde_json::Value,
    create_only: bool,
    swap: &SwapCheck,
) -> Result<(WriteRecordResult, repo_engine::Cid), ApiError> {
    // Validate DID format.
    if !crate::auth::validation::is_valid_did(did) {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    // Authenticate: require a valid access token whose subject owns this repo.
    let token = crate::auth::extract_bearer_token(headers)?;
    let claims = crate::auth::jwt::verify_access_token(token, state)?;
    if claims.sub != *did {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "authenticated account does not own this repository",
        ));
    }

    // Look up the repo root CID and active status in one query.
    let write_state = crate::db::accounts::get_repo_write_state(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to query repo write state");
            ApiError::new(ErrorCode::InternalError, "failed to write record")
        })?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    let root_cid_str = write_state
        .repo_root_cid
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    // A deactivated account is read-only: its repo reports a deactivated status and accepts no
    // writes until reactivated (com.atproto.server.activateAccount). Checked after the existence
    // lookup above so a missing account is still a 404 rather than a deactivation error. The CAS
    // below also carries `deactivated_at IS NULL` to close the gap between this check and commit.
    if !write_state.active {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "account is deactivated",
        ));
    }

    let root_cid = repo_engine::Cid::try_from(root_cid_str.as_str()).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID in database");
        ApiError::new(ErrorCode::InternalError, "failed to write record")
    })?;

    // Open the repo.
    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to write record")
    })?;

    // Capture the pre-write revision: it becomes the firehose event's `since` (the commit
    // this one supersedes).
    let prev_rev = repo.commit().rev().as_str().to_string();

    // Enforce explicit swapCommit/swapRecord preconditions (ATProto optimistic concurrency)
    // before mutating anything, so a stale client fails with InvalidSwap rather than racing.
    enforce_swap(swap, &root_cid_str, &mut repo, mst_key).await?;

    // Determine whether the record already exists — both to enforce create-only semantics
    // and to label the firehose op as a create (new key) vs an update (existing key).
    let existed = repo_engine::get_record_cid(&mut repo, mst_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to check record existence");
            ApiError::new(ErrorCode::InternalError, "failed to write record")
        })?
        .is_some();
    if create_only && existed {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "record already exists; use putRecord to update",
        ));
    }

    // Load the signing key for this account.
    let master_key: &[u8; 32] = state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|s| &*s.0)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::ServiceUnavailable,
                "signing key master key not configured",
            )
        })?;
    let signer = crate::auth::signing_key::load_repo_signer(&state.db, did, master_key).await?;

    // Write the record (JSON is converted to the ATProto data model: $link → CID,
    // $bytes → byte string, floats rejected).
    let record_cid = repo_engine::put_record_json(&mut repo, &signer, mst_key, record)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to write record");
            match e {
                repo_engine::RecordError::InvalidRecord(_) => {
                    ApiError::new(ErrorCode::InvalidClaim, "invalid record")
                }
                _ => ApiError::new(ErrorCode::InternalError, "failed to write record"),
            }
        })?;

    // Advance the repo root with optimistic concurrency: only if it hasn't moved
    // since we read it. If a concurrent write advanced it first, that write wins and
    // we return 409 so the client retries against the new root (rather than silently
    // clobbering the other commit). The new blocks we wrote are orphaned and GC-able.
    let new_root = repo.root().to_string();
    let new_rev = repo.commit().rev().as_str().to_string();
    // `deactivated_at IS NULL` folds the deactivation guard into the commit CAS: the
    // `account_is_active` check above and this swap are not atomic, so an account deactivated in
    // between would otherwise still commit (deactivation leaves `repo_root_cid` untouched, so the
    // CAS would match). Requiring the account to still be active here blocks that write — it
    // surfaces as a concurrent-modification conflict rather than landing on a deactivated repo.
    let updated = sqlx::query(
        "UPDATE accounts SET repo_root_cid = ?, repo_rev = ? \
         WHERE did = ? AND repo_root_cid = ? AND deactivated_at IS NULL",
    )
    .bind(&new_root)
    .bind(&new_rev)
    .bind(did)
    .bind(&root_cid_str)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to update repo root CID");
        ApiError::new(ErrorCode::InternalError, "failed to write record")
    })?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "repository was modified concurrently; retry against the current root",
        ));
    }

    // Emit the firehose `#commit` event before GC, while the previous block set still exists
    // (the diff CAR is computed against it).
    let (collection, rkey) = split_record_path(mst_key);
    let op = crate::firehose::RepoOp {
        action: if existed {
            crate::firehose::OpAction::Update
        } else {
            crate::firehose::OpAction::Create
        },
        collection,
        rkey,
        cid: Some(record_cid.to_string()),
        value: Some(record.clone()),
    };
    emit_firehose_commit(
        state,
        did,
        root_cid,
        repo.root(),
        new_rev,
        Some(prev_rev),
        vec![op],
    )
    .await;

    // Best-effort GC: reclaim blocks superseded by this commit. A GC failure must not
    // fail the write — the commit is durable; orphaned blocks are harmless until swept.
    if let Err(e) = gc_repo_blocks(&state.db, did, repo.root()).await {
        tracing::warn!(error = %e, did = %did, "post-commit block GC failed (non-fatal)");
    }

    Ok((WriteRecordResult { new_root }, record_cid))
}

/// Build the commit's block diff and emit a firehose `#commit` event.
///
/// Best-effort: a failure to assemble the diff CAR is logged and dropped — the commit is
/// already durable, and a subscriber that misses an event can backfill via `getRepo`.
///
/// **Ordering precondition:** call this *after* the root swap but *before* post-commit GC,
/// while both the previous and new block sets are still present (the diff is computed as
/// `reachable(new) − reachable(prev)`, which needs the old blocks to subtract them out).
pub async fn emit_firehose_commit(
    state: &AppState,
    did: &str,
    prev_root: repo_engine::Cid,
    new_root: repo_engine::Cid,
    new_rev: String,
    prev_rev: Option<String>,
    ops: Vec<crate::firehose::RepoOp>,
) {
    let mut store = SqliteBlockStore::new(state.db.clone(), did.to_string());

    // The exact CID set this commit introduced drives two things, computed once here while both
    // block sets are still present (pre-GC): the firehose diff CAR, and the per-block rev tag for
    // getRepo?since. Tagging this precise set (not "all untagged blocks") is what keeps the rev
    // correct under concurrent same-repo writes — see `db::blocks::tag_blocks_rev`.
    let diff_cids = match repo_engine::collect_commit_diff_cids(
        &mut store,
        Some(prev_root),
        new_root,
    )
    .await
    {
        Ok(cids) => cids,
        Err(e) => {
            tracing::warn!(
                error = %e,
                did = %did,
                "failed to compute commit block diff; dropping firehose event + rev tag (non-fatal)"
            );
            return;
        }
    };

    // Stamp this commit's blocks with its revision so getRepo?since reports them as newer than any
    // earlier revision. Best-effort: the commit is durable regardless, and untagged blocks still
    // ship in a full export — they are only absent from `since` deltas.
    let cid_strs: Vec<String> = diff_cids.iter().map(|c| c.to_string()).collect();
    if let Err(e) = crate::db::blocks::tag_blocks_rev(&state.db, did, &cid_strs, &new_rev).await {
        tracing::warn!(error = %e, did = %did, "failed to tag commit block revisions (non-fatal)");
    }

    let blocks = match repo_engine::build_car_from_cids(&mut store, new_root, diff_cids).await {
        Ok(blocks) => blocks,
        Err(e) => {
            tracing::warn!(
                error = %e,
                did = %did,
                "failed to build firehose commit CAR; dropping event (non-fatal)"
            );
            return;
        }
    };

    state.firehose.emit_commit(crate::firehose::CommitInput {
        repo: did.to_string(),
        commit: new_root.to_string(),
        rev: new_rev,
        since: prev_rev,
        ops,
        blocks,
    });

    // New content is live: notify configured crawlers (relays/BGSes) so they pull it promptly.
    // Fire-and-forget and rate-limited — never blocks the commit.
    state.crawlers.notify();
}

/// Split an MST key (`<collection>/<rkey>`) into its collection and record-key halves.
///
/// Record paths are validated via `repo_engine::validate_record_path` before reaching the
/// write paths, so a well-formed key always contains exactly one `/` separating an NSID
/// collection (which may contain dots but no slashes) from a slash-free rkey.
pub(crate) fn split_record_path(mst_key: &str) -> (String, String) {
    match mst_key.split_once('/') {
        Some((collection, rkey)) => (collection.to_string(), rkey.to_string()),
        None => (mst_key.to_string(), String::new()),
    }
}

/// Garbage-collect blocks that are no longer reachable from the given repo root.
///
/// Computes the transitive closure of reachable CIDs from the commit, MST nodes,
/// and record blocks, then deletes any blocks for this account that are not in
/// that set. Returns the number of blocks removed.
pub async fn gc_repo_blocks(
    pool: &SqlitePool,
    did: &str,
    root: repo_engine::Cid,
) -> Result<u64, ApiError> {
    use std::collections::HashSet;

    let mut store = SqliteBlockStore::new(pool.clone(), did.to_string());
    let reachable: HashSet<String> = repo_engine::collect_reachable_cids(&mut store, root)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to compute reachable blocks for GC");
            ApiError::new(ErrorCode::InternalError, "block GC failed")
        })?
        .into_iter()
        .map(|c| c.to_string())
        .collect();

    crate::db::blocks::delete_unreachable_blocks(pool, did, &reachable)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to delete unreachable blocks");
            ApiError::new(ErrorCode::InternalError, "block GC failed")
        })
}
