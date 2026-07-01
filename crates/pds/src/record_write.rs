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

/// Resolve a repo at-identifier (DID or handle) to its DID.
///
/// The `com.atproto.repo.*` lexicons type the `repo` field as an *at-identifier* — a DID **or**
/// a handle. A value already in `did:` form is returned unchanged (the caller's existing
/// `is_valid_did` / account-status checks validate it downstream); anything else is treated as a
/// handle and resolved to its owning DID via `db::accounts::resolve_identifier`.
///
/// All four write routes (`createRecord`, `putRecord`, `deleteRecord`, `applyWrites`) call this
/// *before* their auth/ownership check, so the check binds against the resolved DID and the
/// identifier handling cannot drift between routes.
///
/// Returns [`ErrorCode::InvalidRequest`] (400) when a handle does not resolve to a known account.
pub(crate) async fn resolve_repo_did(state: &AppState, repo: &str) -> Result<String, ApiError> {
    if repo.starts_with("did:") {
        return Ok(repo.to_string());
    }
    crate::db::accounts::resolve_identifier(&state.db, repo)
        .await?
        .map(|account| account.did)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidRequest,
                "could not resolve repo to a known account",
            )
        })
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

    // A deactivated account is read-only: its repo reports a deactivated status and accepts no
    // writes until reactivated (com.atproto.server.activateAccount). Checked right after account
    // existence — before the repo-root lookup — so a deactivated account is a 403 even if it never
    // created a repo; only a truly missing account (handled above) is a 404. The CAS below also
    // carries `deactivated_at IS NULL` to close the gap between this check and commit.
    if !write_state.active {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "account is deactivated",
        ));
    }

    let root_cid_str = write_state
        .repo_root_cid
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

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

    // Advance the repo root with optimistic concurrency: only if it hasn't moved since we read
    // it. If a concurrent write advanced it first, that write wins and we return 409 so the
    // client retries against the new root (rather than silently clobbering the other commit).
    // The new blocks we wrote are orphaned and GC-able. `deactivated_at IS NULL` folds the
    // deactivation guard into the commit CAS: the `account_is_active` check above and this swap
    // are not atomic, so an account deactivated in between would otherwise still commit
    // (deactivation leaves `repo_root_cid` untouched, so the CAS would match). Requiring the
    // account to still be active here blocks that write — it surfaces as a concurrent-
    // modification conflict rather than landing on a deactivated repo.
    //
    // The CAS and the firehose `#commit` event commit atomically (see `commit_repo_write`), while
    // both the previous and new block sets are still present (the diff CAR is computed against
    // them) — call this before GC.
    let new_root = repo.root().to_string();
    let new_rev = repo.commit().rev().as_str().to_string();
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
    commit_repo_write(
        state,
        did,
        root_cid,
        repo.root(),
        new_rev,
        Some(prev_rev),
        vec![op],
        &root_cid_str,
    )
    .await?;

    // Best-effort GC: reclaim blocks superseded by this commit. A GC failure must not
    // fail the write — the commit is durable; orphaned blocks are harmless until swept.
    if let Err(e) = gc_repo_blocks(&state.db, did, repo.root()).await {
        tracing::warn!(error = %e, did = %did, "post-commit block GC failed (non-fatal)");
    }

    Ok((WriteRecordResult { new_root }, record_cid))
}

/// Advance the repo root (optimistic-concurrency CAS) and, while both the previous and new block
/// sets are still present, stage the corresponding firehose `#commit` event in the *same*
/// transaction as the CAS when the diff CAR can be assembled — so the two commit or roll back
/// together once staging is attempted (see [`crate::firehose`]'s module docs and
/// `Firehose::stage_commit`).
///
/// Returns [`ErrorCode::Conflict`] when the CAS didn't land — the repo moved, or the account was
/// deactivated, since the caller last read `expected_root` — mirroring
/// `db::accounts::advance_repo_root_if_active`'s own contract; nothing is staged or emitted in
/// that case.
///
/// The commit's block diff and CARv1 diff blocks are assembled *before* the transaction opens:
/// this crate's DB pool serves a single connection (see `db::open_pool`), so building them
/// inside the transaction — which also needs that connection for the CAS — would deadlock this
/// task against itself waiting on a second connection that will never free up. Assembling them is
/// still best-effort exactly as before: a failure is logged and dropped, and the write still
/// lands (the record data is already durable in the block store) without a firehose event or a
/// rev tag for this commit; a subscriber that misses it backfills via `getRepo`. Only the CAS and
/// the firehose row (once the diff *is* available) are atomic with each other.
///
/// **Ordering precondition:** call this *before* post-commit GC, while both the previous and new
/// block sets are still present (the diff is computed as `reachable(new) − reachable(prev)`,
/// which needs the old blocks to subtract them out).
#[allow(clippy::too_many_arguments)]
pub async fn commit_repo_write(
    state: &AppState,
    did: &str,
    prev_root: repo_engine::Cid,
    new_root: repo_engine::Cid,
    new_rev: String,
    prev_rev: Option<String>,
    ops: Vec<crate::firehose::RepoOp>,
    expected_root: &str,
) -> Result<(), ApiError> {
    let mut store = SqliteBlockStore::new(state.db.clone(), did.to_string());

    // The exact CID set this commit introduced drives two things, computed once here while both
    // block sets are still present (pre-GC): the firehose diff CAR, and the per-block rev tag for
    // getRepo?since. Tagging this precise set (not "all untagged blocks") is what keeps the rev
    // correct under concurrent same-repo writes — see `db::blocks::tag_blocks_rev`. `cid_strs` is
    // kept independently of `blocks` (rather than as one `Option` pair) because the rev tag is
    // still applied even if the CAR later fails to build — only the event is dropped in that case.
    let diff_cids = match repo_engine::collect_commit_diff_cids(
        &mut store,
        Some(prev_root),
        new_root,
    )
    .await
    {
        Ok(cids) => Some(cids),
        Err(e) => {
            tracing::warn!(
                error = %e,
                did = %did,
                "failed to compute commit block diff; dropping firehose event + rev tag (non-fatal)"
            );
            None
        }
    };
    let cid_strs: Option<Vec<String>> = diff_cids
        .as_ref()
        .map(|cids| cids.iter().map(|c| c.to_string()).collect());
    let blocks = match diff_cids {
        Some(cids) => match repo_engine::build_car_from_cids(&mut store, new_root, cids).await {
            Ok(blocks) => Some(blocks),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    did = %did,
                    "failed to build firehose commit CAR; dropping event (non-fatal)"
                );
                None
            }
        },
        None => None,
    };

    // Acquired *before* opening the transaction below — see `Firehose::lock_emit`'s docs for why
    // that order matters on this crate's single-connection pool.
    let emit_guard = state.firehose.lock_emit().await;
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open write transaction");
        ApiError::new(ErrorCode::InternalError, "failed to write record")
    })?;

    let new_root_str = new_root.to_string();
    let advanced = crate::db::accounts::advance_repo_root_if_active(
        &mut *tx,
        did,
        &new_root_str,
        &new_rev,
        expected_root,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to update repo root CID");
        ApiError::new(ErrorCode::InternalError, "failed to write record")
    })?;
    if !advanced {
        tx.rollback().await.ok();
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "repository was modified concurrently; retry against the current root",
        ));
    }

    let pending = match blocks {
        Some(blocks) => {
            let staged = emit_guard
                .stage_commit(
                    &mut tx,
                    crate::firehose::CommitInput {
                        repo: did.to_string(),
                        commit: new_root_str,
                        rev: new_rev.clone(),
                        since: prev_rev,
                        ops,
                        blocks,
                    },
                )
                .await;
            match staged {
                Ok(pending) => Some(pending),
                Err(e) => {
                    // Dropping `tx` here (via the early return) rolls back the CAS too: a commit
                    // must not land without a corresponding durable firehose row, so a failure to
                    // stage that row fails the whole write rather than dropping the event
                    // best-effort.
                    tracing::error!(error = %e, did = %did, "failed to stage firehose commit event");
                    return Err(ApiError::new(
                        ErrorCode::InternalError,
                        "failed to write record",
                    ));
                }
            }
        }
        None => None,
    };

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to commit repo write transaction");
        ApiError::new(ErrorCode::InternalError, "failed to write record")
    })?;
    // Notify crawlers only once the firehose event has actually been finished: when diff/CAR
    // assembly failed (`pending` is `None`) there is nothing to notify them about yet, and the
    // relay would rather learn about this commit from a later one's event than crawl early and
    // find nothing new. The notify itself is deferred past the rev-tag attempt below so a
    // crawler it wakes can't race ahead of `since` tagging and see an incomplete delta.
    let notify_crawlers = pending.is_some();
    if let Some(pending) = pending {
        pending.finish();
    }

    // Best-effort, independent of the firehose durability guarantee above: an untagged block
    // still ships in a full export, just not in a `since` delta.
    if let Some(cid_strs) = cid_strs {
        if let Err(e) = crate::db::blocks::tag_blocks_rev(&state.db, did, &cid_strs, &new_rev).await
        {
            tracing::warn!(error = %e, did = %did, "failed to tag commit block revisions (non-fatal)");
        }
    }

    if notify_crawlers {
        // New content is live and the rev tag has been attempted: notify configured crawlers
        // (relays/BGSes) so they pull it promptly. Fire-and-forget and rate-limited — never
        // blocks the commit.
        state.crawlers.notify();
    }

    Ok(())
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
