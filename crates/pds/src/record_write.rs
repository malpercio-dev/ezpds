// pattern: Imperative Shell

//! Shared record write operations for com.atproto.repo.{create,put,delete}Record.
//!
//! This module consolidates the common write flow (auth, repo open, signer load,
//! optimistic concurrency, GC) so that individual route handlers remain thin
//! gatherers that delegate to a single authoritative write path.
//!
//! The `create_only` flag distinguishes `createRecord` (must reject pre-existing rkeys)
//! from `putRecord` (upsert semantics) and `deleteRecord` (always removes).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::http::{HeaderMap, Method, Uri};
use sqlx::SqlitePool;

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::Repository;

/// Per-DID async locks serializing each repository's logical write sequence.
///
/// A repo write is not one SQL statement but a multi-query sequence spanning await points: read
/// the root, open the repo, write the new blocks (each durable immediately via
/// [`SqliteBlockStore`]), CAS the root, then garbage-collect superseded blocks. The
/// single-connection pool serializes individual statements, not that sequence — so without this
/// lock two in-flight writes to the same DID interleave, and one request's post-commit GC deletes
/// the other's freshly written (not yet root-reachable) blocks, leaving the persisted root
/// pointing at missing blocks and the repo permanently unopenable.
///
/// Every path that mutates a repo's block set or root (`createRecord`/`putRecord` via
/// [`write_record`], `deleteRecord`, `applyWrites`) must hold this lock from before it reads the
/// repo root until after its GC pass. Lock ordering: this lock is acquired *before* the firehose
/// emit lock (inside [`commit_repo_write`]); nothing acquires them in the reverse order.
///
/// Entries are never evicted: the map is bounded by the number of accounts that ever wrote, and
/// one mutex per account is negligible next to the account's rows.
pub struct RepoWriteLocks {
    locks: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl RepoWriteLocks {
    pub fn new() -> Self {
        Self {
            locks: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Acquire the write lock for `did`, waiting behind any in-flight write to the same repo.
    pub async fn lock(&self, did: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut map = self.locks.lock().expect("repo write lock map poisoned");
            Arc::clone(map.entry(did.to_string()).or_default())
        };
        lock.lock_owned().await
    }
}

impl Default for RepoWriteLocks {
    fn default() -> Self {
        Self::new()
    }
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
/// * `headers` - Request headers (for access-token extraction + optional DPoP proof)
/// * `method` / `uri` - The request method and URI, needed to validate a DPoP proof's
///   `htm`/`htu` binding (RFC 9449); the calling handler has both.
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
// The request-context trio (`headers`/`method`/`uri`, needed for DPoP-proof `htm`/`htu`
// validation) plus the write parameters push this over clippy's argument threshold; the
// grouping is already as tight as it can be (same posture as `commit_repo_write`).
#[allow(clippy::too_many_arguments)]
pub async fn write_record(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    did: &str,
    mst_key: &str,
    record: &serde_json::Value,
    create_only: bool,
    swap: &SwapCheck,
) -> Result<repo_engine::Cid, ApiError> {
    // Validate DID format.
    if !crate::auth::validation::is_valid_did(did) {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    // Authenticate: require a valid access token whose subject owns this repo. This runs the
    // shared access-auth path (`authenticate_access`), so the RFC 9449 scheme ↔ `cnf.jkt`
    // binding rules and DPoP-proof validation are identical to the `AuthenticatedUser`
    // extractor — a DPoP-bound token presented as plain `Bearer` with no proof is rejected
    // here, not silently downgraded.
    let user = crate::auth::authenticate_access(headers, method, uri, state)?;
    if !user.scope.is_access() {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }
    if user.did != *did {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "authenticated account does not own this repository",
        ));
    }

    // Serialize this repo's whole logical write (root read → commit → GC) against concurrent
    // writers — see [`RepoWriteLocks`]. Held until this function returns, past the GC pass.
    let _write_guard = state.repo_write_locks.lock(did).await;

    // Look up the repo root CID and active status in one query.
    let write_state = crate::db::accounts::get_repo_write_state(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to query repo write state");
            ApiError::new(ErrorCode::InternalError, "failed to write record")
        })?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    // A deactivated, suspended, or taken-down account is read-only: its repo reports a non-active
    // status and accepts no writes until reactivated (com.atproto.server.activateAccount) or the
    // moderation action is cleared. Checked right after account existence — before the repo-root
    // lookup — so a non-active account is a 403 even if it never created a repo; only a truly
    // missing account (handled above) is a 404. The CAS below also carries the same lifecycle
    // guard to close the gap between this check and commit.
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

    // Capture the pre-write revision and MST root: they become the firehose event's `since` (the
    // commit this one supersedes) and Sync v1.1 `prevData` (the previous commit's MST root CID,
    // the inductive-validation anchor). Both must be read *before* the write mutates the repo.
    let prev_rev = repo.commit().rev().as_str().to_string();
    let prev_data = repo.commit().data().to_string();

    // Look up the record's current CID — both to enforce create-only semantics (and to label the
    // firehose op as a create vs an update) and, when it exists, to carry as the op's Sync v1.1
    // `prev` (the previous record CID for the update). Read before the write mutates the repo.
    let prev_cid = repo_engine::get_record_cid(&mut repo, mst_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to check record existence");
            ApiError::new(ErrorCode::InternalError, "failed to write record")
        })?;
    let existed = prev_cid.is_some();
    let action = if create_only || !existed {
        crate::auth::oauth_scopes::RepoAction::Create
    } else {
        crate::auth::oauth_scopes::RepoAction::Update
    };
    if user.scope == crate::auth::jwt::AuthScope::Access {
        crate::auth::oauth_scopes::require_repo(
            &user.scope_claim,
            mst_key.split('/').next().unwrap_or(""),
            action,
        )?;
    }

    // Enforce explicit swapCommit/swapRecord preconditions (ATProto optimistic concurrency)
    // after authorization and before mutating anything.
    enforce_swap(swap, &root_cid_str, &mut repo, mst_key).await?;

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
    // The new blocks we wrote are orphaned and GC-able. The lifecycle guard folds the
    // deactivation/suspension/takedown check into the commit CAS: the active check above and this
    // swap are not atomic, so an account that lost active status in between would otherwise still
    // commit (a status change leaves `repo_root_cid` untouched, so the CAS would match). Requiring
    // the account to still be active here blocks that write — it surfaces as a concurrent-
    // modification conflict rather than landing on a non-active repo.
    //
    // The CAS and the firehose `#commit` event commit atomically (see `commit_repo_write`), while
    // both the previous and new block sets are still present (the diff CAR is computed against
    // them) — call this before GC.
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
        // The previous record CID — `Some` for an update, `None` for a create.
        prev: prev_cid.map(|c| c.to_string()),
        value: Some(record.clone()),
    };
    commit_repo_write(
        state,
        did,
        root_cid,
        repo.root(),
        new_rev,
        Some(prev_rev),
        Some(prev_data),
        vec![op],
        &root_cid_str,
        user.registration_id.as_deref(),
    )
    .await?;
    // `commit_repo_write` reclaims this commit's superseded blocks incrementally (see its
    // post-commit GC); no separate full-repo reachability sweep runs on the write path.

    Ok(record_cid)
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
    prev_data: Option<String>,
    ops: Vec<crate::firehose::RepoOp>,
    expected_root: &str,
    agent_registration_id: Option<&str>,
) -> Result<(), ApiError> {
    // Charge this commit against the account's repo-write point budget (create=3/update=2/delete=1)
    // before doing any diff/CAR work, so an over-budget account is rejected cheaply. Keyed by the
    // repo's DID, which every caller has already authenticated (the token subject must own `did`).
    let write_cost: u64 = ops
        .iter()
        .map(|op| match op.action {
            crate::firehose::OpAction::Create => crate::rate_limit::WRITE_COST_CREATE,
            crate::firehose::OpAction::Update => crate::rate_limit::WRITE_COST_UPDATE,
            crate::firehose::OpAction::Delete => crate::rate_limit::WRITE_COST_DELETE,
        })
        .sum();
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

    // Summarize the ops for the agent audit trail before `ops` is moved into the firehose
    // staging below. Mechanical facts only — action counts, distinct collections, the new rev —
    // never record values.
    let agent_audit_detail = agent_registration_id.map(|_| {
        let mut creates = 0u32;
        let mut updates = 0u32;
        let mut deletes = 0u32;
        let mut collections: Vec<&str> = Vec::new();
        for op in &ops {
            match op.action {
                crate::firehose::OpAction::Create => creates += 1,
                crate::firehose::OpAction::Update => updates += 1,
                crate::firehose::OpAction::Delete => deletes += 1,
            }
            if !collections.contains(&op.collection.as_str()) {
                collections.push(op.collection.as_str());
            }
        }
        collections.sort_unstable();
        serde_json::json!({
            "creates": creates,
            "updates": updates,
            "deletes": deletes,
            "collections": collections,
            "rev": new_rev,
        })
        .to_string()
    });

    let mut store = SqliteBlockStore::new(state.db.clone(), did.to_string());

    // This commit's block diff, computed once here while both block sets are still present
    // (pre-GC), from a single walk of the new root (plus one of the previous root). `added` drives
    // the firehose diff CAR and the per-block rev tag for getRepo?since — tagging this precise set
    // (not "all untagged blocks") is what keeps the rev correct under concurrent same-repo writes
    // (see `db::blocks::tag_blocks_rev`). `new_reachable` is reused as the post-commit GC keep-set
    // below, so the GC no longer recomputes full-repo reachability a second time on every write.
    // `cid_strs`/`gc_keep` are kept independently of `blocks` (rather than as one `Option` bundle)
    // because the rev tag and GC still run even if the CAR later fails to build — only the firehose
    // event is dropped in that case.
    let diff = match repo_engine::collect_commit_diff(&mut store, Some(prev_root), new_root).await {
        Ok(diff) => Some(diff),
        Err(e) => {
            tracing::warn!(
                error = %e,
                did = %did,
                "failed to compute commit block diff; dropping firehose event + rev tag + \
                 post-commit GC (non-fatal; the next successful write's GC reclaims the leftovers)"
            );
            None
        }
    };
    let cid_strs: Option<Vec<String>> = diff
        .as_ref()
        .map(|d| d.added.iter().map(|c| c.to_string()).collect());
    // The GC keep-set: reachable(new), reused from the diff walk so the post-commit GC need not
    // re-walk the repo. `None` (the diff failed) means "skip GC this write"; the next successful
    // write's exhaustive GC reclaims whatever this one left behind.
    let gc_keep: Option<HashSet<String>> = diff
        .as_ref()
        .map(|d| d.new_reachable.iter().map(|c| c.to_string()).collect());
    let blocks = match diff {
        Some(d) => match repo_engine::build_car_from_cids(&mut store, new_root, d.added).await {
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

    // An agent-attributed commit records its audit row atomically with the CAS: the audit trail
    // is the product's accountability guarantee, so an agent write must not land without one
    // (same fail-closed posture as the firehose staging below — `?` rolls the whole write back).
    if let Some(registration_id) = agent_registration_id {
        crate::db::agent_audit::insert_agent_audit_event(
            &mut *tx,
            &uuid::Uuid::new_v4().to_string(),
            registration_id,
            Some(did),
            crate::db::agent_audit::AgentAuditEventType::RepoWrite,
            agent_audit_detail.as_deref(),
        )
        .await?;
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
                        prev_data,
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

    // Post-commit GC: reclaim every block this account owns that the new head no longer references
    // — superseded MST nodes, intermediate blocks from a multi-write batch, and orphans from a
    // conflicted attempt. The keep-set is `reachable(new)`, reused from the diff walk above, so the
    // GC does not recompute full-repo reachability a second time per write. Safe here because the
    // CAS committed (`new_root` is now the persisted head) and the caller holds the per-DID
    // [`RepoWriteLocks`] guard across this whole function, so no concurrent write can advance the
    // head between the commit and this sweep — the window in which an unguarded GC would delete a
    // sibling write's freshly written, not-yet-root-reachable blocks. Best-effort and last: a
    // failure — or a diff failure that left `gc_keep` `None` — leaves the blocks for the next
    // successful write's exhaustive GC to reclaim; the (durable) write never fails on GC.
    if let Some(keep) = gc_keep {
        if let Err(e) = gc_repo_blocks(&state.db, did, new_root, &keep).await {
            tracing::warn!(error = %e, did = %did, "post-commit block GC failed (non-fatal)");
        }
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

/// Garbage-collect the blocks an account owns that are no longer reachable from its repo head.
///
/// `reachable` is the head's live block set (`reachable(head)`) — every commit/MST/record CID the
/// current root transitively references. The caller supplies it rather than having this function
/// recompute it: a repo write already walks `reachable(new)` to build the firehose diff, so passing
/// that set here keeps the whole commit to a single reachability walk instead of recomputing it for
/// GC on every write. Any block the account owns that is *not* in `reachable` (superseded MST nodes,
/// intermediate blocks from a multi-write batch, orphans from a conflicted attempt) is reclaimed.
/// Returns the number of ownership rows removed.
///
/// Callers must hold the account's [`RepoWriteLocks`] lock and must have already committed `root` as
/// the head: the delete spans many statements, and a concurrent write's fresh blocks are exactly the
/// "unreachable" rows this sweep would destroy. As a second line of defense, the sweep is skipped
/// entirely when `root` is no longer the persisted head — a keep-set computed from a superseded root
/// does not contain the current head's blocks, so deleting against it would corrupt the repo.
pub async fn gc_repo_blocks(
    pool: &SqlitePool,
    did: &str,
    root: repo_engine::Cid,
    reachable: &std::collections::HashSet<String>,
) -> Result<u64, ApiError> {
    let current_root = crate::db::accounts::current_repo_root(pool, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to read repo head for GC");
            ApiError::new(ErrorCode::InternalError, "block GC failed")
        })?;
    if current_root.as_deref() != Some(root.to_string().as_str()) {
        tracing::warn!(
            did = %did,
            gc_root = %root,
            "skipping block GC: repo head is no longer the GC root"
        );
        return Ok(0);
    }

    crate::db::blocks::delete_unreachable_blocks(pool, did, reachable)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to delete unreachable blocks");
            ApiError::new(ErrorCode::InternalError, "block GC failed")
        })
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use tower::ServiceExt;

    use crate::db::blocks::SqliteBlockStore;
    use crate::routes::test_utils::{
        access_jwt, put_record_request, seed_account_with_repo, state_with_master_key,
    };

    async fn repo_root(db: &sqlx::SqlitePool, did: &str) -> String {
        sqlx::query_scalar::<_, Option<String>>("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(db)
            .await
            .unwrap()
            .expect("account must have a repo root")
    }

    /// A GC pass computed against a root that is no longer the persisted head must not delete
    /// blocks belonging to the current head. This is the MM-260 corruption vector reduced to its
    /// deterministic core: write B advances the root between write A's commit and A's post-commit
    /// GC, so A's reachable set does not contain B's new commit/MST/record blocks. B's commit is
    /// applied without its own GC pass here because in the race A's delete runs while B's blocks
    /// are freshly written and B's GC hasn't run yet.
    #[tokio::test]
    async fn stale_root_gc_preserves_committed_repo() {
        let state = state_with_master_key().await;
        let did = "did:plc:gcstaleroot";
        let kp = seed_account_with_repo(&state.db, did).await;
        let stale_root = repo_root(&state.db, did).await;

        // Write B: advance the repo past the captured root (commit + CAS, no GC yet).
        let signer = repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap();
        let store = SqliteBlockStore::new(state.db.clone(), did.to_string());
        let stale_cid = repo_engine::Cid::try_from(stale_root.as_str()).unwrap();
        let mut repo = repo_engine::Repository::open(store, stale_cid)
            .await
            .unwrap();
        repo_engine::put_record_json(
            &mut repo,
            &signer,
            "app.bsky.feed.post/current",
            &serde_json::json!({"text": "must survive stale GC"}),
        )
        .await
        .unwrap();
        let advanced = crate::db::accounts::advance_repo_root_if_active(
            &state.db,
            did,
            &repo.root().to_string(),
            repo.commit().rev().as_str(),
            &stale_root,
        )
        .await
        .unwrap();
        assert!(advanced);
        let current_root = repo_root(&state.db, did).await;
        assert_ne!(current_root, stale_root);

        // A straggling GC keyed on the superseded root must leave the current head intact. The
        // keep-set is deliberately empty: if the stale-root guard regressed and did *not* skip, an
        // empty keep-set would delete every owned block and the current head would fail to open —
        // so this asserts the guard fires, not merely that a correct keep-set was passed.
        let stale_cid = repo_engine::Cid::try_from(stale_root.as_str()).unwrap();
        let _ = super::gc_repo_blocks(&state.db, did, stale_cid, &std::collections::HashSet::new())
            .await;

        let store = SqliteBlockStore::new(state.db.clone(), did.to_string());
        let current_cid = repo_engine::Cid::try_from(current_root.as_str()).unwrap();
        let mut repo = repo_engine::Repository::open(store, current_cid)
            .await
            .expect("repo must still open at the persisted head after a stale-root GC");
        let record = repo_engine::get_record_cid(&mut repo, "app.bsky.feed.post/current")
            .await
            .expect("record lookup must not error");
        assert!(record.is_some(), "committed record lost to stale-root GC");
    }

    /// An agent-derived token's commit records a `repo_write` audit row attributed to its
    /// `registration_id`, with the mechanical op summary and never the record value; an ordinary
    /// session token's commit records nothing.
    #[tokio::test]
    async fn agent_commit_writes_attributed_audit_row() {
        let state = state_with_master_key().await;
        let did = "did:plc:agentauditwrite";
        seed_account_with_repo(&state.db, did).await;
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, scopes, assertion_expires_at, status, created_at, updated_at) \
             VALUES ('reg_write_audit', ?, 'service_auth', '[]', '2099-01-01 00:00:00', 'claimed', \
                     datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        let secret_text = "agent-written post body";
        let agent_token = crate::routes::test_utils::agent_jwt(
            &state.jwt_secret,
            did,
            "com.atproto.access",
            "reg_write_audit",
        );
        let response = crate::app::app(state.clone())
            .oneshot(put_record_request(
                did,
                "app.bsky.feed.post",
                "agentaudit1",
                serde_json::json!({"record": {"text": secret_text}}),
                Some(&agent_token),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let events =
            crate::db::agent_audit::list_agent_audit_events(&state.db, "reg_write_audit", None, 10)
                .await
                .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "repo_write");
        assert_eq!(events[0].did.as_deref(), Some(did));
        let detail = events[0].detail.as_deref().unwrap();
        assert!(detail.contains("app.bsky.feed.post"), "detail: {detail}");
        assert!(detail.contains("\"creates\":1"), "detail: {detail}");
        assert!(
            !detail.contains(secret_text),
            "record bodies must never reach the audit trail: {detail}"
        );

        // A non-agent write to the same repo adds no audit rows.
        let session_token = access_jwt(&state.jwt_secret, did);
        let response = crate::app::app(state.clone())
            .oneshot(put_record_request(
                did,
                "app.bsky.feed.post",
                "plainwrite1",
                serde_json::json!({"record": {"text": "owner post"}}),
                Some(&session_token),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let events =
            crate::db::agent_audit::list_agent_audit_events(&state.db, "reg_write_audit", None, 10)
                .await
                .unwrap();
        assert_eq!(events.len(), 1, "owner writes are not agent-attributed");
    }

    /// Two clients writing to the same repo concurrently (the official app pipelining a post and
    /// a like) must never corrupt it: every write that returned 200 must remain readable, and the
    /// persisted head must stay openable. On an unserialized write path, one request's
    /// post-commit GC deletes the other request's freshly written blocks.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_same_repo_writes_never_corrupt_repo() {
        let state = state_with_master_key().await;
        let did = "did:plc:gcwriterace";
        seed_account_with_repo(&state.db, did).await;
        let token = access_jwt(&state.jwt_secret, did);

        let mut tasks = Vec::new();
        for task in 0..2 {
            let state = state.clone();
            let token = token.clone();
            tasks.push(tokio::spawn(async move {
                let app = crate::app::app(state);
                let mut written = Vec::new();
                for i in 0..8 {
                    let rkey = format!("t{task}k{i}");
                    let mut attempts = 0;
                    loop {
                        let response = app
                            .clone()
                            .oneshot(put_record_request(
                                did,
                                "app.bsky.feed.post",
                                &rkey,
                                serde_json::json!({"record": {"text": format!("post {rkey}")}}),
                                Some(&token),
                            ))
                            .await
                            .unwrap();
                        match response.status() {
                            StatusCode::OK => {
                                written.push(rkey);
                                break;
                            }
                            // A concurrent-write CAS conflict is a legitimate retryable outcome;
                            // anything else (500 = repo no longer opens) is the corruption this
                            // test exists to catch.
                            StatusCode::CONFLICT => {
                                attempts += 1;
                                assert!(attempts < 50, "write {rkey} starved by conflicts");
                            }
                            status => panic!("write {rkey} failed with {status} — repo corrupted"),
                        }
                    }
                }
                written
            }));
        }

        let mut written = Vec::new();
        for task in tasks {
            written.extend(task.await.unwrap());
        }

        let root = repo_root(&state.db, did).await;
        let root_cid = repo_engine::Cid::try_from(root.as_str()).unwrap();
        let store = SqliteBlockStore::new(state.db.clone(), did.to_string());
        let mut repo = repo_engine::Repository::open(store, root_cid)
            .await
            .expect("repo must open at the persisted head after concurrent writes");
        for rkey in &written {
            let record =
                repo_engine::get_record_cid(&mut repo, &format!("app.bsky.feed.post/{rkey}"))
                    .await
                    .expect("record lookup must not error");
            assert!(record.is_some(), "acknowledged record {rkey} lost");
        }
    }

    /// A record rewritten many times must not accumulate blocks: each commit's post-commit GC
    /// reclaims the superseded record, MST node(s), and commit block, so a single-record repo holds
    /// the same number of owned blocks after ten updates as after the first. (Without the GC the
    /// count would grow roughly linearly with the number of writes.) The repo stays openable at head
    /// and reads back the latest value.
    #[tokio::test]
    async fn repeated_updates_reclaim_superseded_blocks() {
        async fn owned_block_count(db: &sqlx::SqlitePool, did: &str) -> i64 {
            sqlx::query_scalar("SELECT COUNT(*) FROM block_owners WHERE account_did = ?")
                .bind(did)
                .fetch_one(db)
                .await
                .unwrap()
        }

        let state = state_with_master_key().await;
        let did = "did:plc:gcincremental";
        seed_account_with_repo(&state.db, did).await;
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state.clone());

        let mut count_after_first = 0i64;
        for i in 0..10 {
            let response = app
                .clone()
                .oneshot(put_record_request(
                    did,
                    "app.bsky.feed.post",
                    "single",
                    serde_json::json!({"record": {"text": format!("revision {i}")}}),
                    Some(&token),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            if i == 0 {
                count_after_first = owned_block_count(&state.db, did).await;
            }
        }

        let count_after_tenth = owned_block_count(&state.db, did).await;
        assert_eq!(
            count_after_tenth, count_after_first,
            "repeated updates to one record must not accumulate owned blocks — the post-commit GC \
             reclaims each superseded version (got {count_after_first} after the first write, \
             {count_after_tenth} after ten)"
        );

        // The repo still opens at the persisted head and reads back the final revision.
        let root = repo_root(&state.db, did).await;
        let root_cid = repo_engine::Cid::try_from(root.as_str()).unwrap();
        let store = SqliteBlockStore::new(state.db.clone(), did.to_string());
        let mut repo = repo_engine::Repository::open(store, root_cid)
            .await
            .expect("repo must open at head after repeated updates");
        let value = repo_engine::get_record_json(&mut repo, "app.bsky.feed.post/single")
            .await
            .expect("record lookup must not error")
            .expect("record must be present at head");
        assert_eq!(value["text"], "revision 9");
    }
}
