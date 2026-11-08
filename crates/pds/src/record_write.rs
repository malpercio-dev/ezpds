// pattern: Imperative Shell

//! The one authorized, locked repo write every `com.atproto.repo.*` writer goes through.
//!
//! [`authorize`] → [`Authorized::lock`] is the opening sequence `createRecord`, `putRecord`,
//! `deleteRecord`, and `applyWrites` share: valid DID, access token, ownership, then the repo
//! write lock, active check, and repo open. The resulting [`LockedRepo`] holds the lock and
//! carries the signer load and the commit ([`commit_repo_write`]: CAS + firehose event + GC).
//! Each route keeps only its own operation body; [`write_record`] is the create/put body.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::http::{HeaderMap, Method, Uri};
use sqlx::SqlitePool;

use crate::app::AppState;
use common::{ApiError, ErrorCode};
use custos_db::blocks::SqliteBlockStore;
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
/// Every path that mutates a repo's block set or root must hold this lock from before it reads
/// the repo root until after its GC pass; the record writers hold it through [`LockedRepo`].
/// Lock ordering: this lock is acquired *before* the firehose emit lock (inside
/// [`commit_repo_write`]); nothing acquires them in the reverse order.
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
            let mut map = self
                .locks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                {
                    tracing::error!(error = %e, key = %mst_key, "failed to read record CID for swap check");
                    ApiError::new(ErrorCode::InternalError, "failed to evaluate swapRecord")
                }
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
    custos_db::accounts::resolve_identifier(&state.db, repo)
        .await?
        .map(|account| account.did)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidRequest,
                "could not resolve repo to a known account",
            )
        })
}

/// An access-token caller proven to own the repo it is about to write. Only [`authorize`] builds
/// one, and only [`Authorized::lock`] opens a repo for writing, so every writer authenticates
/// before it takes the repo write lock.
pub(crate) struct Authorized {
    user: custos_core::auth::AuthenticatedUser,
}

/// The first half of the opening sequence every repo writer shares: valid DID → access token
/// (the shared `authenticate_access` path, so DPoP binding rules match the `AuthenticatedUser`
/// extractor and a DPoP-bound token presented as plain `Bearer` is rejected) → access scope →
/// the token's subject owns `did`.
///
/// Writers run their request-shape validation after this and before [`Authorized::lock`], so a
/// malformed write never waits on the lock and validation can't probe a repo the caller doesn't
/// own.
pub(crate) fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    did: &str,
) -> Result<Authorized, ApiError> {
    if !custos_core::identity::did::is_valid_did(did) {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }
    let user = custos_core::auth::authenticate_access(headers, method, uri, state)?;
    if *user.did != *did {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "authenticated account does not own this repository",
        ));
    }
    Ok(Authorized { user })
}

impl Authorized {
    pub(crate) fn did(&self) -> &str {
        &self.user.did
    }

    /// The OAuth granular-scope check for one record op. Legacy session and app-password tokens
    /// carry no granular grant and pass.
    pub(crate) fn require_repo(
        &self,
        collection: &str,
        action: custos_core::auth::oauth_scopes::RepoAction,
    ) -> Result<(), ApiError> {
        if self.user.scope == custos_core::auth::jwt::AuthScope::Access {
            custos_core::auth::oauth_scopes::require_repo(
                &self.user.scope_claim,
                collection,
                action,
            )?;
        }
        Ok(())
    }

    /// The second half of the opening sequence: take the repo write lock (see
    /// [`RepoWriteLocks`]), then read the root and active status, refuse a non-active account,
    /// and open the repo at its root. The lock lives in the returned [`LockedRepo`], so it is
    /// held until the writer drops it — past the commit and its GC pass.
    pub(crate) async fn lock(self, state: &AppState) -> Result<LockedRepo, ApiError> {
        let did = self.did().to_string();
        let guard = state.repo_write_locks.lock(&did).await;

        let write_state = custos_db::accounts::get_repo_write_state(&state.db, &did)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to query repo write state");
                ApiError::new(ErrorCode::InternalError, "failed to write record")
            })?
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

        // A deactivated, suspended, or taken-down account is read-only until reactivated or the
        // moderation action is cleared. Checked before the repo-root lookup, so a non-active
        // account is a 403 even if it never created a repo; only a missing account is a 404. The
        // commit CAS carries the same lifecycle guard, closing the gap between here and commit.
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

        let block_store = SqliteBlockStore::new(state.db.clone(), did.clone());
        let repo = Repository::open(block_store, root_cid).await.map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to open repo");
            ApiError::new(ErrorCode::InternalError, "failed to write record")
        })?;

        // The pre-write revision and MST root become the firehose event's `since` and Sync v1.1
        // `prevData`; both must be read before the write mutates the repo.
        let prev_rev = repo.commit().rev().as_str().to_string();
        let prev_data = repo.commit().data().to_string();

        Ok(LockedRepo {
            _guard: guard,
            authorized: self,
            root_cid,
            root_cid_str,
            repo,
            prev_rev,
            prev_data,
        })
    }
}

/// An authorized writer's repo, opened at its persisted root under the repo write lock.
pub(crate) struct LockedRepo {
    _guard: tokio::sync::OwnedMutexGuard<()>,
    authorized: Authorized,
    root_cid: repo_engine::Cid,
    root_cid_str: String,
    pub(crate) repo: Repository<SqliteBlockStore>,
    prev_rev: String,
    prev_data: String,
}

impl LockedRepo {
    pub(crate) fn did(&self) -> &str {
        self.authorized.did()
    }

    pub(crate) fn require_repo(
        &self,
        collection: &str,
        action: custos_core::auth::oauth_scopes::RepoAction,
    ) -> Result<(), ApiError> {
        self.authorized.require_repo(collection, action)
    }

    /// The persisted repo head this write started from, as a CID string (`swapCommit` compares
    /// against it).
    pub(crate) fn root_cid_str(&self) -> &str {
        &self.root_cid_str
    }

    /// Enforce `swapCommit` / `swapRecord` for `mst_key` against the repo as opened.
    pub(crate) async fn enforce_swap(
        &mut self,
        swap: &SwapCheck,
        mst_key: &str,
    ) -> Result<(), ApiError> {
        enforce_swap(swap, &self.root_cid_str, &mut self.repo, mst_key).await
    }

    /// Load this account's repo signing key.
    pub(crate) async fn signer(
        &self,
        state: &AppState,
    ) -> Result<repo_engine::CommitSigner, ApiError> {
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
        custos_core::auth::signing_key::load_repo_signer(&state.db, self.did(), master_key).await
    }

    /// Commit the repo's current head (see [`commit_repo_write`]) against the root this write
    /// opened at, attributing it to the caller's agent registration when there is one.
    pub(crate) async fn commit(
        &self,
        state: &AppState,
        ops: Vec<custos_core::firehose::RepoOp>,
    ) -> Result<(), ApiError> {
        commit_repo_write(
            state,
            self.did(),
            self.root_cid,
            self.repo.root(),
            self.repo.commit().rev().as_str().to_string(),
            Some(self.prev_rev.clone()),
            Some(self.prev_data.clone()),
            ops,
            &self.root_cid_str,
            self.authorized.user.registration_id.as_deref(),
        )
        .await
    }
}

/// Whether a single-record write may replace an existing record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RecordMode {
    /// `createRecord`: the key must be absent (409 otherwise).
    Create,
    /// `putRecord`: upsert.
    Put,
}

/// The single-record create/put flow: format + lexicon validation → lock and open → scope check
/// (create vs update needs the current record) → swap preconditions → write → commit.
///
/// # Precondition
/// `mst_key` must already be validated via `repo_engine::validate_record_path`; this
/// helper trusts it and does not re-check the collection/rkey format.
pub async fn write_record(
    state: &AppState,
    authorized: Authorized,
    mst_key: &str,
    record: &serde_json::Value,
    mode: RecordMode,
    swap: &SwapCheck,
    validate: Option<bool>,
) -> Result<
    (
        repo_engine::Cid,
        Option<custos_core::lexicon::RecordValidation>,
    ),
    ApiError,
> {
    // Reject malformed self-describing record formats (top-level `createdAt` datetime, any
    // `at://` AT-URI) before any repo mutation. This schema-free gate still runs for lexicons
    // Custos doesn't vendor; for a vendored (known) lexicon the schema check below subsumes it.
    custos_core::auth::validation::validate_record_formats(record)
        .map_err(|message| ApiError::new(ErrorCode::InvalidRequest, message))?;

    // `validate`-flag record validation (`assertValidRecord` parity): reject an invalid record of
    // a known lexicon by default, require validity when `validate: true`, skip when
    // `validate: false`, and report `validationStatus` for the response.
    let (collection, rkey) = split_record_path(mst_key);
    let validation_status = custos_core::lexicon::registry()
        .validate_record(&collection, &rkey, record, validate)
        .map_err(custos_core::lexicon::record_validation_error)?;

    let mut locked = authorized.lock(state).await?;
    let did = locked.did().to_string();

    // The record's current CID decides create vs update (for both the scope check and the
    // firehose op) and, when present, is the op's Sync v1.1 `prev`.
    let prev_cid = repo_engine::get_record_cid(&mut locked.repo, mst_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to check record existence");
            ApiError::new(ErrorCode::InternalError, "failed to write record")
        })?;
    let existed = prev_cid.is_some();
    let action = if mode == RecordMode::Create || !existed {
        custos_core::auth::oauth_scopes::RepoAction::Create
    } else {
        custos_core::auth::oauth_scopes::RepoAction::Update
    };
    locked.require_repo(&collection, action)?;

    locked.enforce_swap(swap, mst_key).await?;

    if mode == RecordMode::Create && existed {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "record already exists; use putRecord to update",
        ));
    }

    let signer = locked.signer(state).await?;

    // Write the record (JSON is converted to the ATProto data model: $link → CID,
    // $bytes → byte string, floats rejected).
    let record_cid = repo_engine::put_record_json(&mut locked.repo, &signer, mst_key, record)
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

    let op = custos_core::firehose::RepoOp {
        action: if existed {
            custos_core::firehose::OpAction::Update
        } else {
            custos_core::firehose::OpAction::Create
        },
        collection,
        rkey,
        cid: Some(record_cid.to_string()),
        // The previous record CID — `Some` for an update, `None` for a create.
        prev: prev_cid.map(|c| c.to_string()),
        value: Some(record.clone()),
    };
    locked.commit(state, vec![op]).await?;

    Ok((record_cid, validation_status))
}

/// Advance the repo root (optimistic-concurrency CAS) and, while both the previous and new block
/// sets are still present, stage the corresponding firehose `#commit` event in the *same*
/// transaction as the CAS when the diff CAR can be assembled — so the two commit or roll back
/// together once staging is attempted (see [`custos_core::firehose`]'s module docs and
/// `Firehose::stage_commit`).
///
/// Before the CAS, the MST integrity check verifies the new head's actual key count against the
/// maintained per-repo record count (V068) plus this commit's explicit op delta, aborting the
/// write with a 500 when the tree lost keys no op deleted (see the inline comment for the full
/// rationale).
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
    ops: Vec<custos_core::firehose::RepoOp>,
    expected_root: &str,
    agent_registration_id: Option<&str>,
) -> Result<(), ApiError> {
    // Charge this commit against the account's repo-write point budget (create=3/update=2/delete=1)
    // before doing any diff/CAR work, so an over-budget account is rejected cheaply. Keyed by the
    // repo's DID, which every caller has already authenticated (the token subject must own `did`).
    let write_cost: u64 = ops
        .iter()
        .map(|op| match op.action {
            custos_core::firehose::OpAction::Create => custos_core::rate_limit::WRITE_COST_CREATE,
            custos_core::firehose::OpAction::Update => custos_core::rate_limit::WRITE_COST_UPDATE,
            custos_core::firehose::OpAction::Delete => custos_core::rate_limit::WRITE_COST_DELETE,
        })
        .sum();
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

    // MST integrity check (defense in depth): the maintained per-repo record count (V068) is
    // the independent witness the MST otherwise lacks — the PDS keeps no separate record index,
    // so a commit that silently drops keys (the 2026-08-27 atrium-repo `split_subtree` data
    // loss: one create netted −40 keys) leaves no surface that can disagree with the corrupted
    // tree. The new head's actual key count must equal the stored count plus this commit's
    // explicit delta; on a mismatch the write aborts here, before the CAS below, so the
    // corrupted head never becomes the persisted root (its blocks are orphans the next
    // successful write's GC reclaims). The count walk runs before the transaction because it
    // reads the block store, which needs the single pooled connection the transaction would
    // hold; the caller's per-DID write lock keeps the walk, the stored count, and the CAS
    // mutually consistent. A stored count of NULL (pre-V068 account, fresh genesis, or a
    // just-imported repo) skips the comparison and is initialized by this write's walk.
    let expected_delta: i64 =
        ops.iter()
            .map(|op| match op.action {
                // An op whose `prev` is `None` had no previous record, so it introduced its key.
                // (`applyWrites` labels an upsert by its requested kind, so an `Update` that
                // created its key is only visible through `prev`; emitted deletes always carry
                // the removed record's CID as `prev` — no-op deletes never become ops.)
                custos_core::firehose::OpAction::Create
                | custos_core::firehose::OpAction::Update => i64::from(op.prev.is_none()),
                custos_core::firehose::OpAction::Delete => -1,
            })
            .sum();
    let stored_count = custos_db::accounts::repo_record_count(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to read maintained record count");
            ApiError::new(ErrorCode::InternalError, "failed to write record")
        })?;
    // The new head's actual key count. A failed walk is `None`: the check is skipped and NULL is
    // stored, so the next write re-initializes instead of comparing against a stale count.
    let new_count = {
        let store = SqliteBlockStore::new(state.db.clone(), did.to_string());
        match Repository::open(store, new_root).await {
            Ok(mut repo) => match repo_engine::count_records(&mut repo).await {
                Ok(n) => i64::try_from(n).ok(),
                Err(e) => {
                    tracing::warn!(error = %e, did = %did, "failed to count records for the MST integrity check (non-fatal; count resets to unknown)");
                    None
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, did = %did, "failed to open new head for the MST integrity check (non-fatal; count resets to unknown)");
                None
            }
        }
    };
    if let (Some(stored), Some(counted)) = (stored_count, new_count) {
        if stored + expected_delta != counted {
            return Err({
                tracing::error!(
                did = %did,
                stored_count = stored,
                expected_delta,
                counted,
                new_root = %new_root, "MST integrity violation: commit removed keys it did not explicitly delete; write aborted");
                ApiError::new(
                    ErrorCode::InternalError,
                    "repository integrity check failed; write aborted",
                )
            });
        }
    }

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
                custos_core::firehose::OpAction::Create => creates += 1,
                custos_core::firehose::OpAction::Update => updates += 1,
                custos_core::firehose::OpAction::Delete => deletes += 1,
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
    // below, so the GC does not recompute full-repo reachability a second time on every write.
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
    let advanced = custos_db::accounts::advance_repo_root_if_active(
        &mut *tx,
        did,
        &new_root_str,
        &new_rev,
        expected_root,
        new_count,
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
        custos_db::agent_audit::insert_agent_audit_event(
            &mut *tx,
            &uuid::Uuid::new_v4().to_string(),
            registration_id,
            Some(did),
            custos_db::agent_audit::AgentAuditEventType::RepoWrite,
            agent_audit_detail.as_deref(),
        )
        .await?;
    }

    let pending = match blocks {
        Some(blocks) => {
            let staged = emit_guard
                .stage_commit(
                    &mut tx,
                    custos_core::firehose::CommitInput {
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
                    return Err({
                        tracing::error!(error = %e, did = %did, "failed to stage firehose commit event");
                        ApiError::new(ErrorCode::InternalError, "failed to write record")
                    });
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
        if let Err(e) = custos_db::blocks::tag_blocks_rev(&state.db, did, &cid_strs, &new_rev).await
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
    let current_root = custos_db::accounts::current_repo_root(pool, did)
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

    custos_db::blocks::delete_unreachable_blocks(pool, did, reachable)
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

    use crate::routes::test_utils::{
        access_jwt, put_record_request, seed_account_with_repo, state_with_master_key,
    };
    use custos_db::blocks::SqliteBlockStore;

    async fn repo_root(db: &sqlx::SqlitePool, did: &str) -> String {
        sqlx::query_scalar::<_, Option<String>>("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(db)
            .await
            .unwrap()
            .expect("account must have a repo root")
    }

    /// A GC pass computed against a root that is no longer the persisted head must not delete
    /// blocks belonging to the current head. This is the corruption vector reduced to its
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
        let advanced = custos_db::accounts::advance_repo_root_if_active(
            &state.db,
            did,
            &repo.root().to_string(),
            repo.commit().rev().as_str(),
            &stale_root,
            None,
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
            custos_db::agent_audit::list_agent_audit_events(&state.db, "reg_write_audit", None, 10)
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
            custos_db::agent_audit::list_agent_audit_events(&state.db, "reg_write_audit", None, 10)
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

    async fn stored_record_count(db: &sqlx::SqlitePool, did: &str) -> Option<i64> {
        sqlx::query_scalar::<_, Option<i64>>("SELECT record_count FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(db)
            .await
            .unwrap()
    }

    fn delete_record_request(
        did: &str,
        collection: &str,
        rkey: &str,
        token: &str,
    ) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/xrpc/com.atproto.repo.deleteRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(
                serde_json::json!({"repo": did, "collection": collection, "rkey": rkey})
                    .to_string(),
            ))
            .unwrap()
    }

    /// The maintained record count (the MST integrity witness) starts unknown, is initialized by
    /// the first write's key walk, and then tracks every explicit create/update/delete exactly.
    #[tokio::test]
    async fn record_count_initializes_and_tracks_writes() {
        let state = state_with_master_key().await;
        let did = "did:plc:recordcount";
        seed_account_with_repo(&state.db, did).await;
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state.clone());

        assert_eq!(
            stored_record_count(&state.db, did).await,
            None,
            "a fresh account's count is unknown until its first write"
        );

        for (rkey, expected) in [("one", 1), ("two", 2)] {
            let response = app
                .clone()
                .oneshot(put_record_request(
                    did,
                    "app.bsky.feed.post",
                    rkey,
                    serde_json::json!({"record": {"text": rkey}}),
                    Some(&token),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(stored_record_count(&state.db, did).await, Some(expected));
        }

        // An update replaces a key without changing the count.
        let response = app
            .clone()
            .oneshot(put_record_request(
                did,
                "app.bsky.feed.post",
                "one",
                serde_json::json!({"record": {"text": "one v2"}}),
                Some(&token),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(stored_record_count(&state.db, did).await, Some(2));

        // A delete decrements it.
        let response = app
            .clone()
            .oneshot(delete_record_request(
                did,
                "app.bsky.feed.post",
                "one",
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(stored_record_count(&state.db, did).await, Some(1));
    }

    /// A commit whose actual key count disagrees with the maintained count plus the explicit op
    /// delta must abort loudly, leaving the persisted root untouched — the incident shape (a tree
    /// that silently lost keys the bookkeeping still counts) reduced to its deterministic core.
    /// Resetting the count to NULL (unknown) heals: the next write re-initializes it.
    #[tokio::test]
    async fn count_mismatch_aborts_write_and_preserves_root() {
        let state = state_with_master_key().await;
        let did = "did:plc:recordcounttamper";
        seed_account_with_repo(&state.db, did).await;
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state.clone());

        let response = app
            .clone()
            .oneshot(put_record_request(
                did,
                "app.bsky.feed.post",
                "one",
                serde_json::json!({"record": {"text": "one"}}),
                Some(&token),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let root_before = repo_root(&state.db, did).await;

        // Simulate the incident from the witness's side: the bookkeeping claims 40 more records
        // than the tree holds, exactly what a key-dropping commit leaves behind.
        sqlx::query("UPDATE accounts SET record_count = record_count + 40 WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();

        let response = app
            .clone()
            .oneshot(put_record_request(
                did,
                "app.bsky.feed.post",
                "two",
                serde_json::json!({"record": {"text": "two"}}),
                Some(&token),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a count mismatch must fail the write loudly"
        );
        assert_eq!(
            repo_root(&state.db, did).await,
            root_before,
            "an aborted write must not advance the persisted root"
        );

        // Operator remediation path: resetting the witness to unknown lets writes resume, and the
        // first successful write re-initializes it from a fresh key walk.
        sqlx::query("UPDATE accounts SET record_count = NULL WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let response = app
            .clone()
            .oneshot(put_record_request(
                did,
                "app.bsky.feed.post",
                "two",
                serde_json::json!({"record": {"text": "two"}}),
                Some(&token),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(stored_record_count(&state.db, did).await, Some(2));
    }
}
