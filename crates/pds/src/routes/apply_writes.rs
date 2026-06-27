// pattern: Imperative Shell

//! com.atproto.repo.applyWrites - Apply a batch of record writes in one atomic commit.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::{Repository, WriteOp};

#[derive(Deserialize)]
pub struct ApplyWritesBody {
    /// The DID of the repo to write to.
    repo: String,
    /// The ordered list of writes to apply atomically.
    #[serde(default)]
    writes: Vec<WriteItem>,
    /// Optimistic concurrency: if present, the current repo commit must equal this CID.
    #[serde(default, rename = "swapCommit")]
    swap_commit: Option<String>,
    /// Accepted for lexicon compatibility. v0.1 does not run lexicon schema validation,
    /// so this flag has no effect.
    #[serde(default)]
    #[allow(dead_code)]
    validate: Option<bool>,
}

/// A single write in the batch, tagged by its ATProto `$type`.
#[derive(Deserialize)]
#[serde(tag = "$type")]
enum WriteItem {
    #[serde(rename = "com.atproto.repo.applyWrites#create")]
    Create {
        collection: String,
        /// Optional record key; an empty/absent value auto-generates a TID.
        #[serde(default)]
        rkey: Option<String>,
        value: serde_json::Value,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#update")]
    Update {
        collection: String,
        rkey: String,
        value: serde_json::Value,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#delete")]
    Delete { collection: String, rkey: String },
}

#[derive(Clone, Copy)]
enum Kind {
    Create,
    Update,
    Delete,
}

#[derive(Serialize)]
struct CommitMeta {
    cid: String,
    rev: String,
}

#[derive(Serialize)]
#[serde(tag = "$type")]
enum WriteResult {
    #[serde(rename = "com.atproto.repo.applyWrites#createResult")]
    Create {
        uri: String,
        cid: String,
        #[serde(rename = "validationStatus")]
        validation_status: &'static str,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#updateResult")]
    Update {
        uri: String,
        cid: String,
        #[serde(rename = "validationStatus")]
        validation_status: &'static str,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#deleteResult")]
    Delete {},
}

#[derive(Serialize)]
struct ApplyWritesResponse {
    commit: CommitMeta,
    results: Vec<WriteResult>,
}

/// POST /xrpc/com.atproto.repo.applyWrites
///
/// Apply multiple record creates/updates/deletes to a repo in a single atomic commit.
/// Either every write is applied (the repo advances to one new commit) or none is: any
/// error returns before the repo root is swapped, leaving the persisted repo untouched.
pub async fn apply_writes(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<ApplyWritesBody>,
) -> Result<impl IntoResponse, ApiError> {
    let did = &body.repo;

    if !crate::auth::validation::is_valid_did(did) {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    // Authenticate: require a valid access token whose subject owns this repo.
    let token = crate::auth::extract_bearer_token(&headers)?;
    let claims = crate::auth::jwt::verify_access_token(token, &state)?;
    if claims.sub != *did {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "authenticated account does not own this repository",
        ));
    }

    if body.writes.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "writes array must not be empty",
        ));
    }

    // Resolve each write to a concrete (collection, rkey) and validate its path up front,
    // so an invalid path or float rejects the whole batch before any mutation. `value` is
    // moved into the engine op; `kinds` retains each write's variant for building the
    // response (the AT-URI is rebuilt from the matching `WriteOutcome.key`).
    let mut kinds: Vec<Kind> = Vec::with_capacity(body.writes.len());
    let mut ops: Vec<WriteOp> = Vec::with_capacity(body.writes.len());
    // Record values retained per write (cloned out before each value is moved into the engine
    // op) so the firehose `#commit` event can carry the value for creates/updates.
    let mut op_values: Vec<Option<serde_json::Value>> = Vec::with_capacity(body.writes.len());
    for item in body.writes {
        let (kind, collection, rkey, value) = match item {
            WriteItem::Create {
                collection,
                rkey,
                value,
            } => {
                let rkey = rkey
                    .filter(|r| !r.is_empty())
                    .unwrap_or_else(repo_engine::generate_tid);
                (Kind::Create, collection, rkey, Some(value))
            }
            WriteItem::Update {
                collection,
                rkey,
                value,
            } => (Kind::Update, collection, rkey, Some(value)),
            WriteItem::Delete { collection, rkey } => (Kind::Delete, collection, rkey, None),
        };

        repo_engine::validate_record_path(&collection, &rkey).map_err(|_| {
            ApiError::new(ErrorCode::InvalidClaim, "invalid collection or record key")
        })?;

        let key = format!("{collection}/{rkey}");
        op_values.push(value.clone());
        let op = match (kind, value) {
            (Kind::Create, Some(value)) => WriteOp::Create { key, value },
            (Kind::Update, Some(value)) => WriteOp::Update { key, value },
            (Kind::Delete, _) => WriteOp::Delete { key },
            // Create/Update always carry a value (set above); this arm is unreachable.
            (Kind::Create | Kind::Update, None) => {
                return Err(ApiError::new(
                    ErrorCode::InternalError,
                    "failed to apply writes",
                ));
            }
        };
        ops.push(op);
        kinds.push(kind);
    }

    // Look up the repo root CID and active status in one query.
    let write_state = crate::db::accounts::get_repo_write_state(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to query repo write state");
            ApiError::new(ErrorCode::InternalError, "failed to apply writes")
        })?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    // A deactivated account is read-only: no writes until reactivated. Checked right after account
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

    // swapCommit: reject up front if the caller's expected commit no longer matches.
    if let Some(expected) = &body.swap_commit {
        if expected != &root_cid_str {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "swapCommit does not match current repo commit",
            ));
        }
    }

    let root_cid = repo_engine::Cid::try_from(root_cid_str.as_str()).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID in database");
        ApiError::new(ErrorCode::InternalError, "failed to apply writes")
    })?;

    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to apply writes")
    })?;

    // Capture the pre-write revision for the firehose event's `since`.
    let prev_rev = repo.commit().rev().as_str().to_string();

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

    // Apply the batch in memory. On any error we return here without swapping the root.
    let outcomes = repo_engine::apply_writes(&mut repo, &signer, &ops)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to apply writes");
            match e {
                repo_engine::RecordError::AlreadyExists(_) => {
                    ApiError::new(ErrorCode::Conflict, "record already exists")
                }
                repo_engine::RecordError::InvalidRecord(_) => {
                    ApiError::new(ErrorCode::InvalidClaim, "invalid record")
                }
                repo_engine::RecordError::InvalidPath(_) => {
                    ApiError::new(ErrorCode::InvalidClaim, "invalid collection or record key")
                }
                _ => ApiError::new(ErrorCode::InternalError, "failed to apply writes"),
            }
        })?;

    // Atomic commit: advance the persisted root only if it hasn't moved since we read it.
    // A concurrent write losing this race returns 409 rather than clobbering the other commit.
    // The shared helper folds the deactivation guard into the CAS so an account deactivated after
    // the `get_repo_write_state` check above cannot have this batch land.
    let new_root = repo.root().to_string();
    let new_rev = repo.commit().rev().as_str().to_string();
    let advanced = crate::db::accounts::advance_repo_root_if_active(
        &state.db,
        did,
        &new_root,
        &new_rev,
        &root_cid_str,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to update repo root CID");
        ApiError::new(ErrorCode::InternalError, "failed to apply writes")
    })?;
    if !advanced {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "repository was modified concurrently; retry against the current root",
        ));
    }

    // Emit one firehose `#commit` event for the whole batch, before GC (the diff CAR is
    // computed against the previous block set). Each engine outcome maps back to its write's
    // kind and retained value to form a `#repoOp`.
    let fh_ops: Vec<crate::firehose::RepoOp> = kinds
        .iter()
        .zip(outcomes.iter())
        .zip(op_values)
        .map(|((kind, outcome), value)| {
            let (collection, rkey) = crate::record_write::split_record_path(&outcome.key);
            crate::firehose::RepoOp {
                action: match kind {
                    Kind::Create => crate::firehose::OpAction::Create,
                    Kind::Update => crate::firehose::OpAction::Update,
                    Kind::Delete => crate::firehose::OpAction::Delete,
                },
                collection,
                rkey,
                cid: outcome.cid.map(|c| c.to_string()),
                value,
            }
        })
        .collect();
    crate::record_write::emit_firehose_commit(
        &state,
        did,
        root_cid,
        repo.root(),
        new_rev,
        Some(prev_rev),
        fh_ops,
    )
    .await;

    // Best-effort GC: reclaim the intermediate per-write commits and any superseded blocks.
    if let Err(e) = crate::record_write::gc_repo_blocks(&state.db, did, repo.root()).await {
        tracing::warn!(error = %e, did = %did, "post-commit block GC failed (non-fatal)");
    }

    let rev = repo.commit().rev().as_str().to_string();

    // Build per-write results in batch order, pairing each write's variant with its outcome.
    // `outcome.key` is the `<collection>/<rkey>` written by the engine, so the AT-URI is just
    // `at://<did>/<key>` — no need to retain the split collection/rkey separately.
    let results = kinds
        .iter()
        .zip(outcomes.iter())
        .map(|(kind, outcome)| {
            let uri = format!("at://{did}/{}", outcome.key);
            let cid = outcome.cid.map(|c| c.to_string()).unwrap_or_default();
            match kind {
                Kind::Create => WriteResult::Create {
                    uri,
                    cid,
                    validation_status: "unknown",
                },
                Kind::Update => WriteResult::Update {
                    uri,
                    cid,
                    validation_status: "unknown",
                },
                Kind::Delete => WriteResult::Delete {},
            }
        })
        .collect();

    Ok((
        StatusCode::OK,
        axum::Json(ApplyWritesResponse {
            commit: CommitMeta { cid: new_root, rev },
            results,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use tower::ServiceExt;

    use crate::routes::test_utils::{
        access_jwt, body_json, seed_account_with_repo, state_with_master_key,
    };

    async fn setup() -> (AppState, String) {
        let state = state_with_master_key().await;
        let did = "did:plc:applywritestest".to_string();
        seed_account_with_repo(&state.db, &did).await;
        (state, did)
    }

    fn apply_req(body: serde_json::Value, token: Option<&str>) -> Request<Body> {
        let mut b = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.applyWrites")
            .header("Content-Type", "application/json");
        if let Some(t) = token {
            b = b.header("Authorization", format!("Bearer {t}"));
        }
        b.body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap()
    }

    fn create_item(rkey: &str, text: &str) -> serde_json::Value {
        serde_json::json!({
            "$type": "com.atproto.repo.applyWrites#create",
            "collection": "app.bsky.feed.post",
            "rkey": rkey,
            "value": {"text": text, "createdAt": "2026-06-25T00:00:00Z"},
        })
    }

    async fn repo_root(db: &sqlx::SqlitePool, did: &str) -> Option<String> {
        sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn apply_writes_without_auth_returns_401() {
        let (state, did) = setup().await;
        let app = crate::app::app(state);
        let body = serde_json::json!({ "repo": did, "writes": [create_item("k1", "hi")] });
        let resp = app.oneshot(apply_req(body, None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn apply_writes_wrong_did_returns_403() {
        let (state, did) = setup().await;
        let token = access_jwt(&state.jwt_secret, "did:plc:someoneelse");
        let app = crate::app::app(state);
        let body = serde_json::json!({ "repo": did, "writes": [create_item("k1", "hi")] });
        let resp = app.oneshot(apply_req(body, Some(&token))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn apply_writes_on_deactivated_account_returns_403() {
        let (state, did) = setup().await;
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind(&did)
            .execute(&state.db)
            .await
            .unwrap();
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);
        let body = serde_json::json!({ "repo": did, "writes": [create_item("k1", "hi")] });
        let resp = app.oneshot(apply_req(body, Some(&token))).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a deactivated account must not be able to apply writes"
        );
    }

    #[tokio::test]
    async fn apply_writes_empty_writes_returns_400() {
        let (state, did) = setup().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);
        let body = serde_json::json!({ "repo": did, "writes": [] });
        let resp = app.oneshot(apply_req(body, Some(&token))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn apply_writes_invalid_collection_returns_400() {
        let (state, did) = setup().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);
        let body = serde_json::json!({
            "repo": did,
            "writes": [{
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "notanid",
                "rkey": "k1",
                "value": {"text": "x"},
            }],
        });
        let resp = app.oneshot(apply_req(body, Some(&token))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn apply_writes_batch_applies_all_and_returns_results() {
        let (state, did) = setup().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        // create k1, create k2, then update k1, then delete k2 — all in one commit.
        let body = serde_json::json!({
            "repo": did,
            "writes": [
                create_item("k1", "first"),
                create_item("k2", "second"),
                {
                    "$type": "com.atproto.repo.applyWrites#update",
                    "collection": "app.bsky.feed.post",
                    "rkey": "k1",
                    "value": {"text": "updated"},
                },
                {
                    "$type": "com.atproto.repo.applyWrites#delete",
                    "collection": "app.bsky.feed.post",
                    "rkey": "k2",
                },
            ],
        });
        let resp = app
            .clone()
            .oneshot(apply_req(body, Some(&token)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;

        assert!(!json["commit"]["cid"].as_str().unwrap().is_empty());
        let results = json["results"].as_array().unwrap();
        assert_eq!(results.len(), 4);
        assert_eq!(
            results[0]["$type"],
            "com.atproto.repo.applyWrites#createResult"
        );
        assert_eq!(
            results[0]["uri"],
            format!("at://{did}/app.bsky.feed.post/k1")
        );
        assert_eq!(
            results[3]["$type"],
            "com.atproto.repo.applyWrites#deleteResult"
        );

        // k1 reflects the update; k2 was deleted.
        let get_k1 = Request::builder()
            .method(http::Method::GET)
            .uri(format!(
                "/xrpc/com.atproto.repo.getRecord?did={did}&collection=app.bsky.feed.post&rkey=k1"
            ))
            .body(Body::empty())
            .unwrap();
        let r = app.clone().oneshot(get_k1).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body_json(r).await["value"]["text"], "updated");

        let get_k2 = Request::builder()
            .method(http::Method::GET)
            .uri(format!(
                "/xrpc/com.atproto.repo.getRecord?did={did}&collection=app.bsky.feed.post&rkey=k2"
            ))
            .body(Body::empty())
            .unwrap();
        let r = app.oneshot(get_k2).await.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn apply_writes_partial_failure_rolls_back() {
        let (state, did) = setup().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let db = state.db.clone();
        let app = crate::app::app(state);

        // Seed an existing record k1 via a first batch.
        let first = serde_json::json!({ "repo": did, "writes": [create_item("k1", "orig")] });
        let r = app
            .clone()
            .oneshot(apply_req(first, Some(&token)))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);

        let root_before = repo_root(&db, &did).await.unwrap();

        // Batch: create a fresh k2, then create k1 again (conflict). The whole batch must fail.
        let body = serde_json::json!({
            "repo": did,
            "writes": [create_item("k2", "new"), create_item("k1", "dup")],
        });
        let r = app
            .clone()
            .oneshot(apply_req(body, Some(&token)))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CONFLICT);

        // Root is unchanged and k2 was never persisted — nothing in the batch took effect.
        assert_eq!(repo_root(&db, &did).await.unwrap(), root_before);
        let get_k2 = Request::builder()
            .method(http::Method::GET)
            .uri(format!(
                "/xrpc/com.atproto.repo.getRecord?did={did}&collection=app.bsky.feed.post&rkey=k2"
            ))
            .body(Body::empty())
            .unwrap();
        let r = app.oneshot(get_k2).await.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn apply_writes_emits_single_commit_event_with_all_ops() {
        use crate::firehose::{FirehoseEvent, OpAction};

        let (state, did) = setup().await;
        let token = access_jwt(&state.jwt_secret, &did);

        // Seed k1 so the batch can update it; subscribe afterwards to isolate the batch commit.
        let firehose = state.firehose.clone();
        let app = crate::app::app(state);
        let seed = serde_json::json!({ "repo": did, "writes": [create_item("k1", "orig")] });
        let r = app
            .clone()
            .oneshot(apply_req(seed, Some(&token)))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);

        let mut rx = firehose.subscribe();

        // One batch: create k2, update k1, delete k2 — a single commit with three ops.
        let body = serde_json::json!({
            "repo": did,
            "writes": [
                create_item("k2", "second"),
                {
                    "$type": "com.atproto.repo.applyWrites#update",
                    "collection": "app.bsky.feed.post",
                    "rkey": "k1",
                    "value": {"text": "updated"},
                },
                {
                    "$type": "com.atproto.repo.applyWrites#delete",
                    "collection": "app.bsky.feed.post",
                    "rkey": "k2",
                },
            ],
        });
        let resp = app.oneshot(apply_req(body, Some(&token))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Exactly one commit event for the whole batch.
        let FirehoseEvent::Commit(event) = rx.try_recv().expect("batch must emit one commit event")
        else {
            panic!("expected a #commit event");
        };
        assert!(
            rx.try_recv().is_err(),
            "a batch must produce a single commit event, not one per write"
        );
        assert_eq!(event.repo, did);
        assert_eq!(event.ops.len(), 3);

        let actions: Vec<OpAction> = event.ops.iter().map(|o| o.action).collect();
        assert_eq!(
            actions,
            vec![OpAction::Create, OpAction::Update, OpAction::Delete]
        );
        // Create/update carry a CID + value; delete carries neither.
        assert_eq!(event.ops[0].rkey, "k2");
        assert!(event.ops[0].cid.is_some());
        assert_eq!(
            event.ops[0].value,
            Some(serde_json::json!({"text": "second", "createdAt": "2026-06-25T00:00:00Z"}))
        );
        assert_eq!(event.ops[1].rkey, "k1");
        assert_eq!(
            event.ops[1].value,
            Some(serde_json::json!({"text": "updated"}))
        );
        assert_eq!(event.ops[2].rkey, "k2");
        assert_eq!(event.ops[2].cid, None);
        assert!(!event.blocks.is_empty());
    }

    #[tokio::test]
    async fn apply_writes_swap_commit_mismatch_returns_409() {
        let (state, did) = setup().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);
        let body = serde_json::json!({
            "repo": did,
            "swapCommit": "bafyreialwaysdifferentcommitcidthatwillnevermatch00000000000",
            "writes": [create_item("k1", "hi")],
        });
        let resp = app.oneshot(apply_req(body, Some(&token))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn apply_writes_nonexistent_account_returns_404() {
        let state = state_with_master_key().await;
        let did = "did:plc:nosuchaccount".to_string();
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);
        let body = serde_json::json!({ "repo": did, "writes": [create_item("k1", "hi")] });
        let resp = app.oneshot(apply_req(body, Some(&token))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
