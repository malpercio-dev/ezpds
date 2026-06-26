// pattern: Imperative Shell

//! com.atproto.sync.getRepo - Export a repository as a CAR file.

use axum::body::{Body, Bytes};
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::Cid;

#[derive(Deserialize)]
pub struct GetRepoParams {
    did: String,
    /// Incremental export: when set, return only the blocks introduced *after* this revision
    /// (TID), so a consumer holding the repo as of `since` catches up without re-downloading it.
    /// Omitted → the full repo.
    since: Option<String>,
}

/// GET /xrpc/com.atproto.sync.getRepo?did=<did>&since=<rev>
///
/// Streams the ATProto repository as a CARv1 file. The CAR root is the signed commit CID.
/// Without `since` the file is the full repo (commit block, all MST nodes, all record blocks);
/// with `since=<rev>` it carries only the blocks newer than that revision (plus the commit block,
/// so the declared root is always present), which a consumer applies on top of its existing state
/// to reach the current root. The body is streamed block-by-block rather than buffered, so a large
/// repo never materializes the whole CAR in memory.
pub async fn get_repo(
    State(state): State<AppState>,
    Query(params): Query<GetRepoParams>,
) -> Result<Response, ApiError> {
    let did = &params.did;

    // Validate DID format.
    if !crate::auth::validation::is_valid_did(did) {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    // Look up the repo root CID from the accounts table.
    let root_cid_str = crate::db::accounts::get_repo_root_cid(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to query repo root CID");
            ApiError::new(ErrorCode::InternalError, "failed to get repo")
        })?;

    let root_cid_str =
        root_cid_str.ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    let root_cid = Cid::try_from(root_cid_str.as_str()).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID in database");
        ApiError::new(ErrorCode::InternalError, "failed to get repo")
    })?;

    // Resolve the ordered set of block CIDs to export. Only CIDs are held in memory here; the
    // block *bytes* (the bulk) are read lazily one at a time while streaming the response.
    //
    // An empty `?since=` is treated as omitted (full export), not as the revision `""`: the latter
    // would route through the incremental path and, since `rev > ''` matches every tagged block,
    // return a near-full repo while silently dropping any NULL-rev block — a misleading "delta".
    let since = params.since.as_deref().filter(|s| !s.is_empty());
    let cids = match since {
        // Full export: every block reachable from the current commit.
        None => {
            let mut store = SqliteBlockStore::new(state.db.clone(), did.to_string());
            repo_engine::collect_reachable_cids(&mut store, root_cid)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, did = %did, "failed to collect repo blocks");
                    ApiError::new(ErrorCode::InternalError, "failed to get repo")
                })?
        }
        // Incremental export: blocks newer than `since`, plus the commit block so the CAR always
        // contains its declared root (matters when `since` is at or ahead of the current rev).
        Some(since) => {
            let cid_strs = crate::db::blocks::list_block_cids_since(&state.db, did, since)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, did = %did, "failed to list blocks since rev");
                    ApiError::new(ErrorCode::InternalError, "failed to get repo")
                })?;
            let mut cids: Vec<Cid> = Vec::with_capacity(cid_strs.len() + 1);
            for s in &cid_strs {
                cids.push(Cid::try_from(s.as_str()).map_err(|e| {
                    tracing::error!(error = %e, did = %did, cid = %s, "invalid block CID in database");
                    ApiError::new(ErrorCode::InternalError, "failed to get repo")
                })?);
            }
            if !cids.contains(&root_cid) {
                cids.push(root_cid);
            }
            cids
        }
    };

    Ok(stream_car_response(state, did.to_string(), root_cid, cids))
}

/// Build a streaming `application/vnd.ipld.car` response: the CARv1 header followed by one
/// length-prefixed frame per CID, each block's bytes read from the store as the frame is emitted.
///
/// Bounds memory to a single block at a time. If a block is missing when its turn comes — a
/// concurrent GC reclaimed it mid-stream — the stream ends with an error frame rather than
/// silently emitting a truncated, internally-inconsistent CAR.
fn stream_car_response(state: AppState, did: String, root: Cid, cids: Vec<Cid>) -> Response {
    // Deterministic, root-first order: many CARv1 parsers expect the declared root block first.
    let mut cids = cids;
    cids.sort_unstable_by_key(|c| (*c != root, *c));

    struct CarStream {
        pool: sqlx::SqlitePool,
        did: String,
        root: Cid,
        cids: Vec<Cid>,
        next: usize,
        header_sent: bool,
    }

    let init = CarStream {
        pool: state.db.clone(),
        did,
        root,
        cids,
        next: 0,
        header_sent: false,
    };

    let stream = futures_util::stream::unfold(init, |mut st| async move {
        if !st.header_sent {
            st.header_sent = true;
            let header = repo_engine::car_v1_header(st.root);
            return Some((Ok::<Bytes, std::io::Error>(Bytes::from(header)), st));
        }
        if st.next >= st.cids.len() {
            return None;
        }
        let cid = st.cids[st.next];
        st.next += 1;
        match crate::db::blocks::get_block(&st.pool, &cid.to_string()).await {
            Ok(Some(block)) => {
                let frame = repo_engine::car_v1_block_frame(cid, &block.bytes);
                Some((Ok(Bytes::from(frame)), st))
            }
            Ok(None) => {
                tracing::warn!(did = %st.did, cid = %cid, "block missing mid-export (concurrent GC?)");
                st.next = st.cids.len(); // stop after this error frame
                let err = std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "block missing during repo export",
                );
                Some((Err(err), st))
            }
            Err(e) => {
                tracing::error!(error = %e, did = %st.did, cid = %cid, "failed to read block during export");
                st.next = st.cids.len();
                let err = std::io::Error::other("failed to read repo block");
                Some((Err(err), st))
            }
        }
    });

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/vnd.ipld.car")],
        Body::from_stream(stream),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use tower::ServiceExt;

    use crate::db::blocks::SqliteBlockStore;
    use repo_engine::{create_genesis_repo, CommitSigner};

    /// Helper: generate a test keypair and signer.
    fn test_signer() -> (crypto::P256Keypair, CommitSigner) {
        let kp = crypto::generate_p256_keypair().expect("keypair");
        let signer = CommitSigner::from_bytes(&kp.private_key_bytes).expect("signer");
        (kp, signer)
    }

    /// Helper: create a test account with a genesis repo and return the state + DID.
    async fn setup_account_with_repo() -> (AppState, String) {
        let state = crate::app::test_state().await;

        // Insert a test account.
        let did = "did:plc:getrepotest";
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'getrepo@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        // Create genesis repo.
        let (_kp, signer) = test_signer();
        let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
        let cid = create_genesis_repo(block_store, did, &signer)
            .await
            .unwrap();

        // Store root CID.
        let cid_str = cid.to_string();
        sqlx::query("UPDATE accounts SET repo_root_cid = ? WHERE did = ?")
            .bind(&cid_str)
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();

        (state, did.to_string())
    }

    #[tokio::test]
    async fn get_repo_returns_car_with_correct_content_type() {
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/xrpc/com.atproto.sync.getRepo?did={did}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "application/vnd.ipld.car"
        );
    }

    #[tokio::test]
    async fn get_repo_returns_non_empty_car_bytes() {
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/xrpc/com.atproto.sync.getRepo?did={did}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // CAR header + at least one block.
        assert!(
            body.len() > 10,
            "CAR should have header + blocks, got {} bytes",
            body.len()
        );
    }

    #[tokio::test]
    async fn get_repo_nonexistent_account_returns_404() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/xrpc/com.atproto.sync.getRepo?did=did:plc:nonexistent")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_repo_invalid_did_returns_400() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/xrpc/com.atproto.sync.getRepo?did=not-a-did")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_repo_car_root_matches_commit_cid() {
        let (state, did) = setup_account_with_repo().await;

        // Get the expected root CID from the DB.
        let expected_root: String =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
                .bind(&did)
                .fetch_one(&state.db)
                .await
                .unwrap();

        let app = crate::app::app(state);
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/xrpc/com.atproto.sync.getRepo?did={did}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Parse the CAR using CarStore to verify the root CID.
        use atrium_repo::blockstore::CarStore;
        let car = CarStore::open(std::io::Cursor::new(body.as_ref()))
            .await
            .expect("parse CAR");
        let roots: Vec<_> = car.roots().collect();

        assert_eq!(roots.len(), 1, "CAR must have exactly one root");
        assert_eq!(
            roots[0].to_string(),
            expected_root,
            "CAR root CID must match the commit CID"
        );
    }

    // ── since (incremental export) ──────────────────────────────────────────────────

    use crate::routes::test_utils::{access_jwt, seed_account_with_repo, state_with_master_key};

    /// Seed a rev-tagged account (genesis blocks carry the genesis rev) and return its DID.
    async fn setup_revtagged_account() -> (AppState, String) {
        let state = state_with_master_key().await;
        let did = "did:plc:getreposince".to_string();
        seed_account_with_repo(&state.db, &did).await;
        (state, did)
    }

    async fn put_post(app: &axum::Router, token: &str, did: &str, rkey: &str) -> StatusCode {
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "/xrpc/com.atproto.repo.putRecord?did={did}&collection=app.bsky.feed.post&rkey={rkey}"
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::json!({ "record": { "text": "hi", "createdAt": "2026-06-26T00:00:00Z" } })
                    .to_string(),
            ))
            .unwrap();
        app.clone().oneshot(request).await.unwrap().status()
    }

    async fn rev_of(state: &AppState, did: &str) -> String {
        sqlx::query_scalar("SELECT repo_rev FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(&state.db)
            .await
            .unwrap()
    }

    async fn since_car_full(app: &axum::Router, did: &str) -> Vec<u8> {
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/xrpc/com.atproto.sync.getRepo?did={did}"))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    async fn since_car(app: &axum::Router, did: &str, since: &str) -> Vec<u8> {
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!(
                "/xrpc/com.atproto.sync.getRepo?did={did}&since={since}"
            ))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/vnd.ipld.car"
        );
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn get_repo_since_delta_applied_on_prior_state_reaches_current_root() {
        use atrium_repo::blockstore::{
            AsyncBlockStoreWrite, CarStore, MemoryBlockStore, DAG_CBOR, SHA2_256,
        };
        use repo_engine::{collect_reachable_cids, AsyncBlockStoreRead, Repository};

        let (state, did) = setup_revtagged_account().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state.clone());

        // Commit A: rec1. Capture the full repo as of A (the consumer's prior state) and its rev —
        // a genesis→first-write delta is the whole repo (GC reclaims the empty genesis blocks), so
        // we need a *second* commit for `since` to be a genuine subset where rec1 carries over.
        assert_eq!(put_post(&app, &token, &did, "rec1").await, StatusCode::OK);
        let rev_a = rev_of(&state, &did).await;
        let root_a: String = sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(&did)
            .fetch_one(&state.db)
            .await
            .unwrap();
        let root_a_cid = Cid::try_from(root_a.as_str()).unwrap();
        let full_a = since_car_full(&app, &did).await;

        // Commit B: rec2.
        assert_eq!(put_post(&app, &token, &did, "rec2").await, StatusCode::OK);
        let root_b: String = sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(&did)
            .fetch_one(&state.db)
            .await
            .unwrap();
        let root_b_cid = Cid::try_from(root_b.as_str()).unwrap();

        let car = since_car(&app, &did, &rev_a).await;
        let mut delta = CarStore::open(std::io::Cursor::new(&car)).await.unwrap();
        assert_eq!(
            delta.roots().collect::<Vec<_>>(),
            vec![root_b_cid],
            "since CAR must declare the current commit (B) as root"
        );

        // Reconstruct the consumer: load its prior state (every block reachable as of A, read out
        // of the full-A CAR) then apply the delta blocks read out of the since CAR.
        let mut mem = MemoryBlockStore::new();
        let mut a_store = CarStore::open(std::io::Cursor::new(&full_a)).await.unwrap();
        let a_cids = collect_reachable_cids(&mut a_store, root_a_cid)
            .await
            .unwrap();
        for cid in &a_cids {
            let mut buf = Vec::new();
            a_store.read_block_into(*cid, &mut buf).await.unwrap();
            mem.write_block(DAG_CBOR, SHA2_256, &buf).await.unwrap();
        }

        // rec1's record block was committed at A; carried over unchanged at B, it must NOT be in
        // the delta (it is not newer than `since`) — the consumer already holds it.
        let rec1_cid = {
            let mut a_repo = Repository::open(&mut a_store, root_a_cid).await.unwrap();
            a_repo
                .tree()
                .get("app.bsky.feed.post/rec1")
                .await
                .unwrap()
                .expect("rec1 present in commit A")
        };
        assert!(
            delta
                .read_block_into(rec1_cid, &mut Vec::new())
                .await
                .is_err(),
            "rec1's block (committed at or before `since`) must not be in the delta CAR"
        );

        let delta_cids: Vec<String> =
            sqlx::query_scalar("SELECT cid FROM blocks WHERE account_did = ? AND rev > ?")
                .bind(&did)
                .bind(&rev_a)
                .fetch_all(&state.db)
                .await
                .unwrap();
        assert!(!delta_cids.is_empty(), "commit B must introduce new blocks");
        for cid_str in &delta_cids {
            let cid = Cid::try_from(cid_str.as_str()).unwrap();
            let mut buf = Vec::new();
            delta
                .read_block_into(cid, &mut buf)
                .await
                .expect("every delta block must be present in the since CAR");
            mem.write_block(DAG_CBOR, SHA2_256, &buf).await.unwrap();
        }

        // Prior state + delta opens at the current root with BOTH records resolvable — proving the
        // delta is sufficient to advance a consumer from A to B without re-downloading rec1.
        let mut repo = Repository::open(mem, root_b_cid)
            .await
            .expect("prior state + delta must open at the current root");
        assert!(
            repo.tree()
                .get("app.bsky.feed.post/rec1")
                .await
                .unwrap()
                .is_some(),
            "rec1 (carried over from before `since`) must resolve"
        );
        assert!(
            repo.tree()
                .get("app.bsky.feed.post/rec2")
                .await
                .unwrap()
                .is_some(),
            "rec2 (committed after `since`) must resolve"
        );
    }

    #[tokio::test]
    async fn get_repo_empty_since_is_treated_as_full_export() {
        use atrium_repo::blockstore::CarStore;
        use repo_engine::AsyncBlockStoreRead;

        // `?since=` (empty) must mean "full repo", NOT the incremental path with `rev > ''` (which
        // would return a near-full repo while silently dropping any NULL-rev block).
        let (state, did) = setup_revtagged_account().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state.clone());

        assert_eq!(put_post(&app, &token, &did, "rec1").await, StatusCode::OK);
        let current_rev = rev_of(&state, &did).await;
        let new_root: String =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
                .bind(&did)
                .fetch_one(&state.db)
                .await
                .unwrap();

        // A non-root block at the current rev — a genuine `since=current` CAR would exclude it.
        let other_block: String = sqlx::query_scalar(
            "SELECT cid FROM blocks WHERE account_did = ? AND rev = ? AND cid != ?",
        )
        .bind(&did)
        .bind(&current_rev)
        .bind(&new_root)
        .fetch_one(&state.db)
        .await
        .unwrap();

        let car = since_car(&app, &did, "").await; // ?since= (empty)
        let mut store = CarStore::open(std::io::Cursor::new(&car)).await.unwrap();
        store
            .read_block_into(
                Cid::try_from(other_block.as_str()).unwrap(),
                &mut Vec::new(),
            )
            .await
            .expect("empty since must yield the FULL repo, including current-rev blocks");
    }

    #[tokio::test]
    async fn get_repo_since_current_rev_carries_only_the_root() {
        use atrium_repo::blockstore::CarStore;
        use repo_engine::AsyncBlockStoreRead;

        let (state, did) = setup_revtagged_account().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state.clone());

        assert_eq!(put_post(&app, &token, &did, "rec1").await, StatusCode::OK);
        let current_rev = rev_of(&state, &did).await;
        let new_root: String =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
                .bind(&did)
                .fetch_one(&state.db)
                .await
                .unwrap();

        let car = since_car(&app, &did, &current_rev).await;
        let mut delta = CarStore::open(std::io::Cursor::new(&car)).await.unwrap();

        // since == current rev: nothing is newer, so the CAR carries only the commit block (so its
        // declared root is still present) and no other block from this revision.
        let mut buf = Vec::new();
        delta
            .read_block_into(Cid::try_from(new_root.as_str()).unwrap(), &mut buf)
            .await
            .expect("the commit block must always be present");

        let other_block: String = sqlx::query_scalar(
            "SELECT cid FROM blocks WHERE account_did = ? AND rev = ? AND cid != ?",
        )
        .bind(&did)
        .bind(&current_rev)
        .bind(&new_root)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert!(
            delta
                .read_block_into(Cid::try_from(other_block.as_str()).unwrap(), &mut buf)
                .await
                .is_err(),
            "no non-root block at the current rev should be in a since=current CAR"
        );
    }
}
