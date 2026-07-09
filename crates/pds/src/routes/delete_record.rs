// pattern: Imperative Shell

//! com.atproto.repo.deleteRecord - Delete a record from a repository.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::Repository;

#[derive(Deserialize)]
pub struct DeleteRecordBody {
    /// The repo to delete from, carried in the JSON body as `repo` per the
    /// `com.atproto.repo.deleteRecord` lexicon. An at-identifier — a DID (e.g. "did:plc:abc123")
    /// or a registered handle; a handle is resolved to its owning DID before the delete.
    repo: String,
    collection: String,
    rkey: String,
    /// `swapCommit`: when present, only delete if the repo head matches this commit CID.
    #[serde(default, rename = "swapCommit")]
    swap_commit: Option<String>,
    /// `swapRecord`: when present, only delete if the record currently at the key has this CID.
    #[serde(default, rename = "swapRecord")]
    swap_record: Option<String>,
}

/// POST /xrpc/com.atproto.repo.deleteRecord
///
/// Delete a record. Idempotent: deleting a record that does not exist succeeds.
pub async fn delete_record(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<DeleteRecordBody>,
) -> Result<impl IntoResponse, ApiError> {
    // Resolve the at-identifier (DID or handle) to a DID before the ownership check and write.
    let did = crate::record_write::resolve_repo_did(&state, &body.repo).await?;
    let did = did.as_str();
    let collection = &body.collection;
    let rkey = &body.rkey;

    if !crate::auth::validation::is_valid_did(did) {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    // Authenticate: require a valid access token whose subject owns this repo.
    let token = crate::auth::extract_bearer_token(&headers)?;
    let claims = crate::auth::jwt::verify_access_token(token, &state)?;
    let auth_scope = crate::auth::jwt::parse_scope(&claims.scope)?;
    if !auth_scope.is_access() {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }
    if claims.sub != *did {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "authenticated account does not own this repository",
        ));
    }

    repo_engine::validate_record_path(collection, rkey)
        .map_err(|_| ApiError::new(ErrorCode::InvalidClaim, "invalid collection or record key"))?;

    if auth_scope == crate::auth::jwt::AuthScope::Access {
        crate::auth::oauth_scopes::require_repo(
            &claims.scope,
            collection,
            crate::auth::oauth_scopes::RepoAction::Delete,
        )?;
    }

    // Serialize this repo's whole logical write (root read → commit → GC) against concurrent
    // writers — see `record_write::RepoWriteLocks`. Held until this handler returns.
    let _write_guard = state.repo_write_locks.lock(did).await;

    let write_state = crate::db::accounts::get_repo_write_state(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to query repo write state");
            ApiError::new(ErrorCode::InternalError, "failed to delete record")
        })?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    // A deactivated, suspended, or taken-down account is read-only: no writes until reactivated
    // or the moderation action is cleared. Checked right after account existence — before the
    // repo-root lookup — so a non-active account is a 403 even if it never created a repo; only a
    // truly missing account (handled above) is a 404. The CAS below also carries the same
    // lifecycle guard to close the gap between this check and commit.
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
        ApiError::new(ErrorCode::InternalError, "failed to delete record")
    })?;

    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to delete record")
    })?;

    // Capture the pre-delete revision and MST root for the firehose event's `since` and Sync v1.1
    // `prevData` (the previous commit's MST root CID) — both read before the delete mutates the repo.
    let prev_rev = repo.commit().rev().as_str().to_string();
    let prev_data = repo.commit().data().to_string();

    let mst_key = format!("{collection}/{rkey}");

    // Enforce explicit swapCommit/swapRecord preconditions before anything else, so a stale
    // client fails with InvalidSwap rather than the delete silently succeeding (including the
    // idempotent no-op path below, where a mismatched swapRecord must still be a hard error).
    let swap = crate::record_write::SwapCheck {
        commit: body.swap_commit.clone(),
        record: body.swap_record.clone().map(Some),
    };
    crate::record_write::enforce_swap(&swap, &root_cid_str, &mut repo, &mst_key).await?;

    // Idempotent: if the record is already absent, succeed without a new commit. The current CID,
    // read before the delete mutates the repo, doubles as the firehose op's Sync v1.1 `prev` (the
    // previous record CID for this delete).
    let prev_cid = repo_engine::get_record_cid(&mut repo, &mst_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to read record");
            ApiError::new(ErrorCode::InternalError, "failed to delete record")
        })?;
    if prev_cid.is_none() {
        return Ok((StatusCode::OK, axum::Json(serde_json::json!({}))));
    }

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

    repo_engine::delete_record(&mut repo, &signer, &mst_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to delete record");
            ApiError::new(ErrorCode::InternalError, "failed to delete record")
        })?;

    // Advance the root with optimistic concurrency (see putRecord for rationale). The shared
    // helper folds the deactivation guard into the CAS so an account deactivated after the
    // `get_repo_write_state` check above cannot have this delete land, and commits the CAS
    // atomically with the firehose `#commit` event (the diff CAR needs the prior block set, so
    // this must run before GC). This also stamps the commit's blocks with its revision for
    // getRepo?since.
    let new_rev = repo.commit().rev().as_str().to_string();
    let op = crate::firehose::RepoOp {
        action: crate::firehose::OpAction::Delete,
        collection: collection.clone(),
        rkey: rkey.clone(),
        cid: None,
        // The removed record's CID is this delete's previous record CID.
        prev: prev_cid.map(|c| c.to_string()),
        value: None,
    };
    crate::record_write::commit_repo_write(
        &state,
        did,
        root_cid,
        repo.root(),
        new_rev,
        Some(prev_rev),
        Some(prev_data),
        vec![op],
        &root_cid_str,
        claims.registration_id.as_deref(),
    )
    .await?;
    // `commit_repo_write` reclaims this commit's superseded blocks incrementally; no separate
    // full-repo reachability sweep runs on the write path.

    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use crate::routes::test_utils::{
        access_jwt, delete_record_request, put_record_request, seed_account_with_repo,
        state_with_master_key,
    };

    fn delete_req(did: &str, rkey: &str, token: Option<&str>) -> Request<Body> {
        delete_record_request(
            did,
            "app.bsky.feed.post",
            rkey,
            serde_json::json!({}),
            token,
        )
    }

    fn scoped_access_jwt(secret: &[u8; 32], sub: &str, scope: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "scope": scope,
                "sub": sub,
                "iat": now,
                "exp": now + 7200_u64,
            }),
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn delete_record_without_auth_returns_401() {
        let state = state_with_master_key().await;
        let did = "did:plc:delrec".to_string();
        seed_account_with_repo(&state.db, &did).await;
        let app = crate::app::app(state);
        let resp = app.oneshot(delete_req(&did, "t1", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_record_on_deactivated_account_returns_403() {
        let state = state_with_master_key().await;
        let did = "did:plc:delrec".to_string();
        seed_account_with_repo(&state.db, &did).await;
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind(&did)
            .execute(&state.db)
            .await
            .unwrap();
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);
        let resp = app
            .oneshot(delete_req(&did, "t1", Some(&token)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a deactivated account must not be able to delete records"
        );
    }

    /// Helper: create a record via putRecord and return its CID.
    async fn seed_record(app: &axum::Router, token: &str, did: &str, rkey: &str) -> String {
        let request = put_record_request(
            did,
            "app.bsky.feed.post",
            rkey,
            serde_json::json!({"record": {"text": "x"}}),
            Some(token),
        );
        let resp = app.clone().oneshot(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["cid"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn granular_repo_scope_allows_create_post_but_not_delete_follow() {
        let state = state_with_master_key().await;
        let did = "did:plc:delrec".to_string();
        seed_account_with_repo(&state.db, &did).await;
        let token = scoped_access_jwt(
            &state.jwt_secret,
            &did,
            "atproto repo:app.bsky.feed.post?action=create",
        );
        let app = crate::app::app(state);

        let create_post = put_record_request(
            &did,
            "app.bsky.feed.post",
            "scopedpost",
            serde_json::json!({"record": {"text": "allowed"}}),
            Some(&token),
        );
        let created = app.clone().oneshot(create_post).await.unwrap();
        assert_eq!(created.status(), StatusCode::OK);

        let delete_follow = delete_record_request(
            &did,
            "app.bsky.graph.follow",
            "scopedfollow",
            serde_json::json!({}),
            Some(&token),
        );
        let denied = app.oneshot(delete_follow).await.unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(denied.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "InsufficientScope");
    }

    #[tokio::test]
    async fn delete_record_swap_record_matching_cid_succeeds() {
        let state = state_with_master_key().await;
        let did = "did:plc:delrec".to_string();
        seed_account_with_repo(&state.db, &did).await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let cid = seed_record(&app, &token, &did, "d1").await;
        let req = delete_record_request(
            &did,
            "app.bsky.feed.post",
            "d1",
            serde_json::json!({"swapRecord": cid}),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn delete_record_swap_record_stale_cid_returns_invalid_swap() {
        let state = state_with_master_key().await;
        let did = "did:plc:delrec".to_string();
        seed_account_with_repo(&state.db, &did).await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        seed_record(&app, &token, &did, "d2").await;
        // A swapRecord CID that doesn't match the current record → 409 InvalidSwap.
        let bogus = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";
        let req = delete_record_request(
            &did,
            "app.bsky.feed.post",
            "d2",
            serde_json::json!({"swapRecord": bogus}),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "InvalidSwap");
    }

    #[tokio::test]
    async fn delete_record_swap_record_on_absent_returns_invalid_swap() {
        let state = state_with_master_key().await;
        let did = "did:plc:delrec".to_string();
        seed_account_with_repo(&state.db, &did).await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        // swapRecord names a CID, but the record was never written. The swap must be a hard
        // error (current CID is None, expected is Some) rather than the idempotent no-op
        // success that an absent record would otherwise produce.
        let cid = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";
        let req = delete_record_request(
            &did,
            "app.bsky.feed.post",
            "ghost",
            serde_json::json!({"swapRecord": cid}),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "InvalidSwap");
    }

    #[tokio::test]
    async fn delete_record_swap_commit_stale_returns_invalid_swap() {
        let state = state_with_master_key().await;
        let did = "did:plc:delrec".to_string();
        seed_account_with_repo(&state.db, &did).await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        seed_record(&app, &token, &did, "d3").await;
        let bogus = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";
        let req = delete_record_request(
            &did,
            "app.bsky.feed.post",
            "d3",
            serde_json::json!({"swapCommit": bogus}),
            Some(&token),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn delete_record_emits_firehose_delete_op() {
        use crate::firehose::{FirehoseEvent, OpAction};

        let state = state_with_master_key().await;
        let did = "did:plc:delrec".to_string();
        seed_account_with_repo(&state.db, &did).await;
        let token = access_jwt(&state.jwt_secret, &did);
        let firehose = state.firehose.clone();
        let app = crate::app::app(state);

        seed_record(&app, &token, &did, "del1").await;
        // Subscribe after seeding so we only observe the delete commit.
        let mut rx = firehose.subscribe();

        let resp = app
            .oneshot(delete_req(&did, "del1", Some(&token)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let FirehoseEvent::Commit(event) = rx.try_recv().expect("delete must emit a commit event")
        else {
            panic!("expected a #commit event");
        };
        assert_eq!(event.repo, did);
        assert!(event.since.is_some(), "a delete supersedes a prior commit");
        assert_eq!(event.ops.len(), 1);
        let op = &event.ops[0];
        assert_eq!(op.action, OpAction::Delete);
        assert_eq!(op.collection, "app.bsky.feed.post");
        assert_eq!(op.rkey, "del1");
        assert_eq!(op.cid, None, "delete ops carry no record CID");
        assert_eq!(op.value, None);
    }

    #[tokio::test]
    async fn delete_missing_record_is_idempotent() {
        let state = state_with_master_key().await;
        let did = "did:plc:delrec".to_string();
        seed_account_with_repo(&state.db, &did).await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);
        // Nothing was ever written — delete must still succeed.
        let resp = app
            .oneshot(delete_req(&did, "neverexisted", Some(&token)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
