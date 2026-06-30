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
    /// The DID (or handle) of the repo (e.g. "did:plc:abc123"). Per the
    /// `com.atproto.repo.deleteRecord` lexicon this is `repo`, carried in the JSON body.
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
    let did = &body.repo;
    let collection = &body.collection;
    let rkey = &body.rkey;

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

    repo_engine::validate_record_path(collection, rkey)
        .map_err(|_| ApiError::new(ErrorCode::InvalidClaim, "invalid collection or record key"))?;

    let write_state = crate::db::accounts::get_repo_write_state(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to query repo write state");
            ApiError::new(ErrorCode::InternalError, "failed to delete record")
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

    let root_cid = repo_engine::Cid::try_from(root_cid_str.as_str()).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID in database");
        ApiError::new(ErrorCode::InternalError, "failed to delete record")
    })?;

    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to delete record")
    })?;

    // Capture the pre-delete revision for the firehose event's `since`.
    let prev_rev = repo.commit().rev().as_str().to_string();

    let mst_key = format!("{collection}/{rkey}");

    // Enforce explicit swapCommit/swapRecord preconditions before anything else, so a stale
    // client fails with InvalidSwap rather than the delete silently succeeding (including the
    // idempotent no-op path below, where a mismatched swapRecord must still be a hard error).
    let swap = crate::record_write::SwapCheck {
        commit: body.swap_commit.clone(),
        record: body.swap_record.clone().map(Some),
    };
    crate::record_write::enforce_swap(&swap, &root_cid_str, &mut repo, &mst_key).await?;

    // Idempotent: if the record is already absent, succeed without a new commit.
    let existing: Option<serde_json::Value> = repo_engine::get_record(&mut repo, &mst_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to read record");
            ApiError::new(ErrorCode::InternalError, "failed to delete record")
        })?;
    if existing.is_none() {
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
    // `get_repo_write_state` check above cannot have this delete land.
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
        ApiError::new(ErrorCode::InternalError, "failed to delete record")
    })?;
    if !advanced {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "repository was modified concurrently; retry against the current root",
        ));
    }

    // Emit the firehose `#commit` event before GC (the diff CAR needs the prior block set). This
    // also stamps the commit's blocks with its revision for getRepo?since.
    let op = crate::firehose::RepoOp {
        action: crate::firehose::OpAction::Delete,
        collection: collection.clone(),
        rkey: rkey.clone(),
        cid: None,
        value: None,
    };
    crate::record_write::emit_firehose_commit(
        &state,
        did,
        root_cid,
        repo.root(),
        new_rev,
        Some(prev_rev),
        vec![op],
    )
    .await;

    // Best-effort GC: reclaim blocks superseded by this commit (non-fatal on error).
    if let Err(e) = crate::record_write::gc_repo_blocks(&state.db, did, repo.root()).await {
        tracing::warn!(error = %e, did = %did, "post-commit block GC failed (non-fatal)");
    }

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
        delete_record_request(did, "app.bsky.feed.post", rkey, serde_json::json!({}), token)
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
