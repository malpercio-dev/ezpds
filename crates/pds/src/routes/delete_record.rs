// pattern: Imperative Shell

//! com.atproto.repo.deleteRecord - Delete a record from a repository.

use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::lexicon::LexiconInput;
use common::{ApiError, ErrorCode};

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
    method: Method,
    uri: Uri,
    headers: axum::http::HeaderMap,
    LexiconInput(body): LexiconInput<DeleteRecordBody>,
) -> Result<impl IntoResponse, ApiError> {
    // Resolve the at-identifier (DID or handle) to a DID before the ownership check and write.
    let did = crate::record_write::resolve_repo_did(&state, &body.repo).await?;
    let authorized = crate::record_write::authorize(&state, &headers, &method, &uri, &did)?;
    let collection = &body.collection;
    let rkey = &body.rkey;

    repo_engine::validate_record_path(collection, rkey)
        .map_err(|_| ApiError::new(ErrorCode::InvalidClaim, "invalid collection or record key"))?;
    authorized.require_repo(collection, crate::auth::oauth_scopes::RepoAction::Delete)?;

    let mut locked = authorized.lock(&state).await?;
    let mst_key = format!("{collection}/{rkey}");

    // Enforce explicit swapCommit/swapRecord preconditions before anything else, so a stale
    // client fails with InvalidSwap rather than the delete silently succeeding (including the
    // idempotent no-op path below, where a mismatched swapRecord must still be a hard error).
    let swap = crate::record_write::SwapCheck {
        commit: body.swap_commit.clone(),
        record: body.swap_record.clone().map(Some),
    };
    locked.enforce_swap(&swap, &mst_key).await?;

    // Idempotent: if the record is already absent, succeed without a new commit. The current CID,
    // read before the delete mutates the repo, doubles as the firehose op's Sync v1.1 `prev` (the
    // previous record CID for this delete).
    let prev_cid = repo_engine::get_record_cid(&mut locked.repo, &mst_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to read record");
            ApiError::new(ErrorCode::InternalError, "failed to delete record")
        })?;
    if prev_cid.is_none() {
        return Ok((StatusCode::OK, axum::Json(serde_json::json!({}))));
    }

    let signer = locked.signer(&state).await?;
    repo_engine::delete_record(&mut locked.repo, &signer, &mst_key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, key = %mst_key, "failed to delete record");
            ApiError::new(ErrorCode::InternalError, "failed to delete record")
        })?;

    let op = crate::firehose::RepoOp {
        action: crate::firehose::OpAction::Delete,
        collection: collection.clone(),
        rkey: rkey.clone(),
        cid: None,
        // The removed record's CID is this delete's previous record CID.
        prev: prev_cid.map(|c| c.to_string()),
        value: None,
    };
    locked.commit(&state, vec![op]).await?;

    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use tower::ServiceExt;

    use crate::routes::test_utils::{
        access_jwt, cnf_bound_access_jwt, delete_record_request, put_record_request,
        scoped_access_jwt, seed_account_with_repo, state_with_master_key, DpopProofKey,
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
    async fn delete_record_dpop_bound_token_as_bearer_returns_401() {
        // A DPoP-bound token (cnf.jkt present) presented as plain `Bearer` with no proof is the
        // RFC 9449 binding downgrade; deleteRecord must reject it, matching the extractor.
        let state = state_with_master_key().await;
        let did = "did:plc:delrec".to_string();
        seed_account_with_repo(&state.db, &did).await;
        let dpop_key = DpopProofKey::generate();
        let token = cnf_bound_access_jwt(&state.jwt_secret, &did, &dpop_key.thumbprint());
        let app = crate::app::app(state);
        let resp = app
            .oneshot(delete_req(&did, "t1", Some(&token)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a cnf.jkt-bound token presented as plain Bearer must be rejected on deleteRecord"
        );
    }

    #[tokio::test]
    async fn delete_record_valid_dpop_bound_request_succeeds() {
        // The same bound token under the DPoP scheme with a valid proof passes auth; deleting an
        // absent record is the idempotent 200 path, reached only after auth — so a 200 proves the
        // standalone handler threads the request method/URI into proof validation correctly.
        let state = state_with_master_key().await;
        let did = "did:plc:delrec".to_string();
        seed_account_with_repo(&state.db, &did).await;
        let dpop_key = DpopProofKey::generate();
        let token = cnf_bound_access_jwt(&state.jwt_secret, &did, &dpop_key.thumbprint());
        let htu = format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            state.config.public_url
        );
        let proof = dpop_key.proof("POST", &htu, &token);
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.deleteRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("DPoP {token}"))
            .header("DPoP", proof)
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "absent"
                }))
                .unwrap(),
            ))
            .unwrap();

        let resp = app.oneshot(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
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
        assert_eq!(json["error"], "InsufficientScope");
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
        assert_eq!(json["error"], "InvalidSwap");
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
        assert_eq!(json["error"], "InvalidSwap");
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
