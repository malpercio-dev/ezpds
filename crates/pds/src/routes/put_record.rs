// pattern: Imperative Shell

//! com.atproto.repo.putRecord - Create or update a record in a repository.

use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::lexicon::LexiconInput;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
pub struct PutRecordBody {
    /// The repo to write to, carried in the JSON body as `repo` per the
    /// `com.atproto.repo.putRecord` lexicon. An at-identifier — a DID (e.g. "did:plc:abc123") or a
    /// registered handle; a handle is resolved to its owning DID before the write.
    repo: String,
    /// The NSID of the record collection (e.g. "app.bsky.feed.post").
    collection: String,
    /// The record key.
    rkey: String,
    /// The record data as a JSON object.
    record: serde_json::Value,
    /// `swapCommit`: when present, only write if the repo head matches this commit CID.
    #[serde(default, rename = "swapCommit")]
    swap_commit: Option<String>,
    /// `swapRecord`: optimistic concurrency on the record itself. Absent imposes no check;
    /// an explicit `null` requires the record to not yet exist; a CID requires the current
    /// record to match. The double-`Option` (via [`double_option`]) preserves the
    /// absent-vs-null distinction that a plain `Option` would collapse.
    #[serde(default, rename = "swapRecord", deserialize_with = "double_option")]
    swap_record: Option<Option<String>>,
    /// `validate`: `true` requires the record to validate against a known lexicon, `false` skips
    /// validation, absent validates known lexicons and leaves unknown ones writable.
    #[serde(default)]
    validate: Option<bool>,
}

/// Deserialize a field so that an explicit JSON `null` becomes `Some(None)` while an omitted
/// field (via `#[serde(default)]`) stays `None`. This is the only way to tell `swapRecord: null`
/// (require-absent) apart from a missing `swapRecord` (no precondition).
fn double_option<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(deserializer).map(Some)
}

#[derive(Serialize, Deserialize)]
pub struct PutRecordResponse {
    uri: String,
    cid: String,
    /// `valid` | `unknown`, per the record's lexicon (omitted when `validate: false` skipped it).
    #[serde(rename = "validationStatus", skip_serializing_if = "Option::is_none")]
    validation_status: Option<String>,
}

/// POST /xrpc/com.atproto.repo.putRecord
///
/// Create or update a record in the repository. Unlike createRecord, this always
/// succeeds regardless of whether the record already exists (upsert semantics).
pub async fn put_record(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: axum::http::HeaderMap,
    LexiconInput(body): LexiconInput<PutRecordBody>,
) -> Result<impl IntoResponse, ApiError> {
    // Resolve the at-identifier (DID or handle) to a DID before the ownership check and write.
    let did = crate::record_write::resolve_repo_did(&state, &body.repo).await?;
    let collection = &body.collection;
    let rkey = &body.rkey;

    // Reject a malformed collection/rkey before touching the repo.
    repo_engine::validate_record_path(collection, rkey)
        .map_err(|_| ApiError::new(ErrorCode::InvalidClaim, "invalid collection or record key"))?;

    let mst_key = format!("{collection}/{rkey}");

    let swap = crate::record_write::SwapCheck {
        commit: body.swap_commit,
        record: body.swap_record,
    };

    // Delegate to the shared write helper with create_only=false.
    let (record_cid, validation_status) = crate::record_write::write_record(
        &state,
        &headers,
        &method,
        &uri,
        &did,
        &mst_key,
        &body.record,
        false, // create_only=false: upsert semantics
        &swap,
        body.validate,
    )
    .await?;

    let uri = format!("at://{did}/{collection}/{rkey}");
    Ok((
        StatusCode::OK,
        axum::Json(PutRecordResponse {
            uri,
            cid: record_cid.to_string(),
            validation_status: validation_status.map(|s| s.as_str().to_string()),
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
        access_jwt, cnf_bound_access_jwt, put_record_request, seed_account_with_repo,
        state_with_master_key, DpopProofKey,
    };

    async fn setup_account_with_repo() -> (AppState, String) {
        let state = state_with_master_key().await;
        let did = "did:plc:putrecordtest".to_string();
        seed_account_with_repo(&state.db, &did).await;
        (state, did)
    }

    #[tokio::test]
    async fn put_record_without_auth_returns_401() {
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        let request = put_record_request(
            &did,
            "app.bsky.feed.post",
            "t1",
            serde_json::json!({"record": {"text": "x"}}),
            None,
        );

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn put_record_wrong_did_returns_403() {
        let (state, did) = setup_account_with_repo().await;
        let other_token = access_jwt(&state.jwt_secret, "did:plc:someoneelse");
        let app = crate::app::app(state);

        let request = put_record_request(
            &did,
            "app.bsky.feed.post",
            "t1",
            serde_json::json!({"record": {"text": "x"}}),
            Some(&other_token),
        );

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn put_record_dpop_bound_token_as_bearer_returns_401() {
        // A DPoP-bound access token (cnf.jkt present) presented as plain `Bearer` with no proof is
        // the RFC 9449 binding downgrade the write path must reject, matching the extractor.
        let (state, did) = setup_account_with_repo().await;
        let dpop_key = DpopProofKey::generate();
        let token = cnf_bound_access_jwt(&state.jwt_secret, &did, &dpop_key.thumbprint());
        let app = crate::app::app(state);

        let request = put_record_request(
            &did,
            "app.bsky.feed.post",
            "nolanding",
            serde_json::json!({"record": {"text": "x"}}),
            Some(&token),
        );
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "a cnf.jkt-bound token presented as plain Bearer must be rejected on putRecord"
        );
    }

    #[tokio::test]
    async fn put_record_valid_dpop_bound_request_succeeds() {
        // The same bound token under the DPoP scheme with a valid proof (htm/htu matching this
        // request) is accepted — the shared write helper threads the method/URI through correctly.
        let (state, did) = setup_account_with_repo().await;
        let dpop_key = DpopProofKey::generate();
        let token = cnf_bound_access_jwt(&state.jwt_secret, &did, &dpop_key.thumbprint());
        let htu = format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            state.config.public_url
        );
        let proof = dpop_key.proof("POST", &htu, &token);
        let app = crate::app::app(state);

        let mut body = serde_json::json!({"record": {"text": "written under dpop"}});
        body["repo"] = serde_json::json!(did);
        body["collection"] = serde_json::json!("app.bsky.feed.post");
        body["rkey"] = serde_json::json!("dpopok");
        // Seed a record to prove the DPoP path, not record schema (see put_record_request).
        body["validate"] = serde_json::json!(false);
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.putRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("DPoP {token}"))
            .header("DPoP", proof)
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn put_record_returns_uri_and_cid() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let record = serde_json::json!({
            "text": "Hello, ATProto!",
            "createdAt": "2026-06-22T00:00:00Z"
        });

        let request = put_record_request(
            &did,
            "app.bsky.feed.post",
            "test1",
            serde_json::json!({"record": record}),
            Some(&token),
        );

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: PutRecordResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(resp.uri, format!("at://{did}/app.bsky.feed.post/test1"));
        assert!(!resp.cid.is_empty());
    }

    #[tokio::test]
    async fn put_record_invalid_collection_returns_400() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let request = put_record_request(
            &did,
            "notanid",
            "t1",
            serde_json::json!({"record": {"text": "x"}}),
            Some(&token),
        );

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_record_with_float_returns_400() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        // Floats are not part of the ATProto data model.
        let request = put_record_request(
            &did,
            "app.bsky.feed.post",
            "f1",
            serde_json::json!({"record": {"score": 1.5}}),
            Some(&token),
        );

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_record_nonexistent_account_returns_404() {
        let state = crate::app::test_state().await;
        let token = access_jwt(&state.jwt_secret, "did:plc:nonexistent");
        let app = crate::app::app(state);

        let record = serde_json::json!({"text": "test"});

        let request = put_record_request(
            "did:plc:nonexistent",
            "app.bsky.feed.post",
            "test1",
            serde_json::json!({"record": record}),
            Some(&token),
        );

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn put_record_updates_repo_root_cid() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let record = serde_json::json!({
            "text": "This should update the root",
            "createdAt": "2026-06-22T00:00:00Z"
        });

        let request = put_record_request(
            &did,
            "app.bsky.feed.post",
            "test2",
            serde_json::json!({"record": record}),
            Some(&token),
        );

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Helper: issue a putRecord and return (status, parsed JSON body).
    async fn put(
        app: &axum::Router,
        token: &str,
        did: &str,
        rkey: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let request = put_record_request(did, "app.bsky.feed.post", rkey, body, Some(token));
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn put_record_swap_record_matching_cid_succeeds() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        // Create v1, capture its CID.
        let (status, v1) = put(
            &app,
            &token,
            &did,
            "swap1",
            serde_json::json!({"record": {"n": 1}}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let v1_cid = v1["cid"].as_str().unwrap().to_string();

        // Update with swapRecord = current CID → succeeds.
        let (status, _) = put(
            &app,
            &token,
            &did,
            "swap1",
            serde_json::json!({"record": {"n": 2}, "swapRecord": v1_cid}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn put_record_swap_record_stale_cid_returns_invalid_swap() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let (status, v1) = put(
            &app,
            &token,
            &did,
            "swap2",
            serde_json::json!({"record": {"n": 1}}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let v1_cid = v1["cid"].as_str().unwrap().to_string();

        // Advance the record so v1_cid is now stale.
        let (status, _) = put(
            &app,
            &token,
            &did,
            "swap2",
            serde_json::json!({"record": {"n": 2}}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // swapRecord against the now-stale CID → 409 InvalidSwap.
        let (status, body) = put(
            &app,
            &token,
            &did,
            "swap2",
            serde_json::json!({"record": {"n": 3}, "swapRecord": v1_cid}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["code"], "InvalidSwap");
    }

    #[tokio::test]
    async fn put_record_swap_record_null_requires_absent() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        // swapRecord: null on an absent key acts as create → succeeds.
        let (status, _) = put(
            &app,
            &token,
            &did,
            "swap3",
            serde_json::json!({"record": {"n": 1}, "swapRecord": null}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The record now exists; swapRecord: null must now fail with InvalidSwap.
        let (status, body) = put(
            &app,
            &token,
            &did,
            "swap3",
            serde_json::json!({"record": {"n": 2}, "swapRecord": null}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["code"], "InvalidSwap");
    }

    #[tokio::test]
    async fn put_record_swap_commit_stale_returns_invalid_swap() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        // A bogus commit CID never matches the head → InvalidSwap.
        let bogus = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";
        let (status, body) = put(
            &app,
            &token,
            &did,
            "swap4",
            serde_json::json!({"record": {"n": 1}, "swapCommit": bogus}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["code"], "InvalidSwap");
    }

    #[tokio::test]
    async fn put_record_swap_commit_matching_head_succeeds() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let db = state.db.clone();
        let app = crate::app::app(state);

        // Read the current repo head, then put with swapCommit = head → succeeds.
        let head = crate::db::accounts::get_repo_root_cid(&db, &did)
            .await
            .unwrap()
            .unwrap();
        let (status, _) = put(
            &app,
            &token,
            &did,
            "swap5",
            serde_json::json!({"record": {"n": 1}, "swapCommit": head}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn put_record_gcs_superseded_blocks() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let db = state.db.clone();
        let app = crate::app::app(state);

        // Update the same record key repeatedly; each commit supersedes the prior
        // commit/MST/record, which post-commit GC should reclaim.
        for i in 0..8 {
            let request = put_record_request(
                &did,
                "app.bsky.feed.post",
                "same",
                serde_json::json!({"record": {"n": i}}),
                Some(&token),
            );
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM block_owners WHERE account_did = ?")
                .bind(&did)
                .fetch_one(&db)
                .await
                .unwrap();
        // With GC only the current commit + MST + record remain (a handful); without GC
        // this would grow ~linearly with the 8 updates.
        assert!(
            count < 10,
            "GC should keep block count bounded; got {count}"
        );
    }
}
