// pattern: Imperative Shell

//! com.atproto.repo.createRecord - Create a new record in a repository.

use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::lexicon::LexiconInput;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
pub struct CreateRecordBody {
    /// The repo to write to, as an at-identifier — a DID (e.g. "did:plc:abc123") or a
    /// registered handle. A handle is resolved to its owning DID before the write.
    repo: String,
    /// The NSID of the record collection (e.g. "app.bsky.feed.post").
    collection: String,
    /// Optional record key. Auto-generated TID if not provided or empty.
    rkey: Option<String>,
    /// The record data as a JSON object.
    record: serde_json::Value,
    /// `swapCommit`: when present, only write if the repo head matches this commit CID.
    /// `createRecord`'s lexicon defines no `swapRecord` — create-only semantics already
    /// require the target key to be absent.
    #[serde(default, rename = "swapCommit")]
    swap_commit: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateRecordResponse {
    uri: String,
    cid: String,
}

/// POST /xrpc/com.atproto.repo.createRecord
///
/// Create a new record in the repository. If `rkey` is not provided, a TID is auto-generated
/// (an explicit empty string is rejected by the lexicon layer, matching the reference PDS).
/// Returns 409 if the rkey already exists.
pub async fn create_record(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(body): LexiconInput<CreateRecordBody>,
) -> Result<impl IntoResponse, ApiError> {
    // Resolve the at-identifier (DID or handle) to a DID before the ownership check and write.
    let did = crate::record_write::resolve_repo_did(&state, &body.repo).await?;
    let collection = &body.collection;
    // Treat empty string as "absent" — generate a TID.
    let rkey = body
        .rkey
        .filter(|r| !r.is_empty())
        .unwrap_or_else(repo_engine::generate_tid);

    // Reject a malformed collection/rkey before touching the repo.
    repo_engine::validate_record_path(collection, &rkey)
        .map_err(|_| ApiError::new(ErrorCode::InvalidClaim, "invalid collection or record key"))?;

    let mst_key = format!("{collection}/{rkey}");

    // `swapCommit` is the only precondition createRecord's lexicon carries; create-only
    // semantics stand in for the record-absent check `swapRecord: null` would express.
    let swap = crate::record_write::SwapCheck {
        commit: body.swap_commit,
        record: None,
    };

    // Delegate to the shared write helper with create_only=true.
    let record_cid = crate::record_write::write_record(
        &state,
        &headers,
        &method,
        &uri,
        &did,
        &mst_key,
        &body.record,
        true, // create_only: reject if record already exists
        &swap,
    )
    .await?;

    let uri = format!("at://{did}/{collection}/{rkey}");
    Ok((
        axum::http::StatusCode::OK,
        axum::Json(CreateRecordResponse {
            uri,
            cid: record_cid.to_string(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
    use tower::ServiceExt;

    use crate::routes::test_utils::{
        access_jwt, cnf_bound_access_jwt, seed_account_with_repo, state_with_master_key,
        DpopProofKey,
    };

    async fn setup_account_with_repo() -> (AppState, String) {
        let state = state_with_master_key().await;
        let did = "did:plc:createrecordtest".to_string();
        seed_account_with_repo(&state.db, &did).await;
        (state, did)
    }

    #[tokio::test]
    async fn create_record_without_auth_returns_401() {
        let (state, did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "record": {"text": "hello"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_record_wrong_did_returns_403() {
        let (state, did) = setup_account_with_repo().await;
        let other_token = access_jwt(&state.jwt_secret, "did:plc:someoneelse");
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {other_token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "record": {"text": "hello"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_record_dpop_bound_token_as_bearer_returns_401() {
        // A DPoP-bound access token (cnf.jkt present) presented as plain `Bearer` with no proof
        // is the RFC 9449 binding downgrade — a stolen token used without its key. The write path
        // must reject it exactly as the AuthenticatedUser extractor does, not accept it.
        let (state, did) = setup_account_with_repo().await;
        let dpop_key = DpopProofKey::generate();
        let token = cnf_bound_access_jwt(&state.jwt_secret, &did, &dpop_key.thumbprint());
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "record": {"text": "must not land"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "a cnf.jkt-bound token presented as plain Bearer must be rejected on createRecord"
        );
    }

    #[tokio::test]
    async fn create_record_valid_dpop_bound_request_succeeds() {
        // The positive counterpart: the same bound token, presented under the DPoP scheme with a
        // valid proof whose htm/htu match this request, is accepted — proving the handler threads
        // the request method/URI into proof validation correctly.
        let (state, did) = setup_account_with_repo().await;
        let dpop_key = DpopProofKey::generate();
        let token = cnf_bound_access_jwt(&state.jwt_secret, &did, &dpop_key.thumbprint());
        let htu = format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            state.config.public_url
        );
        let proof = dpop_key.proof("POST", &htu, &token);
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("DPoP {token}"))
            .header("DPoP", proof)
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "dpopok",
                    "record": {"text": "written under dpop"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Regression: a simulated `repo_seq` insert failure must not leave a committed
    /// repo-root advance without a corresponding durable firehose row. Dropping the `repo_seq`
    /// table makes the sequencer's insert fail with a real DB error; the whole write transaction
    /// (which now also carries the repo-root CAS) must roll back, so the write fails outright and
    /// the repo root is left exactly where it was — not advanced with a silently-dropped event.
    #[tokio::test]
    async fn create_record_rolls_back_the_repo_root_advance_when_the_firehose_insert_fails() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);

        let root_before: String =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
                .bind(&did)
                .fetch_one(&state.db)
                .await
                .unwrap();

        // Simulate a sequencer write failure: the `repo_seq` insert inside the same transaction
        // as the repo-root CAS now fails with a real DB error.
        sqlx::query("DROP TABLE repo_seq")
            .execute(&state.db)
            .await
            .unwrap();

        let app = crate::app::app(state.clone());
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "shouldnotland",
                    "record": {"text": "hi"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a failed firehose insert must fail the whole write, not silently drop the event"
        );

        let root_after: String =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
                .bind(&did)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(
            root_before, root_after,
            "the repo-root CAS must have rolled back along with the failed firehose insert"
        );
    }

    #[tokio::test]
    async fn create_record_with_explicit_rkey_returns_uri_and_cid() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let record = serde_json::json!({
            "text": "Hello, ATProto!",
            "createdAt": "2026-06-22T00:00:00Z"
        });

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "mykey1",
                    "record": record
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: CreateRecordResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(resp.uri, format!("at://{did}/app.bsky.feed.post/mykey1"));
        assert!(!resp.cid.is_empty());
    }

    #[tokio::test]
    async fn create_record_resolves_handle_to_did() {
        // `repo` accepts an at-identifier: a handle pointing at the account must resolve to the
        // owning DID, and the response AT-URI must carry that resolved DID (not the handle).
        let (state, did) = setup_account_with_repo().await;
        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("alice.example.com")
            .bind(&did)
            .execute(&state.db)
            .await
            .unwrap();
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": "alice.example.com",
                    "collection": "app.bsky.feed.post",
                    "rkey": "viahandle",
                    "record": {"text": "hello via handle"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: CreateRecordResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.uri, format!("at://{did}/app.bsky.feed.post/viahandle"));
    }

    #[tokio::test]
    async fn create_record_unknown_handle_returns_400() {
        // An identifier that is neither a DID nor a registered handle is a clean 400 — and the
        // resolution failure surfaces before auth, so no token is needed to exercise it.
        let (state, _did) = setup_account_with_repo().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": "nobody.example.com",
                    "collection": "app.bsky.feed.post",
                    "record": {"text": "hello"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_record_on_deactivated_account_returns_403() {
        let (state, did) = setup_account_with_repo().await;
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind(&did)
            .execute(&state.db)
            .await
            .unwrap();
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "record": {"text": "should be rejected"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a deactivated account must not be able to write records"
        );
    }

    #[tokio::test]
    async fn create_record_on_deactivated_account_without_repo_returns_403() {
        // A deactivated account that never created a repo (repo_root_cid NULL) must report the
        // deactivation (403), not be misclassified as a missing account (404).
        let state = state_with_master_key().await;
        let did = "did:plc:deactnorepo".to_string();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at, deactivated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'), '2026-01-01T00:00:00Z')",
        )
        .bind(&did)
        .bind("deactnorepo@example.com")
        .execute(&state.db)
        .await
        .unwrap();
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "record": {"text": "should be rejected"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a deactivated account with no repo must be 403, not 404"
        );
    }

    #[tokio::test]
    async fn create_record_auto_generates_tid() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "record": {"text": "auto rkey"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: CreateRecordResponse = serde_json::from_slice(&body).unwrap();

        // URI should contain a 13-char TID as the rkey.
        let parts: Vec<&str> = resp.uri.split('/').collect();
        let auto_rkey = parts.last().unwrap();
        assert_eq!(
            auto_rkey.len(),
            13,
            "auto-generated rkey should be a 13-char TID"
        );
        assert!(
            auto_rkey
                .chars()
                .all(|c| "234567abcdefghijklmnopqrstuvwxyz".contains(c)),
            "auto-generated rkey should use base32-sortable chars"
        );
        assert!(!resp.cid.is_empty());
    }

    #[tokio::test]
    async fn create_record_absent_rkey_generates_tid() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "record": {"text": "absent rkey"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: CreateRecordResponse = serde_json::from_slice(&body).unwrap();

        // Should have auto-generated a TID, not failed with 400.
        let parts: Vec<&str> = resp.uri.split('/').collect();
        let auto_rkey = parts.last().unwrap();
        assert_eq!(auto_rkey.len(), 13);
    }

    /// An explicit empty-string rkey used to be treated as "absent" — a Custos-only leniency.
    /// The lexicon layer now rejects it like the reference PDS (`record-key` format, ≥1 char).
    #[tokio::test]
    async fn create_record_empty_rkey_returns_400() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "",
                    "record": {"text": "empty rkey"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "InvalidRequest");
        assert_eq!(
            body["error"]["message"],
            "Input/rkey must be a valid Record Key"
        );
    }

    #[tokio::test]
    async fn create_record_duplicate_rkey_returns_409() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let record = serde_json::json!({
            "text": "first version",
            "createdAt": "2026-06-22T00:00:00Z"
        });

        // Create the record first.
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "duplicate1",
                    "record": record
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Try to create again with the same rkey — should fail with 409.
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "duplicate1",
                    "record": {"text": "second version"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn create_record_invalid_collection_returns_400() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "notanid",
                    "record": {"text": "x"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_record_with_float_returns_400() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        // Floats are not part of the ATProto data model.
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "record": {"score": 1.5}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_record_nonexistent_account_returns_404() {
        let state = crate::app::test_state().await;
        let token = access_jwt(&state.jwt_secret, "did:plc:nonexistent");
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": "did:plc:nonexistent",
                    "collection": "app.bsky.feed.post",
                    "record": {"text": "test"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_record_retrievable_via_get_record() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        let record = serde_json::json!({
            "text": "Created and retrievable",
            "createdAt": "2026-06-22T00:00:00Z"
        });

        // Create the record.
        let create_request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "retrievable1",
                    "record": record
                }))
                .unwrap(),
            ))
            .unwrap();

        let create_response = app.clone().oneshot(create_request).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::OK);

        // Now retrieve it via getRecord.
        let get_request = Request::builder()
            .method(http::Method::GET)
            .uri(format!(
                "/xrpc/com.atproto.repo.getRecord?did={did}&collection=app.bsky.feed.post&rkey=retrievable1"
            ))
            .body(Body::empty())
            .unwrap();

        let get_response = app.oneshot(get_request).await.unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(get_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            resp["uri"],
            format!("at://{did}/app.bsky.feed.post/retrievable1")
        );
        assert_eq!(resp["value"]["text"], "Created and retrievable");
    }

    #[tokio::test]
    async fn create_record_emits_firehose_commit_event() {
        use crate::firehose::FirehoseEvent;

        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        // Subscribe before issuing the write so the event is captured.
        let mut rx = state.firehose.subscribe();
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "fire1",
                    "record": {"text": "to the firehose"}
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: CreateRecordResponse = serde_json::from_slice(&body).unwrap();

        let FirehoseEvent::Commit(event) = rx.try_recv().expect("a commit event must be emitted")
        else {
            panic!("expected a #commit event");
        };
        assert_eq!(event.seq, 1, "first commit gets sequence 1");
        assert_eq!(event.repo, did);
        assert!(!event.commit.is_empty());
        assert!(!event.rev.is_empty());
        // One create op, matching the record we wrote.
        assert_eq!(event.ops.len(), 1);
        let op = &event.ops[0];
        assert_eq!(op.action, crate::firehose::OpAction::Create);
        assert_eq!(op.collection, "app.bsky.feed.post");
        assert_eq!(op.rkey, "fire1");
        assert_eq!(op.cid.as_deref(), Some(resp.cid.as_str()));
        assert_eq!(
            op.value,
            Some(serde_json::json!({"text": "to the firehose"}))
        );
        assert_eq!(
            op.at_uri(&did),
            format!("at://{did}/app.bsky.feed.post/fire1")
        );
        // The CAR diff carries the new commit as its root.
        assert!(
            !event.blocks.is_empty(),
            "commit event must carry CAR blocks"
        );
        let car = atrium_repo::blockstore::CarStore::open(std::io::Cursor::new(&event.blocks))
            .await
            .expect("blocks must be a valid CAR");
        let roots: Vec<_> = car.roots().collect();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].to_string(), event.commit);
    }

    #[tokio::test]
    async fn consecutive_commits_carry_chained_prev_data() {
        // Sync v1.1 inductive validation: each commit's `prevData` must be the MST root (`data`)
        // of the commit it supersedes. Across two consecutive writes, commit N+1's `prevData` must
        // equal commit N's MST root, and the first write's `prevData` the seeded genesis root's.
        use crate::firehose::FirehoseEvent;

        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let db = state.db.clone();
        let mut rx = state.firehose.subscribe();
        let app = crate::app::app(state);

        // The repo head (a genesis commit) before either write: its MST root is the first
        // write's expected `prevData`.
        let genesis_head: String =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
                .bind(&did)
                .fetch_one(&db)
                .await
                .unwrap();
        let mst_root = |cid: String| {
            let db = db.clone();
            let did = did.clone();
            async move {
                let store = crate::db::blocks::SqliteBlockStore::new(db, did);
                let cid = repo_engine::Cid::try_from(cid.as_str()).unwrap();
                let repo = repo_engine::Repository::open(store, cid).await.unwrap();
                repo.commit().data().to_string()
            }
        };
        let genesis_data = mst_root(genesis_head).await;

        let write = |rkey: &str| {
            let token = token.clone();
            let did = did.clone();
            Request::builder()
                .method(http::Method::POST)
                .uri("/xrpc/com.atproto.repo.createRecord")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "repo": did,
                        "collection": "app.bsky.feed.post",
                        "rkey": rkey,
                        "record": {"text": rkey}
                    }))
                    .unwrap(),
                ))
                .unwrap()
        };

        // First write, then capture commit 1's MST root *before* the second write — post-commit GC
        // reclaims the superseded commit's blocks, so commit 1's root is only readable while it is
        // still the repo head.
        let r1 = app.clone().oneshot(write("one")).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        let FirehoseEvent::Commit(c1) = rx.try_recv().expect("first commit") else {
            panic!("expected a #commit event");
        };
        assert_eq!(
            c1.prev_data.as_deref(),
            Some(genesis_data.as_str()),
            "first commit's prevData must be the genesis MST root"
        );
        let c1_data = mst_root(c1.commit.clone()).await;

        let r2 = app.oneshot(write("two")).await.unwrap();
        assert_eq!(r2.status(), StatusCode::OK);
        let FirehoseEvent::Commit(c2) = rx.try_recv().expect("second commit") else {
            panic!("expected a #commit event");
        };
        // Second write supersedes the first: its prevData is commit 1's MST root, and its `since`
        // the first commit's rev.
        assert_eq!(
            c2.prev_data.as_deref(),
            Some(c1_data.as_str()),
            "second commit's prevData must be the first commit's MST root"
        );
        assert_eq!(c2.since.as_deref(), Some(c1.rev.as_str()));
    }

    #[tokio::test]
    async fn create_record_swap_commit_stale_returns_invalid_swap() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let app = crate::app::app(state);

        // A bogus commit CID never matches the head → 409 InvalidSwap.
        let bogus = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "swapstale",
                    "record": {"text": "should not land"},
                    "swapCommit": bogus
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "InvalidSwap");
    }

    #[tokio::test]
    async fn create_record_swap_commit_matching_head_succeeds() {
        let (state, did) = setup_account_with_repo().await;
        let token = access_jwt(&state.jwt_secret, &did);
        let db = state.db.clone();
        let app = crate::app::app(state);

        // Read the current repo head, then create with swapCommit = head → succeeds.
        let head = crate::db::accounts::get_repo_root_cid(&db, &did)
            .await
            .unwrap()
            .unwrap();
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": "swapmatch",
                    "record": {"text": "lands"},
                    "swapCommit": head
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn generate_tid_produces_valid_format() {
        let tid = repo_engine::generate_tid();
        let alphabet = "234567abcdefghijklmnopqrstuvwxyz";
        assert_eq!(tid.len(), 13);
        assert!(
            tid.chars().all(|c| alphabet.contains(c)),
            "TID should use base32-sortable alphabet"
        );
        // First char must be in [234567abcdefghij]
        assert!(
            "234567abcdefghij".contains(tid.chars().next().unwrap()),
            "first TID char must be in valid range"
        );
    }

    #[test]
    fn generate_tids_are_monotonically_increasing() {
        let tid1 = repo_engine::generate_tid();
        // Small delay to ensure different timestamp.
        std::thread::sleep(std::time::Duration::from_micros(100));
        let tid2 = repo_engine::generate_tid();
        assert!(tid1 < tid2, "TIDs should be monotonically increasing");
    }
}
