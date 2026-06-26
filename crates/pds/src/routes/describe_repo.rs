// pattern: Imperative Shell

//! com.atproto.repo.describeRepo - Return metadata about a repository.

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::Repository;

/// The ATProto sentinel handle used when an account has no valid handle.
const INVALID_HANDLE: &str = "handle.invalid";

#[derive(Deserialize)]
pub struct DescribeRepoParams {
    /// The handle or DID of the repo to describe.
    repo: String,
}

/// GET /xrpc/com.atproto.repo.describeRepo?repo=<handle|did>
///
/// Returns repo metadata: the handle, DID, DID document, the collections currently
/// present in the repo, and whether the handle bidirectionally resolves to the DID.
/// No authentication required (public data).
pub async fn describe_repo(
    State(state): State<AppState>,
    Query(params): Query<DescribeRepoParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Accept either a handle or a DID, mirroring the `at-identifier` the lexicon allows.
    let account = crate::db::accounts::resolve_identifier(&state.db, &params.repo)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "repo not found"))?;
    let did = account.did;

    // Local DID document. For accounts hosted here this is always present; null only
    // for an account whose document was never cached locally.
    let did_doc = crate::db::dids::get_did_document(&state.db, &did)
        .await?
        .unwrap_or(serde_json::Value::Null);

    // The collections present in the repo. A genesis repo (no records) reports none.
    let collections = list_collections(&state, &did).await?;

    // handleIsCorrect: the handle resolves to this DID (it lives in our handles table)
    // *and* the DID document's alsoKnownAs lists `at://<handle>` — a bidirectional match.
    // A missing DID document (`did_doc` is Null) deliberately yields `false`: without a
    // document we cannot confirm the backward link, so an unverifiable handle and a
    // genuine alsoKnownAs mismatch intentionally collapse to the same `false` outcome.
    let (handle, handle_is_correct) = match account.handle {
        Some(handle) => {
            let at_uri = format!("at://{handle}");
            let listed = did_doc
                .get("alsoKnownAs")
                .and_then(|v| v.as_array())
                .is_some_and(|aka| aka.iter().any(|v| v.as_str() == Some(at_uri.as_str())));
            (handle, listed)
        }
        None => (INVALID_HANDLE.to_string(), false),
    };

    Ok(Json(serde_json::json!({
        "handle": handle,
        "did": did,
        "didDoc": did_doc,
        "collections": collections,
        "handleIsCorrect": handle_is_correct,
    })))
}

/// Open the repo and list its distinct collections, returning `[]` when the account
/// has no repo root yet (genesis not created or already empty).
async fn list_collections(state: &AppState, did: &str) -> Result<Vec<String>, ApiError> {
    let root_cid_str = crate::db::accounts::get_repo_root_cid(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to query repo root CID");
            ApiError::new(ErrorCode::InternalError, "failed to describe repo")
        })?;

    let Some(root_cid_str) = root_cid_str else {
        return Ok(Vec::new());
    };

    let root_cid = repo_engine::Cid::try_from(root_cid_str.as_str()).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID in database");
        ApiError::new(ErrorCode::InternalError, "failed to describe repo")
    })?;

    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to describe repo")
    })?;

    repo_engine::list_collections(&mut repo).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to list collections");
        ApiError::new(ErrorCode::InternalError, "failed to describe repo")
    })
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
    use tower::ServiceExt;

    use crate::routes::test_utils::{
        access_jwt, body_json, seed_account_with_repo, seed_did_document, state_with_master_key,
    };

    /// Insert the `handles` row + a DID document whose alsoKnownAs lists the handle.
    async fn seed_handle_and_doc(db: &sqlx::SqlitePool, did: &str, handle: &str) {
        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind(handle)
            .bind(did)
            .execute(db)
            .await
            .unwrap();
        seed_did_document(
            db,
            did,
            serde_json::json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "alsoKnownAs": [format!("at://{handle}")],
                "verificationMethod": [],
                "service": [],
            }),
        )
        .await;
    }

    async fn describe(app: &axum::Router, repo: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/xrpc/com.atproto.repo.describeRepo?repo={repo}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(request).await.unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    async fn put(app: &axum::Router, token: &str, did: &str, collection: &str, rkey: &str) {
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "/xrpc/com.atproto.repo.putRecord?did={did}&collection={collection}&rkey={rkey}"
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({ "record": { "text": "x" } })).unwrap(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn describes_repo_with_handle_did_and_collections() {
        let state = state_with_master_key().await;
        let did = "did:plc:describerepotest";
        seed_account_with_repo(&state.db, did).await;
        seed_handle_and_doc(&state.db, did, "alice.test.example.com").await;
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state);

        put(&app, &token, did, "app.bsky.feed.post", "p1").await;
        put(&app, &token, did, "app.bsky.feed.like", "l1").await;

        let (status, body) = describe(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["did"], did);
        assert_eq!(body["handle"], "alice.test.example.com");
        assert_eq!(body["handleIsCorrect"], true);
        assert_eq!(body["didDoc"]["id"], did);

        // Collections are distinct and lexicographically sorted.
        let collections = body["collections"].as_array().unwrap();
        assert_eq!(
            collections,
            &vec![
                serde_json::json!("app.bsky.feed.like"),
                serde_json::json!("app.bsky.feed.post"),
            ]
        );
    }

    #[tokio::test]
    async fn resolves_by_handle() {
        let state = state_with_master_key().await;
        let did = "did:plc:describebyhandle";
        seed_account_with_repo(&state.db, did).await;
        seed_handle_and_doc(&state.db, did, "bob.test.example.com").await;
        let app = crate::app::app(state);

        let (status, body) = describe(&app, "bob.test.example.com").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["did"], did);
        assert_eq!(body["handle"], "bob.test.example.com");
    }

    #[tokio::test]
    async fn empty_repo_reports_no_collections() {
        let state = state_with_master_key().await;
        let did = "did:plc:describeempty";
        seed_account_with_repo(&state.db, did).await;
        seed_handle_and_doc(&state.db, did, "empty.test.example.com").await;
        let app = crate::app::app(state);

        let (status, body) = describe(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["collections"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn handle_is_incorrect_when_aka_missing() {
        let state = state_with_master_key().await;
        let did = "did:plc:describeakamismatch";
        seed_account_with_repo(&state.db, did).await;
        // Handle present, but the DID document's alsoKnownAs lists a different handle.
        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("real.test.example.com")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        seed_did_document(
            &state.db,
            did,
            serde_json::json!({
                "id": did,
                "alsoKnownAs": ["at://other.test.example.com"],
            }),
        )
        .await;
        let app = crate::app::app(state);

        let (status, body) = describe(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["handle"], "real.test.example.com");
        assert_eq!(body["handleIsCorrect"], false);
    }

    #[tokio::test]
    async fn handle_is_incorrect_when_did_doc_absent() {
        let state = state_with_master_key().await;
        let did = "did:plc:describenodoc";
        seed_account_with_repo(&state.db, did).await;
        // Handle present, but no DID document was ever cached. Without a document we
        // cannot confirm the backward link, so handleIsCorrect is false and didDoc is null.
        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("nodoc.test.example.com")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let app = crate::app::app(state);

        let (status, body) = describe(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["handle"], "nodoc.test.example.com");
        assert!(body["didDoc"].is_null());
        assert_eq!(body["handleIsCorrect"], false);
    }

    #[tokio::test]
    async fn account_without_handle_reports_invalid_handle() {
        let state = state_with_master_key().await;
        let did = "did:plc:describenohandle";
        seed_account_with_repo(&state.db, did).await;
        let app = crate::app::app(state);

        let (status, body) = describe(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["handle"], "handle.invalid");
        assert_eq!(body["handleIsCorrect"], false);
    }

    #[tokio::test]
    async fn nonexistent_repo_returns_404() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let (status, body) = describe(&app, "did:plc:doesnotexist").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "NOT_FOUND");
    }
}
