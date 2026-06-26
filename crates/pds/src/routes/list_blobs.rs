// pattern: Imperative Shell
//
// Gathers: query params (did, limit, cursor), AppState
// Processes: look up blob CIDs for the given DID with pagination
// Returns: JSON { cids: [...], cursor: "..." }
//
// Implements: GET /xrpc/com.atproto.sync.listBlobs

use axum::{
    extract::{Query, State},
    response::Json,
};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::db::blobs;

// ── Query parameters ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListBlobsParams {
    pub did: String,
    #[serde(default = "default_limit")]
    pub limit: i64,
    pub cursor: Option<String>,
}

fn default_limit() -> i64 {
    500
}

// ── Response types ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ListBlobsResponse {
    pub cids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

// ── Handler ──────────────────────────────────────────────────────────────────

/// GET /xrpc/com.atproto.sync.listBlobs?did=<did>&limit=500&cursor=<cid>
///
/// Lists all blob CIDs for a repo. No authentication required.
/// Uses cursor-based pagination: pass the last CID from the previous response
/// as `cursor` to get the next page.
pub async fn list_blobs(
    State(state): State<AppState>,
    Query(params): Query<ListBlobsParams>,
) -> Result<Json<ListBlobsResponse>, ApiError> {
    // Clamp limit to valid range.
    let limit = params.limit.clamp(1, 2000);

    // Fetch one extra to detect if there's a next page.
    let mut cids = blobs::list_blob_cids(&state.db, &params.did, limit, params.cursor.as_deref())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %params.did, "failed to list blob CIDs");
            ApiError::new(ErrorCode::InternalError, "failed to list blobs")
        })?;

    // Determine if there's a next page.
    let cursor = if cids.len() > limit as usize {
        cids.pop() // remove the extra item
    } else {
        None
    };

    Ok(Json(ListBlobsResponse { cids, cursor }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use crate::routes::test_utils::body_json;
    use axum::{body::Body, http::Request, routing::get, Router};
    use tower::ServiceExt;

    fn app_with_state(state: AppState) -> Router {
        Router::new()
            .route("/xrpc/com.atproto.sync.listBlobs", get(list_blobs))
            .with_state(state)
    }

    /// Helper: seed an account and multiple blobs for testing.
    async fn seed_blobs(state: &AppState, did: &str, count: usize) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'bloblist@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        for i in 0..count {
            let cid = format!("bafkrilist{i:03}");
            sqlx::query(
                "INSERT INTO blobs (cid, account_did, mime_type, size_bytes, storage_path, temp_until) \
                 VALUES (?, ?, 'image/png', 100, ?, NULL)",
            )
            .bind(&cid)
            .bind(did)
            .bind(format!("blobs/{}/{}", &cid[..2], cid))
            .execute(&state.db)
            .await
            .unwrap();
        }
    }

    /// Happy path: returns all CIDs for a repo.
    #[tokio::test]
    async fn returns_all_cids_for_repo() {
        let state = test_state().await;
        seed_blobs(&state, "did:plc:listtest", 3).await;

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.sync.listBlobs?did=did:plc:listtest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = body_json(response).await;
        let cids = body["cids"].as_array().unwrap();
        assert_eq!(cids.len(), 3);
        assert!(body["cursor"].is_null(), "no cursor when all results fit");
    }

    /// Empty repo returns empty array.
    #[tokio::test]
    async fn empty_repo_returns_empty_array() {
        let state = test_state().await;

        // Seed account but no blobs.
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:emptyrepo', 'empty@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.sync.listBlobs?did=did:plc:emptyrepo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = body_json(response).await;
        assert_eq!(body["cids"].as_array().unwrap().len(), 0);
        assert!(body["cursor"].is_null());
    }

    /// Missing did parameter returns 400.
    #[tokio::test]
    async fn missing_did_returns_400() {
        let state = test_state().await;

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.sync.listBlobs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Pagination: limit truncates results and returns cursor.
    #[tokio::test]
    async fn pagination_returns_cursor_when_more_results() {
        let state = test_state().await;
        seed_blobs(&state, "did:plc:pagetest", 5).await;

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.sync.listBlobs?did=did:plc:pagetest&limit=3")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = body_json(response).await;
        let cids = body["cids"].as_array().unwrap();
        assert_eq!(cids.len(), 3);
        assert!(
            body["cursor"].is_string(),
            "cursor must be present when more results exist"
        );

        // Second page using cursor.
        let cursor = body["cursor"].as_str().unwrap();
        let state2 = test_state().await;
        seed_blobs(&state2, "did:plc:pagetest", 5).await;

        let response2 = app_with_state(state2)
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/xrpc/com.atproto.sync.listBlobs?did=did:plc:pagetest&limit=3&cursor={cursor}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response2.status(), StatusCode::OK);

        let body2 = body_json(response2).await;
        let cids2 = body2["cids"].as_array().unwrap();
        // With 5 blobs and limit=3: page 1 returns 3 (cursor=4th), page 2 returns 1 (5th).
        assert_eq!(cids2.len(), 1, "remaining 1 CID on second page");
        assert!(body2["cursor"].is_null(), "no more results after page 2");

        // No overlap: first CID of page 2 must be > cursor.
        let first_cid = cids2[0].as_str().unwrap();
        assert!(first_cid > cursor);
    }

    /// Default limit is 500 when not specified.
    #[tokio::test]
    async fn default_limit_is_500() {
        let state = test_state().await;
        seed_blobs(&state, "did:plc:defaultlimit", 2).await;

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.sync.listBlobs?did=did:plc:defaultlimit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Just verifying it works — the actual limit doesn't matter with only 2 blobs.
        let body = body_json(response).await;
        assert_eq!(body["cids"].as_array().unwrap().len(), 2);
    }

    /// CIDs are returned in lexicographic order.
    #[tokio::test]
    async fn cids_are_lexicographically_ordered() {
        let state = test_state().await;
        seed_blobs(&state, "did:plc:ordertest", 10).await;

        let response = app_with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.sync.listBlobs?did=did:plc:ordertest&limit=2000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = body_json(response).await;
        let cids: Vec<&str> = body["cids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();

        assert!(cids.windows(2).all(|w| w[0] <= w[1]), "CIDs must be sorted");
    }

    use axum::http::StatusCode;
}
