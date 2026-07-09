// pattern: Imperative Shell
//
// Gathers: admin Bearer token (Authorization header), account DID (path), DB pool, config quota
// Processes: auth check → account lookup (404 if absent) → aggregate blob storage metrics
// Returns: JSON blob storage metrics on success; ApiError on all failure paths

//! GET /v1/accounts/:id/storage - Operator blob-storage metrics for an account.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Serialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::require_admin_token;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LargestBlob {
    cid: String,
    size: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageResponse {
    /// Number of blobs stored for the account.
    blob_count: i64,
    /// Total bytes occupied by those blobs.
    total_bytes: i64,
    /// The per-account storage quota in bytes (`[blobs] max_storage_per_account`). Tiers are
    /// not yet differentiated in v0.1, so every account reports the same configured quota.
    quota_bytes: i64,
    /// `total_bytes` as a percentage of `quota_bytes` (0.0 when the quota is 0).
    quota_used_pct: f64,
    /// The account's largest blob, or `null` when it has none.
    largest_blob: Option<LargestBlob>,
}

/// GET /v1/accounts/:id/storage
///
/// Operator-only blob-storage metrics for the provisioning dashboard. `:id` is the account
/// DID. Reports on the account regardless of activation state. Requires the admin Bearer token.
pub async fn account_storage(
    State(state): State<AppState>,
    Path(did): Path<String>,
    headers: HeaderMap,
) -> Result<Json<StorageResponse>, ApiError> {
    // Auth first so an unauthenticated caller cannot probe which DIDs exist.
    require_admin_token(&headers, &state)?;

    // Existence check (operator view: deactivated accounts still report storage).
    crate::db::accounts::get_account_overview(&state.db, &did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to load account overview");
            ApiError::new(ErrorCode::InternalError, "failed to load account storage")
        })?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    let (blob_count, total_bytes) = crate::db::blobs::account_blob_metrics(&state.db, &did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to load blob metrics");
            ApiError::new(ErrorCode::InternalError, "failed to load account storage")
        })?;

    let largest_blob = crate::db::blobs::account_largest_blob(&state.db, &did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to load largest blob");
            ApiError::new(ErrorCode::InternalError, "failed to load account storage")
        })?
        .map(|(cid, size)| LargestBlob { cid, size });

    // Quota is u64 in config; clamp into i64 for the JSON number (1 GiB default is far below
    // i64::MAX, and an operator would not set a quota anywhere near it).
    let quota_bytes = i64::try_from(state.config.blobs.max_storage_per_account).unwrap_or(i64::MAX);

    let quota_used_pct = if quota_bytes > 0 {
        (total_bytes as f64 / quota_bytes as f64) * 100.0
    } else {
        0.0
    };

    Ok(Json(StorageResponse {
        blob_count,
        total_bytes,
        quota_bytes,
        quota_used_pct,
        largest_blob,
    }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
    use tower::ServiceExt;

    use crate::routes::test_utils::{body_json, test_state_with_admin_token};

    const ADMIN: &str = "test-admin-token";

    async fn get_storage(
        app: &axum::Router,
        did: &str,
        token: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/v1/accounts/{did}/storage"));
        if let Some(token) = token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        let resp = app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    async fn insert_account(db: &sqlx::SqlitePool, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(db)
        .await
        .unwrap();
    }

    async fn insert_blob(db: &sqlx::SqlitePool, did: &str, cid: &str, size: i64) {
        crate::db::blobs::insert_blob(
            db,
            cid,
            did,
            "image/jpeg",
            size,
            &format!("blobs/xx/{cid}"),
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn missing_token_returns_401() {
        let state = test_state_with_admin_token().await;
        let app = crate::app::app(state);
        let (status, _) = get_storage(&app, "did:plc:whoever", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn nonexistent_account_returns_404() {
        let state = test_state_with_admin_token().await;
        let app = crate::app::app(state);
        let (status, body) = get_storage(&app, "did:plc:ghost", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn account_without_blobs_reports_zeroes_and_null_largest() {
        let state = test_state_with_admin_token().await;
        let did = "did:plc:storagenoblobs";
        insert_account(&state.db, did).await;
        let quota = state.config.blobs.max_storage_per_account as i64;
        let app = crate::app::app(state);

        let (status, body) = get_storage(&app, did, Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["blobCount"], 0);
        assert_eq!(body["totalBytes"], 0);
        assert_eq!(body["quotaBytes"], quota);
        assert_eq!(body["quotaUsedPct"], 0.0);
        assert!(body["largestBlob"].is_null());
    }

    #[tokio::test]
    async fn aggregates_blob_metrics_and_largest() {
        let state = test_state_with_admin_token().await;
        let did = "did:plc:storageblobs";
        insert_account(&state.db, did).await;
        insert_blob(&state.db, did, "bafblobsmall", 100).await;
        insert_blob(&state.db, did, "bafblobbig", 900).await;
        let quota = state.config.blobs.max_storage_per_account as i64;
        let app = crate::app::app(state);

        let (status, body) = get_storage(&app, did, Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["blobCount"], 2);
        assert_eq!(body["totalBytes"], 1000);
        assert_eq!(body["largestBlob"]["cid"], "bafblobbig");
        assert_eq!(body["largestBlob"]["size"], 900);

        let expected_pct = (1000.0 / quota as f64) * 100.0;
        assert!((body["quotaUsedPct"].as_f64().unwrap() - expected_pct).abs() < 1e-9);
    }

    #[tokio::test]
    async fn blobs_scoped_to_requested_account() {
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:storageowner").await;
        insert_account(&state.db, "did:plc:storageother").await;
        insert_blob(&state.db, "did:plc:storageowner", "bafowner", 50).await;
        insert_blob(&state.db, "did:plc:storageother", "bafother", 5000).await;
        let app = crate::app::app(state);

        let (status, body) = get_storage(&app, "did:plc:storageowner", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["blobCount"], 1);
        assert_eq!(body["totalBytes"], 50);
        assert_eq!(body["largestBlob"]["cid"], "bafowner");
    }
}
