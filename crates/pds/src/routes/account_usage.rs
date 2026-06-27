// pattern: Imperative Shell
//
// Gathers: admin Bearer token (Authorization header), account DID (path), DB pool
// Processes: auth check → account lookup (404 if absent) → aggregate repo/blob usage
// Returns: JSON usage metrics on success; ApiError on all failure paths

//! GET /v1/accounts/:id/usage - Operator usage metrics for an account.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Serialize;

use common::{ApiError, ErrorCode};
use repo_engine::Repository;

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use crate::routes::auth::require_admin_token;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageResponse {
    /// Total records across every collection in the repo (0 when the repo has none).
    records_count: i64,
    /// Distinct commit revisions still represented among the account's blocks. GC reclaims
    /// superseded blocks, so this is a lower bound on the full commit history, not an exact
    /// total — there is no separate commit log to count.
    commits_count: i64,
    /// Number of blobs stored for the account.
    blobs_count: i64,
    /// Total bytes stored for the account: repo block bytes plus blob bytes.
    storage_bytes: i64,
    /// Most recent repo-block write or blob upload; falls back to the account's creation
    /// time when it has neither.
    last_active: String,
}

/// GET /v1/accounts/:id/usage
///
/// Operator-only account usage metrics for the provisioning dashboard. `:id` is the account
/// DID. Reports on the account regardless of activation state (a deactivated account still
/// has usage figures). Requires the admin Bearer token.
pub async fn account_usage(
    State(state): State<AppState>,
    Path(did): Path<String>,
    headers: HeaderMap,
) -> Result<Json<UsageResponse>, ApiError> {
    // Auth first so an unauthenticated caller cannot probe which DIDs exist.
    require_admin_token(&headers, &state)?;

    let overview = crate::db::accounts::get_account_overview(&state.db, &did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to load account overview");
            ApiError::new(ErrorCode::InternalError, "failed to load account usage")
        })?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;

    let block_stats = crate::db::blocks::account_block_stats(&state.db, &did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to load block stats");
            ApiError::new(ErrorCode::InternalError, "failed to load account usage")
        })?;

    let (blobs_count, blob_bytes) = crate::db::blobs::account_blob_metrics(&state.db, &did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to load blob metrics");
            ApiError::new(ErrorCode::InternalError, "failed to load account usage")
        })?;

    let last_active = crate::db::accounts::account_last_active(&state.db, &did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to load last active");
            ApiError::new(ErrorCode::InternalError, "failed to load account usage")
        })?
        .unwrap_or(overview.created_at);

    let records_count = count_records(&state, &did, overview.repo_root_cid.as_deref()).await?;

    Ok(Json(UsageResponse {
        records_count,
        commits_count: block_stats.commit_count,
        blobs_count,
        storage_bytes: block_stats.total_bytes + blob_bytes,
        last_active,
    }))
}

/// Open the repo and count its records, returning 0 when the account has no repo root yet.
async fn count_records(
    state: &AppState,
    did: &str,
    root_cid_str: Option<&str>,
) -> Result<i64, ApiError> {
    let Some(root_cid_str) = root_cid_str else {
        return Ok(0);
    };

    let root_cid = repo_engine::Cid::try_from(root_cid_str).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID in database");
        ApiError::new(ErrorCode::InternalError, "failed to load account usage")
    })?;

    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to load account usage")
    })?;

    let count = repo_engine::count_records(&mut repo).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to count records");
        ApiError::new(ErrorCode::InternalError, "failed to load account usage")
    })?;

    Ok(count as i64)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
    use tower::ServiceExt;

    use crate::routes::test_utils::{
        access_jwt, body_json, seed_account_with_repo, test_state_with_admin_token,
    };

    const ADMIN: &str = "test-admin-token";

    async fn get_usage(
        app: &axum::Router,
        did: &str,
        token: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/v1/accounts/{did}/usage"));
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

    /// State with both the admin token and the signing-key master key (the latter so
    /// `seed_account_with_repo` / record writes can sign commits).
    async fn admin_state_with_repo_support() -> crate::app::AppState {
        let base = crate::routes::test_utils::state_with_master_key().await;
        let mut config = (*base.config).clone();
        config.admin_token = Some(ADMIN.to_string());
        crate::app::AppState {
            config: std::sync::Arc::new(config),
            ..base
        }
    }

    async fn put_record(app: &axum::Router, token: &str, did: &str, collection: &str, rkey: &str) {
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
    async fn missing_token_returns_401() {
        let state = test_state_with_admin_token().await;
        let app = crate::app::app(state);
        let (status, _) = get_usage(&app, "did:plc:whoever", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_token_returns_401() {
        let state = test_state_with_admin_token().await;
        let app = crate::app::app(state);
        let (status, _) = get_usage(&app, "did:plc:whoever", Some("nope")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn nonexistent_account_returns_404() {
        let state = test_state_with_admin_token().await;
        let app = crate::app::app(state);
        let (status, body) = get_usage(&app, "did:plc:ghost", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn empty_repo_reports_zero_records_and_one_commit() {
        let state = admin_state_with_repo_support().await;
        let did = "did:plc:usageempty";
        seed_account_with_repo(&state.db, did).await;
        let app = crate::app::app(state);

        let (status, body) = get_usage(&app, did, Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["recordsCount"], 0);
        // The genesis commit tagged its blocks with one rev.
        assert_eq!(body["commitsCount"], 1);
        assert_eq!(body["blobsCount"], 0);
        // Genesis blocks occupy some bytes.
        assert!(body["storageBytes"].as_i64().unwrap() > 0);
        assert!(body["lastActive"].as_str().unwrap().ends_with('Z'));
    }

    #[tokio::test]
    async fn counts_records_across_collections() {
        let state = admin_state_with_repo_support().await;
        let did = "did:plc:usagerecords";
        seed_account_with_repo(&state.db, did).await;
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state);

        put_record(&app, &token, did, "app.bsky.feed.post", "p1").await;
        put_record(&app, &token, did, "app.bsky.feed.post", "p2").await;
        put_record(&app, &token, did, "app.bsky.feed.like", "l1").await;

        let (status, body) = get_usage(&app, did, Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["recordsCount"], 3);
    }

    #[tokio::test]
    async fn account_without_repo_reports_zero_usage() {
        let state = test_state_with_admin_token().await;
        let did = "did:plc:usagenorrepo";
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(&state.db)
        .await
        .unwrap();
        let app = crate::app::app(state);

        let (status, body) = get_usage(&app, did, Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["recordsCount"], 0);
        assert_eq!(body["commitsCount"], 0);
        assert_eq!(body["blobsCount"], 0);
        assert_eq!(body["storageBytes"], 0);
        // No repo, no blobs → last_active falls back to the account creation time.
        assert!(!body["lastActive"].as_str().unwrap().is_empty());
    }
}
