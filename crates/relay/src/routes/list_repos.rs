// pattern: Imperative Shell

//! com.atproto.sync.listRepos - List all repositories hosted on this PDS.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::Repository;

const DEFAULT_LIMIT: i64 = 500;
const MAX_LIMIT: i64 = 1000;

#[derive(Deserialize)]
pub struct ListReposParams {
    limit: Option<i64>,
    cursor: Option<String>,
}

/// GET /xrpc/com.atproto.sync.listRepos?limit=500&cursor=<did>
///
/// Enumerate every repo hosted on this PDS, in DID order, with cursor-based pagination.
/// Each entry carries the repo `head` (commit CID), its `rev`, and whether the account is
/// `active`. This lets a BGS/relay discover and crawl every repo. No authentication
/// required (public data).
pub async fn list_repos(
    State(state): State<AppState>,
    Query(params): Query<ListReposParams>,
) -> Result<impl IntoResponse, ApiError> {
    // Clamp the page size to the documented bounds (default 500, max 1000, min 1).
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    // The cursor is the last DID returned by the previous page; "" yields the first page
    // because every DID sorts strictly after the empty string.
    let cursor = params.cursor.as_deref().unwrap_or("");

    let rows = crate::db::accounts::list_repos(&state.db, cursor, limit)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to list repos");
            ApiError::new(ErrorCode::InternalError, "failed to list repos")
        })?;

    // A full page means more rows may follow — surface the last DID as the next cursor.
    // A short page is the last page, so no cursor is emitted.
    let next_cursor = (rows.len() as i64 == limit)
        .then(|| rows.last().map(|r| r.did.clone()))
        .flatten();

    let mut repos = Vec::with_capacity(rows.len());
    for row in rows {
        let rev = read_repo_rev(&state, &row.did, &row.head).await?;
        repos.push(serde_json::json!({
            "did": row.did,
            "head": row.head,
            "rev": rev,
            "active": row.active,
        }));
    }

    let mut body = serde_json::json!({ "repos": repos });
    if let Some(cursor) = next_cursor {
        body["cursor"] = serde_json::Value::String(cursor);
    }

    Ok((StatusCode::OK, axum::Json(body)).into_response())
}

/// Open `did`'s repo at `head` and return its commit revision (`rev`).
///
/// The rev is not stored in the accounts table; it lives in the signed commit block, so
/// reading it means opening the repo. A parse/open failure is an internal error — the head
/// CID came from our own database and must always resolve to a valid commit block.
async fn read_repo_rev(state: &AppState, did: &str, head: &str) -> Result<String, ApiError> {
    let root_cid = repo_engine::Cid::try_from(head).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID in database");
        ApiError::new(ErrorCode::InternalError, "failed to list repos")
    })?;

    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to list repos")
    })?;

    Ok(repo.commit().rev().as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use tower::ServiceExt;

    use crate::routes::test_utils::{body_json, seed_account_with_repo, state_with_master_key};

    async fn list(app: &axum::Router, query: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/xrpc/com.atproto.sync.listRepos{query}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(request).await.unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    #[tokio::test]
    async fn lists_repos_with_head_rev_and_active() {
        let state = state_with_master_key().await;
        let did = "did:plc:listrepostest";
        seed_account_with_repo(&state.db, did).await;
        let expected_head: String =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&state.db)
                .await
                .unwrap();
        let app = crate::app::app(state);

        let (status, body) = list(&app, "").await;
        assert_eq!(status, StatusCode::OK);

        let repos = body["repos"].as_array().unwrap();
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0]["did"], did);
        assert_eq!(repos[0]["head"], expected_head);
        assert_eq!(repos[0]["active"], true);
        // The rev is the commit's TID — a non-empty 13-char string.
        assert!(repos[0]["rev"].as_str().unwrap().len() == 13);
        // No cursor on a short (final) page.
        assert!(body.get("cursor").is_none());
    }

    #[tokio::test]
    async fn empty_pds_returns_empty_list() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let (status, body) = list(&app, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["repos"].as_array().unwrap().len(), 0);
        assert!(body.get("cursor").is_none());
    }

    #[tokio::test]
    async fn deactivated_account_reports_active_false() {
        let state = state_with_master_key().await;
        let did = "did:plc:listreposdeactivated";
        seed_account_with_repo(&state.db, did).await;
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let app = crate::app::app(state);

        let (status, body) = list(&app, "").await;
        assert_eq!(status, StatusCode::OK);
        let repos = body["repos"].as_array().unwrap();
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0]["did"], did);
        assert_eq!(repos[0]["active"], false);
    }

    #[tokio::test]
    async fn account_without_repo_is_excluded() {
        let state = state_with_master_key().await;
        // Account row with no repo_root_cid (genesis never created) must not appear —
        // head/rev would be undefined.
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'norepo@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .bind("did:plc:listreposnorepo")
        .execute(&state.db)
        .await
        .unwrap();
        let app = crate::app::app(state);

        let (status, body) = list(&app, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["repos"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn paginates_with_cursor() {
        let state = state_with_master_key().await;
        // Three repos with deterministic DID ordering: a < b < c.
        for did in [
            "did:plc:listreposa",
            "did:plc:listreposb",
            "did:plc:listreposc",
        ] {
            seed_account_with_repo(&state.db, did).await;
        }
        let app = crate::app::app(state);

        // First page of 2: a full page, so a cursor is returned.
        let (status, page1) = list(&app, "?limit=2").await;
        assert_eq!(status, StatusCode::OK);
        let repos1 = page1["repos"].as_array().unwrap();
        assert_eq!(repos1.len(), 2);
        assert_eq!(repos1[0]["did"], "did:plc:listreposa");
        assert_eq!(repos1[1]["did"], "did:plc:listreposb");
        let cursor = page1["cursor"].as_str().unwrap();
        assert_eq!(cursor, "did:plc:listreposb");

        // Second page: the remaining repo, no further cursor.
        let (status, page2) = list(&app, &format!("?limit=2&cursor={cursor}")).await;
        assert_eq!(status, StatusCode::OK);
        let repos2 = page2["repos"].as_array().unwrap();
        assert_eq!(repos2.len(), 1);
        assert_eq!(repos2[0]["did"], "did:plc:listreposc");
        assert!(page2.get("cursor").is_none());
    }

    #[tokio::test]
    async fn limit_is_clamped_to_minimum_one() {
        let state = state_with_master_key().await;
        for did in ["did:plc:listrepclampa", "did:plc:listrepclampb"] {
            seed_account_with_repo(&state.db, did).await;
        }
        let app = crate::app::app(state);

        // limit=0 clamps to 1 — exactly one repo, and a cursor since the page is full.
        let (status, body) = list(&app, "?limit=0").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["repos"].as_array().unwrap().len(), 1);
        assert_eq!(body["cursor"], "did:plc:listrepclampa");
    }
}
