// pattern: Imperative Shell

//! com.atproto.sync.listRepos - List all repositories hosted on this PDS.

use axum::extract::{Query, State};
use axum::response::Json;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use common::{ApiError, ErrorCode};

const DEFAULT_LIMIT: i64 = 500;
const MAX_LIMIT: i64 = 1000;

#[derive(Deserialize)]
pub struct ListReposParams {
    limit: Option<i64>,
    cursor: Option<String>,
}

/// A single repo entry in the `listRepos` response.
#[derive(Serialize)]
pub struct RepoEntry {
    pub did: String,
    /// The repo's current commit CID (its `head`).
    pub head: String,
    /// The commit revision (TID), read from the signed commit block.
    pub rev: String,
    /// `false` when the account is deactivated, suspended, or taken down.
    pub active: bool,
}

#[derive(Serialize)]
pub struct ListReposResponse {
    pub repos: Vec<RepoEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
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
) -> Result<Json<ListReposResponse>, ApiError> {
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
    // A short page is the last page, so no cursor is emitted. The cursor is derived from the
    // DB rows (not the emitted entries), so a skipped bad repo still advances pagination and
    // the next page resumes past it rather than re-examining it.
    let next_cursor = (rows.len() as i64 == limit)
        .then(|| rows.last().map(|r| r.did.clone()))
        .flatten();

    let mut repos = Vec::with_capacity(rows.len());
    for row in rows {
        // The rev is normally stored on the account row (written at every commit), so the
        // common path is a pure column read with no repo open. Pre-migration accounts have
        // no stored rev: fall back to reading it from the commit block. A single unreadable
        // repo — e.g. an interrupted write that set `repo_root_cid` before the commit block
        // landed — must not 500 the whole enumeration, so skip it and keep paging.
        let rev = match row.rev {
            Some(rev) => rev,
            None => match crate::repo_rev::read_repo_rev(&state, &row.did, &row.head).await {
                Some(rev) => rev,
                None => continue,
            },
        };
        repos.push(RepoEntry {
            did: row.did,
            head: row.head,
            rev,
            active: row.active,
        });
    }

    Ok(Json(ListReposResponse {
        repos,
        cursor: next_cursor,
    }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
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
    async fn taken_down_or_suspended_account_reports_active_false() {
        // A moderation takedown or suspension must drop `active` to false in listRepos just as a
        // deactivation does — relays key on this to stop serving the repo.
        let state = state_with_master_key().await;
        for (did, column) in [
            ("did:plc:listrepostakendown", "taken_down_at"),
            ("did:plc:listrepossuspended", "suspended_at"),
        ] {
            seed_account_with_repo(&state.db, did).await;
            // Fixed SQL per column (never interpolated) so the query stays static.
            let sql = match column {
                "taken_down_at" => {
                    "UPDATE accounts SET taken_down_at = datetime('now') WHERE did = ?"
                }
                "suspended_at" => {
                    "UPDATE accounts SET suspended_at = datetime('now') WHERE did = ?"
                }
                other => panic!("unsupported lifecycle column: {other}"),
            };
            sqlx::query(sql).bind(did).execute(&state.db).await.unwrap();
        }
        let app = crate::app::app(state);

        let (status, body) = list(&app, "").await;
        assert_eq!(status, StatusCode::OK);
        let repos = body["repos"].as_array().unwrap();
        assert_eq!(repos.len(), 2);
        for repo in repos {
            assert_eq!(
                repo["active"], false,
                "taken-down/suspended repo {} must report active=false",
                repo["did"]
            );
        }
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
    async fn unreadable_repo_is_skipped_not_fatal() {
        let state = state_with_master_key().await;
        // One healthy repo and one whose repo_root_cid points at a commit block that was
        // never written (a valid CIDv1, but absent from `blocks`). The bad repo must be
        // skipped, not turn the whole page into a 500.
        seed_account_with_repo(&state.db, "did:plc:listreposhealthy").await;
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, repo_root_cid, created_at, updated_at) \
             VALUES (?, 'bad@example.com', 'hash', ?, datetime('now'), datetime('now'))",
        )
        .bind("did:plc:listreposbad")
        .bind("bafyreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
        .execute(&state.db)
        .await
        .unwrap();
        let app = crate::app::app(state);

        let (status, body) = list(&app, "").await;
        assert_eq!(status, StatusCode::OK);
        let repos = body["repos"].as_array().unwrap();
        assert_eq!(repos.len(), 1, "only the healthy repo should be returned");
        assert_eq!(repos[0]["did"], "did:plc:listreposhealthy");
    }

    #[tokio::test]
    async fn legacy_null_rev_falls_back_to_commit_block() {
        let state = state_with_master_key().await;
        // A pre-migration account: repo blocks exist and repo_root_cid is set, but repo_rev
        // was never populated. listRepos must still report the rev, read from the commit.
        let did = "did:plc:listreposlegacy";
        seed_account_with_repo(&state.db, did).await;
        let expected_rev: String =
            sqlx::query_scalar("SELECT repo_rev FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&state.db)
                .await
                .unwrap();
        sqlx::query("UPDATE accounts SET repo_rev = NULL WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let app = crate::app::app(state);

        let (status, body) = list(&app, "").await;
        assert_eq!(status, StatusCode::OK);
        let repos = body["repos"].as_array().unwrap();
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0]["rev"], expected_rev);
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
