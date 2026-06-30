// pattern: Imperative Shell

//! com.atproto.sync.getLatestCommit - Report the current commit CID and rev for a repo.

use axum::extract::{Query, State};
use axum::response::Json;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::Repository;

#[derive(Deserialize)]
pub struct GetLatestCommitParams {
    did: String,
}

#[derive(Serialize)]
pub struct GetLatestCommitResponse {
    /// The repo's current commit CID (its `head`).
    pub cid: String,
    /// The commit revision (TID), read from the signed commit block.
    pub rev: String,
}

/// GET /xrpc/com.atproto.sync.getLatestCommit?did=<did>
///
/// Return the repo's current commit `cid` and `rev`. Unlike `getRepoStatus` — which reports an
/// account even before its repo exists — `getLatestCommit` requires a commit: a DID with no repo
/// (or one that does not exist) is a 404. Lifecycle is not considered: a deactivated, suspended,
/// or taken-down repo still has a last-known commit and reports it, matching `getRepoStatus`'s
/// `rev`. No authentication required (public data).
pub async fn sync_get_latest_commit(
    State(state): State<AppState>,
    Query(params): Query<GetLatestCommitParams>,
) -> Result<Json<GetLatestCommitResponse>, ApiError> {
    let did = &params.did;

    // Validate DID format, mirroring the other sync endpoints.
    if !crate::auth::validation::is_valid_did(did) {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    let row = crate::db::accounts::get_repo_status(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to query latest commit");
            ApiError::new(ErrorCode::InternalError, "failed to get latest commit")
        })?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "repo not found"))?;

    // A commit must exist. An account that never created its repo has no head, so it is a 404
    // here (whereas `getRepoStatus` would still report it with `rev` omitted).
    let head = row
        .head
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "repo not found"))?;

    // The response contract guarantees a well-formed commit `cid`, so validate the stored repo
    // root up front — even on the fast path below, where the rev is read straight from the
    // column without opening the repo. A malformed `repo_root_cid` (which the production write
    // paths never produce) is reported as a clean 404 rather than a 200 carrying a bogus cid,
    // matching the unreadable-head behavior of `read_repo_rev`.
    repo_engine::Cid::try_from(head.as_str()).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID in database");
        ApiError::new(ErrorCode::NotFound, "repo not found")
    })?;

    // Prefer the rev stored on the account row (written at every commit) — the common path is a
    // pure column read. A pre-migration account has a repo root but no stored rev: read it from
    // the commit block. A head whose commit block is missing/unreadable cannot yield a latest
    // commit, so it is reported as not found rather than as a 500.
    let rev = match row.rev {
        Some(rev) => rev,
        None => read_repo_rev(&state, did, &head)
            .await
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "repo not found"))?,
    };

    Ok(Json(GetLatestCommitResponse { cid: head, rev }))
}

/// Open `did`'s repo at `head` and return its commit revision (`rev`), or `None` if the
/// repo cannot be read.
///
/// The rev lives in the signed commit block, so reading it means opening the repo. A
/// parse/open failure (bad CID, missing block) yields `None`: the caller maps that to a 404,
/// since a commit it cannot read is, to a client, no servable latest commit.
async fn read_repo_rev(state: &AppState, did: &str, head: &str) -> Option<String> {
    let root_cid = match repo_engine::Cid::try_from(head) {
        Ok(cid) => cid,
        Err(e) => {
            tracing::error!(error = %e, did = %did, "invalid repo root CID in database; omitting rev");
            return None;
        }
    };

    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let repo = match Repository::open(block_store, root_cid).await {
        Ok(repo) => repo,
        Err(e) => {
            tracing::warn!(error = %e, did = %did, "failed to open repo for getLatestCommit; omitting rev");
            return None;
        }
    };

    Some(repo.commit().rev().as_str().to_string())
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
    use tower::ServiceExt;

    use crate::routes::test_utils::{body_json, seed_account_with_repo, state_with_master_key};

    async fn get_latest(app: &axum::Router, did: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/xrpc/com.atproto.sync.getLatestCommit?did={did}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(request).await.unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    /// Insert a bare account row (no repo genesis) and return its DID.
    async fn seed_bare_account(db: &sqlx::SqlitePool, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, 'hash', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn active_repo_returns_cid_and_rev() {
        let state = state_with_master_key().await;
        let did = "did:plc:latestcommitactive";
        seed_account_with_repo(&state.db, did).await;
        let expected_cid: String =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&state.db)
                .await
                .unwrap();
        let expected_rev: String =
            sqlx::query_scalar("SELECT repo_rev FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&state.db)
                .await
                .unwrap();
        let app = crate::app::app(state);

        let (status, body) = get_latest(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["cid"], expected_cid);
        assert_eq!(body["rev"], expected_rev);
    }

    #[tokio::test]
    async fn legacy_null_rev_falls_back_to_commit_block() {
        let state = state_with_master_key().await;
        // A pre-migration account: repo blocks exist and repo_root_cid is set, but repo_rev
        // was never populated. getLatestCommit must still report the rev, read from the commit.
        let did = "did:plc:latestcommitlegacy";
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

        let (status, body) = get_latest(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["rev"], expected_rev);
        // The rev is the commit's TID — a 13-char string.
        assert_eq!(body["rev"].as_str().unwrap().len(), 13);
    }

    #[tokio::test]
    async fn deactivated_repo_still_returns_latest_commit() {
        // getLatestCommit reports the head regardless of lifecycle, matching getRepoStatus's
        // `rev`: a deactivated repo still has a last-known commit.
        let state = state_with_master_key().await;
        let did = "did:plc:latestcommitdeactivated";
        seed_account_with_repo(&state.db, did).await;
        let expected_cid: String =
            sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&state.db)
                .await
                .unwrap();
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let app = crate::app::app(state);

        let (status, body) = get_latest(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["cid"], expected_cid);
    }

    #[tokio::test]
    async fn account_without_repo_returns_404() {
        let state = state_with_master_key().await;
        let did = "did:plc:latestcommitnorepo";
        seed_bare_account(&state.db, did).await;
        let app = crate::app::app(state);

        let (status, body) = get_latest(&app, did).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn nonexistent_did_returns_404() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let (status, body) = get_latest(&app, "did:plc:latestcommitghost").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn invalid_did_returns_400() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let (status, _) = get_latest(&app, "not-a-did").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn unreadable_repo_head_returns_404() {
        let state = state_with_master_key().await;
        // repo_root_cid points at a commit block that was never written (a valid CIDv1, but
        // absent from `blocks`) and repo_rev is NULL — the rev cannot be read, so there is no
        // servable latest commit and the request is a 404 rather than a 500.
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, repo_root_cid, created_at, updated_at) \
             VALUES (?, 'badlatest@example.com', 'hash', ?, datetime('now'), datetime('now'))",
        )
        .bind("did:plc:latestcommitbad")
        .bind("bafyreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
        .execute(&state.db)
        .await
        .unwrap();
        let app = crate::app::app(state);

        let (status, body) = get_latest(&app, "did:plc:latestcommitbad").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn malformed_head_with_rev_returns_404_not_bogus_cid() {
        let state = state_with_master_key().await;
        // A malformed repo_root_cid paired with a populated repo_rev: the fast path reads rev
        // straight from the column, so without up-front CID validation it would 200 with a bogus
        // cid. The head must be validated first, yielding a 404 instead.
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, repo_root_cid, repo_rev, created_at, updated_at) \
             VALUES (?, 'malformedlatest@example.com', 'hash', ?, ?, datetime('now'), datetime('now'))",
        )
        .bind("did:plc:latestcommitmalformed")
        .bind("not-a-valid-cid")
        .bind("3kabcdefghij2")
        .execute(&state.db)
        .await
        .unwrap();
        let app = crate::app::app(state);

        let (status, body) = get_latest(&app, "did:plc:latestcommitmalformed").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn suspended_or_takendown_repo_still_returns_latest_commit() {
        // The contract mirrors getRepoStatus's `rev`: a non-active repo still has a last-known
        // commit. `get_repo_status` derives lifecycle from three separate columns, so cover the
        // suspended and taken-down paths alongside the deactivated case above — a regression in
        // either column would otherwise pass unnoticed.
        let state = state_with_master_key().await;
        let mut expected = Vec::new();
        for (did, column) in [
            ("did:plc:latestcommitsuspended", "suspended_at"),
            ("did:plc:latestcommittakendown", "taken_down_at"),
        ] {
            seed_account_with_repo(&state.db, did).await;
            let cid: String =
                sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
                    .bind(did)
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            // Fixed SQL per column (never interpolated) so the query stays static.
            let sql = match column {
                "suspended_at" => {
                    "UPDATE accounts SET suspended_at = datetime('now') WHERE did = ?"
                }
                "taken_down_at" => {
                    "UPDATE accounts SET taken_down_at = datetime('now') WHERE did = ?"
                }
                other => panic!("unsupported lifecycle column: {other}"),
            };
            sqlx::query(sql).bind(did).execute(&state.db).await.unwrap();
            expected.push((did, cid));
        }
        let app = crate::app::app(state);

        for (did, expected_cid) in expected {
            let (status, body) = get_latest(&app, did).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                body["cid"], expected_cid,
                "{did} must still report its last-known commit"
            );
        }
    }
}
