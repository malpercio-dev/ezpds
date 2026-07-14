// pattern: Imperative Shell

//! com.atproto.sync.getRepoStatus - Report the hosting status of a single repo.

use axum::extract::{Query, State};
use axum::response::Json;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
pub struct GetRepoStatusParams {
    did: String,
}

#[derive(Serialize)]
pub struct GetRepoStatusResponse {
    pub did: String,
    /// `true` when the repo is actively hosted (not deactivated, suspended, or taken down).
    pub active: bool,
    /// Why the repo is not `active`. Omitted when `active` is true, per the lexicon (the `status`
    /// field carries a *reason* and is meaningless for a live repo). Maps from the account's
    /// lifecycle to a lexicon `status` knownValue: `"deactivated"` (user-initiated), `"suspended"`
    /// or `"takendown"` (operator moderation). The remaining knownValues (`deleted`,
    /// `desynchronized`, `throttled`) are not modelled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// The repo's current commit revision (TID). Omitted when the account has no repo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
}

/// GET /xrpc/com.atproto.sync.getRepoStatus?did=<did>
///
/// Report whether the repo is actively hosted, the reason if not, and its current `rev`.
/// A non-existent DID is a 404; a non-active account (deactivated, suspended, or taken down) is
/// reported (not hidden) with `active: false` and the matching lexicon `status`. No
/// authentication required (public data).
pub async fn sync_get_repo_status(
    State(state): State<AppState>,
    Query(params): Query<GetRepoStatusParams>,
) -> Result<Json<GetRepoStatusResponse>, ApiError> {
    let did = &params.did;

    // Validate DID format, mirroring the other sync endpoints.
    if !crate::auth::validation::is_valid_did(did) {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    let row = crate::db::accounts::get_repo_status(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to query repo status");
            ApiError::new(ErrorCode::InternalError, "failed to get repo status")
        })?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "repo not found"))?;

    let active = row.lifecycle.is_active();
    // `status` reports *why* a repo is not active; omitted entirely for a live repo.
    let status = row.lifecycle.as_status_str().map(str::to_string);

    // Prefer the rev stored on the account row (written at every commit) — the common path is
    // a pure column read. A pre-migration account has a repo root but no stored rev: read it
    // from the commit block. An account with no repo at all reports no rev.
    let rev = match (row.rev, row.head) {
        (Some(rev), _) => Some(rev),
        (None, Some(head)) => crate::repo_rev::read_repo_rev(&state, did, &head).await,
        (None, None) => None,
    };

    Ok(Json(GetRepoStatusResponse {
        did: did.clone(),
        active,
        status,
        rev,
    }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
    use tower::ServiceExt;

    use crate::routes::test_utils::{body_json, seed_account_with_repo, state_with_master_key};

    async fn get_status(app: &axum::Router, did: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/xrpc/com.atproto.sync.getRepoStatus?did={did}"))
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
    async fn active_repo_reports_active_with_rev_and_no_status() {
        let state = state_with_master_key().await;
        let did = "did:plc:repostatusactive";
        seed_account_with_repo(&state.db, did).await;
        let expected_rev: String =
            sqlx::query_scalar("SELECT repo_rev FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&state.db)
                .await
                .unwrap();
        let app = crate::app::app(state);

        let (status, body) = get_status(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["did"], did);
        assert_eq!(body["active"], true);
        assert_eq!(body["rev"], expected_rev);
        // `status` is omitted entirely for an active repo.
        assert!(body.get("status").is_none());
    }

    #[tokio::test]
    async fn deactivated_repo_reports_inactive_with_status() {
        let state = state_with_master_key().await;
        let did = "did:plc:repostatusdeactivated";
        seed_account_with_repo(&state.db, did).await;
        let expected_rev: String =
            sqlx::query_scalar("SELECT repo_rev FROM accounts WHERE did = ?")
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

        let (status, body) = get_status(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["did"], did);
        assert_eq!(body["active"], false);
        assert_eq!(body["status"], "deactivated");
        // A deactivated repo still reports its exact last-known rev.
        assert_eq!(body["rev"], expected_rev);
    }

    #[tokio::test]
    async fn suspended_repo_reports_inactive_with_status() {
        let state = state_with_master_key().await;
        let did = "did:plc:repostatussuspended";
        seed_account_with_repo(&state.db, did).await;
        sqlx::query("UPDATE accounts SET suspended_at = datetime('now') WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let app = crate::app::app(state);

        let (status, body) = get_status(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["active"], false);
        assert_eq!(body["status"], "suspended");
    }

    #[tokio::test]
    async fn takendown_repo_reports_inactive_with_status() {
        let state = state_with_master_key().await;
        let did = "did:plc:repostatustakendown";
        seed_account_with_repo(&state.db, did).await;
        sqlx::query("UPDATE accounts SET taken_down_at = datetime('now') WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let app = crate::app::app(state);

        let (status, body) = get_status(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["active"], false);
        assert_eq!(body["status"], "takendown");
    }

    #[tokio::test]
    async fn takedown_supersedes_suspension_and_deactivation() {
        // An account flagged with all three lifecycle timestamps must report the most severe
        // state — `takendown` — not whichever column happens to be read first.
        let state = state_with_master_key().await;
        let did = "did:plc:repostatusallthree";
        seed_account_with_repo(&state.db, did).await;
        sqlx::query(
            "UPDATE accounts \
             SET deactivated_at = datetime('now'), suspended_at = datetime('now'), \
                 taken_down_at = datetime('now') \
             WHERE did = ?",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
        let app = crate::app::app(state);

        let (status, body) = get_status(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["active"], false);
        assert_eq!(body["status"], "takendown");
    }

    #[tokio::test]
    async fn account_without_repo_reports_active_and_omits_rev() {
        let state = state_with_master_key().await;
        let did = "did:plc:repostatusnorepo";
        seed_bare_account(&state.db, did).await;
        let app = crate::app::app(state);

        let (status, body) = get_status(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["did"], did);
        assert_eq!(body["active"], true);
        assert!(body.get("status").is_none());
        // No repo yet — `rev` is omitted rather than null.
        assert!(body.get("rev").is_none());
    }

    #[tokio::test]
    async fn legacy_null_rev_falls_back_to_commit_block() {
        let state = state_with_master_key().await;
        let did = "did:plc:repostatuslegacy";
        seed_account_with_repo(&state.db, did).await;
        let expected_rev: String =
            sqlx::query_scalar("SELECT repo_rev FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&state.db)
                .await
                .unwrap();
        // Simulate a pre-`repo_rev`-migration account: repo blocks exist, rev unpopulated.
        sqlx::query("UPDATE accounts SET repo_rev = NULL WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let app = crate::app::app(state);

        let (status, body) = get_status(&app, did).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["rev"], expected_rev);
    }

    #[tokio::test]
    async fn nonexistent_did_returns_404() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let (status, body) = get_status(&app, "did:plc:repostatusghost").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn invalid_did_returns_400() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let (status, _) = get_status(&app, "not-a-did").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
