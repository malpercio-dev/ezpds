// pattern: Imperative Shell
//
// Gathers: admin credentials (master token or signed device request), the subject DID
// Processes: admin auth → read the account's current lifecycle
// Returns: 200 OK with the subject/takedown status; ApiError on failure
//
// Implements: GET /xrpc/com.atproto.admin.getSubjectStatus

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, Method, Uri},
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::require_admin;
use crate::auth::validation::is_valid_did;
use crate::db::accounts::{get_repo_status, AccountLifecycle};
use crate::routes::admin_subject_defs::{RepoRefView, StatusAttrView};

#[derive(Deserialize)]
pub struct GetSubjectStatusParams {
    did: String,
}

#[derive(Serialize)]
pub struct GetSubjectStatusResponse {
    subject: RepoRefView,
    takedown: StatusAttrView,
}

/// GET /xrpc/com.atproto.admin.getSubjectStatus?did=<did>
///
/// Report an account's current takedown status. Admin-authed: the master token **or** an
/// active companion-app device's signed request ([`require_admin`]). Only the `com.atproto.
/// admin.defs#repoRef` subject kind (account-level) is supported — ezpds does not model
/// record- or blob-level takedown. A non-existent DID is a 404.
pub async fn get_subject_status(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Query(params): Query<GetSubjectStatusParams>,
    body: Bytes,
) -> Result<Json<GetSubjectStatusResponse>, Response> {
    require_admin(method.as_str(), uri.path(), &headers, &body, &state)
        .await
        .map_err(IntoResponse::into_response)?;

    if !is_valid_did(&params.did) {
        return Err(
            ApiError::new(ErrorCode::InvalidRequest, "did is not a valid DID").into_response(),
        );
    }

    let row = get_repo_status(&state.db, &params.did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %params.did, "failed to query subject status");
            ApiError::new(ErrorCode::InternalError, "failed to get subject status").into_response()
        })?
        .ok_or_else(|| {
            ApiError::new(ErrorCode::NotFound, "subject account not found").into_response()
        })?;

    Ok(Json(GetSubjectStatusResponse {
        subject: RepoRefView {
            type_: "com.atproto.admin.defs#repoRef",
            did: params.did,
        },
        takedown: StatusAttrView {
            applied: matches!(row.lifecycle, AccountLifecycle::TakenDown),
        },
    }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::app;
    use crate::routes::test_utils::{body_json, test_state_with_admin_token};

    async fn insert_account(db: &sqlx::SqlitePool, did: &str, email: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(email)
        .execute(db)
        .await
        .unwrap();
    }

    fn request(did: &str, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method("GET").uri(format!(
            "/xrpc/com.atproto.admin.getSubjectStatus?did={did}"
        ));
        if let Some(token) = bearer {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn reports_not_applied_for_active_account() {
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:gsstd1", "gsstd1@example.com").await;

        let response = app(state)
            .oneshot(request("did:plc:gsstd1", Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["subject"]["did"], "did:plc:gsstd1");
        assert_eq!(json["takedown"]["applied"], false);
    }

    #[tokio::test]
    async fn reports_applied_for_takendown_account() {
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:gsstd2", "gsstd2@example.com").await;
        sqlx::query("UPDATE accounts SET taken_down_at = datetime('now') WHERE did = ?")
            .bind("did:plc:gsstd2")
            .execute(&state.db)
            .await
            .unwrap();

        let response = app(state)
            .oneshot(request("did:plc:gsstd2", Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["takedown"]["applied"], true);
    }

    #[tokio::test]
    async fn unknown_did_returns_404() {
        let state = test_state_with_admin_token().await;

        let response = app(state)
            .oneshot(request("did:plc:gsstdghost", Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn invalid_did_returns_400() {
        let state = test_state_with_admin_token().await;

        let response = app(state)
            .oneshot(request("not-a-did", Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn without_admin_auth_returns_401() {
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:gsstd3", "gsstd3@example.com").await;

        let response = app(state)
            .oneshot(request("did:plc:gsstd3", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
