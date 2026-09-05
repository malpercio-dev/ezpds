// pattern: Imperative Shell
//
// Gathers: query params (limit, cursor) + the signed-request/bearer admin credential
// Processes: admin auth, cursor parse, rowid-cursor page over waitlist_signups
// Returns: 200 `{ signups, total, cursor? }`, newest first

//! `GET /v1/admin/waitlist` — the operator's readout of the public interest-signup
//! waitlist (the `waitlist` capability's read side).
//!
//! A newest-first rowid-cursor page (`limit` default 50, max 100) plus the unpaged
//! `total`. Deliberately available even when `[waitlist] enabled` has since been switched off:
//! the rows are data the operator already collected, and reading them back must not
//! depend on the public write endpoint staying open. Admin-authed via `require_admin`;
//! the signature covers the bare path, so paging params vary without re-signing.

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method, Uri};
use axum::Json;
use serde::{Deserialize, Serialize};

use common::{ApiError, ApiResultExt, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::require_admin;
use crate::db::waitlist::{count_signups, list_signups};

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 100;

#[derive(Deserialize)]
pub struct WaitlistQuery {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WaitlistSignupView {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    pub created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WaitlistResponse {
    pub signups: Vec<WaitlistSignupView>,
    /// Total rows on the list (unpaged), the operator's headline number.
    pub total: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

pub async fn admin_waitlist(
    State(state): State<AppState>,
    Query(params): Query<WaitlistQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<WaitlistResponse>, ApiError> {
    // Auth first so an unauthenticated caller cannot enumerate the list.
    require_admin(method.as_str(), uri.path(), &headers, &body, &state).await?;

    let before = match params.cursor.as_deref() {
        None => None,
        Some(raw) => Some(
            raw.parse::<i64>()
                .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "malformed cursor"))?,
        ),
    };
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let rows = list_signups(&state.db, before, limit)
        .await
        .or_internal_as(
            "DB error listing waitlist signups",
            "failed to list waitlist",
        )?;
    let total = count_signups(&state.db).await.or_internal_as(
        "DB error counting waitlist signups",
        "failed to list waitlist",
    )?;

    // A next cursor only on a full page — the admin_audit convention.
    let cursor = (rows.len() as i64 == limit)
        .then(|| rows.last().map(|r| r.rowid.to_string()))
        .flatten();
    let signups = rows
        .into_iter()
        .map(|r| WaitlistSignupView {
            email: r.email,
            handle: r.handle,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(WaitlistResponse {
        signups,
        total,
        cursor,
    }))
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use tower::ServiceExt;

    use crate::app::app;
    use crate::routes::test_utils::{
        body_json, get_request_with_bearer as get, test_state_with_admin_token,
    };

    async fn seed_signup(db: &sqlx::SqlitePool, email: &str, handle: Option<&str>) {
        crate::db::waitlist::insert_signup(db, email, handle)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn requires_admin_auth() {
        let state = test_state_with_admin_token().await;
        let router = app(state);
        let missing = router
            .clone()
            .oneshot(get("/v1/admin/waitlist", None))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        let wrong = router
            .oneshot(get("/v1/admin/waitlist", Some("wrong-token")))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn lists_newest_first_with_cursor() {
        let state = test_state_with_admin_token().await;
        for i in 0..3 {
            seed_signup(
                &state.db,
                &format!("user{i}@example.com"),
                (i == 0).then_some("user0.bsky.social"),
            )
            .await;
        }
        let router = app(state);

        let response = router
            .clone()
            .oneshot(get("/v1/admin/waitlist?limit=2", Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["total"], 3);
        assert_eq!(json["signups"][0]["email"], "user2@example.com");
        assert_eq!(json["signups"][1]["email"], "user1@example.com");
        let cursor = json["cursor"].as_str().expect("full page carries a cursor");

        let response = router
            .oneshot(get(
                &format!("/v1/admin/waitlist?limit=2&cursor={cursor}"),
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        let json = body_json(response).await;
        assert_eq!(json["signups"][0]["email"], "user0@example.com");
        assert_eq!(json["signups"][0]["handle"], "user0.bsky.social");
        assert!(json["cursor"].is_null());
    }

    #[tokio::test]
    async fn malformed_cursor_is_a_400() {
        let state = test_state_with_admin_token().await;
        let response = app(state)
            .oneshot(get(
                "/v1/admin/waitlist?cursor=not-a-rowid",
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
