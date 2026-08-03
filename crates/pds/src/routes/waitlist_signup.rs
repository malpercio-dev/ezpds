// pattern: Imperative Shell
//
// Gathers: JSON body (email + optional atproto handle)
// Processes: waitlist-enabled gate, email/handle validation, idempotent signup insert
// Returns: 200 `{ status: "ok" }` for new and repeat signups alike

//! `POST /waitlist` — the public interest-signup endpoint behind the `waitlist`
//! capability. 404 unless `[waitlist] enabled` — the same condition `capabilities.rs`
//! advertises.
//!
//! Deliberately mounted on the **public** router group (permissive CORS) rather than
//! `/v1/*`: the whole point is that an operator's marketing page — a different origin —
//! can post to it from a browser. That is safe under the crate's CORS doctrine because
//! the endpoint carries no credentials at all, and it keeps the "`/v1/*` gets no CORS"
//! invariant intact.
//!
//! The email is normalized (`uniqueness::normalize_email`) and plausibility-checked. A
//! repeat signup for the same normalized email returns the same 200 as a first
//! signup: the response never discloses whether an address was already on the list.
//! The handle is optional interest signal — syntactically validated
//! (`identity::handle::validate_handle_structure`; a leading `@` is stripped), never
//! resolved —
//! so the operator can see how many signups already have an atproto identity without
//! this endpoint growing an outbound-request (SSRF) surface. Abuse containment is the
//! per-endpoint IP rate limiter (`[rate_limit] waitlist_per_5min`) on top of the
//! global one.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::db::waitlist::insert_signup;
use crate::identity::handle::validate_handle_structure;
use crate::uniqueness::{is_plausible_email, normalize_email};

/// Upper bound on a stored email address (RFC 5321's 320-octet path ceiling, rounded).
/// Anything longer is garbage or abuse, not a mailbox.
const MAX_EMAIL_LEN: usize = 320;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WaitlistSignupRequest {
    pub email: String,
    /// Optional self-reported atproto handle (`alice.bsky.social`). A leading `@` is
    /// tolerated and stripped — it is how most people write their own handle.
    pub handle: Option<String>,
}

#[derive(Serialize)]
pub struct WaitlistSignupResponse {
    pub status: &'static str,
}

pub async fn waitlist_signup(
    State(state): State<AppState>,
    Json(payload): Json<WaitlistSignupRequest>,
) -> Result<Json<WaitlistSignupResponse>, ApiError> {
    // The same condition `capabilities.rs` advertises: a host not offering `waitlist`
    // does not have this surface.
    if !state.config.waitlist.enabled {
        return Err(ApiError::new(
            ErrorCode::NotFound,
            "the waitlist is not enabled on this server",
        ));
    }

    let email = normalize_email(&payload.email);
    if email.len() > MAX_EMAIL_LEN || !is_plausible_email(&email) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "a valid email address is required",
        ));
    }

    let handle = match payload.handle.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(raw) => {
            let candidate = raw.strip_prefix('@').unwrap_or(raw).to_ascii_lowercase();
            if let Err(message) = validate_handle_structure(&candidate) {
                return Err(ApiError::new(ErrorCode::InvalidHandle, message));
            }
            Some(candidate)
        }
    };

    // Both outcomes are the same 200 — no already-signed-up oracle.
    insert_signup(&state.db, &email, handle.as_deref()).await?;
    Ok(Json(WaitlistSignupResponse { status: "ok" }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::app::{app, test_state, AppState};
    use crate::routes::test_utils::body_json;

    async fn waitlist_state() -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.waitlist.enabled = true;
        AppState {
            config: std::sync::Arc::new(config),
            ..base
        }
    }

    fn post_signup(body: &serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/waitlist")
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn signup_records_email_and_handle() {
        let state = waitlist_state().await;
        let db = state.db.clone();
        let response = app(state)
            .oneshot(post_signup(&serde_json::json!({
                "email": "  Alice@Example.COM ",
                "handle": "@Alice.bsky.social"
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["status"], "ok");

        let rows = crate::db::waitlist::list_signups(&db, None, 10)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].email, "alice@example.com");
        assert_eq!(rows[0].handle.as_deref(), Some("alice.bsky.social"));
    }

    #[tokio::test]
    async fn repeat_signup_is_the_same_200() {
        let state = waitlist_state().await;
        let body = serde_json::json!({ "email": "alice@example.com" });
        let router = app(state.clone());
        let first = router.clone().oneshot(post_signup(&body)).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let second = router.oneshot(post_signup(&body)).await.unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(
            crate::db::waitlist::count_signups(&state.db).await.unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn implausible_email_is_rejected() {
        let state = waitlist_state().await;
        let router = app(state);
        for bad in ["no-at-sign", "@example.com", "alice@nodot"] {
            let response = router
                .clone()
                .oneshot(post_signup(&serde_json::json!({ "email": bad })))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "email: {bad}");
        }
    }

    #[tokio::test]
    async fn malformed_handle_is_rejected() {
        let state = waitlist_state().await;
        let response = app(state)
            .oneshot(post_signup(&serde_json::json!({
                "email": "alice@example.com",
                "handle": "not-a-domain"
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn disabled_waitlist_is_not_found() {
        // The default test config leaves the waitlist off — the gate the capability
        // advertisement mirrors.
        let response = app(test_state().await)
            .oneshot(post_signup(
                &serde_json::json!({ "email": "alice@example.com" }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn public_signup_carries_cors_headers() {
        // The marketing site posts cross-origin; the route must sit on the
        // permissive-CORS public group.
        let state = waitlist_state().await;
        let request = Request::builder()
            .method("POST")
            .uri("/waitlist")
            .header("Content-Type", "application/json")
            .header("Origin", "https://obsign.org")
            .body(Body::from(
                serde_json::json!({ "email": "alice@example.com" }).to_string(),
            ))
            .unwrap();
        let response = app(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .contains_key("access-control-allow-origin"));
    }
}
