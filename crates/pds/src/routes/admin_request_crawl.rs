// pattern: Imperative Shell
//
// Gathers: admin credentials (master token or signed device request); the configured crawlers.
// Processes: admin auth → send `requestCrawl` to every configured relay NOW (bypassing the
//            rate-limit window), audit-log the acting admin, collect per-relay outcomes.
// Returns: JSON per-relay crawl-request report on success; ApiError on auth failure or when no
//          relay is configured.

//! POST /v1/admin/request-crawl — ask the upstream relay(s) to crawl this PDS now.
//!
//! The operator companion to [`admin_relay_status`](super::admin_relay_status): when the readout
//! shows the relay behind (or not-yet-crawling), this is the "Request crawl" button. Unlike the
//! automatic, rate-limited, fire-and-forget notification the PDS sends after each firehose emission
//! ([`crate::crawler::CrawlerNotifier::notify`]), this is an explicit, un-throttled action whose
//! per-relay outcome is reported back so the operator sees whether each relay accepted.
//!
//! **Audit.** The acting admin is recorded in the durable server-wide admin audit log
//! (`admin_audit_events`, served at `GET /v1/admin/audit`) with the per-relay outcome tally,
//! plus a structured log line.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::Json;
use serde::Serialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::require_admin;
use crate::crawler::CrawlAttempt;
use crate::db::admin_audit::{record_admin_audit_event, AdminAuditAction};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCrawlResponse {
    /// How many relays the request was sent to (one per configured crawler).
    requested: usize,
    /// How many of them accepted the `requestCrawl`.
    accepted: usize,
    /// Per-relay outcomes, in configuration order.
    relays: Vec<CrawlAttempt>,
}

/// POST /v1/admin/request-crawl
///
/// Admin-authed: the master token **or** an active companion-app device's signed request
/// ([`require_admin`]). Takes no request body.
pub async fn request_crawl(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<RequestCrawlResponse>, ApiError> {
    // Auth first, and capture *who* so the action is attributable.
    let actor = require_admin(method.as_str(), uri.path(), &headers, &body, &state).await?;

    if state.config.crawlers.urls.is_empty() {
        // Nothing to crawl: an operator with federation disabled cannot request a crawl. A 400 is
        // clearer than a 200 reporting zero relays.
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "no relay is configured to crawl this server",
        ));
    }

    tracing::info!(admin = %actor.as_log_str(), "admin requested relay crawl");

    let relays = state.crawlers.request_crawl_now().await;
    let accepted = relays.iter().filter(|attempt| attempt.accepted).count();

    let audit_detail = serde_json::json!({
        "requested": relays.len(),
        "accepted": accepted,
    })
    .to_string();
    record_admin_audit_event(
        &state.db,
        actor.as_log_str().as_ref(),
        AdminAuditAction::RequestCrawl,
        None,
        "ok",
        Some(&audit_detail),
    )
    .await?;

    Ok(Json(RequestCrawlResponse {
        requested: relays.len(),
        accepted,
        relays,
    }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::app::app;
    use crate::routes::test_utils::test_state_with_admin_token;

    async fn post_request_crawl(router: axum::Router, token: Option<&str>) -> StatusCode {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/admin/request-crawl");
        if let Some(token) = token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        router
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn request_crawl_requires_admin_auth() {
        let state = test_state_with_admin_token().await;
        let router = app(state);

        assert_eq!(
            post_request_crawl(router.clone(), None).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post_request_crawl(router, Some("wrong-token")).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn request_crawl_is_rejected_when_no_relay_configured() {
        // The test state configures no crawlers, so there is nothing to crawl → 400.
        let state = test_state_with_admin_token().await;
        let router = app(state);

        assert_eq!(
            post_request_crawl(router, Some("test-admin-token")).await,
            StatusCode::BAD_REQUEST
        );
    }
}
