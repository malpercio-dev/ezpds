// pattern: Imperative Shell

//! `GET /metrics` — Prometheus text exposition of the instrument set in `crate::metrics`.
//!
//! Registered by `app()` only when `[telemetry] metrics_enabled` (the default); when off,
//! the path 404s and no meter exists. The route is added *after* the router's layer stack,
//! so it sits outside the permissive CORS layer, the trace layer, and rate-limit
//! accounting — the endpoint is meant for a private-network scraper (or an operator/agent
//! curl over the deployment's internal network), not for browsers.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::app::AppState;
use crate::auth::guards::require_admin;

/// Prometheus text exposition content type (the format `TextEncoder` produces).
const TEXT_EXPOSITION: &str = "text/plain; version=0.0.4";

pub async fn get_metrics(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // gather: optional admin gate for operators exposing the endpoint beyond a private
    // network. Master token or signed companion-device request, like other admin GETs.
    if state.config.telemetry.metrics_require_admin {
        if let Err(err) = require_admin("GET", "/metrics", &headers, &[], &state).await {
            return err.into_response();
        }
    }

    // process: encode the registry. `render()` is `None` only when metrics are disabled,
    // and `app()` does not register this route in that case — treat it as an internal
    // error rather than unreachable!() so a future wiring mistake degrades to a 500.
    let rendered = match state.metrics.render() {
        Some(Ok(body)) => body,
        Some(Err(err)) => {
            tracing::error!(error = ?err, "failed to encode metrics");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        None => {
            tracing::error!("metrics route registered while metrics are disabled");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // respond
    ([(header::CONTENT_TYPE, TEXT_EXPOSITION)], rendered).into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::app::{app, test_state};

    async fn body_string(response: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_text_exposition_with_request_counts() {
        let router = app(test_state().await);

        // Drive one routed request through the middleware so http_requests_total exists.
        let health = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/xrpc/_health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/plain"));
        // Outside the permissive CORS layer: a scrape response carries no CORS headers.
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_none());

        let body = body_string(response).await;
        assert!(
            body.contains(r#"http_requests_total{"#) && body.contains(r#"route="/xrpc/_health""#),
            "missing counted _health request in:\n{body}"
        );
    }

    #[tokio::test]
    async fn metrics_disabled_returns_404_from_the_router() {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.telemetry.metrics_enabled = false;
        let state = crate::app::AppState {
            config: Arc::new(config),
            metrics: Arc::new(crate::metrics::Metrics::disabled()),
            ..base
        };

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn metrics_require_admin_gates_on_admin_auth() {
        let base = crate::routes::test_utils::test_state_with_admin_token().await;
        let mut config = (*base.config).clone();
        config.telemetry.metrics_require_admin = true;
        let state = crate::app::AppState {
            config: Arc::new(config),
            ..base
        };
        let router = app(state);

        let anonymous = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

        let admin = router
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("Authorization", "Bearer test-admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(admin.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn firehose_frames_are_counted_by_type() {
        let state = test_state().await;
        state
            .firehose
            .emit_identity("did:plc:metrics-test".to_string(), None)
            .await
            .unwrap();

        let rendered = state.metrics.render().unwrap().unwrap();
        assert!(
            rendered.contains("firehose_events_total") && rendered.contains(r#"frame="identity""#),
            "missing counted identity frame in:\n{rendered}"
        );
    }

    #[tokio::test]
    async fn route_labels_are_templates_not_raw_uris() {
        let router = app(test_state().await);

        // Distinct query strings on a registered route and distinct method names on the
        // XRPC catch-all must collapse into their route templates.
        for rkey in ["aaa", "bbb", "ccc"] {
            let uri = format!("/xrpc/com.atproto.repo.getRecord?repo=x&collection=y&rkey={rkey}");
            router
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
        }
        for method in ["com.example.one", "com.example.two"] {
            let uri = format!("/xrpc/{method}");
            router
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
        }

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_string(response).await;

        let get_record_series = body
            .lines()
            .filter(|l| l.contains(r#"route="/xrpc/com.atproto.repo.getRecord""#))
            .count();
        assert_eq!(
            get_record_series, 1,
            "distinct rkeys must share one series:\n{body}"
        );
        let catch_all_series = body
            .lines()
            .filter(|l| l.contains(r#"route="/xrpc/{method}""#))
            .count();
        assert_eq!(
            catch_all_series, 1,
            "catch-all NSIDs must share the template series:\n{body}"
        );
        assert!(
            !body.contains("rkey=") && !body.contains("com.example.one"),
            "raw URI leaked into labels:\n{body}"
        );
    }
}
