// pattern: Imperative Shell
//
// Gathers: DB health via SELECT 1 (pool liveness only — does not verify schema or migrations)
// Processes: none (response shape is trivial — no pure core to extract)
// Returns: JSON response with version and db status

//! `GET /xrpc/_health` — liveness probe.
//!
//! `version` is the self-identifying `custos vX.Y.Z`
//! (`capabilities::IDENTIFYING_VERSION`) — the shape third-party atproto diagnostic
//! tooling fingerprints on, not a bare version number. `db` reports pool liveness
//! (`SELECT 1`, not schema or migrations); a failed check is a 503 with `db: "error"`.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::Serialize;

use crate::app::AppState;
use crate::capabilities::IDENTIFYING_VERSION;

#[derive(Serialize)]
struct HealthResponse {
    /// Self-identifying `custos vX.Y.Z`, not a bare version number: this endpoint is what
    /// third-party atproto diagnostic tooling reads to fingerprint an implementation, and
    /// a bare version says nothing about which software is answering. See
    /// `crate::capabilities::IDENTIFYING_VERSION`.
    version: &'static str,
    db: &'static str,
}

pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let version = IDENTIFYING_VERSION;
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, Json(HealthResponse { version, db: "ok" })),
        Err(e) => {
            tracing::error!(error = %e, "db health check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthResponse {
                    version,
                    db: "error",
                }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};

    #[tokio::test]
    async fn health_returns_200_with_db_ok() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/_health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["db"], "ok");
    }

    #[tokio::test]
    async fn health_version_is_self_identifying() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/_health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["version"],
            concat!("custos v", env!("CARGO_PKG_VERSION"))
        );
    }

    #[tokio::test]
    async fn health_response_has_json_content_type() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/_health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn health_db_error_returns_503_with_db_error() {
        let state = test_state().await;
        // Closing the pool causes the next acquire() to fail, simulating DB unavailability.
        state.db.close().await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/_health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["db"], "error");
        assert_eq!(
            json["version"],
            concat!("custos v", env!("CARGO_PKG_VERSION"))
        );
    }

    #[tokio::test]
    async fn health_post_returns_405() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/_health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
