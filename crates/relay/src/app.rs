use std::sync::Arc;

use axum::{extract::Path, routing::get, Router};
use common::{ApiError, Config, ErrorCode};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

/// Shared application state cloned into every request handler via Axum's `State` extractor.
/// Fields are marked as dead_code until XRPC endpoint handlers are implemented and read them.
#[derive(Clone)]
pub struct AppState {
    #[allow(dead_code)]
    pub config: Arc<Config>,
    #[allow(dead_code)]
    pub db: sqlx::SqlitePool,
}

/// Build the Axum router with middleware and routes.
///
/// Keeping router construction separate from `main` makes it testable without a real TCP
/// listener — callers can use `tower::ServiceExt::oneshot` to drive requests in tests.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/xrpc/:method", get(xrpc_handler).post(xrpc_handler))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Catch-all XRPC handler — returns `MethodNotImplemented` for any unrecognised NSID.
///
/// Axum gives static path segments priority over parameterised ones, so specific routes
/// registered for individual NSIDs will match before this catch-all.
async fn xrpc_handler(Path(method): Path<String>) -> ApiError {
    ApiError::new(
        ErrorCode::MethodNotImplemented,
        format!("XRPC method {method:?} is not implemented"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use common::{BlobsConfig, IrohConfig, OAuthConfig};
    use std::path::PathBuf;
    use tower::ServiceExt;

    async fn test_state() -> AppState {
        let pool = crate::db::open_pool("sqlite::memory:")
            .await
            .expect("failed to open test pool");
        crate::db::run_migrations(&pool)
            .await
            .expect("failed to run test migrations");
        AppState {
            config: Arc::new(Config {
                bind_address: "127.0.0.1".to_string(),
                port: 8080,
                data_dir: PathBuf::from("/tmp"),
                database_url: "sqlite::memory:".to_string(),
                public_url: "https://test.example.com".to_string(),
                blobs: BlobsConfig::default(),
                oauth: OAuthConfig::default(),
                iroh: IrohConfig::default(),
            }),
            db: pool,
        }
    }

    #[tokio::test]
    async fn xrpc_get_unknown_method_returns_501() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.example.unknownMethod")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn xrpc_post_unknown_method_returns_501() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.example.unknownMethod")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // XRPC only defines GET (queries) and POST (procedures); other methods are not part of
    // the protocol and correctly return 405.
    #[tokio::test]
    async fn xrpc_delete_returns_405() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/xrpc/com.example.unknownMethod")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn xrpc_response_has_json_content_type() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.example.unknownMethod")
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
    async fn xrpc_response_body_is_method_not_implemented() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.createSession")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(json["error"]["code"], "MethodNotImplemented");
    }

    #[tokio::test]
    async fn appstate_db_pool_is_queryable() {
        let state = test_state().await;
        sqlx::query("SELECT 1")
            .execute(&state.db)
            .await
            .expect("db pool in AppState must be queryable");
    }
}
