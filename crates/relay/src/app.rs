// pattern: Functional Core (router construction is pure — no I/O)

use std::sync::Arc;

use axum::{extract::Path, routing::get, Router};
use common::{ApiError, Config, ErrorCode};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

/// Shared application state cloned into every request handler via Axum's `State` extractor.
///
/// Fields will grow as waves are implemented (MM-72 adds the DB pool, etc.).
#[derive(Clone)]
pub struct AppState {
    // Read by handlers from MM-73 onward; suppressed until then.
    #[allow(dead_code)]
    pub config: Arc<Config>,
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
/// Real XRPC endpoints (MM-73+) will register specific routes that shadow this catch-all
/// for their own NSIDs.
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

    fn test_state() -> AppState {
        AppState {
            config: Arc::new(Config {
                bind_address: "127.0.0.1".to_string(),
                port: 8080,
                data_dir: PathBuf::from("/tmp"),
                database_url: "/tmp/test.db".to_string(),
                public_url: "https://test.example.com".to_string(),
                blobs: BlobsConfig::default(),
                oauth: OAuthConfig::default(),
                iroh: IrohConfig::default(),
            }),
        }
    }

    #[tokio::test]
    async fn xrpc_get_unknown_method_returns_501() {
        let response = app(test_state())
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
        let response = app(test_state())
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

    #[tokio::test]
    async fn xrpc_response_body_is_method_not_implemented() {
        let response = app(test_state())
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.createSession")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "MethodNotImplemented");
    }
}
