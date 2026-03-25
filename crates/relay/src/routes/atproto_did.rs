// pattern: Imperative Shell
//
// Gathers: Host header from request, DID from handles table
// Processes: none (handle → DID lookup is a direct DB read)
// Returns: 200 text/plain with DID, or 404 if the host is not a registered handle

use axum::{
    extract::{Host, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use common::{ApiError, ErrorCode};

use crate::app::AppState;

pub async fn atproto_did_handler(
    Host(host): Host,
    State(state): State<AppState>,
) -> Response {
    // Strip port if present (e.g. "example.com:8080" → "example.com").
    let handle = host.split(':').next().unwrap_or(&host);

    let row: Option<(String,)> =
        match sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(handle)
            .fetch_optional(&state.db)
            .await
        {
            Ok(row) => row,
            Err(e) => {
                tracing::error!(error = %e, handle = %handle, "DB error in well-known atproto-did");
                return ApiError::new(ErrorCode::InternalError, "handle lookup failed")
                    .into_response();
            }
        };

    match row {
        Some((did,)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain")],
            did,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
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
    use crate::routes::test_utils::seed_handle;

    fn well_known_request(host: &str) -> Request<Body> {
        Request::builder()
            .uri("/.well-known/atproto-did")
            .header("host", host)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn registered_handle_returns_did_as_plain_text() {
        let state = test_state().await;
        let did = "did:plc:alice123456789012345678901";
        seed_handle(&state.db, "alice.example.com", did).await;

        let response = app(state)
            .oneshot(well_known_request("alice.example.com"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), did);
    }

    #[tokio::test]
    async fn unregistered_host_returns_404() {
        let state = test_state().await;

        let response = app(state)
            .oneshot(well_known_request("nobody.example.com"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn response_content_type_is_text_plain() {
        let state = test_state().await;
        let did = "did:plc:alice123456789012345678901";
        seed_handle(&state.db, "alice.example.com", did).await;

        let response = app(state)
            .oneshot(well_known_request("alice.example.com"))
            .await
            .unwrap();

        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/plain",
        );
    }

    #[tokio::test]
    async fn host_with_port_is_resolved_correctly() {
        let state = test_state().await;
        let did = "did:plc:alice123456789012345678901";
        seed_handle(&state.db, "alice.example.com", did).await;

        let response = app(state)
            .oneshot(well_known_request("alice.example.com:8080"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), did);
    }

    #[tokio::test]
    async fn closed_db_pool_returns_500() {
        let state = test_state().await;
        state.db.close().await;

        let response = app(state)
            .oneshot(well_known_request("alice.example.com"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn post_returns_405() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/.well-known/atproto-did")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
