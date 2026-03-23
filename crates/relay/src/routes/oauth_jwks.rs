// pattern: Imperative Shell
//
// Gathers: OAuth signing keypair from AppState
// Processes: none (wraps pre-built public JWK in a JWK Set envelope)
// Returns: RFC 7517 JWK Set JSON with Cache-Control for client-side caching

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Json},
};
use serde_json::json;

use crate::app::AppState;

pub async fn oauth_jwks(State(state): State<AppState>) -> impl IntoResponse {
    let keypair = &state.oauth_signing_keypair;
    // Merge key_id into the JWK as `kid` if the stored JWK omits it.
    // The kid in JWKS must match the kid header in issued JWTs (RFC 7517 §4.5).
    let mut jwk = keypair.public_key_jwk.clone();
    if let Some(obj) = jwk.as_object_mut() {
        obj.entry("kid")
            .or_insert_with(|| serde_json::Value::String(keypair.key_id.clone()));
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );

    (headers, Json(json!({ "keys": [jwk] })))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};

    async fn jwks_json() -> serde_json::Value {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/oauth/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn returns_200_with_json_content_type() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/oauth/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn accessible_without_auth_headers() {
        // Lock in that this public discovery endpoint requires no credentials.
        // A future global auth middleware must not inadvertently protect this route.
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/oauth/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn has_cache_control_header() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/oauth/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers().get("cache-control").unwrap(),
            "public, max-age=3600"
        );
    }

    #[tokio::test]
    async fn response_has_non_empty_keys_array() {
        let json = jwks_json().await;
        let keys = json["keys"].as_array().expect("keys must be an array");
        assert!(!keys.is_empty());
    }

    #[tokio::test]
    async fn key_is_ec_p256() {
        let json = jwks_json().await;
        let key = &json["keys"][0];
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-256");
    }

    #[tokio::test]
    async fn key_has_x_and_y_coordinates() {
        let json = jwks_json().await;
        let key = &json["keys"][0];
        assert!(key["x"].is_string(), "key must have base64url x coordinate");
        assert!(key["y"].is_string(), "key must have base64url y coordinate");
    }

    #[tokio::test]
    async fn kid_matches_signing_key_id() {
        // The kid in JWKS must match the kid embedded in issued JWTs.
        let state = test_state().await;
        let expected_kid = state.oauth_signing_keypair.key_id.clone();
        let json = jwks_json().await;
        assert_eq!(json["keys"][0]["kid"], expected_kid);
    }
}
