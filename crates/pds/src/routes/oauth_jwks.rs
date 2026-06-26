// pattern: Imperative Shell
//
// Gathers: OAuth signing keypair from AppState
// Processes: ensures kid, use, and alg fields are present in the JWK; wraps in JWK Set envelope
// Returns: RFC 7517 JWK Set JSON with Cache-Control for client-side caching

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde_json::json;

use crate::app::AppState;

pub async fn oauth_jwks(State(state): State<AppState>) -> Response {
    let keypair = &state.oauth_signing_keypair;
    let mut jwk = keypair.public_key_jwk.clone();

    // The production key builder (signing_key.rs) always stores kid, use, and alg in the JWK.
    // The or_insert_with guards below are defensive: they ensure correctness even if the stored
    // JWK is missing these fields (e.g., keys created before alg/use were added, or test fixtures).
    let Some(obj) = jwk.as_object_mut() else {
        tracing::error!(
            key_id = %keypair.key_id,
            "OAuth signing key JWK is not a JSON object — key store may be corrupted"
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    obj.entry("kid")
        .or_insert_with(|| serde_json::Value::String(keypair.key_id.clone()));
    obj.entry("use")
        .or_insert_with(|| serde_json::Value::String("sig".to_string()));
    obj.entry("alg")
        .or_insert_with(|| serde_json::Value::String("ES256".to_string()));

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );

    (headers, Json(json!({ "keys": [jwk] }))).into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state, AppState};
    use crate::auth::OAuthSigningKey;

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
    async fn response_has_exactly_one_key() {
        // Locks in the single-key contract; key rotation changes must update this test explicitly.
        let json = jwks_json().await;
        let keys = json["keys"].as_array().expect("keys must be an array");
        assert_eq!(keys.len(), 1);
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
    async fn key_has_use_sig_and_alg_es256() {
        let json = jwks_json().await;
        let key = &json["keys"][0];
        assert_eq!(key["use"], "sig");
        assert_eq!(key["alg"], "ES256");
    }

    #[tokio::test]
    async fn key_does_not_expose_private_scalar() {
        // Security: the JWKS endpoint must never leak the private key `d` field.
        let json = jwks_json().await;
        assert!(
            json["keys"][0]["d"].is_null(),
            "JWKS must not contain private key scalar `d`"
        );
    }

    #[tokio::test]
    async fn kid_matches_signing_key_id() {
        // Uses the same AppState instance for the request and the expected kid —
        // avoids relying on the hardcoded "test-oauth-key-01" fixture value.
        let state = test_state().await;
        let expected_kid = state.oauth_signing_keypair.key_id.clone();
        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/oauth/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["keys"][0]["kid"], expected_kid);
    }

    #[tokio::test]
    async fn kid_not_overwritten_when_already_present_in_jwk() {
        // Production always stores kid in the JWK — this test exercises the or_insert_with no-op
        // and verifies a pre-existing kid is preserved rather than overwritten.
        let base = test_state().await;
        let mut jwk = base.oauth_signing_keypair.public_key_jwk.clone();
        jwk.as_object_mut().unwrap().insert(
            "kid".to_string(),
            serde_json::Value::String("pre-existing-kid".to_string()),
        );
        let state = AppState {
            oauth_signing_keypair: OAuthSigningKey {
                public_key_jwk: jwk,
                ..base.oauth_signing_keypair.clone()
            },
            ..base
        };
        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/oauth/jwks")
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
            json["keys"][0]["kid"], "pre-existing-kid",
            "existing kid must not be overwritten by the defensive guard"
        );
    }
}
