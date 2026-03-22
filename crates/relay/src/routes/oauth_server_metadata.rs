// pattern: Imperative Shell
//
// Gathers: public URL from config
// Processes: none (response shape is fixed by RFC 8414 and AT Protocol OAuth spec)
// Returns: JSON matching the OAuth 2.0 Authorization Server Metadata format (RFC 8414)

use axum::{
    extract::State,
    response::{IntoResponse, Json},
};
use serde::Serialize;

use crate::app::AppState;

/// RFC 8414 OAuth 2.0 Authorization Server Metadata response.
///
/// Field names are snake_case per the OAuth spec — intentionally different from the
/// camelCase used by XRPC/AT Protocol Lexicon endpoints in this codebase.
///
/// AT Protocol OAuth extensions:
/// - `dpop_signing_alg_values_supported`: signals that DPoP (RFC 9449) is required.
/// - `token_endpoint_auth_methods_supported: ["none"]`: public clients only — no client secrets.
#[derive(Serialize)]
pub struct OAuthServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    pushed_authorization_request_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    dpop_signing_alg_values_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
}

pub async fn oauth_server_metadata(State(state): State<AppState>) -> impl IntoResponse {
    let base = state.config.public_url.trim_end_matches('/');
    Json(OAuthServerMetadata {
        issuer: base.to_string(),
        authorization_endpoint: format!("{base}/oauth/authorize"),
        token_endpoint: format!("{base}/oauth/token"),
        pushed_authorization_request_endpoint: format!("{base}/oauth/par"),
        jwks_uri: format!("{base}/oauth/jwks.json"),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string()],
        dpop_signing_alg_values_supported: vec!["ES256".to_string()],
        token_endpoint_auth_methods_supported: vec!["none".to_string()],
    })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};

    async fn metadata_json() -> serde_json::Value {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-authorization-server")
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
                    .uri("/.well-known/oauth-authorization-server")
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
    async fn issuer_matches_public_url() {
        let json = metadata_json().await;
        assert_eq!(json["issuer"], "https://test.example.com");
    }

    #[tokio::test]
    async fn endpoints_use_public_url_as_base() {
        let json = metadata_json().await;
        assert_eq!(
            json["authorization_endpoint"],
            "https://test.example.com/oauth/authorize"
        );
        assert_eq!(
            json["token_endpoint"],
            "https://test.example.com/oauth/token"
        );
        assert_eq!(
            json["pushed_authorization_request_endpoint"],
            "https://test.example.com/oauth/par"
        );
        assert_eq!(json["jwks_uri"], "https://test.example.com/oauth/jwks.json");
    }

    #[tokio::test]
    async fn response_types_contains_code() {
        let json = metadata_json().await;
        assert!(json["response_types_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "code"));
    }

    #[tokio::test]
    async fn grant_types_include_authorization_code_and_refresh_token() {
        let json = metadata_json().await;
        let grants = json["grant_types_supported"].as_array().unwrap();
        assert!(grants.iter().any(|v| v == "authorization_code"));
        assert!(grants.iter().any(|v| v == "refresh_token"));
    }

    #[tokio::test]
    async fn dpop_signing_alg_includes_es256() {
        let json = metadata_json().await;
        assert!(json["dpop_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "ES256"));
    }

    #[tokio::test]
    async fn token_endpoint_auth_method_is_none() {
        let json = metadata_json().await;
        assert!(json["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "none"));
    }

    #[tokio::test]
    async fn pkce_method_is_s256() {
        let json = metadata_json().await;
        assert!(json["code_challenge_methods_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "S256"));
    }

    #[tokio::test]
    async fn trailing_slash_in_public_url_does_not_double_slash_endpoints() {
        use crate::app::AppState;
        use std::sync::Arc;

        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.public_url = "https://pds.example.com/".to_string();
        let state = AppState {
            config: Arc::new(config),
            db: base.db,
            http_client: base.http_client,
            dns_provider: base.dns_provider,
            txt_resolver: base.txt_resolver,
            well_known_resolver: base.well_known_resolver,
            jwt_secret: base.jwt_secret,
        };

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-authorization-server")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // public_url with trailing slash must not produce "...com//oauth/..."
        assert_eq!(
            json["authorization_endpoint"],
            "https://pds.example.com/oauth/authorize"
        );
    }
}
