// pattern: Imperative Shell
//
// Gathers: public URL from config
// Processes: none (response shape is fixed by RFC 9728 and AT Protocol OAuth spec)
// Returns: JSON matching the OAuth 2.0 Protected Resource Metadata format (RFC 9728)

use axum::{
    extract::State,
    response::{IntoResponse, Json},
};
use serde::Serialize;

use crate::app::AppState;

/// RFC 9728 OAuth 2.0 Protected Resource Metadata response.
///
/// Field names are snake_case per the OAuth spec — intentionally different from the
/// camelCase used by XRPC/AT Protocol Lexicon endpoints in this codebase.
///
/// ezpds is both the protected resource server and the authorization server, so
/// `resource` and `authorization_servers[0]` are the same public origin.
#[derive(Serialize)]
struct OAuthProtectedResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
    bearer_methods_supported: Vec<String>,
    resource_documentation: String,
}

pub async fn oauth_protected_resource_metadata(State(state): State<AppState>) -> impl IntoResponse {
    let base = state.config.public_url.trim_end_matches('/');
    Json(OAuthProtectedResourceMetadata {
        resource: base.to_string(),
        authorization_servers: vec![base.to_string()],
        scopes_supported: crate::auth::oauth_scopes::supported_scopes()
            .into_iter()
            .map(String::from)
            .collect(),
        bearer_methods_supported: vec!["header".to_string()],
        resource_documentation: "https://atproto.com".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state, AppState};

    async fn metadata_json() -> serde_json::Value {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-protected-resource")
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
                    .uri("/.well-known/oauth-protected-resource")
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
        // Lock in that the discovery endpoint requires no credentials.
        // A future global auth middleware must not inadvertently protect this route.
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn resource_matches_public_url() {
        let json = metadata_json().await;
        assert_eq!(json["resource"], "https://test.example.com");
    }

    #[tokio::test]
    async fn authorization_server_points_to_same_origin() {
        let json = metadata_json().await;
        assert_eq!(
            json["authorization_servers"],
            serde_json::json!(["https://test.example.com"])
        );
    }

    #[tokio::test]
    async fn scopes_supported_reflects_the_full_granular_scope_grammar() {
        // Mirrors oauth_server_metadata.rs's contract (oauth-scopes-permission-sets.AC6.2) —
        // both discovery documents advertise the same supported scope surface.
        let json = metadata_json().await;
        assert_eq!(
            json["scopes_supported"],
            serde_json::json!([
                "atproto",
                "transition:email",
                "transition:generic",
                "transition:chat.bsky",
                "repo:*",
                "rpc:*",
                "blob:*/*",
                "account:*",
                "identity:*",
                "include:*"
            ])
        );
    }

    #[tokio::test]
    async fn bearer_methods_supported_is_header() {
        let json = metadata_json().await;
        assert_eq!(
            json["bearer_methods_supported"],
            serde_json::json!(["header"])
        );
    }

    #[tokio::test]
    async fn resource_documentation_points_to_atproto_docs() {
        let json = metadata_json().await;
        assert_eq!(json["resource_documentation"], "https://atproto.com");
    }

    #[tokio::test]
    async fn trailing_slash_in_public_url_does_not_affect_resource_origin() {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.public_url = "https://pds.example.com/".to_string();
        let state = AppState {
            config: Arc::new(config),
            ..base
        };

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["resource"], "https://pds.example.com");
        assert_eq!(
            json["authorization_servers"],
            serde_json::json!(["https://pds.example.com"])
        );
    }
}
