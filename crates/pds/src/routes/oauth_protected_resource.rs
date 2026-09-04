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
///
/// `resource_name` is the human-readable instance name from config (`service_name`,
/// default `"custos"`), intended for display to an end user during an authorization flow.
#[derive(Serialize)]
struct OAuthProtectedResourceMetadata {
    resource: String,
    resource_name: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
    bearer_methods_supported: Vec<String>,
    resource_documentation: String,
}

pub async fn oauth_protected_resource_metadata(State(state): State<AppState>) -> impl IntoResponse {
    let base = state.config.issuer();
    Json(OAuthProtectedResourceMetadata {
        resource: base.to_string(),
        resource_name: state.config.service_name.clone(),
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
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::routes::test_utils;

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

    /// Every field the handler emits, in one whole-document assertion (test_state() sets
    /// service_name = "custos", the default). `scopes_supported` is asserted against
    /// `auth::oauth_scopes::supported_scopes()`, the same source the handler reads — mirrored in
    /// `oauth_server_metadata.rs`'s equivalent test, both discovery documents advertising the
    /// same supported scope surface — rather than a second hand-typed copy of the list.
    #[tokio::test]
    async fn metadata_document_matches_expected_shape() {
        let json = metadata_json().await;
        let scopes_supported: Vec<String> = crate::auth::oauth_scopes::supported_scopes()
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(
            json,
            serde_json::json!({
                "resource": "https://test.example.com",
                "resource_name": "custos",
                "authorization_servers": ["https://test.example.com"],
                "scopes_supported": scopes_supported,
                "bearer_methods_supported": ["header"],
                "resource_documentation": "https://atproto.com",
            })
        );
    }

    #[tokio::test]
    async fn resource_name_reflects_configured_service_name() {
        // Prove the field is sourced from config, not hardcoded: a custom service_name
        // flows through to the advertised resource_name.
        let state = test_utils::state_with(|c| c.service_name = "Custos Relay".to_string()).await;

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

        assert_eq!(json["resource_name"], "Custos Relay");
    }

    #[tokio::test]
    async fn trailing_slash_in_public_url_does_not_affect_resource_origin() {
        let state =
            test_utils::state_with(|c| c.public_url = "https://pds.example.com/".to_string()).await;

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
