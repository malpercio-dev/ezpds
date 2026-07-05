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
/// - `scopes_supported`: the AT Protocol scopes this server recognises.
/// - `dpop_signing_alg_values_supported`: signals that DPoP (RFC 9449) is required.
/// - `token_endpoint_auth_methods_supported`: public clients + private_key_jwt per spec §1.2.
/// - `require_pushed_authorization_requests`: PAR is mandatory per AT Protocol OAuth spec.
/// - `agent_auth`: advertises the auth.md agent-registration discovery surface.
#[derive(Serialize)]
struct OAuthServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    pushed_authorization_request_endpoint: String,
    jwks_uri: String,
    scopes_supported: Vec<String>,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    dpop_signing_alg_values_supported: Vec<String>,
    require_pushed_authorization_requests: bool,
    agent_auth: AgentAuthMetadata,
}

#[derive(Serialize)]
struct AgentAuthMetadata {
    skill: String,
    identity_endpoint: String,
    claim_endpoint: String,
    events_endpoint: String,
    identity_types_supported: Vec<String>,
    identity_assertion: IdentityAssertionMetadata,
    events_supported: Vec<String>,
}

#[derive(Serialize)]
struct IdentityAssertionMetadata {
    assertion_types_supported: Vec<String>,
}

pub async fn oauth_server_metadata(State(state): State<AppState>) -> impl IntoResponse {
    let base = state.config.public_url.trim_end_matches('/');
    Json(OAuthServerMetadata {
        issuer: base.to_string(),
        authorization_endpoint: format!("{base}/oauth/authorize"),
        token_endpoint: format!("{base}/oauth/token"),
        pushed_authorization_request_endpoint: format!("{base}/oauth/par"),
        jwks_uri: format!("{base}/oauth/jwks"),
        scopes_supported: vec!["atproto".to_string(), "transition:generic".to_string()],
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
            "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
            "urn:workos:agent-auth:grant-type:claim".to_string(),
        ],
        token_endpoint_auth_methods_supported: vec![
            "none".to_string(),
            "private_key_jwt".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string()],
        dpop_signing_alg_values_supported: vec!["ES256".to_string()],
        require_pushed_authorization_requests: true,
        agent_auth: AgentAuthMetadata {
            skill: format!("{base}/auth.md"),
            identity_endpoint: format!("{base}/agent/identity"),
            claim_endpoint: format!("{base}/agent/identity/claim"),
            events_endpoint: format!("{base}/agent/event/notify"),
            identity_types_supported: vec![
                "anonymous".to_string(),
                "identity_assertion".to_string(),
                "service_auth".to_string(),
            ],
            identity_assertion: IdentityAssertionMetadata {
                assertion_types_supported: vec![
                    "urn:ietf:params:oauth:token-type:id-jag".to_string()
                ],
            },
            events_supported: vec![
                "https://schemas.workos.com/events/agent/auth/identity/assertion/revoked"
                    .to_string(),
            ],
        },
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
    async fn accessible_without_auth_headers() {
        // Lock in that the discovery endpoint requires no credentials.
        // A future global auth middleware must not inadvertently protect this route.
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
        assert_eq!(json["jwks_uri"], "https://test.example.com/oauth/jwks");
    }

    #[tokio::test]
    async fn scopes_supported_are_atproto_scopes() {
        let json = metadata_json().await;
        assert_eq!(
            json["scopes_supported"],
            serde_json::json!(["atproto", "transition:generic"])
        );
    }

    #[tokio::test]
    async fn response_types_is_exactly_code() {
        let json = metadata_json().await;
        assert_eq!(
            json["response_types_supported"],
            serde_json::json!(["code"])
        );
    }

    #[tokio::test]
    async fn grant_types_include_authorization_code_refresh_token_and_agent_auth_grants() {
        let json = metadata_json().await;
        let grants = json["grant_types_supported"].as_array().unwrap();
        assert!(grants.iter().any(|v| v == "authorization_code"));
        assert!(grants.iter().any(|v| v == "refresh_token"));
        assert!(grants
            .iter()
            .any(|v| v == "urn:ietf:params:oauth:grant-type:jwt-bearer"));
        assert!(grants
            .iter()
            .any(|v| v == "urn:workos:agent-auth:grant-type:claim"));
    }

    #[tokio::test]
    async fn agent_auth_advertises_agent_endpoints_from_public_url() {
        let json = metadata_json().await;
        assert_eq!(
            json["agent_auth"]["skill"],
            "https://test.example.com/auth.md"
        );
        assert_eq!(
            json["agent_auth"]["identity_endpoint"],
            "https://test.example.com/agent/identity"
        );
        assert_eq!(
            json["agent_auth"]["claim_endpoint"],
            "https://test.example.com/agent/identity/claim"
        );
        assert_eq!(
            json["agent_auth"]["events_endpoint"],
            "https://test.example.com/agent/event/notify"
        );
    }

    #[tokio::test]
    async fn agent_auth_advertises_supported_identity_types_assertions_and_events() {
        let json = metadata_json().await;
        assert_eq!(
            json["agent_auth"]["identity_types_supported"],
            serde_json::json!(["anonymous", "identity_assertion", "service_auth"])
        );
        assert_eq!(
            json["agent_auth"]["identity_assertion"]["assertion_types_supported"],
            serde_json::json!(["urn:ietf:params:oauth:token-type:id-jag"])
        );
        assert_eq!(
            json["agent_auth"]["events_supported"],
            serde_json::json!([
                "https://schemas.workos.com/events/agent/auth/identity/assertion/revoked"
            ])
        );
    }

    #[tokio::test]
    async fn token_endpoint_auth_methods_are_none_and_private_key_jwt() {
        let json = metadata_json().await;
        let methods: Vec<&str> = json["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(methods.contains(&"none"), "must support public clients");
        assert!(
            methods.contains(&"private_key_jwt"),
            "must support private_key_jwt per AT Protocol OAuth spec §1.2"
        );
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
    async fn pkce_method_is_exactly_s256() {
        // AT Protocol OAuth prohibits plain — assert the exact set, not just contains.
        let json = metadata_json().await;
        assert_eq!(
            json["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
    }

    #[tokio::test]
    async fn par_is_required() {
        let json = metadata_json().await;
        assert_eq!(json["require_pushed_authorization_requests"], true);
    }

    #[tokio::test]
    async fn trailing_slash_in_public_url_does_not_double_slash_endpoints() {
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

        // URL-bearing fields must not produce "...com//oauth/..." or
        // "...com//agent/..." when public_url has a trailing slash.
        assert_eq!(
            json["authorization_endpoint"],
            "https://pds.example.com/oauth/authorize"
        );
        assert_eq!(
            json["token_endpoint"],
            "https://pds.example.com/oauth/token"
        );
        assert_eq!(
            json["pushed_authorization_request_endpoint"],
            "https://pds.example.com/oauth/par"
        );
        assert_eq!(json["jwks_uri"], "https://pds.example.com/oauth/jwks");
        assert_eq!(
            json["agent_auth"]["skill"],
            "https://pds.example.com/auth.md"
        );
        assert_eq!(
            json["agent_auth"]["identity_endpoint"],
            "https://pds.example.com/agent/identity"
        );
        assert_eq!(
            json["agent_auth"]["claim_endpoint"],
            "https://pds.example.com/agent/identity/claim"
        );
        assert_eq!(
            json["agent_auth"]["events_endpoint"],
            "https://pds.example.com/agent/event/notify"
        );
    }
}
