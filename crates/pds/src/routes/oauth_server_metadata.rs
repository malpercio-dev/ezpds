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
/// - `token_endpoint_auth_signing_alg_values_supported`: the JWS algs accepted for a
///   `private_key_jwt` client-assertion. AT Protocol clients sign these with ES256, and the
///   atproto OAuth metadata validator rejects a server that advertises `private_key_jwt`
///   without this field including `ES256` — omitting it breaks discovery for every client.
/// - `require_pushed_authorization_requests`: PAR is mandatory per AT Protocol OAuth spec.
/// - `authorization_response_iss_parameter_supported`: the AT Protocol OAuth metadata
///   validator requires this to be `true` (the authorization endpoint returns the RFC 9207
///   `iss` parameter in its responses, which `oauth_authorize.rs` emits).
/// - `client_id_metadata_document_supported`: the AT Protocol OAuth metadata validator
///   requires this to be `true` — clients are identified by a client-metadata-document URL
///   rather than pre-registration (resolved in `auth::oauth_client_resolution`).
/// - `agent_auth`: advertises the auth.md agent-registration discovery surface.
/// - `response_modes_supported`: states `query` and `fragment` explicitly rather than relying
///   on the RFC 8414 default, so the metadata stays honest if the authorization endpoint's
///   supported modes ever change.
/// - `request_uri_parameter_supported` / `require_request_uri_registration` /
///   `request_parameter_supported`: the three OpenID Connect Discovery `request`/`request_uri`
///   capability fields, stated explicitly rather than left to their spec defaults — at least
///   one real client (a Laravel atproto app) treats their absence as "legacy server without
///   PAR" and silently downgrades. Only PAR-minted `request_uri` values are ever accepted
///   (`require_request_uri_registration` is `true`, the only value the atproto profile
///   permits), and JAR (RFC 9101) `request` objects are not accepted
///   (`request_parameter_supported` is `false`, diverging from the reference provider's
///   `true`).
#[derive(Serialize)]
struct OAuthServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
    pushed_authorization_request_endpoint: String,
    jwks_uri: String,
    scopes_supported: Vec<String>,
    response_types_supported: Vec<String>,
    /// See the struct doc's `response_modes_supported` bullet.
    response_modes_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    revocation_endpoint_auth_methods_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    dpop_signing_alg_values_supported: Vec<String>,
    require_pushed_authorization_requests: bool,
    /// See the struct doc's `request_uri_parameter_supported` bullet.
    request_uri_parameter_supported: bool,
    /// See the struct doc's `require_request_uri_registration` bullet.
    require_request_uri_registration: bool,
    /// See the struct doc's `request_parameter_supported` bullet.
    request_parameter_supported: bool,
    authorization_response_iss_parameter_supported: bool,
    client_id_metadata_document_supported: bool,
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
    /// This server can end a claim ceremony by minting the agent an account of its own (a
    /// `child` registration) instead of binding it to the confirming user's account. Advertised
    /// statically, like `identity_types_supported`: whether any given ceremony takes that arm is
    /// the confirming human's choice, not a server capability that comes and goes.
    child_provisioning: bool,
}

#[derive(Serialize)]
struct IdentityAssertionMetadata {
    assertion_types_supported: Vec<String>,
}

pub async fn oauth_server_metadata(State(state): State<AppState>) -> impl IntoResponse {
    let base = state.config.issuer();
    Json(OAuthServerMetadata {
        issuer: base.to_string(),
        authorization_endpoint: format!("{base}/oauth/authorize"),
        token_endpoint: format!("{base}/oauth/token"),
        revocation_endpoint: format!("{base}/oauth/revoke"),
        pushed_authorization_request_endpoint: format!("{base}/oauth/par"),
        jwks_uri: format!("{base}/oauth/jwks"),
        scopes_supported: crate::auth::oauth_scopes::supported_scopes()
            .into_iter()
            .map(String::from)
            .collect(),
        response_types_supported: vec!["code".to_string()],
        response_modes_supported: vec!["query".to_string(), "fragment".to_string()],
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
        token_endpoint_auth_signing_alg_values_supported: vec!["ES256".to_string()],
        revocation_endpoint_auth_methods_supported: vec![
            "none".to_string(),
            "private_key_jwt".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string()],
        dpop_signing_alg_values_supported: vec!["ES256".to_string()],
        require_pushed_authorization_requests: true,
        request_uri_parameter_supported: true,
        require_request_uri_registration: true,
        request_parameter_supported: false,
        authorization_response_iss_parameter_supported: true,
        client_id_metadata_document_supported: true,
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
            events_supported: vec![crate::auth::issuer_trust::REVOKED_EVENT_TYPE.to_string()],
            child_provisioning: true,
        },
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

    /// Every field the handler emits, in one whole-document assertion. See `OAuthServerMetadata`'s
    /// struct doc for why each field holds the value it does.
    ///
    /// `scopes_supported` is asserted against `auth::oauth_scopes::supported_scopes()`, the same
    /// source the handler reads, rather than a second hand-typed copy of the list that would
    /// have to be edited in lockstep.
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
                "issuer": "https://test.example.com",
                "authorization_endpoint": "https://test.example.com/oauth/authorize",
                "token_endpoint": "https://test.example.com/oauth/token",
                "revocation_endpoint": "https://test.example.com/oauth/revoke",
                "pushed_authorization_request_endpoint": "https://test.example.com/oauth/par",
                "jwks_uri": "https://test.example.com/oauth/jwks",
                "scopes_supported": scopes_supported,
                "response_types_supported": ["code"],
                "response_modes_supported": ["query", "fragment"],
                "grant_types_supported": [
                    "authorization_code",
                    "refresh_token",
                    "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "urn:workos:agent-auth:grant-type:claim"
                ],
                "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
                "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
                "revocation_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
                "code_challenge_methods_supported": ["S256"],
                "dpop_signing_alg_values_supported": ["ES256"],
                "require_pushed_authorization_requests": true,
                "request_uri_parameter_supported": true,
                "require_request_uri_registration": true,
                "request_parameter_supported": false,
                "authorization_response_iss_parameter_supported": true,
                "client_id_metadata_document_supported": true,
                "agent_auth": {
                    "skill": "https://test.example.com/auth.md",
                    "identity_endpoint": "https://test.example.com/agent/identity",
                    "claim_endpoint": "https://test.example.com/agent/identity/claim",
                    "events_endpoint": "https://test.example.com/agent/event/notify",
                    "identity_types_supported": ["anonymous", "identity_assertion", "service_auth"],
                    "identity_assertion": {
                        "assertion_types_supported": ["urn:ietf:params:oauth:token-type:id-jag"]
                    },
                    "events_supported": [
                        "https://schemas.workos.com/events/agent/auth/identity/assertion/revoked"
                    ],
                    "child_provisioning": true
                }
            })
        );
    }

    #[tokio::test]
    async fn trailing_slash_in_public_url_does_not_double_slash_endpoints() {
        let state =
            test_utils::state_with(|c| c.public_url = "https://pds.example.com/".to_string()).await;

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
            json["revocation_endpoint"],
            "https://pds.example.com/oauth/revoke"
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
