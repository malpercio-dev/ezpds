// pattern: Imperative Shell
//
// Gathers: server metadata from config
// Processes: none (response shape maps 1:1 from config fields)
// Returns: JSON matching com.atproto.server.describeServer Lexicon

use axum::{
    extract::State,
    response::{IntoResponse, Json},
};
use serde::Serialize;

use crate::app::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DescribeServerResponse {
    did: String,
    available_user_domains: Vec<String>,
    invite_code_required: bool,
    phone_verification_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<ServerLinks>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact: Option<Contact>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerLinks {
    #[serde(skip_serializing_if = "Option::is_none")]
    privacy_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    terms_of_service: Option<String>,
}

#[derive(Serialize)]
struct Contact {
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

pub async fn describe_server(State(state): State<AppState>) -> impl IntoResponse {
    let config = &state.config;

    let links = if config.links.privacy_policy.is_some() || config.links.terms_of_service.is_some()
    {
        Some(ServerLinks {
            privacy_policy: config.links.privacy_policy.clone(),
            terms_of_service: config.links.terms_of_service.clone(),
        })
    } else {
        None
    };

    let contact = config.contact.email.as_ref().map(|email| Contact {
        email: Some(email.clone()),
    });

    Json(DescribeServerResponse {
        did: config.resolve_server_did(),
        available_user_domains: config.available_user_domains.clone(),
        invite_code_required: config.invite_code_required,
        phone_verification_required: false,
        links,
        contact,
    })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use std::sync::Arc;

    use crate::app::{app, test_state, AppState};

    #[tokio::test]
    async fn describe_server_did_derived_from_public_url() {
        // test_state() sets public_url = "https://test.example.com", server_did = None
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.describeServer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["did"], "did:web:test.example.com");
    }

    #[tokio::test]
    async fn describe_server_did_from_config() {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.server_did = Some("did:plc:configured123".to_string());
        let state = AppState {
            config: Arc::new(config),
            db: base.db,
            http_client: base.http_client,
            dns_provider: base.dns_provider,
            txt_resolver: base.txt_resolver,
            well_known_resolver: base.well_known_resolver,
            jwt_secret: base.jwt_secret,
            oauth_signing_keypair: base.oauth_signing_keypair,
            dpop_nonces: base.dpop_nonces,
            failed_login_attempts: base.failed_login_attempts,
            firehose: base.firehose,
            crawlers: base.crawlers,
            iroh: base.iroh,
            rate_limiter: base.rate_limiter,
            email: base.email,
            allow_loopback_proxy_targets: base.allow_loopback_proxy_targets,
        };

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.describeServer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["did"], "did:plc:configured123");
    }

    #[tokio::test]
    async fn describe_server_returns_200() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.describeServer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn describe_server_has_json_content_type() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.describeServer")
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
    async fn describe_server_available_user_domains_from_config() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.describeServer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["availableUserDomains"][0], "example.com");
    }

    #[tokio::test]
    async fn describe_server_invite_code_required_from_config() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.describeServer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["inviteCodeRequired"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn describe_server_phone_verification_required_is_false() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.describeServer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(!json["phoneVerificationRequired"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn describe_server_omits_links_when_not_configured() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.describeServer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json.get("links").is_none());
    }

    #[tokio::test]
    async fn describe_server_omits_contact_when_not_configured() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.describeServer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json.get("contact").is_none());
    }
}
