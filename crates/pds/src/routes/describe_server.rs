// pattern: Imperative Shell
//
// Gathers: server metadata from config
// Processes: capability derivation delegated to the pure `capabilities` module
// Returns: JSON matching com.atproto.server.describeServer Lexicon, plus the `custos`
//          capability extension

//! `GET /xrpc/com.atproto.server.describeServer` — the lexicon fields plus the
//! off-lexicon `custos` extension.
//!
//! The extension is `{version, capabilities}`, derived by `crate::capabilities` from
//! the running config. Lexicon objects are open, so the extension is additive — a
//! client that does not know the field ignores it — and a single distinctively-named
//! key avoids the collision hazard of a generic name the lexicon authority could later
//! claim (millipds already ships a top-level `version` with different semantics).

use axum::{
    extract::State,
    response::{IntoResponse, Json},
};
use serde::Serialize;

use crate::app::AppState;
use crate::capabilities;

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
    /// Off-lexicon Custos extension. Lexicon objects are open — a client that does not
    /// know this field ignores it — and a single distinctively-named key avoids the
    /// collision hazard of a generic name the lexicon authority could later claim
    /// (millipds already ships a top-level `version` with different semantics).
    custos: CustosExtension,
}

/// What this deployment is and what it offers. See `crate::capabilities`.
#[derive(Serialize)]
struct CustosExtension {
    version: &'static str,
    capabilities: Vec<&'static str>,
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
        custos: CustosExtension {
            version: capabilities::VERSION,
            capabilities: capabilities::advertised(config),
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
            ..base
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

    async fn describe(state: AppState) -> serde_json::Value {
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
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn describe_server_carries_the_custos_extension() {
        let json = describe(test_state().await).await;

        assert_eq!(json["custos"]["version"], env!("CARGO_PKG_VERSION"));
        assert!(
            json["custos"]["capabilities"].is_array(),
            "capabilities must be an array, got {}",
            json["custos"]["capabilities"]
        );
    }

    #[tokio::test]
    async fn describe_server_capabilities_track_the_running_config() {
        // The shared test config has no master key, so the two capabilities that need one
        // are withheld; the inherent ones are always offered.
        let json = describe(test_state().await).await;
        let capabilities: Vec<String> =
            serde_json::from_value(json["custos"]["capabilities"].clone()).unwrap();

        assert!(!capabilities.contains(&"createCeremony".to_string()));
        assert!(!capabilities.contains(&"escrow".to_string()));
        assert!(capabilities.contains(&"sovereignSessions".to_string()));
        assert!(capabilities.contains(&"walletConsent".to_string()));
        assert!(capabilities.contains(&"didWebHosting".to_string()));
    }

    #[tokio::test]
    async fn describe_server_advertises_master_key_capabilities_when_configured() {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new([9u8; 32])));
        let state = AppState {
            config: Arc::new(config),
            ..base
        };

        let json = describe(state).await;
        let capabilities: Vec<String> =
            serde_json::from_value(json["custos"]["capabilities"].clone()).unwrap();

        assert!(capabilities.contains(&"createCeremony".to_string()));
        assert!(capabilities.contains(&"escrow".to_string()));
    }

    #[tokio::test]
    async fn describe_server_still_carries_every_lexicon_field() {
        // The extension is additive: a client that ignores `custos` sees exactly the
        // response it saw before.
        let json = describe(test_state().await).await;

        for field in [
            "did",
            "availableUserDomains",
            "inviteCodeRequired",
            "phoneVerificationRequired",
        ] {
            assert!(json.get(field).is_some(), "missing lexicon field {field}");
        }
    }
}
