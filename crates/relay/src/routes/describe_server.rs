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

/// Resolve the DID to return in the `did` field.
///
/// The ATProto Lexicon marks `did` as required, but in Wave 1 the server DID may not be
/// configured — DID generation is deferred to Wave 3. This function decides what to surface
/// in the meantime.
///
/// TODO: implement this function (5-10 lines).
///
/// Parameters:
///   - `server_did`: the configured `server_did` value, if any
///   - `public_url`: the server's configured public URL (e.g. "https://pds.example.com")
///
/// Consider the trade-offs:
///   - Returning `""` is the simplest option; the Bluesky app tolerates it during initial setup
///   - Deriving `did:web:<hostname>` from `public_url` is a valid DID and more semantically correct
///   - Whatever you choose becomes the pattern for how Wave 3 replaces the placeholder
fn resolve_did(server_did: &Option<String>, public_url: &str) -> String {
    if let Some(did) = server_did {
        return did.clone();
    }
    let host = public_url
        .strip_prefix("https://")
        .or_else(|| public_url.strip_prefix("http://"))
        .unwrap_or(public_url)
        .split('/')
        .next()
        .unwrap_or("");
    format!("did:web:{host}")
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
        did: resolve_did(&config.server_did, &config.public_url),
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

    use crate::app::{app, test_state};

    #[test]
    fn resolve_did_returns_configured_did() {
        let did = super::resolve_did(&Some("did:plc:abc123".to_string()), "https://pds.example.com");
        assert_eq!(did, "did:plc:abc123");
    }

    #[test]
    fn resolve_did_derives_did_web_from_public_url() {
        let did = super::resolve_did(&None, "https://pds.example.com");
        assert_eq!(did, "did:web:pds.example.com");
    }

    #[test]
    fn resolve_did_did_web_strips_path() {
        let did = super::resolve_did(&None, "https://pds.example.com/some/path");
        assert_eq!(did, "did:web:pds.example.com");
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

        assert_eq!(json["availableUserDomains"][0], "test.example.com");
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
