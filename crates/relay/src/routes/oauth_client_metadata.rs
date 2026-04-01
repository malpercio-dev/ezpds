// pattern: Imperative Shell
//
// Gathers: public_url from AppState config
// Processes: none (static JSON shape with dynamic client_id from config)
// Returns: OAuth client metadata JSON per AT Protocol spec

use axum::{extract::State, response::IntoResponse, Json};
use serde::Serialize;

use crate::app::AppState;

#[derive(Serialize)]
struct ClientMetadata {
    client_id: String,
    client_name: &'static str,
    client_uri: String,
    application_type: &'static str,
    grant_types: Vec<&'static str>,
    response_types: Vec<&'static str>,
    redirect_uris: Vec<&'static str>,
    scope: &'static str,
    dpop_bound_access_tokens: bool,
    token_endpoint_auth_method: &'static str,
}

pub async fn oauth_client_metadata(State(state): State<AppState>) -> impl IntoResponse {
    let base = state.config.public_url.trim_end_matches('/');
    let client_id = format!("{base}/oauth/client-metadata.json");

    Json(ClientMetadata {
        client_id,
        client_name: "Identity Wallet",
        client_uri: base.to_string(),
        application_type: "native",
        grant_types: vec!["authorization_code", "refresh_token"],
        response_types: vec!["code"],
        redirect_uris: vec!["dev.malpercio.identitywallet:/oauth/callback"],
        scope: "atproto transition:generic",
        dpop_bound_access_tokens: true,
        token_endpoint_auth_method: "none",
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

    #[tokio::test]
    async fn client_metadata_returns_200_with_correct_client_id() {
        let state = test_state().await;
        let response = app(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/oauth/client-metadata.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // client_id must be the full URL to this endpoint
        assert_eq!(
            json["client_id"],
            format!(
                "{}/oauth/client-metadata.json",
                state.config.public_url.trim_end_matches('/')
            )
        );
        assert_eq!(json["application_type"], "native");
        assert_eq!(json["dpop_bound_access_tokens"], true);
        assert_eq!(json["token_endpoint_auth_method"], "none");
    }

    #[tokio::test]
    async fn client_metadata_has_json_content_type() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/oauth/client-metadata.json")
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
    async fn client_metadata_redirect_uri_matches_wallet() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/oauth/client-metadata.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let uris = json["redirect_uris"].as_array().unwrap();
        assert!(uris
            .iter()
            .any(|u| u == "dev.malpercio.identitywallet:/oauth/callback"));
    }
}
