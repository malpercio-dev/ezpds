// pattern: Imperative Shell
//
// Gathers: Path param (device_id), Authorization header, AppState (config)
// Processes: device_token auth → read relay URLs from config
// Returns: JSON { relay_url, websocket_url, iroh_endpoint? } on success; ApiError on failure

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Json,
};
use serde::Serialize;

use common::ApiError;

use crate::app::AppState;
use crate::routes::auth::require_device_token;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDeviceRelayResponse {
    relay_url: String,
    websocket_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    iroh_endpoint: Option<String>,
}

pub async fn get_device_relay(
    Path(device_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<GetDeviceRelayResponse>, ApiError> {
    require_device_token(&headers, &device_id, &state.db).await?;

    let relay_url = state.config.public_url.clone();
    // validate_and_build enforces public_url.starts_with("https://"), so this substitution
    // always produces a wss:// URL. The assert catches any future relaxation of that invariant.
    debug_assert!(
        relay_url.starts_with("https://"),
        "public_url must start with https://, got: {relay_url:?}"
    );
    let websocket_url = relay_url.replacen("https://", "wss://", 1);
    let iroh_endpoint = state.config.iroh.endpoint.clone();

    Ok(Json(GetDeviceRelayResponse {
        relay_url,
        websocket_url,
        iroh_endpoint,
    }))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::routes::test_utils::{body_json, seed_device};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn get_device_relay(device_id: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(format!("/v1/devices/{device_id}/relay"))
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    fn get_device_relay_no_auth(device_id: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(format!("/v1/devices/{device_id}/relay"))
            .body(Body::empty())
            .unwrap()
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn authenticated_device_returns_200() {
        let state = test_state().await;
        let (device_id, token) = seed_device(&state.db).await;

        let response = app(state)
            .oneshot(get_device_relay(&device_id, &token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn relay_url_matches_config_public_url() {
        let state = test_state().await;
        let (device_id, token) = seed_device(&state.db).await;
        let expected = state.config.public_url.clone();

        let response = app(state)
            .oneshot(get_device_relay(&device_id, &token))
            .await
            .unwrap();

        let json = body_json(response).await;
        assert_eq!(json["relayUrl"], expected);
    }

    #[tokio::test]
    async fn websocket_url_uses_wss_scheme() {
        let state = test_state().await;
        let (device_id, token) = seed_device(&state.db).await;
        // public_url is "https://test.example.com" in test_state
        let expected_ws = "wss://test.example.com";

        let response = app(state)
            .oneshot(get_device_relay(&device_id, &token))
            .await
            .unwrap();

        let json = body_json(response).await;
        assert_eq!(json["websocketUrl"], expected_ws);
    }

    #[tokio::test]
    async fn iroh_endpoint_absent_when_not_configured() {
        // IrohConfig.endpoint defaults to None — field must be omitted from JSON
        let state = test_state().await;
        let (device_id, token) = seed_device(&state.db).await;

        let response = app(state)
            .oneshot(get_device_relay(&device_id, &token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert!(
            !json.as_object().unwrap().contains_key("irohEndpoint"),
            "irohEndpoint key must be absent from JSON when not configured; got: {json}"
        );
    }

    #[tokio::test]
    async fn iroh_endpoint_present_when_configured() {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.iroh.endpoint = Some("abc123nodeid".to_string());
        let state = crate::app::AppState {
            config: Arc::new(config),
            ..base
        };
        let (device_id, token) = seed_device(&state.db).await;

        let response = app(state)
            .oneshot(get_device_relay(&device_id, &token))
            .await
            .unwrap();

        let json = body_json(response).await;
        assert_eq!(json["irohEndpoint"], "abc123nodeid");
    }

    #[tokio::test]
    async fn websocket_url_is_derived_from_relay_url_by_replacing_https_scheme() {
        // Documents the invariant: websocketUrl is always relay_url with https:// → wss://.
        // validate_and_build requires public_url to start with https://, so this is safe.
        let state = test_state().await;
        let (device_id, token) = seed_device(&state.db).await;

        let response = app(state.clone())
            .oneshot(get_device_relay(&device_id, &token))
            .await
            .unwrap();

        let json = body_json(response).await;
        let relay_url = json["relayUrl"].as_str().unwrap();
        let websocket_url = json["websocketUrl"].as_str().unwrap();
        assert!(
            relay_url.starts_with("https://"),
            "relayUrl must start with https://"
        );
        assert_eq!(websocket_url, relay_url.replacen("https://", "wss://", 1));
    }

    // ── Auth failures ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn unauthenticated_request_returns_401() {
        let state = test_state().await;
        let (device_id, _) = seed_device(&state.db).await;

        let response = app(state)
            .oneshot(get_device_relay_no_auth(&device_id))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_device_token_returns_401() {
        let state = test_state().await;
        let (device_id, _) = seed_device(&state.db).await;
        let wrong_token = crate::routes::token::generate_token().plaintext;

        let response = app(state)
            .oneshot(get_device_relay(&device_id, &wrong_token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_token_for_different_device_returns_401() {
        // Token belongs to device A but path is device B — must be rejected
        let state = test_state().await;
        let (device_a_id, token_a) = seed_device(&state.db).await;
        let (device_b_id, _) = seed_device(&state.db).await;
        let _ = device_a_id;

        let response = app(state)
            .oneshot(get_device_relay(&device_b_id, &token_a))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
