// pattern: Imperative Shell
//
// Gathers: AppState (DB), form body (authorization request parameters)
// Processes: client lookup → redirect_uri validation → param validation → DB store
// Returns:
//   POST: 201 JSON { request_uri, expires_in } on success
//         400 JSON { error, error_description } on invalid request (RFC 9126 §2.3)

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Form, Json,
};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::db::oauth::{
    cleanup_expired_par_requests, get_oauth_client, store_par_request, StoredPARParams,
};
use crate::routes::token::generate_token;

// ── Request / response types ──────────────────────────────────────────────────

/// Form body for `POST /oauth/par` (application/x-www-form-urlencoded).
///
/// Accepts the same authorization request parameters as `GET /oauth/authorize`
/// so clients can push large parameter sets before sending the user to the auth endpoint.
#[derive(Debug, Deserialize)]
pub struct PARForm {
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub state: Option<String>,
    pub response_type: Option<String>,
    pub scope: Option<String>,
    pub login_hint: Option<String>,
}

/// Successful PAR response body (RFC 9126 §2.2).
#[derive(Debug, Serialize)]
pub struct PARResponse {
    pub request_uri: String,
    pub expires_in: u32,
}

/// OAuth 2.0 error response (RFC 6749 §5.2 / RFC 9126 §2.3).
struct PARError {
    error: &'static str,
    error_description: &'static str,
}

impl PARError {
    fn new(error: &'static str, error_description: &'static str) -> Self {
        Self {
            error,
            error_description,
        }
    }
}

impl IntoResponse for PARError {
    fn into_response(self) -> Response {
        let status = if self.error == "server_error" {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::BAD_REQUEST
        };
        (
            status,
            Json(serde_json::json!({
                "error": self.error,
                "error_description": self.error_description,
            })),
        )
            .into_response()
    }
}

// ── Handler ───────────────────────────────────────────────────────────────────

/// `POST /oauth/par` — accept pushed authorization request parameters.
///
/// Clients POST their authorization parameters here first, receiving back an opaque
/// `request_uri` they then pass to `GET /oauth/authorize?request_uri=...`. This keeps
/// large payloads (DPoP key assertions, PKCE challenges) out of query strings and
/// browser history (RFC 9126).
pub async fn post_par(State(state): State<AppState>, Form(form): Form<PARForm>) -> Response {
    let client_id = match form.client_id.as_deref().filter(|s| !s.is_empty()) {
        Some(id) => id.to_string(),
        None => return PARError::new("invalid_request", "client_id is required").into_response(),
    };

    let redirect_uri = match form.redirect_uri.as_deref().filter(|s| !s.is_empty()) {
        Some(u) => u.to_string(),
        None => {
            return PARError::new("invalid_request", "redirect_uri is required").into_response()
        }
    };

    let code_challenge = match form.code_challenge.as_deref().filter(|s| !s.is_empty()) {
        Some(c) => c.to_string(),
        None => {
            return PARError::new("invalid_request", "code_challenge is required").into_response()
        }
    };

    let code_challenge_method = match form
        .code_challenge_method
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        Some(m) => m.to_string(),
        None => {
            return PARError::new("invalid_request", "code_challenge_method is required")
                .into_response()
        }
    };

    let state_param = match form.state.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None => return PARError::new("invalid_request", "state is required").into_response(),
    };

    let response_type = match form.response_type.as_deref().filter(|s| !s.is_empty()) {
        Some(r) => r.to_string(),
        None => {
            return PARError::new("invalid_request", "response_type is required").into_response()
        }
    };

    let scope = form
        .scope
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("atproto")
        .to_string();

    // Look up the registered client and validate redirect_uri.
    let client = match get_oauth_client(&state.db, &client_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return PARError::new("invalid_client", "client_id is not registered").into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "db error looking up OAuth client in PAR");
            return PARError::new("server_error", "database error").into_response();
        }
    };

    let metadata: serde_json::Value = match serde_json::from_str(&client.client_metadata) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(
                client_id = %client_id,
                error = %e,
                "failed to parse stored client metadata in PAR"
            );
            return PARError::new("server_error", "client metadata is malformed").into_response();
        }
    };

    let registered_redirect_uris: Vec<String> = metadata["redirect_uris"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    if !registered_redirect_uris.contains(&redirect_uri) {
        return PARError::new(
            "invalid_request",
            "redirect_uri does not match registered URIs",
        )
        .into_response();
    }

    if response_type != "code" {
        return PARError::new(
            "unsupported_response_type",
            "only response_type=code is supported",
        )
        .into_response();
    }

    if code_challenge_method != "S256" {
        return PARError::new("invalid_request", "code_challenge_method must be S256")
            .into_response();
    }

    let params = StoredPARParams {
        redirect_uri,
        code_challenge,
        code_challenge_method,
        state: state_param,
        response_type,
        scope,
        login_hint: form.login_hint.filter(|s| !s.is_empty()),
    };

    let params_json = match serde_json::to_string(&params) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(client_id = %client_id, error = %e, "failed to serialize PAR params to JSON");
            return PARError::new("server_error", "failed to serialize request parameters")
                .into_response();
        }
    };

    // Generate the opaque request_uri token. The plaintext is used as the URN reference.
    let token = generate_token();
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", token.plaintext);

    if let Err(e) = store_par_request(&state.db, &request_uri, &client_id, &params_json).await {
        tracing::error!(error = %e, "failed to store PAR request");
        return PARError::new("server_error", "failed to store authorization request")
            .into_response();
    }

    if let Err(e) = cleanup_expired_par_requests(&state.db).await {
        tracing::warn!(error = %e, "failed to cleanup expired PAR requests");
    }

    (
        StatusCode::CREATED,
        Json(PARResponse {
            request_uri,
            expires_in: 60,
        }),
    )
        .into_response()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::db::oauth::register_oauth_client;

    const CLIENT_ID: &str = "https://app.example.com/client-metadata.json";
    const REDIRECT_URI: &str = "https://app.example.com/callback";
    const CLIENT_METADATA: &str =
        r#"{"redirect_uris":["https://app.example.com/callback"],"client_name":"Test App"}"#;

    /// Build a form-urlencoded body for POST /oauth/par.
    ///
    /// Pass `overrides` to replace specific field values. Pass `("field", "")` to
    /// simulate a missing/empty required field.
    ///
    /// Note: values are NOT percent-encoded. Test data is chosen to contain only
    /// characters safe in form values (no `&`, `=`, `+`, `?`). Do not add test
    /// values that contain these characters without first encoding them.
    fn par_body(overrides: &[(&str, &str)]) -> String {
        let mut fields = vec![
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT_URI),
            ("code_challenge", "abc123challengevalue"),
            ("code_challenge_method", "S256"),
            ("state", "state-value-xyz"),
            ("response_type", "code"),
            ("scope", "atproto"),
        ];
        for (k, v) in overrides {
            if let Some(pos) = fields.iter().position(|(fk, _)| fk == k) {
                fields[pos] = (k, v);
            } else {
                fields.push((k, v));
            }
        }
        fields
            .iter()
            .filter(|(_, v)| !v.is_empty()) // empty value = omit the field entirely
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&")
    }

    async fn register_client(state: &crate::app::AppState) {
        register_oauth_client(&state.db, CLIENT_ID, CLIENT_METADATA)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn post_par_returns_201_with_request_uri_and_expires_in() {
        let state = test_state().await;
        register_client(&state).await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let request_uri = json["request_uri"]
            .as_str()
            .expect("request_uri must be present");
        assert!(
            request_uri.starts_with("urn:ietf:params:oauth:request_uri:"),
            "request_uri must use the OAuth PAR URN scheme"
        );
        assert_eq!(json["expires_in"].as_u64(), Some(60));
    }

    #[tokio::test]
    async fn post_par_returns_400_for_unknown_client() {
        let state = test_state().await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"].as_str(), Some("invalid_client"));
    }

    #[tokio::test]
    async fn post_par_returns_400_for_invalid_redirect_uri() {
        let state = test_state().await;
        register_client(&state).await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[(
                        "redirect_uri",
                        "https://evil.example.com/cb",
                    )])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"].as_str(), Some("invalid_request"));
    }

    #[tokio::test]
    async fn post_par_returns_400_for_unsupported_response_type() {
        let state = test_state().await;
        register_client(&state).await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[("response_type", "token")])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"].as_str(), Some("unsupported_response_type"));
    }

    #[tokio::test]
    async fn post_par_returns_400_for_non_s256_challenge_method() {
        let state = test_state().await;
        register_client(&state).await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[("code_challenge_method", "plain")])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"].as_str(), Some("invalid_request"));
    }

    #[tokio::test]
    async fn post_par_returns_400_when_client_id_missing() {
        let state = test_state().await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[("client_id", "")])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"].as_str(), Some("invalid_request"));
    }

    #[tokio::test]
    async fn post_par_returns_400_when_redirect_uri_missing() {
        let state = test_state().await;
        register_client(&state).await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[("redirect_uri", "")])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"].as_str(), Some("invalid_request"));
    }

    #[tokio::test]
    async fn post_par_returns_400_when_code_challenge_missing() {
        let state = test_state().await;
        register_client(&state).await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[("code_challenge", "")])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"].as_str(), Some("invalid_request"));
    }

    #[tokio::test]
    async fn post_par_returns_400_when_code_challenge_method_missing() {
        let state = test_state().await;
        register_client(&state).await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[("code_challenge_method", "")])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"].as_str(), Some("invalid_request"));
    }

    #[tokio::test]
    async fn post_par_returns_400_when_state_missing() {
        let state = test_state().await;
        register_client(&state).await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[("state", "")])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"].as_str(), Some("invalid_request"));
    }

    #[tokio::test]
    async fn post_par_returns_400_when_response_type_missing() {
        let state = test_state().await;
        register_client(&state).await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[("response_type", "")])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"].as_str(), Some("invalid_request"));
    }

    #[tokio::test]
    async fn post_par_returns_distinct_request_uri_per_call() {
        let state = test_state().await;
        register_client(&state).await;

        async fn call_par(state: crate::app::AppState, body: String) -> String {
            let response = app(state)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/oauth/par")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            json["request_uri"].as_str().unwrap().to_string()
        }

        let state1 = test_state().await;
        register_oauth_client(&state1.db, CLIENT_ID, CLIENT_METADATA)
            .await
            .unwrap();
        let state2 = state1.clone();

        let uri1 = call_par(state1, par_body(&[])).await;
        let uri2 = call_par(state2, par_body(&[])).await;

        assert_ne!(
            uri1, uri2,
            "each PAR call must produce a unique request_uri"
        );
    }

    #[tokio::test]
    async fn post_par_accepts_optional_login_hint() {
        let state = test_state().await;
        register_client(&state).await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[("login_hint", "alice.example.com")])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "PAR with login_hint must succeed"
        );
    }
}
