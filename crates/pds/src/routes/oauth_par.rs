// pattern: Imperative Shell
//
// Gathers: AppState (DB + outbound HTTP client), form body (authorization request parameters)
// Processes: client lookup (with ATProto URL-client_id metadata resolution on a cache miss)
//            → redirect_uri validation → param validation → DB store
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
    cleanup_expired_par_requests, get_oauth_client, store_par_request, upsert_oauth_client,
    ClientMetadata, StoredPARParams,
};
use crate::token::generate_token;

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
    error_description: String,
}

impl PARError {
    fn new(error: &'static str, error_description: impl Into<String>) -> Self {
        Self {
            error,
            error_description: error_description.into(),
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

// ── Redirect-URI policy ───────────────────────────────────────────────────────

/// atproto OAuth: for a discoverable (URL) client_id, a private-use-scheme redirect
/// URI's scheme must be the client_id host's FQDN in reverse order (e.g. client_id
/// host `identitywallet.obsign.org` ⇒ scheme `org.obsign.identitywallet`). This binds
/// the custom scheme to a domain the client demonstrably controls — without it, any
/// app could register a metadata document listing another app's callback scheme.
///
/// The rule only applies to https client_ids (discoverable metadata): loopback-http
/// client_ids are the spec's local-development exception with no meaningful domain,
/// non-URL client_ids are operator-registered rows the rule predates, and http(s)
/// redirect URIs are not private-use schemes.
fn validate_private_use_redirect(client_id: &str, redirect_uri: &str) -> Result<(), String> {
    let Ok(client_url) = url::Url::parse(client_id) else {
        return Ok(());
    };
    if client_url.scheme() != "https" {
        return Ok(());
    }
    let Ok(redirect_url) = url::Url::parse(redirect_uri) else {
        return Ok(());
    };
    let scheme = redirect_url.scheme();
    if scheme == "http" || scheme == "https" {
        return Ok(());
    }
    let Some(host) = client_url.host_str() else {
        return Ok(());
    };
    let reversed = host.split('.').rev().collect::<Vec<_>>().join(".");
    if scheme.eq_ignore_ascii_case(&reversed) {
        Ok(())
    } else {
        Err(format!(
            "Private-Use URI Scheme redirect URI, for discoverable client metadata, \
             must be the fully qualified domain name (FQDN) of the client_id, \
             in reverse order ({reversed}:)"
        ))
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

    // Validate & canonically normalize the requested granular scopes; a malformed
    // or unsupported scope is rejected up-front (RFC 6749 §4.1.2.1 `invalid_scope`).
    let requested_scope = form
        .scope
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("atproto");
    let scope = match crate::auth::oauth_scopes::normalize_scope_request(requested_scope) {
        Ok(s) => s,
        Err(desc) => return PARError::new("invalid_scope", desc).into_response(),
    };

    // Look up the client: registered/cached rows first; on a miss, a URL-shaped
    // client_id is resolved by fetching its metadata document (ATProto OAuth —
    // client_id IS the metadata URL). The fetched document is only cached below,
    // after the whole request validates.
    let known_client = match get_oauth_client(&state.db, &client_id).await {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(error = %e, "db error looking up OAuth client in PAR");
            return PARError::new("server_error", "database error").into_response();
        }
    };
    let (client_metadata_json, freshly_fetched) = match known_client {
        Some(row) => (row.client_metadata, false),
        None if client_id.starts_with("https://") || client_id.starts_with("http://") => {
            match crate::oauth_client_resolution::resolve_client_metadata(
                &state.http_client,
                &client_id,
            )
            .await
            {
                Ok(json) => (json, true),
                Err(e) => {
                    tracing::info!(client_id = %client_id, error = %e, "URL client_id resolution failed in PAR");
                    return PARError::new("invalid_client", e.to_string()).into_response();
                }
            }
        }
        None => {
            return PARError::new("invalid_client", "client_id is not registered").into_response()
        }
    };

    let metadata: ClientMetadata = match serde_json::from_str(&client_metadata_json) {
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

    if !metadata.redirect_uris.contains(&redirect_uri) {
        return PARError::new(
            "invalid_request",
            "redirect_uri does not match registered URIs",
        )
        .into_response();
    }

    if let Err(desc) = validate_private_use_redirect(&client_id, &redirect_uri) {
        return PARError::new("invalid_redirect_uri", desc).into_response();
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

    // The request has fully validated — now cache a freshly resolved metadata document
    // so the authorize/token endpoints' client lookups find it. Caching only after full
    // validation keeps rejected requests from planting rows.
    if freshly_fetched {
        if let Err(e) = upsert_oauth_client(&state.db, &client_id, &client_metadata_json).await {
            tracing::error!(error = %e, client_id = %client_id, "failed to cache resolved OAuth client metadata");
            return PARError::new("server_error", "database error").into_response();
        }
    }

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

        // A non-URL client_id exercises the registered-only path: a URL-shaped one
        // would instead attempt live metadata resolution (covered by its own tests).
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[(
                        "client_id",
                        "dev.unregistered.client",
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

    /// Serve a client-metadata document at `/oauth/client-metadata.json` on an ephemeral
    /// loopback port; returns the document's URL (which doubles as the client_id). The JSON
    /// is produced by `make_json(url)` so the document can reference its own URL as
    /// `client_id`, mirroring a real ATProto OAuth client metadata document.
    async fn serve_client_metadata(make_json: impl FnOnce(&str) -> String) -> String {
        use std::future::IntoFuture;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://127.0.0.1:{}/oauth/client-metadata.json",
            listener.local_addr().unwrap().port()
        );
        let json = make_json(&url);
        let router = axum::Router::new().route(
            "/oauth/client-metadata.json",
            axum::routing::get(move || {
                let json = json.clone();
                async move { ([("content-type", "application/json")], json) }
            }),
        );
        tokio::spawn(axum::serve(listener, router).into_future());
        url
    }

    async fn par_with_client_id(
        state: crate::app::AppState,
        client_id: &str,
    ) -> axum::response::Response {
        app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[("client_id", client_id)])))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn error_json(response: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn post_par_fetches_and_caches_metadata_for_unregistered_url_client_id() {
        let state = test_state().await;
        let client_id = serve_client_metadata(|url| {
            serde_json::json!({
                "client_id": url,
                "redirect_uris": [REDIRECT_URI],
                "client_name": "Fetched Test App",
            })
            .to_string()
        })
        .await;

        let response = par_with_client_id(state.clone(), &client_id).await;

        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "PAR must resolve an unregistered URL client_id by fetching its metadata document"
        );
        let cached = crate::db::oauth::get_oauth_client(&state.db, &client_id)
            .await
            .unwrap();
        assert!(
            cached.is_some(),
            "fetched metadata must be cached so authorize/token lookups find the client"
        );
    }

    #[tokio::test]
    async fn post_par_rejects_url_client_metadata_with_mismatched_client_id() {
        let state = test_state().await;
        let client_id = serve_client_metadata(|_url| {
            serde_json::json!({
                "client_id": "https://elsewhere.example.com/client-metadata.json",
                "redirect_uris": [REDIRECT_URI],
            })
            .to_string()
        })
        .await;

        let response = par_with_client_id(state.clone(), &client_id).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = error_json(response).await;
        assert_eq!(json["error"].as_str(), Some("invalid_client"));
        assert!(
            json["error_description"]
                .as_str()
                .unwrap()
                .contains("client_id mismatch"),
            "mismatch must be reported distinctly, got: {}",
            json["error_description"]
        );
        let cached = crate::db::oauth::get_oauth_client(&state.db, &client_id)
            .await
            .unwrap();
        assert!(cached.is_none(), "mismatched metadata must not be cached");
    }

    #[tokio::test]
    async fn post_par_rejects_url_client_when_redirect_uri_not_listed() {
        let state = test_state().await;
        let client_id = serve_client_metadata(|url| {
            serde_json::json!({
                "client_id": url,
                "redirect_uris": ["https://other.example.com/cb"],
            })
            .to_string()
        })
        .await;

        let response = par_with_client_id(state.clone(), &client_id).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = error_json(response).await;
        assert_eq!(
            json["error"].as_str(),
            Some("invalid_request"),
            "resolved-but-unlisted redirect_uri is an invalid_request, not an unknown client"
        );
        let cached = crate::db::oauth::get_oauth_client(&state.db, &client_id)
            .await
            .unwrap();
        assert!(
            cached.is_none(),
            "metadata must only be cached after the PAR fully validates"
        );
    }

    #[tokio::test]
    async fn post_par_rejects_unreachable_url_client_id() {
        let state = test_state().await;
        // Bind then immediately drop a listener to obtain a loopback port that refuses
        // connections — a deterministic "metadata document unreachable" target.
        let port = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let client_id = format!("http://127.0.0.1:{port}/oauth/client-metadata.json");

        let response = par_with_client_id(state, &client_id).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = error_json(response).await;
        assert_eq!(json["error"].as_str(), Some("invalid_client"));
        assert!(
            json["error_description"]
                .as_str()
                .unwrap()
                .contains("failed to fetch"),
            "unreachable metadata must be reported as a fetch failure, got: {}",
            json["error_description"]
        );
    }

    #[tokio::test]
    async fn post_par_rejects_http_url_client_id_for_non_loopback_host() {
        let state = test_state().await;

        let response =
            par_with_client_id(state, "http://app.example.com/client-metadata.json").await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = error_json(response).await;
        assert_eq!(json["error"].as_str(), Some("invalid_client"));
        assert!(
            json["error_description"].as_str().unwrap().contains("https"),
            "plain-http client_id on a non-loopback host must be rejected before any fetch, got: {}",
            json["error_description"]
        );
    }

    // ── Reverse-FQDN rule for private-use-scheme redirect URIs ─────────────────

    #[test]
    fn private_use_redirect_scheme_must_reverse_client_id_host() {
        use super::validate_private_use_redirect;

        // Matching reverse-FQDN passes.
        assert!(validate_private_use_redirect(
            "https://identitywallet.obsign.org/oauth/client-metadata.json",
            "org.obsign.identitywallet:/oauth/callback",
        )
        .is_ok());

        // Mismatched scheme is rejected, naming the required scheme.
        let err = validate_private_use_redirect(
            "https://ezpds-staging.up.railway.app/oauth/client-metadata.json",
            "dev.malpercio.identitywallet:/oauth/callback",
        )
        .unwrap_err();
        assert!(
            err.contains("app.railway.up.ezpds-staging:"),
            "the error must name the required reverse-FQDN scheme, got: {err}"
        );

        // Scheme comparison is case-insensitive.
        assert!(validate_private_use_redirect(
            "https://IdentityWallet.Obsign.Org/oauth/client-metadata.json",
            "org.obsign.identitywallet:/oauth/callback",
        )
        .is_ok());
    }

    #[test]
    fn private_use_redirect_rule_exemptions() {
        use super::validate_private_use_redirect;

        // https redirect URIs are not private-use schemes.
        assert!(validate_private_use_redirect(
            "https://app.example.com/client-metadata.json",
            "https://app.example.com/callback",
        )
        .is_ok());

        // Loopback-http client_ids (local development) are exempt.
        assert!(validate_private_use_redirect(
            "http://localhost:8080/oauth/client-metadata.json",
            "org.obsign.identitywallet:/oauth/callback",
        )
        .is_ok());

        // Non-URL client_ids (operator-registered rows) are exempt.
        assert!(validate_private_use_redirect(
            "dev.malpercio.identitywallet",
            "dev.malpercio.identitywallet:/oauth/callback",
        )
        .is_ok());
    }

    #[tokio::test]
    async fn post_par_rejects_private_use_redirect_not_matching_reverse_fqdn() {
        let state = test_state().await;
        // A registered discoverable client whose metadata lists a custom-scheme
        // redirect that does NOT reverse the client_id host.
        register_oauth_client(
            &state.db,
            CLIENT_ID,
            r#"{"redirect_uris":["dev.other.app:/oauth/callback"],"client_name":"Test App"}"#,
        )
        .await
        .unwrap();

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[(
                        "redirect_uri",
                        "dev.other.app:/oauth/callback",
                    )])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = error_json(response).await;
        assert_eq!(json["error"].as_str(), Some("invalid_redirect_uri"));
        assert!(
            json["error_description"]
                .as_str()
                .unwrap()
                .contains("com.example.app:"),
            "the rejection must name the required reverse-FQDN scheme, got: {}",
            json["error_description"]
        );
    }

    #[tokio::test]
    async fn post_par_accepts_private_use_redirect_matching_reverse_fqdn() {
        let state = test_state().await;
        register_oauth_client(
            &state.db,
            CLIENT_ID,
            r#"{"redirect_uris":["com.example.app:/oauth/callback"],"client_name":"Test App"}"#,
        )
        .await
        .unwrap();

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[(
                        "redirect_uri",
                        "com.example.app:/oauth/callback",
                    )])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "a reverse-FQDN-matching private-use redirect must be accepted"
        );
    }

    #[tokio::test]
    async fn post_par_freshly_fetched_loopback_client_is_exempt_from_reverse_fqdn() {
        // The freshly-fetched (unregistered URL client_id) branch resolves metadata live via
        // resolve_client_metadata. The harness serves it over loopback http, which is the spec's
        // local-development exception, so its private-use redirect is NOT held to the reverse-FQDN
        // rule even though the scheme doesn't reverse the (loopback) host. This exercises the new
        // check on the fetch branch and pins that exemption. The rule itself — for https URL
        // client_ids — is covered by the registered-client tests above, since redirect validation
        // runs after and independent of the registered-vs-fetched branch.
        let state = test_state().await;
        let client_id = serve_client_metadata(|url| {
            serde_json::json!({
                "client_id": url,
                "redirect_uris": ["dev.anything.at.all:/oauth/callback"],
            })
            .to_string()
        })
        .await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(par_body(&[
                        ("client_id", client_id.as_str()),
                        ("redirect_uri", "dev.anything.at.all:/oauth/callback"),
                    ])))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "a loopback-http fetched client is exempt from the reverse-FQDN rule (local-dev exception)"
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
