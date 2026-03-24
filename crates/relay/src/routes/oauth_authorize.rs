// pattern: Imperative Shell
//
// Gathers: query params (client_id, redirect_uri, code_challenge, code_challenge_method,
//          state, scope, response_type) on GET; form body (action + same fields) on POST
// Processes:
//   GET:  looks up client → validates redirect_uri → validates remaining params → renders HTML
//   POST: validates client + redirect_uri first → handles deny/approve → generates auth code
// Returns:
//   GET:  HTML consent page (200) or HTML error page (400) when redirect is unsafe
//   POST: 303 redirect to redirect_uri?code=...&state=... or redirect_uri?error=...

use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::password::{verify_password, VerifyResult, TIMING_DUMMY_HASH};
use crate::auth::rate_limit::{clear_failures, is_rate_limited, record_failure};
use crate::db::accounts::resolve_identifier;
use crate::db::oauth::{consume_par_request, get_oauth_client, store_authorization_code, StoredPARParams};
use crate::routes::oauth_templates::{
    encode_param, error_page, error_redirect, render_consent_page,
};
use crate::routes::token::generate_token;

/// Fully-resolved parameters for the authorization consent page.
///
/// Constructed either directly from query params (non-PAR flow) or by looking up
/// the stored PAR request and deserializing its JSON (PAR flow via `request_uri`).
pub struct AuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: String,
    pub response_type: String,
    pub scope: String,
    /// ATProto extension: the client's hint about which account is authorizing.
    /// Pre-populates the identifier field on the consent page.
    pub login_hint: Option<String>,
}

/// Raw query parameters for `GET /oauth/authorize`.
///
/// All authorization-specific fields are `Option<String>` so that PAR requests
/// (which only send `client_id` and `request_uri`) pass serde deserialization.
/// The handler resolves these into a fully-populated `AuthorizeQuery`.
#[derive(Deserialize)]
pub struct GetAuthorizationQuery {
    pub client_id: String,
    /// PAR reference. When present, all other params come from the stored request.
    pub request_uri: Option<String>,
    // Direct auth params — required when request_uri is absent:
    pub redirect_uri: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub state: Option<String>,
    pub response_type: Option<String>,
    pub scope: Option<String>,
    pub login_hint: Option<String>,
}

fn default_scope() -> String {
    "atproto".to_string()
}

/// Form body for `POST /oauth/authorize`.
#[derive(Deserialize)]
pub struct ConsentForm {
    pub action: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: String,
    pub scope: String,
    pub response_type: String,
    /// Handle or DID entered by the user to identify the account being authorized.
    /// `None` when the field is absent (e.g. deny submissions don't send credentials).
    pub identifier: Option<String>,
    /// Password for the identified account. `None` when absent (same as above).
    pub password: Option<String>,
}

/// Subset of RFC 7591 client metadata fields used by the authorization endpoint.
#[derive(Deserialize, Default)]
struct ClientMetadata {
    #[serde(default)]
    redirect_uris: Vec<String>,
    client_name: Option<String>,
}

/// Distinguishes client-caused failures from server-caused failures in PAR resolution.
///
/// Callers use this to pick the right error page title so the framing is accurate for
/// both the user ("Invalid Request" for client errors) and operators ("Server Error" for
/// infrastructure failures that should trigger alerts).
enum ResolveError {
    /// The client sent an invalid or expired `request_uri`, or a mismatched `client_id`.
    Client(&'static str),
    /// A database or deserialization failure prevented resolution.
    Server(&'static str),
}

/// Resolve `GetAuthorizationQuery` into a fully-populated `AuthorizeQuery`.
///
/// When `request_uri` is present (PAR flow), atomically consumes the stored request
/// (single-use per RFC 9126 §4), deserializes the params JSON, and validates `client_id`
/// matches. When absent (direct flow), constructs `AuthorizeQuery` from raw params.
async fn resolve_authorize_params(
    state: &AppState,
    raw: GetAuthorizationQuery,
) -> Result<AuthorizeQuery, ResolveError> {
    if let Some(uri) = raw.request_uri {
        let row = match consume_par_request(&state.db, &uri).await {
            Ok(Some(r)) => r,
            Ok(None) => return Err(ResolveError::Client("request_uri is invalid or has expired")),
            Err(e) => {
                tracing::error!(error = %e, "db error consuming PAR request");
                return Err(ResolveError::Server(
                    "database error looking up pushed authorization request",
                ));
            }
        };

        if row.client_id != raw.client_id {
            return Err(ResolveError::Client(
                "client_id does not match the pushed authorization request",
            ));
        }

        let stored: StoredPARParams = match serde_json::from_str(&row.request_parameters) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    client_id = %raw.client_id,
                    error = %e,
                    "failed to deserialize stored PAR request parameters; possible schema drift or DB corruption"
                );
                return Err(ResolveError::Server(
                    "stored authorization request parameters are malformed",
                ));
            }
        };

        Ok(AuthorizeQuery {
            client_id: raw.client_id,
            redirect_uri: stored.redirect_uri,
            code_challenge: stored.code_challenge,
            code_challenge_method: stored.code_challenge_method,
            state: stored.state,
            response_type: stored.response_type,
            scope: stored.scope,
            login_hint: stored.login_hint,
        })
    } else {
        Ok(AuthorizeQuery {
            client_id: raw.client_id,
            redirect_uri: raw.redirect_uri.unwrap_or_default(),
            code_challenge: raw.code_challenge.unwrap_or_default(),
            code_challenge_method: raw.code_challenge_method.unwrap_or_default(),
            state: raw.state.unwrap_or_default(),
            response_type: raw.response_type.unwrap_or_default(),
            scope: raw
                .scope
                .filter(|s| !s.is_empty())
                .unwrap_or_else(default_scope),
            login_hint: raw.login_hint,
        })
    }
}

/// `GET /oauth/authorize` — validate request parameters and render the consent page.
///
/// Accepts either direct query parameters or a PAR `request_uri` (RFC 9126).
/// Returns an HTML error page (400) for errors that make a redirect unsafe:
/// unknown `client_id` or mismatched `redirect_uri`. All other parameter errors
/// redirect to `redirect_uri` with an `error` query parameter per RFC 6749 §4.1.2.1.
pub async fn get_authorization(
    State(state): State<AppState>,
    Query(raw): Query<GetAuthorizationQuery>,
) -> Response {
    let params = match resolve_authorize_params(&state, raw).await {
        Ok(p) => p,
        Err(ResolveError::Client(msg)) => {
            return error_page("Invalid Request", msg).into_response()
        }
        Err(ResolveError::Server(msg)) => return error_page("Server Error", msg).into_response(),
    };

    // Client and redirect_uri must be validated before any redirect is issued.
    let client = match get_oauth_client(&state.db, &params.client_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return error_page(
                "Unknown Client",
                "The client_id is not registered with this server.",
            )
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "db error looking up OAuth client");
            return error_page(
                "Server Error",
                "A database error occurred. Please try again.",
            )
            .into_response();
        }
    };

    let metadata: ClientMetadata = match serde_json::from_str(&client.client_metadata) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(
                client_id = %client.client_id,
                error = %e,
                "failed to parse stored client metadata"
            );
            return error_page(
                "Client Configuration Error",
                "The client's registered metadata is malformed.",
            )
            .into_response();
        }
    };

    if !metadata.redirect_uris.contains(&params.redirect_uri) {
        return error_page(
            "Invalid Redirect URI",
            "The redirect_uri does not match the client's registered URIs.",
        )
        .into_response();
    }

    // From here on redirect_uri is validated — errors redirect there, not to an error page.
    if params.response_type != "code" {
        return error_redirect(
            &params.redirect_uri,
            "unsupported_response_type",
            "only response_type=code is supported",
            &params.state,
        )
        .into_response();
    }

    if params.code_challenge_method != "S256" {
        return error_redirect(
            &params.redirect_uri,
            "invalid_request",
            "code_challenge_method must be S256",
            &params.state,
        )
        .into_response();
    }

    let client_name = metadata
        .client_name
        .unwrap_or_else(|| params.client_id.clone());

    Html(render_consent_page(
        &client_name,
        &params.client_id,
        &params.redirect_uri,
        &params.code_challenge,
        &params.code_challenge_method,
        &params.state,
        &params.scope,
        &params.response_type,
        &state.config.public_url,
        params.login_hint.as_deref(),
        None,
    ))
    .into_response()
}

/// `POST /oauth/authorize` — handle the user's approval or denial of the consent request.
///
/// Re-validates client_id and redirect_uri against the database, and enforces
/// code_challenge_method=S256, before issuing an authorization code or redirect.
/// Hidden form fields could be tampered with by a malicious browser.
pub async fn post_authorization(
    State(state): State<AppState>,
    Form(form): Form<ConsentForm>,
) -> Response {
    // Validate client and redirect_uri first — deny/approve both redirect there,
    // so we must confirm it is safe before using it as a redirect target.
    let client = match get_oauth_client(&state.db, &form.client_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return error_page("Unknown Client", "The client_id is not registered.").into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "db error looking up OAuth client");
            return error_page("Server Error", "A database error occurred.").into_response();
        }
    };

    let metadata: ClientMetadata = match serde_json::from_str(&client.client_metadata) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(
                client_id = %client.client_id,
                error = %e,
                "failed to parse stored client metadata"
            );
            return error_page(
                "Client Configuration Error",
                "Client metadata is malformed.",
            )
            .into_response();
        }
    };

    if !metadata.redirect_uris.contains(&form.redirect_uri) {
        return error_page(
            "Invalid Redirect URI",
            "The redirect_uri does not match the client's registered URIs.",
        )
        .into_response();
    }

    // redirect_uri is now validated — denial and all subsequent errors redirect there.
    if form.action == "deny" {
        return error_redirect(
            &form.redirect_uri,
            "access_denied",
            "User denied access",
            &form.state,
        )
        .into_response();
    }

    if form.action != "approve" {
        return error_redirect(
            &form.redirect_uri,
            "invalid_request",
            "invalid action",
            &form.state,
        )
        .into_response();
    }

    if form.response_type != "code" {
        return error_redirect(
            &form.redirect_uri,
            "unsupported_response_type",
            "only response_type=code is supported",
            &form.state,
        )
        .into_response();
    }

    if form.code_challenge_method != "S256" {
        return error_redirect(
            &form.redirect_uri,
            "invalid_request",
            "code_challenge_method must be S256",
            &form.state,
        )
        .into_response();
    }

    // Resolve the identifier and verify the password before issuing any auth code.
    // Re-render the consent form (200) on all credential errors so the user can retry
    // without the OAuth client seeing a denial. "Not found" and "wrong password" produce
    // identical messages and timing to prevent enumeration.
    let client_name_str = metadata
        .client_name
        .clone()
        .unwrap_or_else(|| form.client_id.clone());

    // Helper closure to re-render the consent page without redirecting to the client.
    let rerender = |hint: Option<&str>, error: &str| -> Response {
        Html(render_consent_page(
            &client_name_str,
            &form.client_id,
            &form.redirect_uri,
            &form.code_challenge,
            &form.code_challenge_method,
            &form.state,
            &form.scope,
            &form.response_type,
            &state.config.public_url,
            hint,
            Some(error),
        ))
        .into_response()
    };

    let identifier = match form.identifier.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(id) => id.to_string(),
        None => return rerender(None, "Please enter your handle or DID."),
    };

    // Rate-limit check: guard before any DB work or argon2 to shed load early.
    {
        let mut attempts = match state.failed_login_attempts.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!("failed_login_attempts mutex is poisoned");
                return error_redirect(
                    &form.redirect_uri,
                    "server_error",
                    "Internal server error",
                    &form.state,
                )
                .into_response();
            }
        };
        if is_rate_limited(&mut attempts, &identifier) {
            return rerender(
                Some(&identifier),
                "Too many failed attempts. Please try again later.",
            );
        }
    }

    let password = match form.password.as_deref().filter(|s| !s.is_empty()) {
        Some(p) => p.to_string(),
        None => return rerender(Some(&identifier), "Please enter your password."),
    };

    let account = match resolve_identifier(&state.db, &identifier).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            // Run a dummy argon2 to equalize timing with the wrong-password path,
            // preventing timing-based account enumeration.
            let _ = verify_password(TIMING_DUMMY_HASH, &password);
            tracing::debug!(
                identifier = %identifier,
                "OAuth consent: identifier not found or account deactivated"
            );
            let mut attempts = match state.failed_login_attempts.lock() {
                Ok(g) => g,
                Err(_) => {
                    tracing::error!("failed_login_attempts mutex is poisoned");
                    return error_redirect(
                        &form.redirect_uri,
                        "server_error",
                        "Internal server error",
                        &form.state,
                    )
                    .into_response();
                }
            };
            record_failure(&mut attempts, &identifier);
            return rerender(Some(&identifier), "Invalid credentials.");
        }
        Err(e) => {
            tracing::error!(error = %e, "db error resolving identifier for OAuth approval");
            return error_redirect(
                &form.redirect_uri,
                "server_error",
                "Internal server error",
                &form.state,
            )
            .into_response();
        }
    };

    let verify_result = match account.password_hash.as_deref() {
        // Mobile accounts (NULL or empty password_hash) cannot authenticate via OAuth consent.
        None | Some("") => VerifyResult::WrongPassword,
        Some(h) => verify_password(h, &password),
    };

    match verify_result {
        VerifyResult::Ok => {}
        VerifyResult::WrongPassword => {
            tracing::warn!(
                client_id = %form.client_id,
                did = %account.did,
                "OAuth consent: credential verification failed"
            );
            let mut attempts = match state.failed_login_attempts.lock() {
                Ok(g) => g,
                Err(_) => {
                    tracing::error!("failed_login_attempts mutex is poisoned");
                    return error_redirect(
                        &form.redirect_uri,
                        "server_error",
                        "Internal server error",
                        &form.state,
                    )
                    .into_response();
                }
            };
            record_failure(&mut attempts, &identifier);
            return rerender(Some(&identifier), "Invalid credentials.");
        }
        VerifyResult::CorruptHash => {
            tracing::error!(
                identifier = %identifier,
                did = %account.did,
                "stored password_hash is not a valid PHC string; possible DB corruption"
            );
            return error_redirect(
                &form.redirect_uri,
                "server_error",
                "Internal server error",
                &form.state,
            )
            .into_response();
        }
    }

    {
        let mut attempts = match state.failed_login_attempts.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!("failed_login_attempts mutex is poisoned");
                return error_redirect(
                    &form.redirect_uri,
                    "server_error",
                    "Internal server error",
                    &form.state,
                )
                .into_response();
            }
        };
        clear_failures(&mut attempts, &identifier);
    }

    let did = account.did;

    // Store the SHA-256 hash of the code, matching the session/refresh-token pattern.
    // The token endpoint hashes the presented code before lookup, consistent with all
    // other tokens in this codebase.
    let token = generate_token();
    if let Err(e) = store_authorization_code(
        &state.db,
        &token.hash,
        &form.client_id,
        &did,
        &form.code_challenge,
        &form.code_challenge_method,
        &form.redirect_uri,
        &form.scope,
    )
    .await
    {
        tracing::error!(error = %e, "failed to store authorization code");
        return error_redirect(
            &form.redirect_uri,
            "server_error",
            "Failed to generate authorization code",
            &form.state,
        )
        .into_response();
    }

    // Return plaintext to the client; the DB stores only the hash.
    let sep = if form.redirect_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    let redirect_url = format!(
        "{}{}code={}&state={}",
        form.redirect_uri,
        sep,
        encode_param(&token.plaintext),
        encode_param(&form.state),
    );
    Redirect::to(&redirect_url).into_response()
}


#[cfg(test)]
mod tests {
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Argon2, PasswordHasher,
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::db::oauth::register_oauth_client;
    use crate::routes::token::hash_bearer_token;

    const CLIENT_ID: &str = "https://app.example.com/client-metadata.json";
    const REDIRECT_URI: &str = "https://app.example.com/callback";
    const CLIENT_METADATA: &str =
        r#"{"redirect_uris":["https://app.example.com/callback"],"client_name":"Test App"}"#;
    const DID: &str = "did:plc:testaccount000000000000";
    const TEST_HANDLE: &str = "alice.test";
    const TEST_PASSWORD: &str = "correcthorse";

    async fn state_with_client() -> crate::app::AppState {
        let state = test_state().await;
        register_oauth_client(&state.db, CLIENT_ID, CLIENT_METADATA)
            .await
            .unwrap();
        state
    }

    async fn state_with_client_and_account() -> crate::app::AppState {
        let state = state_with_client().await;
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(DID)
        .bind("test@example.com")
        .execute(&state.db)
        .await
        .unwrap();
        state
    }

    /// Creates a test state with a registered client and an account that has a real Argon2id
    /// password hash, plus an associated handle for identifier-based login tests.
    async fn state_with_client_and_account_with_password(password: &str) -> crate::app::AppState {
        let state = state_with_client().await;
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, ?, datetime('now'), datetime('now'))",
        )
        .bind(DID)
        .bind("test@example.com")
        .bind(&password_hash)
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind(TEST_HANDLE)
            .bind(DID)
            .execute(&state.db)
            .await
            .unwrap();
        state
    }

    fn approve_form_with_credentials(identifier: &str, password: &str) -> String {
        format!(
            "action=approve\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &code_challenge=e3b0c44298fc1c149afb\
             &code_challenge_method=S256\
             &state=teststate\
             &scope=atproto\
             &response_type=code\
             &identifier={}&password={}",
            super::encode_param(identifier),
            super::encode_param(password),
        )
    }

    /// Test state with a mobile-provisioned account: handle is set but password_hash is NULL.
    async fn state_with_client_and_mobile_account() -> crate::app::AppState {
        let state = state_with_client().await;
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(DID)
        .bind("test@example.com")
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind(TEST_HANDLE)
            .bind(DID)
            .execute(&state.db)
            .await
            .unwrap();
        state
    }

    /// Test state with a deactivated account (deactivated_at is set).
    async fn state_with_client_and_deactivated_account() -> crate::app::AppState {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind(DID)
            .execute(&state.db)
            .await
            .unwrap();
        state
    }

    fn authorize_url(extra_params: &str) -> String {
        format!(
            "/oauth/authorize\
             ?client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &code_challenge=e3b0c44298fc1c149afb\
             &code_challenge_method=S256\
             &state=teststate\
             &response_type=code\
             &scope=atproto\
             {extra_params}"
        )
    }

    async fn get_authorize(state: crate::app::AppState, url: &str) -> axum::response::Response {
        app(state)
            .oneshot(Request::builder().uri(url).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn post_authorize(state: crate::app::AppState, body: &str) -> axum::response::Response {
        app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/authorize")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    fn approve_form(extra: &str) -> String {
        format!(
            "action=approve\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &code_challenge=e3b0c44298fc1c149afb\
             &code_challenge_method=S256\
             &state=teststate\
             &scope=atproto\
             &response_type=code\
             {extra}"
        )
    }

    fn deny_form() -> &'static str {
        "action=deny\
         &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
         &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
         &code_challenge=e3b0c44298fc1c149afb\
         &code_challenge_method=S256\
         &state=teststate\
         &scope=atproto\
         &response_type=code"
    }

    // ── GET tests ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_returns_200_with_html_content_type() {
        let resp = get_authorize(state_with_client().await, &authorize_url("")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/html"));
    }

    #[tokio::test]
    async fn get_returns_400_for_unknown_client_id() {
        let state = test_state().await; // no client registered
        let resp = get_authorize(state, &authorize_url("")).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_returns_400_for_mismatched_redirect_uri() {
        let resp = get_authorize(
            state_with_client().await,
            &authorize_url("").replace(
                "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
                "redirect_uri=https%3A%2F%2Fevil.example.com%2Fcallback",
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_redirects_with_error_for_wrong_response_type() {
        // response_type check happens after redirect_uri validation — redirects, not error page.
        let resp = get_authorize(
            state_with_client().await,
            &authorize_url("").replace("response_type=code", "response_type=token"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=unsupported_response_type"));
    }

    #[tokio::test]
    async fn get_redirects_with_error_for_non_s256_challenge_method() {
        let url =
            authorize_url("").replace("code_challenge_method=S256", "code_challenge_method=plain");
        let resp = get_authorize(state_with_client().await, &url).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn get_consent_page_contains_client_name() {
        let resp = get_authorize(state_with_client().await, &authorize_url("")).await;
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("Test App"),
            "client_name should appear in the consent page"
        );
    }

    #[tokio::test]
    async fn get_consent_page_falls_back_to_client_id_when_no_client_name() {
        let state = test_state().await;
        let metadata_no_name = r#"{"redirect_uris":["https://app.example.com/callback"]}"#;
        register_oauth_client(&state.db, CLIENT_ID, metadata_no_name)
            .await
            .unwrap();
        let resp = get_authorize(state, &authorize_url("")).await;
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("app.example.com"),
            "client_id should appear when client_name is absent"
        );
    }

    #[tokio::test]
    async fn get_consent_page_escapes_xss_in_client_name() {
        let state = test_state().await;
        let xss_metadata = r#"{"redirect_uris":["https://app.example.com/callback"],"client_name":"<script>alert(1)</script>"}"#;
        register_oauth_client(&state.db, CLIENT_ID, xss_metadata)
            .await
            .unwrap();
        let resp = get_authorize(state, &authorize_url("")).await;
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            !html.contains("<script>"),
            "raw <script> must not appear in output"
        );
        assert!(
            html.contains("&lt;script&gt;"),
            "script tag must be HTML-escaped"
        );
    }

    #[tokio::test]
    async fn get_consent_page_escapes_xss_in_scope() {
        // scope=<b>bold</b> URL-encoded in the request
        let url = authorize_url("").replace("scope=atproto", "scope=%3Cb%3Ebold%3C%2Fb%3E");
        let resp = get_authorize(state_with_client().await, &url).await;
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            !html.contains("<b>"),
            "raw HTML tags must not appear in scope output"
        );
        assert!(
            html.contains("&lt;b&gt;"),
            "scope tags must be HTML-escaped"
        );
    }

    #[tokio::test]
    async fn get_consent_page_contains_scope_tag() {
        let resp = get_authorize(state_with_client().await, &authorize_url("")).await;
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("atproto"),
            "requested scope should appear in the consent page"
        );
    }

    #[tokio::test]
    async fn get_consent_page_has_approve_and_deny_buttons() {
        let resp = get_authorize(state_with_client().await, &authorize_url("")).await;
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("value=\"approve\""));
        assert!(html.contains("value=\"deny\""));
    }

    #[tokio::test]
    async fn get_consent_page_has_hidden_inputs_with_request_values() {
        let resp = get_authorize(state_with_client().await, &authorize_url("")).await;
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("name=\"state\""));
        assert!(html.contains("name=\"code_challenge\""));
        assert!(html.contains("name=\"redirect_uri\""));
        assert!(html.contains("name=\"response_type\""));
    }

    // ── POST tests ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn post_deny_redirects_with_access_denied() {
        let resp = post_authorize(state_with_client_and_account().await, deny_form()).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=access_denied"));
        assert!(location.contains("state=teststate"));
    }

    #[tokio::test]
    async fn post_deny_with_tampered_redirect_uri_returns_400() {
        // Tampered redirect_uri fails DB validation before the deny redirect is issued.
        let body = deny_form().replace(
            "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
            "redirect_uri=https%3A%2F%2Fevil.example.com%2Fcallback",
        );
        let resp = post_authorize(state_with_client_and_account().await, &body).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "tampered redirect_uri must return an error page, not redirect to attacker URI"
        );
    }

    #[tokio::test]
    async fn post_invalid_action_redirects_with_invalid_request() {
        let body = approve_form("").replace("action=approve", "action=blah");
        let resp = post_authorize(state_with_client_and_account().await, &body).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn post_approve_redirects_with_code() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let resp = post_authorize(
            state,
            &approve_form_with_credentials(TEST_HANDLE, TEST_PASSWORD),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with(REDIRECT_URI));
        assert!(location.contains("code="));
        assert!(location.contains("state=teststate"));
        assert!(!location.contains("error="));
    }

    #[tokio::test]
    async fn post_approve_stores_hashed_code_in_db() {
        // The DB stores the SHA-256 hash of the code; the plaintext goes in the redirect URL.
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let db = state.db.clone();
        let resp = post_authorize(
            state,
            &approve_form_with_credentials(TEST_HANDLE, TEST_PASSWORD),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let plaintext = location
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        let code_hash = hash_bearer_token(plaintext).unwrap();

        let row: Option<(String,)> =
            sqlx::query_as("SELECT code FROM oauth_authorization_codes WHERE code = ?")
                .bind(&code_hash)
                .fetch_optional(&db)
                .await
                .unwrap();
        assert!(row.is_some(), "DB must store the hash, not the plaintext");
    }

    #[tokio::test]
    async fn post_approve_encodes_special_chars_in_state() {
        // state with &, =, spaces must be percent-encoded in the Location header.
        let body = approve_form_with_credentials(TEST_HANDLE, TEST_PASSWORD)
            .replace("state=teststate", "state=a%26b%3Dc%20d");
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let resp = post_authorize(state, &body).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        // a&b=c d percent-encoded: a%26b%3Dc%20d
        assert!(
            location.contains("state=a%26b%3Dc%20d"),
            "special chars in state must be percent-encoded: {location}"
        );
    }

    #[tokio::test]
    async fn post_approve_redirects_with_error_for_non_s256_method() {
        let body =
            approve_form("").replace("code_challenge_method=S256", "code_challenge_method=plain");
        let resp = post_authorize(state_with_client_and_account().await, &body).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn post_approve_without_credentials_rerenders_form() {
        // No identifier submitted → re-render the consent page asking the user to identify
        // themselves. The client never sees a denial; the user can try again.
        let resp = post_authorize(state_with_client().await, &approve_form("")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("type=\"password\""),
            "should re-render the consent form with credential fields"
        );
    }

    // ── Credential-gate tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn get_consent_page_renders_identifier_input() {
        let resp = get_authorize(state_with_client().await, &authorize_url("")).await;
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("name=\"identifier\""),
            "consent page must have identifier input"
        );
    }

    #[tokio::test]
    async fn get_consent_page_renders_password_input() {
        let resp = get_authorize(state_with_client().await, &authorize_url("")).await;
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("type=\"password\""),
            "consent page must have a password input"
        );
    }

    #[tokio::test]
    async fn get_consent_page_prepopulates_identifier_from_login_hint() {
        let url = authorize_url("&login_hint=alice.test");
        let resp = get_authorize(state_with_client().await, &url).await;
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("alice.test"),
            "login_hint value should appear in the identifier input"
        );
    }

    #[tokio::test]
    async fn post_approve_with_valid_credentials_redirects_with_code() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let body = approve_form_with_credentials(TEST_HANDLE, TEST_PASSWORD);
        let resp = post_authorize(state, &body).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with(REDIRECT_URI));
        assert!(location.contains("code="));
        assert!(!location.contains("error="));
    }

    #[tokio::test]
    async fn post_approve_with_wrong_password_rerenders_consent_page() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let body = approve_form_with_credentials(TEST_HANDLE, "wrongpassword");
        let resp = post_authorize(state, &body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            html.contains("Invalid credentials."),
            "exact error message must appear"
        );
        assert!(
            html.contains(TEST_HANDLE),
            "identifier should be pre-populated on re-render so the user can correct only the password"
        );
    }

    #[tokio::test]
    async fn post_approve_with_unknown_identifier_rerenders_consent_page() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let body = approve_form_with_credentials("nobody.test", TEST_PASSWORD);
        let resp = post_authorize(state, &body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            html.contains("Invalid credentials."),
            "must show same message as wrong-password to prevent enumeration"
        );
    }

    #[tokio::test]
    async fn post_approve_without_identifier_rerenders_consent_page() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let resp = post_authorize(state, &approve_form("")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            html.contains("type=\"password\""),
            "should re-render the consent form"
        );
    }

    #[tokio::test]
    async fn post_approve_returns_400_for_tampered_redirect_uri() {
        let body = approve_form("").replace(
            "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
            "redirect_uri=https%3A%2F%2Fevil.example.com%2Fcallback",
        );
        let resp = post_authorize(state_with_client_and_account().await, &body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_approve_returns_400_for_tampered_client_id() {
        let body = approve_form("").replace(
            "client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json",
            "client_id=https%3A%2F%2Fevil.example.com%2Fclient-metadata.json",
        );
        let resp = post_authorize(state_with_client_and_account().await, &body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_approve_returns_400_for_malformed_client_metadata() {
        let state = test_state().await;
        register_oauth_client(&state.db, CLIENT_ID, "not valid json")
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(DID)
        .bind("test@example.com")
        .execute(&state.db)
        .await
        .unwrap();
        let resp = post_authorize(state, &approve_form("")).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── Additional credential-gate tests ──────────────────────────────────────

    #[tokio::test]
    async fn post_approve_with_mobile_account_rerenders_consent_page() {
        // Mobile accounts have NULL password_hash — they can't log in via the consent page.
        let state = state_with_client_and_mobile_account().await;
        let body = approve_form_with_credentials(TEST_HANDLE, "anypassword");
        let resp = post_authorize(state, &body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            html.contains("Invalid credentials."),
            "mobile account (NULL password_hash) must not pass the credential gate"
        );
    }

    #[tokio::test]
    async fn post_approve_with_deactivated_account_rerenders_consent_page() {
        let state = state_with_client_and_deactivated_account().await;
        let body = approve_form_with_credentials(TEST_HANDLE, TEST_PASSWORD);
        let resp = post_authorize(state, &body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            html.contains("Invalid credentials."),
            "deactivated account must be rejected with the same message as unknown identifier"
        );
    }

    #[tokio::test]
    async fn post_approve_with_did_identifier_redirects_with_code() {
        // The DID branch of resolve_identifier must also work through the OAuth consent path.
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let body = approve_form_with_credentials(DID, TEST_PASSWORD);
        let resp = post_authorize(state, &body).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("code="));
        assert!(!location.contains("error="));
    }

    #[tokio::test]
    async fn post_approve_rate_limited_rerenders_form() {
        use crate::auth::rate_limit::RATE_LIMIT_MAX_FAILURES;
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        // Exhaust the failure budget.
        for _ in 0..RATE_LIMIT_MAX_FAILURES {
            post_authorize(
                state.clone(),
                &approve_form_with_credentials(TEST_HANDLE, "wrongpassword"),
            )
            .await;
        }
        // Next attempt must be rate-limited — the form re-renders with a rate-limit message.
        let resp = post_authorize(
            state,
            &approve_form_with_credentials(TEST_HANDLE, "wrongpassword"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            html.contains("Too many"),
            "rate-limited attempt must show a rate-limit message, not an auth error"
        );
    }

    // ── PAR (Pushed Authorization Request) flow ───────────────────────────────

    async fn store_test_par_request(state: &crate::app::AppState, request_uri: &str) {
        use crate::db::oauth::store_par_request;
        store_par_request(
            &state.db,
            request_uri,
            CLIENT_ID,
            r#"{"redirect_uri":"https://app.example.com/callback","code_challenge":"testchallenge","code_challenge_method":"S256","state":"teststate","response_type":"code","scope":"atproto","login_hint":null}"#,
        )
        .await
        .unwrap();
    }

    async fn store_test_par_request_with_login_hint(
        state: &crate::app::AppState,
        request_uri: &str,
        login_hint: &str,
    ) {
        use crate::db::oauth::store_par_request;
        let params = format!(
            r#"{{"redirect_uri":"https://app.example.com/callback","code_challenge":"testchallenge","code_challenge_method":"S256","state":"teststate","response_type":"code","scope":"atproto","login_hint":"{}"}}"#,
            login_hint
        );
        store_par_request(&state.db, request_uri, CLIENT_ID, &params)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn get_authorization_with_valid_request_uri_renders_consent_page() {
        let state = state_with_client().await;
        let request_uri = "urn:ietf:params:oauth:request_uri:test-par-token-abc";
        store_test_par_request(&state, request_uri).await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/oauth/authorize?client_id={}&request_uri={}",
                        CLIENT_ID, request_uri
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("Test App"),
            "consent page should show the registered client name"
        );
    }

    #[tokio::test]
    async fn get_authorization_with_invalid_request_uri_returns_error_page() {
        let state = state_with_client().await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/oauth/authorize?client_id={}&request_uri=urn:ietf:params:oauth:request_uri:nonexistent",
                        CLIENT_ID
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("Invalid Request"),
            "invalid request_uri should render an error page"
        );
    }

    #[tokio::test]
    async fn get_authorization_with_expired_request_uri_returns_error_page() {
        let state = state_with_client().await;

        // Insert a PAR request that is already expired.
        sqlx::query(
            "INSERT INTO oauth_par_requests \
             (request_uri, client_id, request_parameters, expires_at, created_at) \
             VALUES (?, ?, ?, datetime('now', '-1 seconds'), datetime('now'))",
        )
        .bind("urn:ietf:params:oauth:request_uri:formerly-valid-expired")
        .bind(CLIENT_ID)
        .bind(r#"{"redirect_uri":"https://app.example.com/callback","code_challenge":"c","code_challenge_method":"S256","state":"s","response_type":"code","scope":"atproto","login_hint":null}"#)
        .execute(&state.db)
        .await
        .unwrap();

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/oauth/authorize?client_id={}&request_uri=urn:ietf:params:oauth:request_uri:formerly-valid-expired",
                        CLIENT_ID
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("Invalid Request"),
            "expired request_uri should render an error page"
        );
    }

    #[tokio::test]
    async fn get_authorization_with_par_forwards_login_hint_to_consent_page() {
        let state = state_with_client().await;
        let request_uri = "urn:ietf:params:oauth:request_uri:test-par-login-hint";
        store_test_par_request_with_login_hint(&state, request_uri, "alice.example.com").await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/oauth/authorize?client_id={}&request_uri={}",
                        CLIENT_ID, request_uri
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("alice.example.com"),
            "login_hint from PAR should pre-populate the identifier field on the consent page"
        );
    }

    #[tokio::test]
    async fn get_authorization_direct_flow_without_redirect_uri_returns_error_page() {
        let state = state_with_client().await;

        // No redirect_uri → resolves to "" → fails registered-URIs check
        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/oauth/authorize?client_id={}&code_challenge=abc&code_challenge_method=S256&state=s&response_type=code",
                        CLIENT_ID
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("Invalid Redirect URI"),
            "missing redirect_uri on direct flow should return an Invalid Redirect URI error page"
        );
    }

    #[tokio::test]
    async fn get_authorization_with_mismatched_client_id_returns_error_page() {
        let state = state_with_client().await;
        let request_uri = "urn:ietf:params:oauth:request_uri:test-par-mismatch";
        store_test_par_request(&state, request_uri).await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/oauth/authorize?client_id=https://other.example.com/client&request_uri={}",
                        request_uri
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("Invalid Request"),
            "mismatched client_id should render an error page"
        );
    }
}
