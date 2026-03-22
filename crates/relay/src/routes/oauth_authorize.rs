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
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use crate::app::AppState;
use crate::db::oauth::{get_oauth_client, get_single_account_did, store_authorization_code};
use crate::routes::token::generate_token;

/// Query parameters for `GET /oauth/authorize`.
#[derive(Deserialize)]
pub struct AuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: String,
    pub response_type: String,
    #[serde(default = "default_scope")]
    pub scope: String,
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
}

/// Subset of RFC 7591 client metadata fields used by the authorization endpoint.
#[derive(Deserialize, Default)]
struct ClientMetadata {
    #[serde(default)]
    redirect_uris: Vec<String>,
    client_name: Option<String>,
}

/// `GET /oauth/authorize` — validate request parameters and render the consent page.
///
/// Returns an HTML error page (400) for errors that make a redirect unsafe:
/// unknown `client_id` or mismatched `redirect_uri`. All other parameter errors
/// redirect to `redirect_uri` with an `error` query parameter per RFC 6749 §4.1.2.1.
pub async fn get_authorization(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeQuery>,
) -> Response {
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
            return error_page("Server Error", "A database error occurred. Please try again.")
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
            return error_page("Client Configuration Error", "Client metadata is malformed.")
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

    let did = match get_single_account_did(&state.db).await {
        Ok(Some(did)) => did,
        Ok(None) => {
            return error_redirect(
                &form.redirect_uri,
                "server_error",
                "No account exists on this server",
                &form.state,
            )
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "db error fetching account DID for OAuth approval");
            return error_redirect(
                &form.redirect_uri,
                "server_error",
                "Internal server error",
                &form.state,
            )
            .into_response();
        }
    };

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

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Percent-encode a string for safe inclusion as a URL query parameter value.
fn encode_param(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// HTML-escape a string for safe embedding in HTML content or attribute values.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Build an OAuth error redirect (303) to `redirect_uri` with error parameters.
fn error_redirect(redirect_uri: &str, error: &str, description: &str, state: &str) -> Redirect {
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let url = format!(
        "{}{}error={}&error_description={}&state={}",
        redirect_uri,
        sep,
        encode_param(error),
        encode_param(description),
        encode_param(state),
    );
    Redirect::to(&url)
}

/// Render a standalone HTML error page for cases where redirecting is unsafe
/// (unknown `client_id`, mismatched `redirect_uri`).
fn error_page(title: &str, message: &str) -> (StatusCode, Html<String>) {
    let mut html = String::with_capacity(1500);
    html.push_str(ERROR_PAGE_HEADER);
    html.push_str(&html_escape(title));
    html.push_str("</title>\n  <style>");
    html.push_str(ERROR_CSS);
    html.push_str("  </style>\n</head>\n<body>\n");
    html.push_str("  <div class=\"card\">\n");
    html.push_str("    <div class=\"badge\">Error</div>\n");
    html.push_str("    <h1>");
    html.push_str(&html_escape(title));
    html.push_str("</h1>\n    <p>");
    html.push_str(&html_escape(message));
    html.push_str("</p>\n  </div>\n</body>\n</html>");
    (StatusCode::BAD_REQUEST, Html(html))
}

/// Render the neobrutal OAuth consent page.
///
/// All user-controlled values are HTML-escaped before insertion.
#[allow(clippy::too_many_arguments)]
fn render_consent_page(
    client_name: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    state: &str,
    scope: &str,
    response_type: &str,
    public_url: &str,
) -> String {
    let scope_tags: String = scope
        .split_whitespace()
        .map(|s| format!("<span class=\"scope-tag\">{}</span>", html_escape(s)))
        .collect::<Vec<_>>()
        .join("\n      ");

    // Build HTML by concatenation — avoids doubling all CSS braces for format!.
    let mut html = String::with_capacity(4096);
    html.push_str(CONSENT_PAGE_HEADER);
    html.push_str(CONSENT_CSS);
    html.push_str("  </style>\n</head>\n<body>\n");
    html.push_str("  <div class=\"card\">\n");
    html.push_str("    <div class=\"header\">\n");
    html.push_str("      <div class=\"badge\">Authorization Request</div>\n");
    html.push_str("      <h1>Allow Access?</h1>\n");
    html.push_str("    </div>\n");
    html.push_str("    <div class=\"section-label\">Application</div>\n");
    html.push_str("    <div class=\"client-name\">");
    html.push_str(&html_escape(client_name));
    html.push_str("</div>\n");
    html.push_str("    <div class=\"client-id\">");
    html.push_str(&html_escape(client_id));
    html.push_str("</div>\n");
    html.push_str("    <div class=\"section-label\">Requesting Permissions</div>\n");
    html.push_str("    <div class=\"scopes\">\n      ");
    html.push_str(&scope_tags);
    html.push_str("\n    </div>\n");
    html.push_str("    <form method=\"POST\" action=\"/oauth/authorize\">\n");
    for (name, value) in [
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code_challenge", code_challenge),
        ("code_challenge_method", code_challenge_method),
        ("state", state),
        ("scope", scope),
        ("response_type", response_type),
    ] {
        html.push_str(&format!(
            "      <input type=\"hidden\" name=\"{}\" value=\"{}\" />\n",
            name,
            html_escape(value)
        ));
    }
    html.push_str("      <div class=\"actions\">\n");
    html.push_str("        <button type=\"submit\" name=\"action\" value=\"deny\" class=\"btn btn-deny\">Deny</button>\n");
    html.push_str("        <button type=\"submit\" name=\"action\" value=\"approve\" class=\"btn btn-approve\">Approve</button>\n");
    html.push_str("      </div>\n    </form>\n");
    html.push_str("    <div class=\"server-info\">");
    html.push_str(&html_escape(public_url));
    html.push_str("</div>\n  </div>\n</body>\n</html>");
    html
}

// ── Static HTML fragments ─────────────────────────────────────────────────────

const CONSENT_CSS: &str = r#"
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: ui-sans-serif, system-ui, sans-serif;
      background: #FFFBF0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .card {
      background: #fff;
      border: 3px solid #000;
      box-shadow: 6px 6px 0 #000;
      max-width: 440px;
      width: 100%;
      padding: 2rem;
    }
    .header {
      border-bottom: 3px solid #000;
      padding-bottom: 1.25rem;
      margin-bottom: 1.5rem;
    }
    .badge {
      display: inline-block;
      background: #FFE600;
      border: 2px solid #000;
      padding: 2px 10px;
      font-size: .75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .05em;
      margin-bottom: .75rem;
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 900;
      line-height: 1.2;
      color: #000;
    }
    .section-label {
      font-size: .7rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: #555;
      margin-bottom: .5rem;
      margin-top: 1rem;
    }
    .client-name { font-size: 1.1rem; font-weight: 800; color: #000; }
    .client-id { font-size: .78rem; color: #555; word-break: break-all; margin-top: .2rem; }
    .scopes {
      display: flex;
      flex-wrap: wrap;
      gap: .5rem;
      margin-top: .5rem;
      margin-bottom: 1.5rem;
    }
    .scope-tag {
      background: #E8F4FF;
      border: 2px solid #000;
      padding: 3px 10px;
      font-size: .85rem;
      font-weight: 600;
      font-family: ui-monospace, monospace;
    }
    .actions { display: flex; gap: .75rem; }
    .btn {
      flex: 1;
      border: 3px solid #000;
      padding: .75rem 1.5rem;
      font-size: 1rem;
      font-weight: 800;
      cursor: pointer;
      text-transform: uppercase;
      letter-spacing: .05em;
    }
    .btn:active { transform: translate(3px, 3px); box-shadow: none !important; }
    .btn-approve { background: #00C853; box-shadow: 4px 4px 0 #000; }
    .btn-approve:hover { background: #00E676; }
    .btn-deny { background: #fff; box-shadow: 4px 4px 0 #000; }
    .btn-deny:hover { background: #FFE600; }
    .server-info {
      margin-top: 1.25rem;
      padding-top: 1rem;
      border-top: 2px solid #eee;
      font-size: .75rem;
      color: #888;
    }
"#;

const CONSENT_PAGE_HEADER: &str = concat!(
    "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n",
    "  <meta charset=\"UTF-8\" />\n",
    "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n",
    "  <title>Authorize Access</title>\n",
    "  <style>",
);

const ERROR_CSS: &str = r#"
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: ui-sans-serif, system-ui, sans-serif;
      background: #FFFBF0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .card {
      background: #fff;
      border: 3px solid #000;
      box-shadow: 6px 6px 0 #000;
      max-width: 420px;
      width: 100%;
      padding: 2rem;
    }
    .badge {
      display: inline-block;
      background: #FF3B30;
      color: #fff;
      border: 2px solid #000;
      padding: 2px 10px;
      font-size: .75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .05em;
      margin-bottom: .75rem;
    }
    h1 { font-size: 1.5rem; font-weight: 900; color: #000; margin-bottom: 1rem; }
    p { color: #333; font-size: .95rem; line-height: 1.5; }
"#;

const ERROR_PAGE_HEADER: &str = concat!(
    "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n",
    "  <meta charset=\"UTF-8\" />\n",
    "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n",
    "  <title>",
);

#[cfg(test)]
mod tests {
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

    async fn post_authorize(
        state: crate::app::AppState,
        body: &str,
    ) -> axum::response::Response {
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
        assert!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
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
        let url = authorize_url("")
            .replace("code_challenge_method=S256", "code_challenge_method=plain");
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
        assert!(html.contains("Test App"), "client_name should appear in the consent page");
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
        assert!(!html.contains("<script>"), "raw <script> must not appear in output");
        assert!(html.contains("&lt;script&gt;"), "script tag must be HTML-escaped");
    }

    #[tokio::test]
    async fn get_consent_page_escapes_xss_in_scope() {
        // scope=<b>bold</b> URL-encoded in the request
        let url =
            authorize_url("").replace("scope=atproto", "scope=%3Cb%3Ebold%3C%2Fb%3E");
        let resp = get_authorize(state_with_client().await, &url).await;
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(!html.contains("<b>"), "raw HTML tags must not appear in scope output");
        assert!(html.contains("&lt;b&gt;"), "scope tags must be HTML-escaped");
    }

    #[tokio::test]
    async fn get_consent_page_contains_scope_tag() {
        let resp = get_authorize(state_with_client().await, &authorize_url("")).await;
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("atproto"), "requested scope should appear in the consent page");
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
        let resp =
            post_authorize(state_with_client_and_account().await, &approve_form("")).await;
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
        let state = state_with_client_and_account().await;
        let db = state.db.clone();
        let resp = post_authorize(state, &approve_form("")).await;
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
        let body = approve_form("").replace("state=teststate", "state=a%26b%3Dc%20d");
        let resp = post_authorize(state_with_client_and_account().await, &body).await;
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
        let body = approve_form("").replace("code_challenge_method=S256", "code_challenge_method=plain");
        let resp = post_authorize(state_with_client_and_account().await, &body).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn post_approve_with_no_account_redirects_with_server_error() {
        let resp = post_authorize(state_with_client().await, &approve_form("")).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=server_error"));
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
}
