// pattern: Functional Core
//
// Pure rendering functions for OAuth consent UI. All inputs are plain data; all
// outputs are plain strings or Axum response types that carry no side effects.
// No I/O, no database, no AppState.

use axum::http::StatusCode;
use axum::response::{Html, Redirect};

// ── Public rendering functions ────────────────────────────────────────────────

/// Build an OAuth error redirect (303) to `redirect_uri` with error parameters.
pub(super) fn error_redirect(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: &str,
) -> Redirect {
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
pub(super) fn error_page(title: &str, message: &str) -> (StatusCode, Html<String>) {
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
/// `login_hint` pre-populates the identifier field (from the ATProto `login_hint` param
/// or from a previous failed submission so the user can correct their handle).
/// `error` renders an error banner above the form when credential validation fails.
#[allow(clippy::too_many_arguments)]
pub(super) fn render_consent_page(
    client_name: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    state: &str,
    scope: &str,
    response_type: &str,
    public_url: &str,
    login_hint: Option<&str>,
    error: Option<&str>,
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
    if let Some(msg) = error {
        html.push_str("    <div class=\"error-banner\">");
        html.push_str(&html_escape(msg));
        html.push_str("</div>\n");
    }
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
    html.push_str("      <div class=\"section-label\">Your Account</div>\n");
    html.push_str(&format!(
        "      <input type=\"text\" name=\"identifier\" placeholder=\"Handle or DID\" \
         autocomplete=\"username\" value=\"{}\" class=\"field\" />\n",
        html_escape(login_hint.unwrap_or(""))
    ));
    html.push_str(
        "      <input type=\"password\" name=\"password\" placeholder=\"Password\" \
         autocomplete=\"current-password\" class=\"field\" />\n",
    );
    html.push_str("      <div class=\"actions\">\n");
    html.push_str("        <button type=\"submit\" name=\"action\" value=\"deny\" class=\"btn btn-deny\">Deny</button>\n");
    html.push_str("        <button type=\"submit\" name=\"action\" value=\"approve\" class=\"btn btn-approve\">Approve</button>\n");
    html.push_str("      </div>\n    </form>\n");
    html.push_str("    <div class=\"server-info\">");
    html.push_str(&html_escape(public_url));
    html.push_str("</div>\n  </div>\n</body>\n</html>");
    html
}

// ── Pure helpers ──────────────────────────────────────────────────────────────

/// Percent-encode a string for safe inclusion as a URL query parameter value.
pub(super) fn encode_param(s: &str) -> String {
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
pub(super) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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
    .error-banner {
      background: #FFE5E5;
      border: 2px solid #000;
      padding: .6rem 1rem;
      font-size: .88rem;
      font-weight: 600;
      color: #c00;
      margin-bottom: 1rem;
    }
    .field {
      display: block;
      width: 100%;
      border: 2px solid #000;
      padding: .6rem .75rem;
      font-size: .95rem;
      margin-bottom: .75rem;
      background: #fff;
      outline: none;
    }
    .field:focus { box-shadow: 3px 3px 0 #000; }
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
