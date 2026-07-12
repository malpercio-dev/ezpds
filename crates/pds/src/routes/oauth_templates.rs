// pattern: Functional Core
//
// Pure rendering functions for the OAuth consent UI. All inputs are plain data; all
// outputs are plain strings or Axum response types that carry no side effects.
// No I/O, no database, no AppState.
//
// Visual system: "The Sealed Credential" (see DESIGN.md). Brand fonts are served by the
// the PDS's own /static/fonts route (no third-party CDN — an auth page must not leak logins).

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
    let mut html = String::with_capacity(2048);
    html.push_str(ERROR_PAGE_HEADER);
    html.push_str(&html_escape(title));
    html.push_str("</title>\n  <style>");
    html.push_str(FONT_FACES);
    html.push_str(ERROR_CSS);
    html.push_str("  </style>\n</head>\n<body>\n");
    html.push_str(
        "  <div class=\"card\">\n    <div class=\"top\">\n      <span class=\"seal alarm\">",
    );
    html.push_str(ICON_ALARM);
    html.push_str("</span>\n      <h1>");
    html.push_str(&html_escape(title));
    html.push_str("</h1>\n      <p class=\"err-msg\">");
    html.push_str(&html_escape(message));
    html.push_str("</p>\n    </div>\n  </div>\n</body>\n</html>");
    (StatusCode::BAD_REQUEST, Html(html))
}

/// Render the OAuth consent + sign-in page.
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
    // Monogram for the application mark — the first character of the client name.
    let app_initial = client_name
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "·".to_string());

    // Build HTML by concatenation — avoids doubling all CSS braces for format!.
    let mut html = String::with_capacity(6144);
    html.push_str(CONSENT_PAGE_HEADER);
    html.push_str(FONT_FACES);
    html.push_str(CONSENT_CSS);
    html.push_str("  </style>\n</head>\n<body>\n");
    html.push_str("  <div class=\"card\">\n");

    // Header: seal, title, subtitle.
    html.push_str("    <div class=\"top\">\n      <span class=\"seal\">");
    html.push_str(ICON_SEAL_LG);
    html.push_str("</span>\n      <h1>Authorize access</h1>\n");
    html.push_str("      <p class=\"sub\">An app wants to sign in as your identity. Review the request, then approve to continue.</p>\n    </div>\n");
    html.push_str("    <div class=\"rule\"></div>\n");

    // Application.
    html.push_str("    <div class=\"section-label\">Application</div>\n");
    html.push_str("    <div class=\"app\">\n      <span class=\"app-mark\">");
    html.push_str(&html_escape(&app_initial));
    html.push_str("</span>\n      <span>\n        <div class=\"client-name\">");
    html.push_str(&html_escape(client_name));
    html.push_str("</div>\n        <div class=\"client-id\">");
    html.push_str(&html_escape(client_id));
    html.push_str("</div>\n      </span>\n    </div>\n");

    // The <form> opens BEFORE the permissions section: the `granted_scope` checkboxes
    // must be form members or the browser silently omits them from the POST, and the
    // consent reduction filter would strip every non-`atproto` grant the user approved.
    html.push_str("    <form method=\"POST\" action=\"/oauth/authorize\">\n");

    // Permissions: `atproto` is the mandatory base — always granted, never a checkbox.
    // Everything else is grouped by resource type with a checked-by-default checkbox, so the
    // user can deny individual permissions before approving.
    html.push_str("    <div class=\"section-label\">Base access</div>\n");
    html.push_str(
        "    <div class=\"scopes\">\n        <span class=\"scope-tag\">atproto</span>\n    </div>\n",
    );
    html.push_str(&render_permission_groups(scope));
    html.push_str("    <p class=\"scope-note\">Uncheck anything you don't want to grant — the app will only be able to do what's left checked.</p>\n");

    // Sign in.
    html.push_str("    <div class=\"section-label\">Sign in to approve</div>\n");
    if let Some(msg) = error {
        html.push_str("    <div class=\"error-banner\">");
        html.push_str(ICON_ALERT);
        html.push_str("<span>");
        html.push_str(&html_escape(msg));
        html.push_str("</span></div>\n");
    }
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
    html.push_str(&format!(
        "      <input type=\"text\" name=\"identifier\" placeholder=\"alice.bsky.social or did:plc:…\" \
         autocomplete=\"username\" value=\"{}\" class=\"field mono\" />\n",
        html_escape(login_hint.unwrap_or(""))
    ));
    html.push_str(
        "      <input type=\"password\" name=\"password\" placeholder=\"Password\" \
         autocomplete=\"current-password\" class=\"field\" />\n",
    );
    html.push_str("      <div class=\"actions\">\n");
    html.push_str("        <button type=\"submit\" name=\"action\" value=\"deny\" class=\"btn btn-deny\">Deny</button>\n");
    html.push_str("        <button type=\"submit\" name=\"action\" value=\"approve\" class=\"btn btn-approve\">");
    html.push_str(ICON_SEAL_SM);
    html.push_str("Approve</button>\n");
    html.push_str("      </div>\n    </form>\n");

    // Footer: which PDS is serving this page.
    html.push_str("    <div class=\"server-info\">");
    html.push_str(ICON_LOCK);
    html.push_str("<span>");
    html.push_str(&html_escape(public_url));
    html.push_str("</span></div>\n  </div>\n</body>\n</html>");
    html
}

// ── Permission grouping ─────────────────────────────────────────────────────────

/// Render every non-`atproto` scope token as a checked-by-default checkbox, grouped under a
/// resource-type heading. `atproto` is rendered separately by the caller — it's mandatory and
/// never a checkbox.
fn render_permission_groups(scope: &str) -> String {
    let mut groups: Vec<(&'static str, Vec<&str>)> = Vec::new();
    for token in scope.split_whitespace() {
        if token == "atproto" {
            continue;
        }
        let label = crate::auth::oauth_scopes::resource_group_label(token);
        match groups.iter_mut().find(|(l, _)| *l == label) {
            Some((_, tokens)) => tokens.push(token),
            None => groups.push((label, vec![token])),
        }
    }

    let mut html = String::new();
    for (label, tokens) in groups {
        html.push_str("    <div class=\"section-label\">");
        html.push_str(&html_escape(label));
        html.push_str("</div>\n    <div class=\"permission-group\">\n");
        for token in tokens {
            let escaped = html_escape(token);
            html.push_str(&format!(
                "      <label class=\"permission-row\"><input type=\"checkbox\" name=\"granted_scope\" value=\"{escaped}\" checked /> <span class=\"mono\">{escaped}</span></label>\n"
            ));
        }
        html.push_str("    </div>\n");
    }
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

/// Self-hosted brand fonts, served by the PDS at /static/fonts (no third-party CDN).
const FONT_FACES: &str = r#"
    @font-face{font-family:'Public Sans';font-style:normal;font-weight:400;font-display:swap;src:url('/static/fonts/PublicSans-Regular.woff2') format('woff2')}
    @font-face{font-family:'Public Sans';font-style:normal;font-weight:600;font-display:swap;src:url('/static/fonts/PublicSans-SemiBold.woff2') format('woff2')}
    @font-face{font-family:'JetBrains Mono';font-style:normal;font-weight:400;font-display:swap;src:url('/static/fonts/JetBrainsMono-Regular.woff2') format('woff2')}
    @font-face{font-family:'Libre Caslon Display';font-style:normal;font-weight:400;font-display:swap;src:url('/static/fonts/LibreCaslonDisplay-Regular.ttf') format('truetype')}
"#;

const CONSENT_CSS: &str = r#"
    :root{
      --serif:'Libre Caslon Display',Georgia,serif;
      --sans:'Public Sans',system-ui,-apple-system,sans-serif;
      --mono:'JetBrains Mono',ui-monospace,monospace;
      --gold:oklch(0.46 0.105 62); --gold-deep:oklch(0.38 0.09 60);
      --aubergine:oklch(0.34 0.10 330);
      --ink:oklch(0.23 0.012 60); --ink-soft:oklch(0.31 0.012 60); --muted:oklch(0.40 0.012 60);
      --bg:oklch(1 0 0); --parchment:oklch(0.975 0.004 75); --sunk:oklch(0.955 0.005 75);
      --line:oklch(0.90 0.004 75); --on:oklch(0.99 0.005 80);
      --crit:oklch(0.44 0.16 25); --crit-surface:oklch(0.95 0.045 25);
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: var(--sans);
      background: oklch(0.965 0.006 75);
      color: var(--ink);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px 16px;
      -webkit-font-smoothing: antialiased;
    }
    .card {
      width: 100%;
      max-width: 420px;
      background: var(--bg);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 28px 26px;
      box-shadow: 0 1px 0 var(--line), 0 12px 44px oklch(0.23 0.012 60 / 0.09);
    }
    .top { display: flex; flex-direction: column; align-items: center; text-align: center; gap: 10px; margin-bottom: 20px; }
    .seal {
      width: 56px; height: 56px; border-radius: 9999px;
      background: var(--gold); color: var(--on);
      display: flex; align-items: center; justify-content: center;
      box-shadow: inset 0 0 0 2px oklch(0.99 0.05 80 / 0.35), inset 0 -3px 8px oklch(0.2 0.05 60 / 0.22);
    }
    h1 { font-family: var(--serif); font-weight: 400; font-size: 25px; line-height: 1.12; color: var(--ink); }
    .sub { font-size: 14.5px; line-height: 1.5; color: var(--ink-soft); max-width: 34ch; }
    .rule { height: 1px; background: var(--line); margin: 0 -26px 18px; }
    .section-label { font-size: 12px; font-weight: 600; color: var(--muted); margin-bottom: 8px; }
    .section-label + .section-label { margin-top: 18px; }
    .app { display: flex; align-items: center; gap: 12px; background: var(--parchment); border: 1px solid var(--line); border-radius: 12px; padding: 12px 14px; }
    .app-mark {
      width: 38px; height: 38px; border-radius: 10px; flex-shrink: 0;
      background: var(--aubergine); color: var(--on);
      display: flex; align-items: center; justify-content: center;
      font-family: var(--serif); font-size: 19px;
    }
    .client-name { font-size: 15px; font-weight: 600; color: var(--ink); }
    .client-id { font-family: var(--mono); font-size: 12px; color: var(--muted); word-break: break-all; margin-top: 1px; }
    .scopes { display: flex; flex-wrap: wrap; gap: 7px; margin-bottom: 6px; }
    .scope-tag {
      font-family: var(--mono); font-size: 12.5px; color: var(--ink-soft);
      background: var(--sunk); border: 1px solid var(--line); border-radius: 7px; padding: 4px 9px;
    }
    .scope-note { font-size: 13px; color: var(--muted); line-height: 1.45; }
    .permission-group { display: flex; flex-direction: column; gap: 6px; margin-bottom: 4px; }
    .permission-row {
      display: flex; align-items: center; gap: 9px;
      background: var(--parchment); border: 1px solid var(--line); border-radius: 9px;
      padding: 9px 11px; cursor: pointer;
    }
    .permission-row input[type="checkbox"] { width: 16px; height: 16px; accent-color: var(--aubergine); flex-shrink: 0; }
    .permission-row .mono { font-family: var(--mono); font-size: 12.5px; color: var(--ink-soft); word-break: break-all; }
    .error-banner {
      display: flex; align-items: center; gap: 8px;
      background: var(--crit-surface); color: var(--crit);
      font-size: 13.5px; font-weight: 500; border-radius: 10px; padding: 10px 12px; margin: 14px 0;
    }
    .field {
      display: block; width: 100%;
      font-family: var(--sans); font-size: 15px; color: var(--ink);
      background: var(--bg); border: 1px solid var(--line); border-radius: 10px;
      padding: 12px 14px; margin-bottom: 10px; outline: none;
    }
    .field.mono { font-family: var(--mono); font-size: 14px; }
    .field::placeholder { color: var(--muted); }
    .field:focus-visible { border-color: var(--aubergine); box-shadow: 0 0 0 3px oklch(0.34 0.10 330 / 0.12); }
    .actions { display: flex; gap: 10px; margin-top: 6px; }
    .btn {
      flex: 1; display: inline-flex; align-items: center; justify-content: center; gap: 8px;
      border-radius: 11px; padding: 14px; border: none; cursor: pointer;
      font-family: var(--sans); font-size: 15px; font-weight: 600;
    }
    .btn-approve { background: var(--gold); color: var(--on); }
    .btn-approve:hover { background: var(--gold-deep); }
    .btn-deny { background: var(--bg); color: var(--ink); border: 1px solid var(--line); }
    .btn-deny:hover { background: var(--sunk); }
    .server-info {
      display: flex; align-items: center; justify-content: center; gap: 6px;
      font-family: var(--mono); font-size: 12px; color: var(--muted);
      margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--line);
    }
"#;

const CONSENT_PAGE_HEADER: &str = concat!(
    "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n",
    "  <meta charset=\"UTF-8\" />\n",
    "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n",
    "  <title>Authorize access</title>\n",
    "  <style>",
);

const ERROR_CSS: &str = r#"
    :root{
      --serif:'Libre Caslon Display',Georgia,serif;
      --sans:'Public Sans',system-ui,-apple-system,sans-serif;
      --ink:oklch(0.23 0.012 60); --ink-soft:oklch(0.31 0.012 60);
      --bg:oklch(1 0 0); --line:oklch(0.90 0.004 75);
      --crit:oklch(0.44 0.16 25); --crit-surface:oklch(0.95 0.045 25);
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: var(--sans);
      background: oklch(0.965 0.006 75);
      color: var(--ink);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px 16px;
      -webkit-font-smoothing: antialiased;
    }
    .card {
      width: 100%; max-width: 420px;
      background: var(--bg); border: 1px solid var(--line); border-radius: 18px;
      padding: 28px 26px;
      box-shadow: 0 1px 0 var(--line), 0 12px 44px oklch(0.23 0.012 60 / 0.09);
    }
    .top { display: flex; flex-direction: column; align-items: center; text-align: center; gap: 12px; }
    .seal { width: 56px; height: 56px; border-radius: 9999px; display: flex; align-items: center; justify-content: center; }
    .seal.alarm { background: var(--crit-surface); color: var(--crit); box-shadow: inset 0 0 0 2px oklch(0.44 0.16 25 / 0.18); }
    h1 { font-family: var(--serif); font-weight: 400; font-size: 25px; line-height: 1.12; color: var(--ink); }
    .err-msg { font-size: 14.5px; line-height: 1.55; color: var(--ink-soft); max-width: 36ch; }
"#;

const ERROR_PAGE_HEADER: &str = concat!(
    "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n",
    "  <meta charset=\"UTF-8\" />\n",
    "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n",
    "  <title>",
);

// ── Inline SVG icons (stroke = currentColor; sized per use site) ───────────────

const ICON_SEAL_LG: &str = r#"<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 11.5 2 2 4-4"/></svg>"#;
const ICON_SEAL_SM: &str = r#"<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 11.5 2 2 4-4"/></svg>"#;
const ICON_LOCK: &str = r#"<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>"#;
const ICON_ALERT: &str = r#"<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>"#;
const ICON_ALARM: &str = r#"<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `granted_scope` checkbox must be a member of the consent <form> —
    /// controls outside the form element are silently omitted from the POST, which
    /// would strip every non-`atproto` grant the user approved (the consent
    /// reduction filter only grants tokens echoed back in `granted_scope`).
    #[test]
    fn granted_scope_checkboxes_are_inside_the_consent_form() {
        let html = render_consent_page(
            "Test App",
            "https://app.example.com/client-metadata.json",
            "https://app.example.com/callback",
            "challenge",
            "S256",
            "state",
            "atproto transition:generic repo:app.bsky.feed.post",
            "code",
            "https://pds.example.com",
            None,
            None,
        );

        let form_open = html.find("<form").expect("consent form present");
        let form_close = html.find("</form>").expect("consent form closed");
        let mut checkbox_count = 0;
        for (idx, _) in html.match_indices("name=\"granted_scope\"") {
            checkbox_count += 1;
            assert!(
                idx > form_open && idx < form_close,
                "granted_scope input at byte {idx} is outside the <form> \
                 ({form_open}..{form_close}) and would not be submitted"
            );
        }
        assert!(
            checkbox_count >= 2,
            "expected a checkbox per non-atproto scope token, found {checkbox_count}"
        );
    }
}
