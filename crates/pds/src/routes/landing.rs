// pattern: Imperative Shell
//
// Gathers: instance metadata from config
// Processes: render_landing (pure template substitution)
// Returns: the HTML landing page served at `/`
//
// Visual system: "The Sealed Credential" (see DESIGN.md), matching the OAuth consent
// page. The template is embedded via include_str! so the deployed OCI container needs
// no asset directory; brand fonts come from the PDS's own /static/fonts route.

use axum::{extract::State, response::Html};
use common::Config;

use crate::app::AppState;

const LANDING_TEMPLATE: &str = include_str!("../../assets/landing.html");

/// `GET /` — the instance landing page: what this server is, its public facts
/// (host, DID, version, signup policy), and where people and tools go next.
pub async fn landing(State(state): State<AppState>) -> Html<String> {
    Html(render_landing(&state.config))
}

/// Pure template render: substitute escaped instance facts into the embedded page.
fn render_landing(config: &Config) -> String {
    let host = host_of(&config.public_url);
    let did = resolve_did(&config.server_did, &config.public_url);
    let domains = if config.available_user_domains.is_empty() {
        "none configured".to_string()
    } else {
        config.available_user_domains.join(", ")
    };
    let signup = if config.invite_code_required {
        "claim code required"
    } else {
        "open"
    };
    let contact_row = match &config.contact.email {
        Some(email) => {
            let escaped = html_escape(email);
            format!(
                "        <dt>contact</dt>\n        <dd><a href=\"mailto:{escaped}\">{escaped}</a></dd>"
            )
        }
        None => String::new(),
    };

    LANDING_TEMPLATE
        .replace("{{host}}", &html_escape(&host))
        .replace("{{did}}", &html_escape(&did))
        .replace("{{version}}", env!("CARGO_PKG_VERSION"))
        .replace("{{domains}}", &html_escape(&domains))
        .replace("{{signup}}", signup)
        .replace("{{contact_row}}", &contact_row)
}

/// Extract the bare hostname from the configured public URL.
fn host_of(public_url: &str) -> String {
    public_url
        .strip_prefix("https://")
        .or_else(|| public_url.strip_prefix("http://"))
        .unwrap_or(public_url)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Resolve the DID shown on the page: the configured `server_did` verbatim, else a
/// `did:web` derived from the public URL's hostname. Mirrors the derivation in
/// `describe_server.rs` (kept local — routes must not import from other routes).
fn resolve_did(server_did: &Option<String>, public_url: &str) -> String {
    match server_did {
        Some(did) => did.clone(),
        None => format!("did:web:{}", host_of(public_url)),
    }
}

/// HTML-escape a string for safe embedding in HTML content or attribute values.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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
    async fn landing_returns_200_html() {
        let response = app(test_state().await)
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response.headers().get("content-type").unwrap();
        assert!(content_type.to_str().unwrap().starts_with("text/html"));
    }

    #[tokio::test]
    async fn landing_shows_instance_facts() {
        // test_state() sets public_url = "https://test.example.com", server_did = None
        let response = app(test_state().await)
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(html.contains("test.example.com"));
        assert!(html.contains("did:web:test.example.com"));
        assert!(html.contains(concat!("custos v", env!("CARGO_PKG_VERSION"))));
        assert!(html.contains("claim code required"));
        assert!(!html.contains("{{"), "unsubstituted template placeholder");
    }

    #[tokio::test]
    async fn landing_escapes_configured_values() {
        let mut state = test_state().await;
        let mut config = (*state.config).clone();
        config.contact.email = Some("ops@example.com<script>".to_string());
        state.config = std::sync::Arc::new(config);

        let response = app(state)
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(html.contains("ops@example.com&lt;script&gt;"));
        assert!(!html.contains("ops@example.com<script>"));
    }

    #[tokio::test]
    async fn landing_omits_contact_row_when_not_configured() {
        let response = app(test_state().await)
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();

        assert!(!html.contains("mailto:"));
    }

    #[test]
    fn resolve_did_prefers_configured_did() {
        assert_eq!(
            super::resolve_did(&Some("did:plc:abc".to_string()), "https://x.example.com"),
            "did:plc:abc"
        );
    }

    #[test]
    fn resolve_did_derives_did_web_and_strips_path() {
        assert_eq!(
            super::resolve_did(&None, "https://pds.example.com/some/path"),
            "did:web:pds.example.com"
        );
    }
}
