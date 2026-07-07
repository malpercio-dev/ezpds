// pattern: Imperative Shell
//
// Gathers: instance facts from config (public URL, service name)
// Processes: render_auth_md (pure template substitution)
// Returns: the auth.md agent-registration discovery document served at `/auth.md`
//
// The prose companion to the machine-readable OAuth discovery documents: the AS metadata's
// `agent_auth.skill` points here (`{public_url}/auth.md`), and this document walks an agent
// through registration → assertion exchange → API use. The template is embedded via include_str!
// so the deployed OCI container needs no asset directory; the served copy substitutes this
// instance's public URL and service name so every example targets the live origin.

use axum::{
    extract::State,
    http::{header, HeaderValue},
    response::IntoResponse,
};
use common::Config;

use crate::app::AppState;

const AUTH_MD_TEMPLATE: &str = include_str!("../../assets/auth.md");

/// `GET /auth.md` — the auth.md agent-registration discovery document. No auth: this is a
/// discovery surface an unregistered agent reads before it has any credential.
pub async fn serve_auth_md(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/markdown; charset=utf-8"),
        )],
        render_auth_md(&state.config),
    )
}

/// Pure template render: substitute this instance's facts into the embedded document. The public
/// URL is trimmed of a trailing slash so examples never emit `https://host//oauth/...`.
fn render_auth_md(config: &Config) -> String {
    let base = config.public_url.trim_end_matches('/');
    AUTH_MD_TEMPLATE
        .replace("{{public_url}}", base)
        .replace("{{service_name}}", &config.service_name)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state, AppState};

    async fn get_auth_md(state: AppState) -> (StatusCode, String, Option<String>) {
        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/auth.md")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let content_type = response
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_string());
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            String::from_utf8(body.to_vec()).unwrap(),
            content_type,
        )
    }

    #[tokio::test]
    async fn serves_markdown_content_type() {
        let (status, _, content_type) = get_auth_md(test_state().await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            content_type.as_deref(),
            Some("text/markdown; charset=utf-8")
        );
    }

    #[tokio::test]
    async fn accessible_without_auth_headers() {
        // Lock in that this discovery surface requires no credentials — an unregistered agent
        // reads it before it has any token. A future global auth middleware must not protect it.
        let (status, _, _) = get_auth_md(test_state().await).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn substitutes_public_url_and_leaves_no_placeholders() {
        // test_state() sets public_url = "https://test.example.com", service_name = "custos".
        let (_, body, _) = get_auth_md(test_state().await).await;
        assert!(body.contains("https://test.example.com/agent/identity"));
        assert!(body.contains("https://test.example.com/oauth/token"));
        assert!(body.contains("https://test.example.com/auth.md"));
        assert!(
            !body.contains("{{"),
            "unsubstituted template placeholder remains"
        );
    }

    #[tokio::test]
    async fn trailing_slash_in_public_url_does_not_double_slash_examples() {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.public_url = "https://pds.example.com/".to_string();
        let state = AppState {
            config: std::sync::Arc::new(config),
            ..base
        };

        let (_, body, _) = get_auth_md(state).await;
        assert!(body.contains("https://pds.example.com/agent/identity"));
        assert!(!body.contains("pds.example.com//"));
    }

    #[tokio::test]
    async fn reflects_configured_service_name() {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.service_name = "Custos Relay".to_string();
        let state = AppState {
            config: std::sync::Arc::new(config),
            ..base
        };

        let (_, body, _) = get_auth_md(state).await;
        assert!(body.contains("Custos Relay"));
    }
}
