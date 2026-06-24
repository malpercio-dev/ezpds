// pattern: Functional Core
//
// Serves embedded static web assets (brand fonts now; more web-UI assets later) under
// `/static/*`. Bytes are baked into the binary via `include_bytes!`, so the deployed OCI
// container needs no asset directory and the response is a pure function of the request
// path — no I/O, no database, no AppState.

use axum::extract::Path;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

const PUBLIC_SANS_400: &[u8] = include_bytes!("../../assets/fonts/PublicSans-Regular.woff2");
const PUBLIC_SANS_500: &[u8] = include_bytes!("../../assets/fonts/PublicSans-Medium.woff2");
const PUBLIC_SANS_600: &[u8] = include_bytes!("../../assets/fonts/PublicSans-SemiBold.woff2");
const PUBLIC_SANS_700: &[u8] = include_bytes!("../../assets/fonts/PublicSans-Bold.woff2");
const JETBRAINS_MONO_400: &[u8] = include_bytes!("../../assets/fonts/JetBrainsMono-Regular.woff2");
const JETBRAINS_MONO_500: &[u8] = include_bytes!("../../assets/fonts/JetBrainsMono-Medium.woff2");
const LIBRE_CASLON_400: &[u8] = include_bytes!("../../assets/fonts/LibreCaslonDisplay-Regular.ttf");

const WOFF2: &str = "font/woff2";
const TTF: &str = "font/ttf";

/// Map a request path (relative to `/static/`) to an embedded asset + its content type.
/// Returns `None` for anything not explicitly served — there is no filesystem lookup, so
/// path traversal is impossible.
fn lookup(path: &str) -> Option<(&'static [u8], &'static str)> {
    Some(match path {
        "fonts/PublicSans-Regular.woff2" => (PUBLIC_SANS_400, WOFF2),
        "fonts/PublicSans-Medium.woff2" => (PUBLIC_SANS_500, WOFF2),
        "fonts/PublicSans-SemiBold.woff2" => (PUBLIC_SANS_600, WOFF2),
        "fonts/PublicSans-Bold.woff2" => (PUBLIC_SANS_700, WOFF2),
        "fonts/JetBrainsMono-Regular.woff2" => (JETBRAINS_MONO_400, WOFF2),
        "fonts/JetBrainsMono-Medium.woff2" => (JETBRAINS_MONO_500, WOFF2),
        "fonts/LibreCaslonDisplay-Regular.ttf" => (LIBRE_CASLON_400, TTF),
        _ => return None,
    })
}

/// `GET /static/*path` — serve an embedded static asset with a long immutable cache.
pub async fn static_handler(Path(path): Path<String>) -> Response {
    match lookup(&path) {
        Some((bytes, content_type)) => (
            [
                (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=31536000, immutable"),
                ),
            ],
            bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn serves_known_font_with_content_type() {
        let resp = static_handler(Path("fonts/PublicSans-Regular.woff2".to_string())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("content-type").unwrap(), "font/woff2");
    }

    #[tokio::test]
    async fn unknown_path_is_404() {
        let resp = static_handler(Path("fonts/nope.woff2".to_string())).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
