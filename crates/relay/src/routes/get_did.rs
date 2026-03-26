// pattern: Imperative Shell
//
// Gathers: DID from path parameter, document from local cache or PLC directory proxy
// Processes: DID format validation (rejects strings that don't start with "did:")
// Returns: DID document JSON with 200; 400 on invalid DID format; 404 if not found
//          in local cache or PLC directory; 502 on PLC infrastructure errors

use axum::{
    extract::{Path, State},
    Json,
};
use common::{ApiError, ErrorCode};
use serde_json::Value;

use crate::app::AppState;
use crate::db::dids::get_did_document;

pub async fn get_did_handler(
    Path(did): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    // Reject strings that don't look like DIDs to prevent path traversal into the
    // upstream PLC URL (e.g. "../../other-path" appended to plc_directory_url).
    if !did.starts_with("did:") {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    // 1. Check local cache. DB errors propagate as 500 — we do NOT fall through to
    //    PLC on infrastructure failures; that would mask broken rows.
    if let Some(doc) = get_did_document(&state.db, &did).await? {
        return Ok(Json(doc));
    }

    // 2. Proxy to PLC directory. Responses are not cached locally — the caller
    //    receives the live document but it is not written to did_documents here.
    tracing::debug!(did = %did, "DID not in local cache; proxying to plc.directory");
    let plc_url = format!(
        "{}/{}",
        state.config.plc_directory_url.trim_end_matches('/'),
        did
    );
    let response = state
        .http_client
        .get(&plc_url)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(did = %did, error = %e, plc_url = %plc_url, "failed to contact plc.directory");
            ApiError::new(ErrorCode::PlcDirectoryError, "failed to contact plc.directory")
        })?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        tracing::debug!(did = %did, "DID not found in plc.directory");
        return Err(ApiError::new(ErrorCode::NotFound, "DID not found"));
    }

    if !response.status().is_success() {
        let status = response.status();
        let body_preview = response.text().await.unwrap_or_default();
        let truncated = &body_preview[..body_preview.len().min(500)];
        tracing::error!(did = %did, status = %status, response_body = %truncated, "plc.directory returned error");
        return Err(ApiError::new(
            ErrorCode::PlcDirectoryError,
            "plc.directory returned error",
        ));
    }

    let doc: Value = response.json().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to parse plc.directory response");
        ApiError::new(ErrorCode::PlcDirectoryError, "invalid response from plc.directory")
    })?;

    Ok(Json(doc))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use serde_json::json;
    use tower::ServiceExt;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::app::{app, test_state_with_plc_url};
    use crate::routes::test_utils::{body_json, seed_did_document};

    fn get_did_request(did: &str) -> Request<Body> {
        Request::builder()
            .uri(format!("/v1/dids/{did}"))
            .body(Body::empty())
            .unwrap()
    }

    // ── Input validation ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn invalid_did_format_returns_400() {
        let state = test_state_with_plc_url("https://plc.directory".to_string()).await;

        let response = app(state)
            .oneshot(get_did_request("notadid"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "INVALID_CLAIM");
    }

    // ── Local cache hit ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn known_did_returns_cached_document_200() {
        let state = test_state_with_plc_url("https://plc.directory".to_string()).await;
        let did = "did:plc:cacheduser12345678901234567";
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "alsoKnownAs": ["at://alice.test"],
            "verificationMethod": [],
            "service": []
        });
        seed_did_document(&state.db, did, doc.clone()).await;

        let response = app(state)
            .oneshot(get_did_request(did))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["id"], did);
        assert_eq!(body["alsoKnownAs"][0], "at://alice.test");
    }

    #[tokio::test]
    async fn malformed_json_in_db_returns_500() {
        let state = test_state_with_plc_url("https://plc.directory".to_string()).await;
        let did = "did:plc:malformedjsontest12345678901";

        // Bypass seed_did_document to insert invalid JSON directly.
        sqlx::query(
            "INSERT INTO did_documents (did, document, created_at, updated_at) \
             VALUES (?, 'not valid json', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        let response = app(state)
            .oneshot(get_did_request(did))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "INTERNAL_ERROR");
    }

    // ── PLC directory proxy ───────────────────────────────────────────────────

    #[tokio::test]
    async fn unknown_did_proxies_to_plc_and_returns_document() {
        let mock_server = MockServer::start().await;
        let did = "did:plc:externaluser12345678901234";
        let plc_doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "alsoKnownAs": [],
            "verificationMethod": [],
            "service": []
        });

        Mock::given(method("GET"))
            .and(path_regex(r"^/did:plc:.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&plc_doc))
            .expect(1)
            .named("plc.directory GET did")
            .mount(&mock_server)
            .await;

        let state = test_state_with_plc_url(mock_server.uri()).await;

        let response = app(state)
            .oneshot(get_did_request(did))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["id"], did);
    }

    #[tokio::test]
    async fn did_not_found_in_plc_returns_404() {
        let mock_server = MockServer::start().await;
        let did = "did:plc:nobody1234567890123456789";

        Mock::given(method("GET"))
            .and(path_regex(r"^/did:plc:.+"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .named("plc.directory 404")
            .mount(&mock_server)
            .await;

        let state = test_state_with_plc_url(mock_server.uri()).await;

        let response = app(state)
            .oneshot(get_did_request(did))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn plc_directory_5xx_returns_502() {
        let mock_server = MockServer::start().await;
        let did = "did:plc:errordid12345678901234567";

        Mock::given(method("GET"))
            .and(path_regex(r"^/did:plc:.+"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .named("plc.directory 500")
            .mount(&mock_server)
            .await;

        let state = test_state_with_plc_url(mock_server.uri()).await;

        let response = app(state)
            .oneshot(get_did_request(did))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "PLC_DIRECTORY_ERROR");
    }

    #[tokio::test]
    async fn plc_directory_4xx_non_404_returns_502() {
        let mock_server = MockServer::start().await;
        let did = "did:plc:ratelimitedtest1234567890123";

        Mock::given(method("GET"))
            .and(path_regex(r"^/did:plc:.+"))
            .respond_with(ResponseTemplate::new(429))
            .expect(1)
            .named("plc.directory 429")
            .mount(&mock_server)
            .await;

        let state = test_state_with_plc_url(mock_server.uri()).await;

        let response = app(state)
            .oneshot(get_did_request(did))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "PLC_DIRECTORY_ERROR");
    }

    #[tokio::test]
    async fn plc_returns_non_json_body_returns_502() {
        let mock_server = MockServer::start().await;
        let did = "did:plc:htmlresponsedid12345678901234";

        Mock::given(method("GET"))
            .and(path_regex(r"^/did:plc:.+"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("<html><body>Not JSON</body></html>")
                    .append_header("content-type", "text/html"),
            )
            .expect(1)
            .named("plc.directory html response")
            .mount(&mock_server)
            .await;

        let state = test_state_with_plc_url(mock_server.uri()).await;

        let response = app(state)
            .oneshot(get_did_request(did))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "PLC_DIRECTORY_ERROR");
    }

    #[tokio::test]
    async fn plc_network_failure_returns_502() {
        // Connect to a port that refuses connections. Port 1 (tcpmux) is not in use
        // on standard developer machines and returns ECONNREFUSED immediately.
        let state = test_state_with_plc_url("http://127.0.0.1:1".to_string()).await;

        let response = app(state)
            .oneshot(get_did_request("did:plc:networkfailuretest1234567890"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "PLC_DIRECTORY_ERROR");
    }

    // ── Local cache priority ──────────────────────────────────────────────────

    #[tokio::test]
    async fn local_cache_takes_priority_over_plc() {
        let mock_server = MockServer::start().await;
        let did = "did:plc:localoverride12345678901234";
        let local_doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "alsoKnownAs": ["at://local.test"],
            "verificationMethod": [],
            "service": []
        });

        // PLC server should NOT be called; if it is, wiremock's expect(0) will fail.
        Mock::given(method("GET"))
            .and(path_regex(r"^/did:plc:.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "wrong"})))
            .expect(0)
            .named("plc.directory should not be called")
            .mount(&mock_server)
            .await;

        let state = test_state_with_plc_url(mock_server.uri()).await;
        seed_did_document(&state.db, did, local_doc).await;

        let response = app(state)
            .oneshot(get_did_request(did))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["alsoKnownAs"][0], "at://local.test");
    }

    // ── URL construction ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn plc_url_with_trailing_slash_produces_correct_path() {
        let mock_server = MockServer::start().await;
        let did = "did:plc:trailingslashtest1234567890";
        let plc_doc = json!({"id": did, "@context": [], "alsoKnownAs": [], "verificationMethod": [], "service": []});

        Mock::given(method("GET"))
            .and(path_regex(r"^/did:plc:.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&plc_doc))
            .expect(1)
            .named("plc.directory trailing slash")
            .mount(&mock_server)
            .await;

        // URI with trailing slash — should not produce a double-slash path.
        let plc_url_with_slash = format!("{}/", mock_server.uri());
        let state = test_state_with_plc_url(plc_url_with_slash).await;

        let response = app(state)
            .oneshot(get_did_request(did))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
