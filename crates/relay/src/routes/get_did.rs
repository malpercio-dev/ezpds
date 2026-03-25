// pattern: Imperative Shell
//
// Gathers: DID from path parameter, document from local cache or PLC directory proxy
// Processes: none (lookup priority is local did_documents → PLC directory)
// Returns: DID document JSON with 200, or 404 if not found anywhere

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
    // 1. Check local cache.
    if let Some(doc) = get_did_document(&state.db, &did).await? {
        return Ok(Json(doc));
    }

    // 2. Proxy to PLC directory.
    let plc_url = format!("{}/{}", state.config.plc_directory_url, did);
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
        return Err(ApiError::new(ErrorCode::NotFound, "DID not found"));
    }

    if !response.status().is_success() {
        let status = response.status();
        tracing::error!(did = %did, status = %status, "plc.directory returned error");
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
    async fn plc_directory_error_returns_502() {
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
}
