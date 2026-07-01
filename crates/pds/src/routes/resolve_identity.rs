// pattern: Imperative Shell
//
// Gathers: DID/identifier query parameters or refresh body
// Processes: shared ATProto identity resolution (DID document + bidirectionally verified handle)
// Returns: spec-shaped resolveDid / resolveIdentity / refreshIdentity JSON responses

use axum::{
    extract::{Query, State},
    Json,
};
use common::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::app::AppState;
use crate::identity_resolution::{
    resolve_did_document, resolve_handle_to_did, verified_handle_for_did,
    verified_handle_for_identifier,
};

#[derive(Deserialize)]
pub struct ResolveDidQuery {
    pub did: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveDidResponse {
    pub did_doc: Value,
}

#[derive(Deserialize)]
pub struct ResolveIdentityQuery {
    pub identifier: String,
}

#[derive(Deserialize)]
pub struct RefreshIdentityRequest {
    pub identifier: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInfoResponse {
    pub did: String,
    pub handle: String,
    pub did_doc: Value,
}

pub async fn resolve_did_handler(
    State(state): State<AppState>,
    Query(params): Query<ResolveDidQuery>,
) -> Result<Json<ResolveDidResponse>, ApiError> {
    let did_doc = resolve_did_document(&state, &params.did).await?;
    Ok(Json(ResolveDidResponse { did_doc }))
}

pub async fn resolve_identity_handler(
    State(state): State<AppState>,
    Query(params): Query<ResolveIdentityQuery>,
) -> Result<Json<IdentityInfoResponse>, ApiError> {
    resolve_identity(&state, &params.identifier).await.map(Json)
}

pub async fn refresh_identity_handler(
    State(state): State<AppState>,
    Json(payload): Json<RefreshIdentityRequest>,
) -> Result<Json<IdentityInfoResponse>, ApiError> {
    // ezpds does not maintain a separate remote-identity cache today. Resolving through the shared
    // path still re-checks the authoritative handle and DID-document sources available to the PDS.
    resolve_identity(&state, &payload.identifier)
        .await
        .map(Json)
}

async fn resolve_identity(
    state: &AppState,
    identifier: &str,
) -> Result<IdentityInfoResponse, ApiError> {
    if identifier.starts_with("did:") {
        let did_doc = resolve_did_document(state, identifier).await?;
        let handle = verified_handle_for_did(state, identifier, &did_doc).await?;
        return Ok(IdentityInfoResponse {
            did: identifier.to_string(),
            handle,
            did_doc,
        });
    }

    let did = resolve_handle_to_did(state, identifier)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::HandleNotFound, "handle not found"))?;
    let did_doc = resolve_did_document(state, &did).await?;
    let handle = verified_handle_for_identifier(state, &did, &did_doc, identifier).await?;

    Ok(IdentityInfoResponse {
        did,
        handle,
        did_doc,
    })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use serde_json::json;
    use tower::ServiceExt;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::app::{app, test_state, test_state_with_plc_url};
    use crate::routes::test_utils::{body_json, seed_did_document, seed_handle};

    fn get(path: String) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    fn post_json(path: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn query_encode(value: &str) -> String {
        urlencoding::encode(value).into_owned()
    }

    #[tokio::test]
    async fn resolve_did_returns_cached_document_in_did_doc_field() {
        let state = test_state().await;
        let did = "did:plc:cachedidentity1234567890123";
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "alsoKnownAs": ["at://alice.test.example.com"],
            "verificationMethod": [],
            "service": []
        });
        seed_did_document(&state.db, did, doc).await;

        let response = app(state)
            .oneshot(get(format!(
                "/xrpc/com.atproto.identity.resolveDid?did={}",
                query_encode(did)
            )))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["didDoc"]["id"], did);
    }

    #[tokio::test]
    async fn resolve_did_fetches_did_plc_from_plc_directory() {
        let mock_server = MockServer::start().await;
        let did = "did:plc:externalidentity123456789";
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "alsoKnownAs": [],
            "verificationMethod": [],
            "service": []
        });

        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&doc))
            .expect(1)
            .mount(&mock_server)
            .await;

        let state = test_state_with_plc_url(mock_server.uri()).await;
        let response = app(state)
            .oneshot(get(format!(
                "/xrpc/com.atproto.identity.resolveDid?did={}",
                query_encode(did)
            )))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["didDoc"]["id"], did);
    }

    #[tokio::test]
    async fn resolve_did_maps_plc_gone_to_did_deactivated() {
        let mock_server = MockServer::start().await;
        let did = "did:plc:deactivatedidentity12345";

        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(ResponseTemplate::new(410))
            .expect(1)
            .mount(&mock_server)
            .await;

        let state = test_state_with_plc_url(mock_server.uri()).await;
        let response = app(state)
            .oneshot(get(format!(
                "/xrpc/com.atproto.identity.resolveDid?did={}",
                query_encode(did)
            )))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::GONE);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "DidDeactivated");
    }

    #[tokio::test]
    async fn resolve_did_error_preview_handles_multibyte_response_body() {
        let mock_server = MockServer::start().await;
        let did = "did:plc:unicodeerroridentity1234";

        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(ResponseTemplate::new(503).set_body_string("é".repeat(600)))
            .expect(1)
            .mount(&mock_server)
            .await;

        let state = test_state_with_plc_url(mock_server.uri()).await;
        let response = app(state)
            .oneshot(get(format!(
                "/xrpc/com.atproto.identity.resolveDid?did={}",
                query_encode(did)
            )))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "PLC_DIRECTORY_ERROR");
    }

    #[tokio::test]
    async fn resolve_did_returns_cached_did_web_document() {
        let state = test_state().await;
        let did = "did:web:alice.example.com";
        seed_did_document(
            &state.db,
            did,
            json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "alsoKnownAs": [],
                "verificationMethod": [],
                "service": []
            }),
        )
        .await;

        let response = app(state)
            .oneshot(get(format!(
                "/xrpc/com.atproto.identity.resolveDid?did={}",
                query_encode(did)
            )))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["didDoc"]["id"], did);
    }

    #[tokio::test]
    async fn resolve_identity_for_handle_returns_verified_identity_info() {
        let state = test_state().await;
        let did = "did:plc:identityhandle123456789012";
        let handle = "alice.test.example.com";
        seed_handle(&state.db, handle, did).await;
        seed_did_document(
            &state.db,
            did,
            json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "alsoKnownAs": [format!("at://{handle}")],
                "verificationMethod": [],
                "service": []
            }),
        )
        .await;

        let response = app(state)
            .oneshot(get(format!(
                "/xrpc/com.atproto.identity.resolveIdentity?identifier={handle}"
            )))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["did"], did);
        assert_eq!(body["handle"], handle);
        assert_eq!(body["didDoc"]["id"], did);
    }

    #[tokio::test]
    async fn resolve_identity_returns_handle_invalid_when_did_doc_does_not_assert_handle() {
        let state = test_state().await;
        let did = "did:plc:unverifiedhandle1234567890";
        let handle = "alice.test.example.com";
        seed_handle(&state.db, handle, did).await;
        seed_did_document(
            &state.db,
            did,
            json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "alsoKnownAs": [],
                "verificationMethod": [],
                "service": []
            }),
        )
        .await;

        let response = app(state)
            .oneshot(get(format!(
                "/xrpc/com.atproto.identity.resolveIdentity?identifier={handle}"
            )))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["did"], did);
        assert_eq!(body["handle"], "handle.invalid");
    }

    #[tokio::test]
    async fn resolve_identity_for_did_picks_first_bidirectionally_verified_handle() {
        let state = test_state().await;
        let did = "did:plc:identitydid12345678901234";
        let handle = "alice.test.example.com";
        seed_handle(&state.db, handle, did).await;
        seed_did_document(
            &state.db,
            did,
            json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "alsoKnownAs": ["at://wrong.test.example.com", format!("at://{handle}")],
                "verificationMethod": [],
                "service": []
            }),
        )
        .await;

        let response = app(state)
            .oneshot(get(format!(
                "/xrpc/com.atproto.identity.resolveIdentity?identifier={}",
                query_encode(did)
            )))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["did"], did);
        assert_eq!(body["handle"], handle);
    }

    #[tokio::test]
    async fn refresh_identity_returns_identity_info() {
        let state = test_state().await;
        let did = "did:plc:refreshidentity12345678901";
        let handle = "refresh.test.example.com";
        seed_handle(&state.db, handle, did).await;
        seed_did_document(
            &state.db,
            did,
            json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "alsoKnownAs": [format!("at://{handle}")],
                "verificationMethod": [],
                "service": []
            }),
        )
        .await;

        let response = app(state)
            .oneshot(post_json(
                "/xrpc/com.atproto.identity.refreshIdentity",
                json!({ "identifier": handle }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["did"], did);
        assert_eq!(body["handle"], handle);
        assert_eq!(body["didDoc"]["id"], did);
    }

    #[tokio::test]
    async fn resolve_identity_unknown_handle_returns_handle_not_found() {
        let state = test_state().await;

        let response = app(state)
            .oneshot(get(
                "/xrpc/com.atproto.identity.resolveIdentity?identifier=nobody.test.example.com"
                    .to_string(),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "HANDLE_NOT_FOUND");
    }
}
