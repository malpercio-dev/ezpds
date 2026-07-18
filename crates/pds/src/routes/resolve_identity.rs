// pattern: Imperative Shell
//
// Gathers: DID/identifier query parameters or refresh body
// Processes: shared ATProto identity resolution (DID document + bidirectionally verified handle)
// Returns: spec-shaped resolveDid / resolveIdentity / refreshIdentity JSON responses

use axum::{extract::State, Json};
use common::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::app::AppState;
use crate::identity::resolution::{
    resolve_did_document, resolve_did_document_force_refresh, resolve_handle_to_did,
    verified_handle_for_did, verified_handle_for_identifier, INVALID_HANDLE,
};
use crate::lexicon::{LexiconInput, LexiconParams};

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
    LexiconParams(params): LexiconParams<ResolveDidQuery>,
) -> Result<Json<ResolveDidResponse>, ApiError> {
    let did_doc = resolve_did_document(&state, &params.did).await?;
    Ok(Json(ResolveDidResponse { did_doc }))
}

pub async fn resolve_identity_handler(
    State(state): State<AppState>,
    LexiconParams(params): LexiconParams<ResolveIdentityQuery>,
) -> Result<Json<IdentityInfoResponse>, ApiError> {
    resolve_identity(&state, &params.identifier, false)
        .await
        .map(Json)
}

pub async fn refresh_identity_handler(
    State(state): State<AppState>,
    LexiconInput(payload): LexiconInput<RefreshIdentityRequest>,
) -> Result<Json<IdentityInfoResponse>, ApiError> {
    // Snapshot the currently-cached DID document *before* the force-refresh rewrites it, so we can
    // tell whether this refresh actually changed anything.
    let prior_doc = prior_cached_document(&state, &payload.identifier).await;

    // refreshIdentity's contract is "purge caches, re-resolve, return the fresh view". Force a
    // fresh fetch from the authoritative DID source (plc.directory / did:web) and rewrite the
    // cache row, rather than serving the possibly-stale cached document a plain resolveIdentity
    // would return.
    let info = resolve_identity(&state, &payload.identifier, true).await?;

    // If this PDS hosts the refreshed account *and the document actually changed*, announce it on
    // the firehose so relays re-resolve. This is the leg that propagates an externally-hosted
    // did:web edit — the operator repointed `did.json` to Custos and the refresh above rewrote our
    // cached copy, but a relay won't notice until an `#identity` frame tells it to re-resolve. The
    // emission is method-agnostic: a did:plc doc change announces the same way.
    //
    // The change check is load-bearing, not an optimization: refreshIdentity is an unauthenticated,
    // public resolution endpoint, so emitting a durable, broadcast frame on *every* call would let
    // anyone amplify re-resolution load onto every relay (and turn a status-polling client into a
    // spurious-`#identity` source). A genuine change emits exactly once; a no-op refresh emits
    // nothing.
    emit_identity_if_changed_and_hosted(&state, &info, prior_doc.as_ref()).await;

    Ok(Json(info))
}

/// The DID document currently cached for whatever `identifier` resolves to, read *before* a
/// force-refresh so a real change can be told apart from a no-op re-resolution.
///
/// Best-effort: an unresolvable handle, a DB error, or an absent cache row all yield `None`, which
/// the caller treats as "no prior" — a first-time resolution of a hosted DID is itself a change
/// worth announcing (and a hosted account always has a cached row, so this is not a spam vector:
/// repeated no-op refreshes read the same row and compare equal).
async fn prior_cached_document(state: &AppState, identifier: &str) -> Option<Value> {
    let did = if identifier.starts_with("did:") {
        identifier.to_string()
    } else {
        resolve_handle_to_did(state, identifier)
            .await
            .ok()
            .flatten()?
    };
    crate::db::dids::get_did_document(&state.db, &did)
        .await
        .ok()
        .flatten()
}

/// Emit an `#identity` firehose frame for `info` when this PDS hosts the account and the
/// re-resolved document differs from `prior_doc` (the copy cached before the force-refresh).
///
/// Best-effort throughout: the authoritative DID source already answered and the cache was
/// rewritten, so neither the hosting check nor the firehose emission may fail the refresh. We only
/// announce for DIDs this PDS actually hosts — its firehose describes its own repos, so emitting an
/// `#identity` for a foreign DID would be spurious. A verified handle is asserted when we have one;
/// `handle.invalid` collapses to `None` ("identity changed, re-resolve"), never a bogus handle.
async fn emit_identity_if_changed_and_hosted(
    state: &AppState,
    info: &IdentityInfoResponse,
    prior_doc: Option<&Value>,
) {
    // A no-op refresh (the re-resolved document matches what we already had cached) announces
    // nothing. Only an actual change — or a first-time resolution with no prior row — emits.
    if prior_doc == Some(&info.did_doc) {
        return;
    }

    match crate::db::accounts::account_exists(&state.db, &info.did).await {
        Ok(true) => {
            let handle = (info.handle != INVALID_HANDLE).then(|| info.handle.clone());
            if let Err(e) = state.firehose.emit_identity(info.did.clone(), handle).await {
                tracing::warn!(error = %e, did = %info.did, "failed to emit #identity after refreshIdentity (non-fatal)");
            }
        }
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(error = %e, did = %info.did, "failed to check hosting for #identity emission after refreshIdentity (non-fatal)");
        }
    }
}

async fn resolve_identity(
    state: &AppState,
    identifier: &str,
    force_refresh: bool,
) -> Result<IdentityInfoResponse, ApiError> {
    if identifier.starts_with("did:") {
        let did_doc = resolve_doc(state, identifier, force_refresh).await?;
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
    let did_doc = resolve_doc(state, &did, force_refresh).await?;
    let handle = verified_handle_for_identifier(state, &did, &did_doc, identifier).await?;

    Ok(IdentityInfoResponse {
        did,
        handle,
        did_doc,
    })
}

/// Resolve a DID document cache-first, or force-refreshed from the authoritative source when
/// `force_refresh` is set (the `refreshIdentity` path).
async fn resolve_doc(state: &AppState, did: &str, force_refresh: bool) -> Result<Value, ApiError> {
    if force_refresh {
        resolve_did_document_force_refresh(state, did).await
    } else {
        resolve_did_document(state, did).await
    }
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
        // The handle-identifier path: resolve handle → DID locally, then force-refresh the DID
        // document from the authoritative source (a plc mock here, since refreshIdentity never
        // serves the cached document).
        let mock_server = MockServer::start().await;
        let did = "did:plc:refreshidentity12345678901";
        let handle = "refresh.test.example.com";
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "alsoKnownAs": [format!("at://{handle}")],
            "verificationMethod": [],
            "service": []
        });
        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&doc))
            .mount(&mock_server)
            .await;

        let state = test_state_with_plc_url(mock_server.uri()).await;
        seed_handle(&state.db, handle, did).await;
        // A cached row exists (as it would for a hosted/migrated account); refresh must re-resolve
        // rather than serve it.
        seed_did_document(&state.db, did, doc).await;

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
    async fn refresh_identity_force_refreshes_and_rewrites_cached_document() {
        // refreshIdentity must re-resolve from the authoritative source and heal the cache: a stale
        // cached doc is replaced by plc.directory's current document, and a subsequent cache-first
        // resolveDid then serves the fresh doc without another network fetch.
        let mock_server = MockServer::start().await;
        let did = "did:plc:refreshrewrite1234567890";
        let handle = "refresh.test.example.com";

        let fresh_doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "alsoKnownAs": [format!("at://{handle}")],
            "verificationMethod": [{
                "id": format!("{did}#atproto"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": "zFreshKey",
            }],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://new.example.com",
            }]
        });
        // Exactly one plc fetch: refreshIdentity's. The later cache-first resolveDid must not add
        // a second.
        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&fresh_doc))
            .expect(1)
            .mount(&mock_server)
            .await;

        let state = test_state_with_plc_url(mock_server.uri()).await;
        seed_handle(&state.db, handle, did).await;
        // Stale cached doc: a fossil key and an outdated PDS endpoint.
        seed_did_document(
            &state.db,
            did,
            json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "alsoKnownAs": [format!("at://{handle}")],
                "verificationMethod": [{
                    "id": format!("{did}#atproto"),
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": "zFossilKey",
                }],
                "service": [{
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://old.example.com",
                }]
            }),
        )
        .await;
        let db = state.db.clone();

        // refreshIdentity returns the fresh document, not the stale cache.
        let refresh_resp = app(state.clone())
            .oneshot(post_json(
                "/xrpc/com.atproto.identity.refreshIdentity",
                json!({ "identifier": did }),
            ))
            .await
            .unwrap();
        assert_eq!(refresh_resp.status(), StatusCode::OK);
        let refresh_body = body_json(refresh_resp).await;
        assert_eq!(refresh_body["did"], did);
        assert_eq!(refresh_body["handle"], handle);
        assert_eq!(
            refresh_body["didDoc"]["service"][0]["serviceEndpoint"],
            "https://new.example.com"
        );

        // The cache row was rewritten with the fresh document.
        let cached: String = sqlx::query_scalar("SELECT document FROM did_documents WHERE did = ?")
            .bind(did)
            .fetch_one(&db)
            .await
            .unwrap();
        let cached: serde_json::Value = serde_json::from_str(&cached).unwrap();
        assert_eq!(
            cached["service"][0]["serviceEndpoint"], "https://new.example.com",
            "refreshIdentity must rewrite the cached DID document"
        );
        assert_eq!(
            cached["verificationMethod"][0]["publicKeyMultibase"],
            "zFreshKey"
        );

        // A subsequent cache-first resolveDid serves the healed document, with no second plc fetch.
        let resolve_resp = app(state)
            .oneshot(get(format!(
                "/xrpc/com.atproto.identity.resolveDid?did={}",
                query_encode(did)
            )))
            .await
            .unwrap();
        assert_eq!(resolve_resp.status(), StatusCode::OK);
        let resolve_body = body_json(resolve_resp).await;
        assert_eq!(
            resolve_body["didDoc"]["service"][0]["serviceEndpoint"], "https://new.example.com",
            "resolveDid must serve the refreshed document from cache"
        );
    }

    /// refreshIdentity announces the re-resolved identity on the firehose when this PDS hosts the
    /// account AND the document actually changed — the leg that tells relays to re-resolve after an
    /// externally-hosted did.json edit. Models the edit: the cache holds the old PDS endpoint, the
    /// authoritative source now returns the new one.
    #[tokio::test]
    async fn refresh_identity_emits_identity_frame_on_change_for_hosted_account() {
        let mock_server = MockServer::start().await;
        let did = "did:plc:refreshemitshosted12345";
        let handle = "hosted.test.example.com";
        let doc_with = |endpoint: &str| {
            json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "alsoKnownAs": [format!("at://{handle}")],
                "verificationMethod": [],
                "service": [{
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": endpoint,
                }]
            })
        };
        // The authoritative source returns the *new* document (post-edit).
        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(doc_with("https://new.example.com")),
            )
            .mount(&mock_server)
            .await;

        let state = test_state_with_plc_url(mock_server.uri()).await;
        // `seed_handle` inserts the account row (so `account_exists` reports it hosted) and the
        // handle (so `verified_handle_for_did` resolves it).
        seed_handle(&state.db, handle, did).await;
        // Cache holds the *old* document, so the refresh sees a real change.
        seed_did_document(&state.db, did, doc_with("https://old.example.com")).await;

        let firehose = state.firehose.clone();
        let mut rx = firehose.subscribe();

        let response = app(state)
            .oneshot(post_json(
                "/xrpc/com.atproto.identity.refreshIdentity",
                json!({ "identifier": did }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let event = rx.try_recv().expect("an #identity frame must be emitted");
        let crate::firehose::FirehoseEvent::Identity(identity) = event else {
            panic!("expected an #identity frame, got {event:?}");
        };
        assert_eq!(identity.did, did);
        assert_eq!(identity.handle.as_deref(), Some(handle));
        drop(firehose);
    }

    /// A no-op refreshIdentity (the re-resolved document matches the cache) must emit NOTHING, even
    /// for a hosted account — otherwise the unauthenticated, public endpoint would let anyone
    /// amplify `#identity` fan-out onto every relay just by polling it.
    #[tokio::test]
    async fn refresh_identity_does_not_emit_on_no_op_refresh() {
        let mock_server = MockServer::start().await;
        let did = "did:plc:refreshnoopnochange123";
        let handle = "noop.test.example.com";
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "alsoKnownAs": [format!("at://{handle}")],
            "verificationMethod": [],
            "service": []
        });
        // The authoritative source returns the *same* document the cache already holds.
        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&doc))
            .mount(&mock_server)
            .await;

        let state = test_state_with_plc_url(mock_server.uri()).await;
        seed_handle(&state.db, handle, did).await;
        seed_did_document(&state.db, did, doc).await;

        let firehose = state.firehose.clone();
        let mut rx = firehose.subscribe();

        let response = app(state)
            .oneshot(post_json(
                "/xrpc/com.atproto.identity.refreshIdentity",
                json!({ "identifier": did }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        assert!(
            matches!(
                rx.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "a no-op refresh must not emit an #identity frame"
        );
        drop(firehose);
    }

    /// refreshIdentity must NOT announce an identity this PDS does not host — its firehose describes
    /// only its own repos, so a foreign DID refresh emits nothing.
    #[tokio::test]
    async fn refresh_identity_does_not_emit_for_unhosted_did() {
        let mock_server = MockServer::start().await;
        let did = "did:plc:refreshnothosted123456";
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
            .mount(&mock_server)
            .await;

        // No account row for `did`: it is a foreign identity this PDS merely resolves.
        let state = test_state_with_plc_url(mock_server.uri()).await;
        let firehose = state.firehose.clone();
        let mut rx = firehose.subscribe();

        let response = app(state)
            .oneshot(post_json(
                "/xrpc/com.atproto.identity.refreshIdentity",
                json!({ "identifier": did }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        assert!(
            matches!(
                rx.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "no firehose frame may be emitted for an unhosted DID"
        );
        drop(firehose);
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
