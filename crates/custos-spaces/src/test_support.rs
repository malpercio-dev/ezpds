//! Fixtures for tests that drive the Spaces surface: everything in `custos_core::test_support`
//! (re-exported below) with the state constructors returning a [`SpacesState`], the router the
//! tests send through ([`test_app`]), the space request signer ([`SpaceSigKey`]), and the
//! request builders and record bodies the space test modules share.
//!
//! What stays file-local on purpose, because it genuinely differs rather than merely being
//! spelled differently: each module's `setup()` (different fixtures per surface), `write_one`
//! (`space_notify_routes_test`'s fans a write out to registered subscribers,
//! `space_sync_routes_test`'s does not), and `simplespace_routes_test::create_body` (builds a
//! space *declaration*, not a record write).

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use axum::Router;
use custos_core::test_support as core;
pub use custos_core::test_support::*;
use tower::ServiceExt;

use crate::SpacesState;

/// Both Spaces routers over `state`, wrapped the way `pds` wraps them: the shared layer stack on
/// each group, plus the XRPC error dialect and permissive CORS on the public one. The rest of the
/// `pds` app is absent, so a path no Spaces route claims is a plain 404 here, not the
/// `/xrpc/{method}` catch-all's `MethodNotImplemented`.
pub fn test_app(state: SpacesState) -> Router {
    let config = &state.config.spaces;
    let public = crate::router::<SpacesState>(config).layer(axum::middleware::from_fn(
        custos_core::lexicon::validate_xrpc_output,
    ));
    let public = custos_core::apply_shared_layers(public, &state)
        .layer(axum::middleware::from_fn(
            custos_core::xrpc_error_shape::flatten_xrpc_errors,
        ))
        .layer(tower_http::cors::CorsLayer::permissive());
    let internal =
        custos_core::apply_shared_layers(crate::internal_router::<SpacesState>(config), &state);
    public.merge(internal).with_state(state)
}

// ── `SpacesState` versions of the core state constructors ──────────────────
//
// Each shadows the glob-imported `CoreState` constructor of the same name.

/// The default test state (spaces enabled, no master key).
pub async fn test_state() -> SpacesState {
    SpacesState::new(core::test_state().await)
}

/// `test_state()` resolving DIDs against `plc_directory_url`.
pub async fn test_state_with_plc_url(plc_directory_url: String) -> SpacesState {
    SpacesState::new(core::test_state_with_plc_url(plc_directory_url).await)
}

/// `test_state()` with the signing-key master key configured (see [`test_master_key`]).
pub async fn state_with_master_key() -> SpacesState {
    SpacesState::new(core::state_with_master_key().await)
}

/// `state` with a [`FixedTxtResolver`] wired in, answering every TXT lookup with `records`.
pub fn state_with_txt_records(state: SpacesState, records: Vec<String>) -> SpacesState {
    SpacesState::new(core::state_with_txt_records(state.core, records))
}

/// A P-256 key a space client binds its credential to, plus the RFC 9421 `atproto-space`
/// signatures it attaches: [`SpaceSigKey::delegation_headers`] for the `getSpaceCredential`
/// exchange (whose `keyid` becomes the credential's `cnf.kid`), and
/// [`SpaceSigKey::credential_headers`] for each credential-authed request. Both return the full
/// header set, so a request builder takes them with `headers_mut().extend(..)`.
pub struct SpaceSigKey {
    signer: repo_engine::CommitSigner,
    key_id: String,
}

impl SpaceSigKey {
    pub fn generate() -> Self {
        let kp = crypto::generate_p256_keypair().unwrap();
        Self {
            signer: repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap(),
            key_id: kp.key_id.0,
        }
    }

    /// The key's `did:key` — what a credential minted for it carries as `cnf.kid`.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    fn signed(&self, authorization: &str, audience: Option<&str>) -> axum::http::HeaderMap {
        use crate::auth::http_signature::{sign_space_request, AUDIENCE_HEADER};
        let (input, signature) = sign_space_request(
            |b| self.signer.sign(b),
            &self.key_id,
            authorization,
            audience,
        );
        let mut h = axum::http::HeaderMap::new();
        h.insert("authorization", authorization.parse().unwrap());
        h.insert("signature-input", input.parse().unwrap());
        h.insert("signature", signature.parse().unwrap());
        if let Some(audience) = audience {
            h.insert(AUDIENCE_HEADER, audience.parse().unwrap());
        }
        h
    }

    /// `Authorization: Bearer <delegation token>` signed for the credential exchange.
    pub fn delegation_headers(&self, delegation_token: &str) -> axum::http::HeaderMap {
        self.signed(&format!("Bearer {delegation_token}"), None)
    }

    /// `Authorization: Atproto-Space <credential>` addressed to `audience` and signed.
    pub fn credential_headers(&self, credential: &str, audience: &str) -> axum::http::HeaderMap {
        self.signed(&format!("Atproto-Space {credential}"), Some(audience))
    }
}

/// A GET at an exact path, bearer-authenticated — the primitive every space test module's `get`
/// reduces to.
pub fn path_get(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(http::Method::GET)
        .uri(path)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// A JSON POST at an exact path, bearer-authenticated.
pub fn path_post(path: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(http::Method::POST)
        .uri(path)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// A GET against `/xrpc/<lexicon id>`.
pub fn xrpc_get(method: &str, token: &str) -> Request<Body> {
    path_get(&format!("/xrpc/{method}"), token)
}

/// A JSON POST against `/xrpc/<lexicon id>`.
pub fn xrpc_post(method: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    path_post(&format!("/xrpc/{method}"), token, body)
}

/// Run a request through the real router and decode the JSON response body.
pub async fn send(state: &SpacesState, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = test_app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    (status, body_json(response).await)
}

/// `send`, keeping only the status — for call sites that never read the body.
pub async fn send_status(state: &SpacesState, request: Request<Body>) -> StatusCode {
    send(state, request).await.0
}

/// A `com.atproto.space.createRecord` request body. Space, repo and collection vary per test
/// fixture; only the shape is shared.
pub fn space_record_body(
    space: &str,
    repo: &str,
    collection: &str,
    rkey: &str,
    text: &str,
) -> serde_json::Value {
    serde_json::json!({
        "space": space,
        "repo": repo,
        "collection": collection,
        "rkey": rkey,
        "record": {"text": text},
    })
}
