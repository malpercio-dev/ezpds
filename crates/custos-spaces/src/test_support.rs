//! Fixtures for tests that drive the Spaces surface: everything in `custos_core::test_support`
//! (re-exported below), the router the tests send through ([`test_app`]), the space request
//! signer ([`SpaceSigKey`]), and the request builders and record bodies the space test modules share.
//!
//! What stays file-local on purpose, because it genuinely differs rather than merely being
//! spelled differently: each module's `setup()` (different fixtures per surface), `write_one`
//! (`space_notify_routes_test`'s fans a write out to registered subscribers,
//! `space_sync_routes_test`'s does not), and `space_policy_routes_test::create_body` (builds a
//! `createSpace` body, not a record write).

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use axum::Router;
use custos_core::test_support as core;
pub use custos_core::test_support::*;
use custos_core::CoreState;
use tower::ServiceExt;

/// [`custos_core::test_support::seed_account_with_repo`], plus a published KEM key: every space
/// writer needs one, or its writes answer `KemKeyNotPublished`.
pub async fn seed_account_with_repo(db: &sqlx::SqlitePool, did: &str) -> crypto::P256Keypair {
    let kp = core::seed_account_with_repo(db, did).await;
    core::publish_kem_key(db, did).await;
    kp
}

/// Both Spaces routers over `state`, wrapped as `pds` wraps them (see
/// [`custos_core::test_support::test_app`]).
pub fn test_app(state: CoreState) -> Router {
    let config = &state.config.spaces;
    let (public, internal) = (crate::router(config), crate::internal_router(config));
    core::test_app(public, internal, state)
}

/// A P-256 key a space client binds its credential to (`authorizeSpaceSync`'s `credentialKey`),
/// plus the RFC 9421 signature it attaches to each credential-authed request
/// ([`SpaceSigKey::credential_headers`], the full header set, so a request builder takes it with
/// `headers_mut().extend(..)`).
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

    /// `Authorization: Atproto-Space-Credential <credential>` addressed to `audience` and signed.
    pub fn credential_headers(&self, credential: &str, audience: &str) -> axum::http::HeaderMap {
        use crate::auth::http_signature::{sign_credential_request, AUDIENCE_HEADER};
        let authorization = format!("Atproto-Space-Credential {credential}");
        let (input, signature) =
            sign_credential_request(|b| self.signer.sign(b), &authorization, audience);
        let mut h = axum::http::HeaderMap::new();
        h.insert("authorization", authorization.parse().unwrap());
        h.insert("signature-input", input.parse().unwrap());
        h.insert("signature", signature.parse().unwrap());
        h.insert(AUDIENCE_HEADER, audience.parse().unwrap());
        h
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
pub async fn send(state: &CoreState, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = test_app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    (status, body_json(response).await)
}

/// `send`, keeping only the status — for call sites that never read the body.
pub async fn send_status(state: &CoreState, request: Request<Body>) -> StatusCode {
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

/// A memberspace policy in its stored form; `public` opens both reads and writes.
pub fn memberspace_policy(public: bool) -> String {
    serde_json::json!({
        "$type": crate::policy::MEMBERSPACE,
        "publicRead": public,
        "publicWrite": public,
        "publishPolicy": false,
        "publishMembers": false,
    })
    .to_string()
}

/// Seed a space this host is the authority for, at `uri`, under the stored `policy`.
pub async fn seed_authority_space(db: &sqlx::SqlitePool, uri: &str, policy: &str) {
    let space = custos_core::space_uri::parse_space_ref(uri).unwrap();
    let created = crate::db::spaces::create_space(
        db,
        &crate::db::spaces::NewSpace {
            uri: &space.uri,
            authority_did: &space.authority,
            space_type: &space.space_type,
            skey: &space.skey,
        },
        policy,
    )
    .await
    .unwrap();
    assert!(created, "{uri} already exists");
}
