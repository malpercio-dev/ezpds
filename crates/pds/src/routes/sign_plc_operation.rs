// pattern: Imperative Shell
//
// POST /xrpc/com.atproto.identity.signPlcOperation
//
// Signs a DID-repointing PLC operation on the authenticated account's behalf, using
// the PDS-held rotation key, and returns it UNSUBMITTED (the caller submits it, or
// passes it to `submitPlcOperation`). This is the interop (PDS-signed) migration path
// (ADR-0002): it lets off-the-shelf tooling migrate off ezpds the standard way. The
// wallet-authorized path signs its identity leg locally and never calls this.
//
// The operation is built by overlaying the request's changes onto the DID's current
// PLC state (fetched from plc.directory) and chaining it via `prev` onto the current
// head. Authorization is two-factor: a full-access session AND a single-use email
// token minted by `requestPlcOperationSignature`.
//
// Gather:  AuthenticatedUser (full access) + JSON { token?, rotationKeys?, alsoKnownAs?,
//          verificationMethods?, services? }
// Process: validate email token → fetch current PLC state → overlay changes →
//          load + decrypt the PDS rotation key → consume the token → build + sign the operation
// Respond: { operation }

use axum::{extract::State, response::Json};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::auth::oauth_scopes;
use crate::auth::token::hash_bearer_token;
use crate::db::plc_operation_tokens::{consume_plc_operation_token, plc_operation_token_is_valid};
use crate::db::repo_keys::get_signing_key_by_did;
use crate::identity::plc::{
    ensure_did_plc, fetch_current_plc_state, parse_services, parse_verification_methods,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignPlcOperationRequest {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    rotation_keys: Option<Vec<String>>,
    #[serde(default)]
    also_known_as: Option<Vec<String>>,
    #[serde(default)]
    verification_methods: Option<serde_json::Value>,
    #[serde(default)]
    services: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct SignPlcOperationResponse {
    operation: serde_json::Value,
}

pub async fn sign_plc_operation(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    Json(request): Json<SignPlcOperationRequest>,
) -> Result<Json<SignPlcOperationResponse>, ApiError> {
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "full access token required",
        ));
    }
    oauth_scopes::require_identity(&user.scope_claim, "*")?;
    let did = &user.did;

    // PLC operations only apply to a did:plc identity — reject a did:web account explicitly here
    // rather than 404ing later on its (non-existent) plc.directory audit log.
    ensure_did_plc(did)?;

    // Two-factor gate: a full-access session (above) AND a single-use email token. We validate the
    // token here without consuming it, then redeem it atomically at the very end — so a transient
    // plc.directory outage or a downstream rejection doesn't burn a valid token and force the user
    // through a fresh email round-trip. The final atomic consume still guarantees single-use.
    let token_plaintext = request
        .token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidToken,
                "a PLC operation signature token is required (call requestPlcOperationSignature)",
            )
        })?;
    let token_hash = hash_bearer_token(token_plaintext)?;
    if !plc_operation_token_is_valid(&state.db, did, &token_hash).await? {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "invalid or expired PLC operation token",
        ));
    }

    // The new operation is built on top of the DID's current PLC state.
    let current =
        fetch_current_plc_state(&state.http_client, &state.config.plc_directory_url, did).await?;

    // Load + decrypt the PDS-held rotation/signing key. In ezpds this is the account's
    // per-account key, placed at `rotationKeys[1]` in the genesis op.
    let master_key: &[u8; 32] = state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|s| &*s.0)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::ServiceUnavailable,
                "signing key master key not configured",
            )
        })?;
    let signing_key = get_signing_key_by_did(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to load signing key");
            ApiError::new(ErrorCode::InternalError, "failed to load account keys")
        })?
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::NotFound,
                "no signing key is registered for this account",
            )
        })?;

    // Authorize against the DID's CURRENT rotation set — a PLC op is valid iff signed by a key in
    // the previous op's `rotationKeys`. Checking the request's (overlaid) rotationKeys instead would
    // reject a valid migration that removes the PDS key from the *new* op, and would admit a request
    // that adds the PDS key it doesn't actually hold (only to be rejected later at plc.directory).
    if !current.rotation_keys.contains(&signing_key.key_id) {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "this PDS does not hold a rotation key in the DID's current rotationKeys; \
             it cannot sign an operation for this identity",
        ));
    }

    let rotation_keys = request.rotation_keys.unwrap_or(current.rotation_keys);
    let also_known_as = request.also_known_as.unwrap_or(current.also_known_as);
    let verification_methods = match request.verification_methods {
        Some(v) => parse_verification_methods(&v)?,
        None => current.verification_methods,
    };
    let services = match request.services {
        Some(v) => parse_services(&v)?,
        None => current.services,
    };

    let private_key = crypto::decrypt_private_key(&signing_key.private_key_encrypted, master_key)
        .map_err(|e| {
        tracing::error!(error = %e, "failed to decrypt signing key");
        ApiError::new(ErrorCode::InternalError, "failed to prepare signing key")
    })?;
    let signer = repo_engine::CommitSigner::from_bytes(&private_key).map_err(|e| {
        tracing::error!(error = %e, "invalid signing key bytes");
        ApiError::new(ErrorCode::InternalError, "failed to prepare signing key")
    })?;

    // Redeem the token now that every fallible precondition has passed — the last step before
    // signing. Atomic, so it still can't be spent twice even under concurrent requests. A racing
    // request that consumed it between the pre-flight check and here fails closed with 401.
    if !consume_plc_operation_token(&state.db, did, &token_hash).await? {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "invalid or expired PLC operation token",
        ));
    }

    let signed = crypto::build_did_plc_rotation_op(
        &current.cid,
        rotation_keys,
        verification_methods,
        also_known_as,
        services,
        |bytes| Ok(signer.sign(bytes)),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to build PLC rotation operation");
        ApiError::new(ErrorCode::InternalError, "failed to sign PLC operation")
    })?;

    let operation: serde_json::Value =
        serde_json::from_str(&signed.signed_op_json).map_err(|e| {
            tracing::error!(error = %e, "signed PLC op is not valid JSON");
            ApiError::new(
                ErrorCode::InternalError,
                "failed to serialize signed operation",
            )
        })?;

    Ok(Json(SignPlcOperationResponse { operation }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::app::{app, AppState};
    use crate::routes::test_utils::{
        access_jwt, seed_account_with_signing_key, state_with_master_key,
    };

    /// A `state_with_master_key` whose plc.directory points at `plc_uri`.
    pub(super) async fn state_with_master_key_and_plc(plc_uri: String) -> AppState {
        let base = state_with_master_key().await;
        let mut config = (*base.config).clone();
        config.plc_directory_url = plc_uri;
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    /// Mount a plc.directory audit log whose head op lists `signing_key_id` as a rotation key.
    pub(super) async fn mount_audit_log(
        server: &MockServer,
        did: &str,
        handle: &str,
        signing_key_id: &str,
        endpoint: &str,
    ) {
        let log = serde_json::json!([{
            "did": did,
            "cid": "bafyCurrentHead",
            "createdAt": "2026-07-02T00:00:00Z",
            "nullified": false,
            "operation": {
                "type": "plc_operation",
                "prev": null,
                "rotationKeys": ["did:key:zDeviceKeyPlaceholder", signing_key_id],
                "verificationMethods": { "atproto": signing_key_id },
                "alsoKnownAs": [format!("at://{handle}")],
                "services": {
                    "atproto_pds": {
                        "type": "AtprotoPersonalDataServer",
                        "endpoint": endpoint
                    }
                }
            }
        }]);
        Mock::given(method("GET"))
            .and(path(format!("/{did}/log/audit")))
            .respond_with(ResponseTemplate::new(200).set_body_json(log))
            .mount(server)
            .await;
    }

    /// Seed a single-use PLC operation token, returning its plaintext.
    pub(super) async fn seed_token(db: &sqlx::SqlitePool, did: &str) -> String {
        let token = crate::auth::token::generate_token();
        crate::db::plc_operation_tokens::insert_plc_operation_token(db, did, &token.hash)
            .await
            .unwrap();
        token.plaintext
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn post_req(jwt: Option<&str>, body: serde_json::Value) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.identity.signPlcOperation")
            .header("Content-Type", "application/json");
        if let Some(jwt) = jwt {
            builder = builder.header("Authorization", format!("Bearer {jwt}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    #[tokio::test]
    async fn signs_operation_chained_on_current_head() {
        let plc = MockServer::start().await;
        let state = state_with_master_key_and_plc(plc.uri()).await;
        let db = state.db.clone();
        let did = "did:plc:signplc11111111111111111";
        let key_id = seed_account_with_signing_key(&db, did, "alice.example.com").await;
        mount_audit_log(
            &plc,
            did,
            "alice.example.com",
            &key_id,
            &state.config.public_url,
        )
        .await;
        let token = seed_token(&db, did).await;
        let jwt = access_jwt(&[0x42u8; 32], did);

        let response = app(state)
            .oneshot(post_req(Some(&jwt), serde_json::json!({ "token": token })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let op = &json["operation"];

        // Chains onto the mocked head and is signed by the PDS-held key.
        assert_eq!(op["prev"], "bafyCurrentHead");
        assert_eq!(op["type"], "plc_operation");
        assert!(op["sig"].as_str().is_some(), "operation must be signed");
        let signed_op_str = serde_json::to_string(op).unwrap();
        crypto::verify_plc_operation(&signed_op_str, &[crypto::DidKeyUri(key_id)])
            .expect("operation signature must verify against the PDS rotation key");
    }

    /// Authorization is against the DID's CURRENT rotation set, not the request overlay: an op
    /// that DROPS the PDS key from the *new* rotationKeys is still valid, because the PDS key is
    /// still authorized to sign it (it's in the current op). This is a legitimate migration shape.
    #[tokio::test]
    async fn authorizes_op_that_removes_pds_key_from_new_rotation_set() {
        let plc = MockServer::start().await;
        let state = state_with_master_key_and_plc(plc.uri()).await;
        let db = state.db.clone();
        let did = "did:plc:signplc55555555555555555";
        let key_id = seed_account_with_signing_key(&db, did, "erin.example.com").await;
        mount_audit_log(
            &plc,
            did,
            "erin.example.com",
            &key_id,
            &state.config.public_url,
        )
        .await;
        let token = seed_token(&db, did).await;
        let jwt = access_jwt(&[0x42u8; 32], did);

        // New rotationKeys deliberately EXCLUDE the PDS key (only a fresh device key remains).
        let new_device = crypto::generate_p256_keypair().unwrap();
        let body = serde_json::json!({
            "token": token,
            "rotationKeys": [new_device.key_id.0],
        });
        let response = app(state)
            .oneshot(post_req(Some(&jwt), body))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "removing the PDS key from the new op is authorized by the current rotation set"
        );
        let op = body_json(response).await["operation"].clone();
        assert_eq!(op["rotationKeys"][0], new_device.key_id.0);
        assert_eq!(op["rotationKeys"].as_array().unwrap().len(), 1);
    }

    /// A transient plc.directory failure must NOT burn the single-use token — the user should be
    /// able to retry once plc.directory recovers, without a fresh email round-trip.
    #[tokio::test]
    async fn transient_plc_failure_preserves_token() {
        let plc = MockServer::start().await;
        let did = "did:plc:signplc66666666666666666";
        // Audit-log fetch fails (500) → the sign flow aborts before consuming the token.
        Mock::given(method("GET"))
            .and(path(format!("/{did}/log/audit")))
            .respond_with(ResponseTemplate::new(500))
            .mount(&plc)
            .await;
        let state = state_with_master_key_and_plc(plc.uri()).await;
        let db = state.db.clone();
        seed_account_with_signing_key(&db, did, "frank.example.com").await;
        let token = seed_token(&db, did).await;
        let jwt = access_jwt(&[0x42u8; 32], did);

        let response = app(state)
            .oneshot(post_req(Some(&jwt), serde_json::json!({ "token": token })))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "a plc.directory outage surfaces as 502"
        );

        // The token was NOT consumed — used_at is still NULL, so it can be retried.
        let used_at: Option<String> =
            sqlx::query_scalar("SELECT used_at FROM plc_operation_tokens WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            used_at.is_none(),
            "a transient plc.directory failure must not burn the token"
        );
    }

    /// A did:web account gets an explicit "not a did:plc" 400 up front, without a plc.directory
    /// round trip — the guard fires before any audit-log fetch that would otherwise 404.
    #[tokio::test]
    async fn did_web_account_rejected_without_plc_call() {
        let plc = MockServer::start().await;
        // No audit-log mock mounted: any plc.directory GET would 404, proving the guard short-circuits.
        let state = state_with_master_key_and_plc(plc.uri()).await;
        let did = "did:web:malpercio.dev";
        let jwt = access_jwt(&[0x42u8; 32], did);

        let response = app(state)
            .oneshot(post_req(
                Some(&jwt),
                serde_json::json!({ "token": "irrelevant" }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn missing_token_rejected() {
        let plc = MockServer::start().await;
        let state = state_with_master_key_and_plc(plc.uri()).await;
        let db = state.db.clone();
        let did = "did:plc:signplc22222222222222222";
        seed_account_with_signing_key(&db, did, "bob.example.com").await;
        let jwt = access_jwt(&[0x42u8; 32], did);

        let response = app(state)
            .oneshot(post_req(Some(&jwt), serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_token_rejected_and_no_plc_call() {
        let plc = MockServer::start().await;
        let state = state_with_master_key_and_plc(plc.uri()).await;
        let db = state.db.clone();
        let did = "did:plc:signplc33333333333333333";
        seed_account_with_signing_key(&db, did, "carol.example.com").await;
        let jwt = access_jwt(&[0x42u8; 32], did);

        // A token that was never issued: base64url of 32 bytes so hash_bearer_token succeeds.
        let bogus = crate::auth::token::generate_token().plaintext;
        let response = app(state)
            .oneshot(post_req(Some(&jwt), serde_json::json!({ "token": bogus })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Full interop handshake: the account requests a PDS-signed identity operation that
    /// repoints its PDS endpoint (`signPlcOperation`), then submits it (`submitPlcOperation`).
    /// Exercises both identity-signing endpoints end-to-end against a mocked plc.directory —
    /// the standard-tooling path an account uses to migrate off ezpds (ADR-0002 interop leg).
    #[tokio::test]
    async fn sign_then_submit_repoints_the_did() {
        let plc = MockServer::start().await;
        let state = state_with_master_key_and_plc(plc.uri()).await;
        let db = state.db.clone();
        let did = "did:plc:handshake1111111111111111";
        let key_id = seed_account_with_signing_key(&db, did, "alice.example.com").await;
        mount_audit_log(
            &plc,
            did,
            "alice.example.com",
            &key_id,
            &state.config.public_url,
        )
        .await;
        // plc.directory accepts the eventual submit.
        Mock::given(method("POST"))
            .and(path(format!("/{did}")))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&plc)
            .await;
        let token = seed_token(&db, did).await;
        let jwt = access_jwt(&[0x42u8; 32], did);
        let new_endpoint = "https://new-pds.example.com";

        // Leg 1: sign an operation moving the atproto_pds service endpoint.
        let sign_body = serde_json::json!({
            "token": token,
            "services": {
                "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": new_endpoint }
            }
        });
        let signed = app(state.clone())
            .oneshot(post_req(Some(&jwt), sign_body))
            .await
            .unwrap();
        assert_eq!(signed.status(), StatusCode::OK);
        let operation = body_json(signed).await["operation"].clone();

        // Leg 2: submit that operation to repoint the DID.
        let submit_req = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.identity.submitPlcOperation")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::from(
                serde_json::json!({ "operation": operation }).to_string(),
            ))
            .unwrap();
        let submitted = app(state).oneshot(submit_req).await.unwrap();
        assert_eq!(submitted.status(), StatusCode::OK);

        // The cached DID document now points at the new PDS.
        let doc: String = sqlx::query_scalar("SELECT document FROM did_documents WHERE did = ?")
            .bind(did)
            .fetch_one(&db)
            .await
            .unwrap();
        let doc: serde_json::Value = serde_json::from_str(&doc).unwrap();
        assert_eq!(doc["service"][0]["serviceEndpoint"], new_endpoint);
        // plc mock's `.expect(1)` verifies the submit POST fired on drop.
    }

    #[tokio::test]
    async fn token_is_single_use() {
        let plc = MockServer::start().await;
        let state = state_with_master_key_and_plc(plc.uri()).await;
        let db = state.db.clone();
        let did = "did:plc:signplc44444444444444444";
        let key_id = seed_account_with_signing_key(&db, did, "dave.example.com").await;
        mount_audit_log(
            &plc,
            did,
            "dave.example.com",
            &key_id,
            &state.config.public_url,
        )
        .await;
        let token = seed_token(&db, did).await;
        let jwt = access_jwt(&[0x42u8; 32], did);

        let first = app(state.clone())
            .oneshot(post_req(
                Some(&jwt),
                serde_json::json!({ "token": token.clone() }),
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = app(state)
            .oneshot(post_req(Some(&jwt), serde_json::json!({ "token": token })))
            .await
            .unwrap();
        assert_eq!(
            second.status(),
            StatusCode::UNAUTHORIZED,
            "a consumed token must not sign a second operation"
        );
    }
}
