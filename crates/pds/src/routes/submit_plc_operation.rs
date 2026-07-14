// pattern: Imperative Shell
//
// POST /xrpc/com.atproto.identity.submitPlcOperation
//
// Validates a signed PLC operation and submits it to plc.directory, repointing the
// authenticated account's DID. Provided for interop (ADR-0002): the wallet-authorized
// path POSTs its own operations to plc.directory directly and does not route them here.
//
// Validation before submit: the operation must be signed by one of the DID's CURRENT
// rotation keys (fetched from plc.directory) and must chain onto the current head via
// `prev`. After a successful submit the locally-cached DID document is refreshed.
//
// Gather:  AuthenticatedUser (full access) + JSON { operation }
// Process: verify signature vs. current rotation keys → check prev → POST to plc.directory
//          → refresh cached DID document
// Respond: 200, empty body

use axum::{extract::State, response::Json};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::auth::oauth_scopes;
use crate::identity::plc::{build_did_document_from_op, ensure_did_plc, fetch_current_plc_state};

#[derive(Deserialize)]
pub struct SubmitPlcOperationRequest {
    operation: serde_json::Value,
}

#[derive(Serialize)]
pub struct SubmitPlcOperationResponse {}

pub async fn submit_plc_operation(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    Json(request): Json<SubmitPlcOperationRequest>,
) -> Result<Json<SubmitPlcOperationResponse>, ApiError> {
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

    let operation_str = serde_json::to_string(&request.operation).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize submitted operation");
        ApiError::new(ErrorCode::InvalidRequest, "operation is not valid JSON")
    })?;

    // The operation must be authorized by, and chain onto, the DID's CURRENT PLC state.
    let current =
        fetch_current_plc_state(&state.http_client, &state.config.plc_directory_url, did).await?;
    let authorized_keys: Vec<crypto::DidKeyUri> = current
        .rotation_keys
        .iter()
        .cloned()
        .map(crypto::DidKeyUri)
        .collect();

    let verified = crypto::verify_plc_operation(&operation_str, &authorized_keys).map_err(|e| {
        tracing::warn!(error = %e, did = %did, "submitted PLC operation failed verification");
        ApiError::new(
            ErrorCode::InvalidRequest,
            "operation is not signed by a current rotation key",
        )
    })?;
    if verified.prev.as_deref() != Some(current.cid.as_str()) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "operation does not chain onto the current PLC head (prev mismatch)",
        ));
    }

    crate::identity::genesis::post_to_plc_directory(
        &state.http_client,
        &state.config.plc_directory_url,
        did,
        &operation_str,
    )
    .await?;

    // Refresh the cached DID document so local reads (e.g. getSession) reflect the new state.
    // The PLC directory is the source of truth; a cache-update failure is logged, not fatal.
    match build_did_document_from_op(
        did,
        &verified.verification_methods,
        &verified.also_known_as,
        &verified.services,
    ) {
        Ok(doc) => {
            if let Err(e) = update_cached_did_document(&state.db, did, &doc).await {
                tracing::warn!(error = %e, did = %did, "failed to refresh cached DID document after submitPlcOperation (non-fatal)");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, did = %did, "submitted operation had no renderable DID document; cache left unchanged");
        }
    }

    Ok(Json(SubmitPlcOperationResponse {}))
}

/// Upsert the locally-cached DID document for `did`.
async fn update_cached_did_document(
    db: &sqlx::SqlitePool,
    did: &str,
    document: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO did_documents (did, document, created_at, updated_at) \
         VALUES (?, ?, datetime('now'), datetime('now')) \
         ON CONFLICT(did) DO UPDATE SET document = excluded.document, updated_at = datetime('now')",
    )
    .bind(did)
    .bind(document.to_string())
    .execute(db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::app::{app, test_state_with_plc_url, AppState};
    use crate::routes::test_utils::access_jwt;

    async fn state_with_plc(plc_uri: String) -> AppState {
        test_state_with_plc_url(plc_uri).await
    }

    /// Mount an audit log whose head op authorizes `rotation_key_id` and has CID `head_cid`.
    async fn mount_audit_log(
        server: &MockServer,
        did: &str,
        rotation_key_id: &str,
        head_cid: &str,
    ) {
        let log = serde_json::json!([{
            "did": did,
            "cid": head_cid,
            "createdAt": "2026-07-02T00:00:00Z",
            "nullified": false,
            "operation": {
                "type": "plc_operation",
                "prev": null,
                "rotationKeys": [rotation_key_id],
                "verificationMethods": { "atproto": rotation_key_id },
                "alsoKnownAs": ["at://alice.example.com"],
                "services": {
                    "atproto_pds": {
                        "type": "AtprotoPersonalDataServer",
                        "endpoint": "https://old.example.com"
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

    /// Build a signed rotation op chained on `prev`, signed by `kp`, moving the PDS endpoint.
    fn build_op(kp: &crypto::P256Keypair, prev: &str, endpoint: &str) -> serde_json::Value {
        let key_id = kp.key_id.0.clone();
        let mut vms = BTreeMap::new();
        vms.insert("atproto".to_string(), key_id.clone());
        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            crypto::PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: endpoint.to_string(),
            },
        );
        let pk: [u8; 32] = *kp.private_key_bytes;
        let signer = repo_engine::CommitSigner::from_bytes(&pk).unwrap();
        let signed = crypto::build_did_plc_rotation_op(
            prev,
            vec![key_id],
            vms,
            vec!["at://alice.example.com".to_string()],
            services,
            |bytes| Ok(signer.sign(bytes)),
        )
        .unwrap();
        serde_json::from_str(&signed.signed_op_json).unwrap()
    }

    fn post_req(jwt: Option<&str>, body: serde_json::Value) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.identity.submitPlcOperation")
            .header("Content-Type", "application/json");
        if let Some(jwt) = jwt {
            builder = builder.header("Authorization", format!("Bearer {jwt}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    #[tokio::test]
    async fn submits_valid_operation_and_refreshes_cache() {
        let plc = MockServer::start().await;
        let did = "did:plc:submitplc111111111111111";
        let kp = crypto::generate_p256_keypair().unwrap();
        mount_audit_log(&plc, did, &kp.key_id.0, "bafyCurrentHead").await;
        Mock::given(method("POST"))
            .and(path(format!("/{did}")))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&plc)
            .await;

        let state = state_with_plc(plc.uri()).await;
        let db = state.db.clone();
        let op = build_op(&kp, "bafyCurrentHead", "https://new.example.com");
        let jwt = access_jwt(&[0x42u8; 32], did);

        let response = app(state)
            .oneshot(post_req(Some(&jwt), serde_json::json!({ "operation": op })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Cache reflects the submitted op's new PDS endpoint.
        let doc: Option<String> =
            sqlx::query_scalar("SELECT document FROM did_documents WHERE did = ?")
                .bind(did)
                .fetch_optional(&db)
                .await
                .unwrap();
        let doc: serde_json::Value = serde_json::from_str(&doc.expect("did doc cached")).unwrap();
        assert_eq!(
            doc["service"][0]["serviceEndpoint"],
            "https://new.example.com"
        );
        // plc mock's `.expect(1)` verifies the POST happened on drop.
    }

    #[tokio::test]
    async fn wrong_prev_rejected_without_submitting() {
        let plc = MockServer::start().await;
        let did = "did:plc:submitplc222222222222222";
        let kp = crypto::generate_p256_keypair().unwrap();
        mount_audit_log(&plc, did, &kp.key_id.0, "bafyCurrentHead").await;
        // No POST mock mounted: a submit attempt would 404, but we expect prev-check to reject first.

        let state = state_with_plc(plc.uri()).await;
        let op = build_op(&kp, "bafyStalePrev", "https://new.example.com");
        let jwt = access_jwt(&[0x42u8; 32], did);

        let response = app(state)
            .oneshot(post_req(Some(&jwt), serde_json::json!({ "operation": op })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn unauthorized_signer_rejected() {
        let plc = MockServer::start().await;
        let did = "did:plc:submitplc333333333333333";
        let authorized = crypto::generate_p256_keypair().unwrap();
        let attacker = crypto::generate_p256_keypair().unwrap();
        // Audit log authorizes `authorized`, but the op is signed by `attacker`.
        mount_audit_log(&plc, did, &authorized.key_id.0, "bafyCurrentHead").await;

        let state = state_with_plc(plc.uri()).await;
        let op = build_op(&attacker, "bafyCurrentHead", "https://new.example.com");
        let jwt = access_jwt(&[0x42u8; 32], did);

        let response = app(state)
            .oneshot(post_req(Some(&jwt), serde_json::json!({ "operation": op })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn requires_auth() {
        let plc = MockServer::start().await;
        let state = state_with_plc(plc.uri()).await;
        let response = app(state)
            .oneshot(post_req(None, serde_json::json!({ "operation": {} })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A did:web account gets an explicit "not a did:plc" 400 up front, before any plc.directory
    /// round trip.
    #[tokio::test]
    async fn did_web_account_rejected() {
        let plc = MockServer::start().await;
        // No audit-log mock: any plc.directory GET would 404, proving the guard short-circuits.
        let state = state_with_plc(plc.uri()).await;
        let did = "did:web:malpercio.dev";
        let jwt = access_jwt(&[0x42u8; 32], did);

        let response = app(state)
            .oneshot(post_req(Some(&jwt), serde_json::json!({ "operation": {} })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
