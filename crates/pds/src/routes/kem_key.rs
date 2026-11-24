// pattern: Imperative Shell

//! Install or rotate the account's Spaces KEM key (ADR-0043), account-owner authed:
//!
//! * `POST /v1/kem-key` — stage a fresh KEM key.
//! * `POST /v1/kem-key/complete` — publish it, then make it the active key.
//!
//! Space writes are refused with `KemKeyNotPublished` until the account's DID document carries
//! its active KEM key as `#atproto_kem`. Accounts created before KEM keys existed reach that state
//! through this ceremony; any account can use it again to rotate the key. Publishing is different
//! for each kind of DID, because each is controlled by someone different:
//!
//! * **did:plc.** The wallet's device key outranks the PDS key in `rotationKeys`, so the wallet
//!   builds the op: it sets `verificationMethods.atproto_kem` to the staged key, drops the retired
//!   `atproto_space` method and `atproto_space_host` service if present, changes nothing else,
//!   and signs it with the device key. `complete` takes that op, checks it against the DID's
//!   current state, submits it to plc.directory, and promotes the staged key.
//! * **Self-hosted did:web.** The user publishes `did.json` on their own domain. The wallet
//!   composes the updated document; the user uploads it; `complete` fetches the live document
//!   and promotes the staged key only if it publishes exactly that key.
//! * **Custos-hosted did:web.** Custos serves the document itself, so `POST /v1/kem-key` writes
//!   the key into the stored document and promotes it at once; there is nothing to complete.
//!
//! Every path ends with an `#identity` frame, so syncers re-resolve the document and pick up the
//! new key. No repo write lock is held: the KEM key signs nothing, and a syncer whose MAC fails
//! against a cached key re-fetches the document and retries.

use axum::{
    extract::State,
    http::{HeaderMap, Method, Uri},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::app::AppState;
use crate::wallet_plc_op::{announce_identity, submit_and_cache, verify_wallet_op};
use common::{ApiError, ErrorCode};
use custos_core::auth::guards::authenticate_owner;
use custos_core::identity::plc::CurrentPlcState;
use custos_core::kem::{generate_wrapped_key, master_key, KEM_VERIFICATION_METHOD_ID};
use custos_db::kem_keys::{
    get_active_kem_key, get_staged_kem_key, promote_staged_kem_key, stage_kem_key, KemKey,
};

/// The retired Spaces entries a KEM-key op may delete (Custos used to recommend them).
const SPACE_VERIFICATION_METHOD_ID: &str = "atproto_space";
const SPACE_HOST_SERVICE_ID: &str = "atproto_space_host";

fn key_query_error(e: sqlx::Error) -> ApiError {
    ApiError::internal_as(e, "KEM key query failed", "failed to access KEM keys")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KemKeyResponse {
    /// The KEM key's `did:key`: the staged key after `POST /v1/kem-key`, the active key once
    /// published.
    pub kem_key: String,
    /// `staged` (publish it, then call `complete`) or `published` (now the active key).
    pub status: &'static str,
}

// ── POST /v1/kem-key ──────────────────────────────────────────────────────────

pub async fn stage_kem_key_handler(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<KemKeyResponse>, ApiError> {
    let did = authenticate_owner(&headers, &method, &uri, &state).await?;
    master_key(&state)?;

    // Always a fresh key, replacing anything staged earlier: rotating because a key leaked is
    // pointless if the replacement was minted before the leak.
    let staged = generate_wrapped_key(&state)?;
    stage_kem_key(&state.db, &did, &staged)
        .await
        .map_err(key_query_error)?;

    // A Custos-hosted did:web document is ours to edit: publish and promote now.
    if did.starts_with("did:web:")
        && custos_db::dids::did_web_hosting_enabled(&state.db, &did).await?
    {
        let stored = custos_db::dids::get_did_document(&state.db, &did)
            .await?
            .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "no stored DID document"))?;
        let updated = document_with_kem_key(&stored, &staged.key_id);
        custos_db::dids::rewrite_did_document(&state.db, &did, &updated).await?;
        promote(&state, &did, &staged).await?;
        announce_identity(&state, &did).await;
        tracing::info!(did = %did, key_id = %staged.key_id, "published KEM key in hosted did:web document");
        return Ok(Json(KemKeyResponse {
            kem_key: staged.key_id,
            status: "published",
        }));
    }

    tracing::info!(did = %did, key_id = %staged.key_id, "staged KEM key");
    Ok(Json(KemKeyResponse {
        kem_key: staged.key_id,
        status: "staged",
    }))
}

// ── POST /v1/kem-key/complete ─────────────────────────────────────────────────

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct CompleteKemKeyRequest {
    /// The wallet-signed PLC op publishing the staged key (did:plc only).
    pub operation: Option<Value>,
}

pub async fn complete_kem_key_handler(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Json(request): Json<CompleteKemKeyRequest>,
) -> Result<Json<KemKeyResponse>, ApiError> {
    let did = authenticate_owner(&headers, &method, &uri, &state).await?;

    if did.starts_with("did:plc:") {
        let operation = request.operation.ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidRequest,
                "operation is required for a did:plc account",
            )
        })?;
        return complete_did_plc(&state, &did, &operation).await.map(Json);
    }

    if custos_db::dids::did_web_hosting_enabled(&state.db, &did).await? {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "a Custos-hosted did:web document is published by POST /v1/kem-key itself",
        ));
    }
    complete_self_hosted_did_web(&state, &did).await.map(Json)
}

/// did:plc: check the wallet's op, submit it, promote.
async fn complete_did_plc(
    state: &AppState,
    did: &common::Did,
    operation: &Value,
) -> Result<KemKeyResponse, ApiError> {
    let op = verify_wallet_op(state, did, operation).await?;
    let op_kem_key = op
        .verified
        .verification_methods
        .get(KEM_VERIFICATION_METHOD_ID)
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidRequest,
                "operation has no atproto_kem verification method",
            )
        })?;

    let Some(staged) = get_staged_kem_key(&state.db, did)
        .await
        .map_err(key_query_error)?
    else {
        // Nothing staged: a retry after this exact op already landed and was promoted succeeds.
        return already_published(state, did, op.already_landed.then_some(op_kem_key.as_str()))
            .await;
    };

    // When the op already is the head, `current` is its own state, so the diff check below
    // would pass trivially; that is fine, because a landed op was checked before it was sent.
    if !op.already_landed {
        check_kem_op(&op.current, &op.verified, &staged.key_id)?;
    } else if op_kem_key != staged.key_id {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "operation does not publish the staged KEM key",
        ));
    }

    submit_and_cache(state, did, &op).await?;
    promote(state, did, &staged).await?;
    announce_identity(state, did).await;
    tracing::info!(did = %did, key_id = %staged.key_id, "published KEM key through PLC");
    Ok(KemKeyResponse {
        kem_key: staged.key_id,
        status: "published",
    })
}

/// Self-hosted did:web: fetch the live document and promote only on an exact match.
async fn complete_self_hosted_did_web(
    state: &AppState,
    did: &common::Did,
) -> Result<KemKeyResponse, ApiError> {
    let Some(staged) = get_staged_kem_key(&state.db, did)
        .await
        .map_err(key_query_error)?
    else {
        return already_published(state, did, None).await;
    };

    // Fetched through the SSRF-hardened client: the URL comes from a user-controlled domain.
    let bytes =
        custos_core::identity::resolution::resolve_web_did_document_bytes(state, did).await?;
    let document: Value = serde_json::from_str(&bytes).map_err(|_| {
        ApiError::new(
            ErrorCode::InvalidRequest,
            "published did:web document is not valid JSON",
        )
    })?;
    if document.get("id").and_then(Value::as_str) != Some(did) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "published did:web document id does not match your DID",
        ));
    }
    if !custos_core::kem::publishes(&document, &staged) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "published did:web document does not carry the staged KEM key as #atproto_kem",
        ));
    }

    custos_db::dids::upsert_did_document(&state.db, did, &document).await?;
    promote(state, did, &staged).await?;
    announce_identity(state, did).await;
    tracing::info!(did = %did, key_id = %staged.key_id, "published KEM key through did.json");
    Ok(KemKeyResponse {
        kem_key: staged.key_id,
        status: "published",
    })
}

/// The answer to a `complete` with nothing staged: success when the active key is `expected`
/// (a did:plc retry) or is published in the cached document (a did:web retry), 400 otherwise.
async fn already_published(
    state: &AppState,
    did: &common::Did,
    expected: Option<&str>,
) -> Result<KemKeyResponse, ApiError> {
    let active = get_active_kem_key(&state.db, did)
        .await
        .map_err(key_query_error)?;
    let done = match (&active, expected) {
        (Some(active), Some(expected)) => active.key_id == expected,
        (Some(active), None) if did.starts_with("did:web:") => {
            custos_db::dids::get_did_document(&state.db, did)
                .await?
                .is_some_and(|doc| custos_core::kem::publishes(&doc, active))
        }
        _ => false,
    };
    match active {
        Some(active) if done => Ok(KemKeyResponse {
            kem_key: active.key_id,
            status: "published",
        }),
        _ => Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "no KEM key is staged for this account; call POST /v1/kem-key first",
        )),
    }
}

/// Staged → active, deleting the key it replaces. A `false` from the store means a concurrent
/// `complete` promoted it first, which is fine only if that left this key active.
async fn promote(state: &AppState, did: &common::Did, staged: &KemKey) -> Result<(), ApiError> {
    if promote_staged_kem_key(&state.db, did, &staged.key_id)
        .await
        .map_err(key_query_error)?
    {
        return Ok(());
    }
    let active = get_active_kem_key(&state.db, did)
        .await
        .map_err(key_query_error)?;
    if active.is_some_and(|active| active.key_id == staged.key_id) {
        return Ok(());
    }
    tracing::error!(did = %did, key_id = %staged.key_id, "KEM key cutover failed: staged key vanished before promotion");
    Err(ApiError::new(
        ErrorCode::InternalError,
        "failed to promote the staged KEM key",
    ))
}

/// The server-side mirror of the wallet's guard: the op may set `atproto_kem` to the staged key
/// and delete the retired Spaces entries, and must change nothing else. A KEM op that also moved
/// the signing key, a rotation key, the handle, or the PDS endpoint would be a different
/// ceremony smuggled through this one.
fn check_kem_op(
    current: &CurrentPlcState,
    op: &crypto::VerifiedPlcOp,
    staged_key_id: &str,
) -> Result<(), ApiError> {
    let invalid = |msg: &str| Err(ApiError::new(ErrorCode::InvalidRequest, msg.to_string()));
    if op
        .verification_methods
        .get(KEM_VERIFICATION_METHOD_ID)
        .map(String::as_str)
        != Some(staged_key_id)
    {
        return invalid("operation does not publish the staged KEM key");
    }
    if op
        .verification_methods
        .contains_key(SPACE_VERIFICATION_METHOD_ID)
        || op.services.contains_key(SPACE_HOST_SERVICE_ID)
    {
        return invalid("operation must drop the retired atproto_space entries");
    }
    let without = |methods: &BTreeMap<String, String>| {
        let mut methods = methods.clone();
        methods.remove(KEM_VERIFICATION_METHOD_ID);
        methods.remove(SPACE_VERIFICATION_METHOD_ID);
        methods
    };
    if without(&op.verification_methods) != without(&current.verification_methods) {
        return invalid("a KEM key operation may change only atproto_kem");
    }
    let mut current_services = current.services.clone();
    current_services.remove(SPACE_HOST_SERVICE_ID);
    if op.services != current_services {
        return invalid("a KEM key operation must not change the DID's services");
    }
    if op.rotation_keys != current.rotation_keys || op.also_known_as != current.also_known_as {
        return invalid("a KEM key operation must not change rotationKeys or alsoKnownAs");
    }
    Ok(())
}

/// A Custos-hosted did:web document with `kem_key_id` as its only `#atproto_kem` method and the
/// retired `#atproto_space` method and `#atproto_space_host` service removed.
fn document_with_kem_key(document: &Value, kem_key_id: &str) -> Value {
    let mut document = document.clone();
    let did = document
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let is = |entry: &Value, fragment: &str| {
        entry.get("id").and_then(Value::as_str).is_some_and(|id| {
            custos_core::identity::resolution::fragment_id_matches(id, &did, fragment)
        })
    };
    let mut methods: Vec<Value> = document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    methods.retain(|m| !is(m, KEM_VERIFICATION_METHOD_ID) && !is(m, SPACE_VERIFICATION_METHOD_ID));
    methods.push(serde_json::json!({
        "id": format!("{did}#{KEM_VERIFICATION_METHOD_ID}"),
        "type": "Multikey",
        "controller": did,
        "publicKeyMultibase": kem_key_id.strip_prefix("did:key:").unwrap_or(kem_key_id),
    }));
    document["verificationMethod"] = Value::Array(methods);
    if let Some(services) = document.get_mut("service").and_then(Value::as_array_mut) {
        services.retain(|s| !is(s, SPACE_HOST_SERVICE_ID));
    }
    document
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use serde_json::json;
    use tower::ServiceExt;
    use uuid::Uuid;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;
    use crate::app::{app, test_state_with_plc_url};
    use crate::routes::test_utils::{
        body_json, seed_account_with_signing_key, seed_kem_key, state_with_master_key,
        test_master_key,
    };
    use custos_core::auth::token::generate_token;

    const DID: &str = "did:plc:kemceremony1111111111111";
    const HEAD_CID: &str = "bafyreidmwn2nk3hb2ta2b3wgqzted5cixmwjjmpq2vt6potol7cke2ptoq";
    const PDS: &str = "https://pds.example.com";

    async fn session_for(state: &AppState, did: &str) -> String {
        let token = generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(did)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .unwrap();
        token.plaintext
    }

    fn post(uri: &str, token: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn services() -> BTreeMap<String, crypto::PlcService> {
        let mut m = BTreeMap::new();
        m.insert(
            "atproto_pds".to_string(),
            crypto::PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: PDS.to_string(),
            },
        );
        m
    }

    fn state_of(
        vms: &[(&str, &str)],
        services: BTreeMap<String, crypto::PlcService>,
    ) -> CurrentPlcState {
        CurrentPlcState {
            cid: HEAD_CID.to_string(),
            rotation_keys: vec!["did:key:zDevice".to_string(), "did:key:zPds".to_string()],
            verification_methods: vms
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            also_known_as: vec!["at://alice.example.com".to_string()],
            services,
        }
    }

    /// The op shape `check_kem_op` reads, built by actually signing one.
    fn signed_op(
        current: &CurrentPlcState,
        vms: BTreeMap<String, String>,
        services: BTreeMap<String, crypto::PlcService>,
    ) -> crypto::VerifiedPlcOp {
        let device = crypto::generate_p256_keypair().unwrap();
        let signer = repo_engine::CommitSigner::from_bytes(&device.private_key_bytes).unwrap();
        let op = crypto::build_did_plc_rotation_op(
            HEAD_CID,
            current.rotation_keys.clone(),
            vms,
            current.also_known_as.clone(),
            services,
            |bytes| Ok(signer.sign(bytes)),
        )
        .unwrap();
        crypto::verify_plc_operation(&op.signed_op_json, &[device.key_id]).unwrap()
    }

    #[test]
    fn a_kem_op_may_set_the_kem_key_and_drop_the_space_entries_only() {
        let mut with_host = services();
        with_host.insert(
            "atproto_space_host".to_string(),
            crypto::PlcService {
                service_type: "AtprotoSpaceHost".to_string(),
                endpoint: PDS.to_string(),
            },
        );
        let current = state_of(
            &[
                ("atproto", "did:key:zSigning"),
                ("atproto_space", "did:key:zSigning"),
            ],
            with_host,
        );
        let vms = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        let good = signed_op(
            &current,
            vms(&[
                ("atproto", "did:key:zSigning"),
                ("atproto_kem", "did:key:zStaged"),
            ]),
            services(),
        );
        assert!(check_kem_op(&current, &good, "did:key:zStaged").is_ok());

        for (label, op) in [
            (
                "other key",
                signed_op(
                    &current,
                    vms(&[
                        ("atproto", "did:key:zSigning"),
                        ("atproto_kem", "did:key:zOther"),
                    ]),
                    services(),
                ),
            ),
            (
                "signing key moved",
                signed_op(
                    &current,
                    vms(&[
                        ("atproto", "did:key:zMoved"),
                        ("atproto_kem", "did:key:zStaged"),
                    ]),
                    services(),
                ),
            ),
            (
                "space method kept",
                signed_op(
                    &current,
                    vms(&[
                        ("atproto", "did:key:zSigning"),
                        ("atproto_space", "did:key:zSigning"),
                        ("atproto_kem", "did:key:zStaged"),
                    ]),
                    services(),
                ),
            ),
            (
                "services changed",
                signed_op(
                    &current,
                    vms(&[
                        ("atproto", "did:key:zSigning"),
                        ("atproto_kem", "did:key:zStaged"),
                    ]),
                    BTreeMap::new(),
                ),
            ),
        ] {
            assert!(
                check_kem_op(&current, &op, "did:key:zStaged").is_err(),
                "{label}"
            );
        }
    }

    #[test]
    fn a_hosted_document_gains_the_kem_key_and_loses_the_space_entries() {
        let did = "did:web:alice.example.com";
        let before = json!({
            "id": did,
            "verificationMethod": [
                {"id": "#atproto", "type": "Multikey", "controller": did, "publicKeyMultibase": "zSigning"},
                {"id": "#atproto_space", "type": "Multikey", "controller": did, "publicKeyMultibase": "zSigning"},
                {"id": format!("{did}#atproto_kem"), "type": "Multikey", "controller": did, "publicKeyMultibase": "zOld"}
            ],
            "service": [
                {"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": PDS},
                {"id": "#atproto_space_host", "type": "AtprotoSpaceHost", "serviceEndpoint": PDS}
            ]
        });
        let after = document_with_kem_key(&before, "did:key:zNew");
        assert_eq!(
            after,
            json!({
                "id": did,
                "verificationMethod": [
                    {"id": "#atproto", "type": "Multikey", "controller": did, "publicKeyMultibase": "zSigning"},
                    {"id": format!("{did}#atproto_kem"), "type": "Multikey", "controller": did, "publicKeyMultibase": "zNew"}
                ],
                "service": [
                    {"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": PDS}
                ]
            })
        );
    }

    /// did:plc end to end: stage, then complete with a device-signed op; the cached document
    /// publishes the new key and the old one is gone.
    #[tokio::test]
    async fn did_plc_stage_then_complete_promotes_the_key() {
        let plc = MockServer::start().await;
        let base = test_state_with_plc_url(plc.uri()).await;
        let mut config = (*base.config).clone();
        config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(
            test_master_key(),
        )));
        let state = AppState {
            core: custos_core::CoreState {
                config: std::sync::Arc::new(config),
                ..base.core
            },
            ..base
        };
        let signing = seed_account_with_signing_key(&state.db, DID, "alice.example.com").await;
        let old = seed_kem_key(&state.db, DID).await;
        let token = session_for(&state, DID).await;
        let device = crypto::generate_p256_keypair().unwrap();
        let rotation_keys = vec![device.key_id.0.clone(), signing.clone()];
        let audit = json!([{
            "did": DID, "cid": HEAD_CID, "createdAt": "2026-11-01T00:00:00Z", "nullified": false,
            "operation": {
                "type": "plc_operation", "prev": null, "sig": "x",
                "rotationKeys": rotation_keys,
                "verificationMethods": {"atproto": signing, "atproto_kem": old.key_id},
                "alsoKnownAs": ["at://alice.example.com"],
                "services": {"atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": PDS}}
            }
        }]);
        Mock::given(method("GET"))
            .and(path(format!("/{DID}/log/audit")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&audit))
            .mount(&plc)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/{DID}")))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&plc)
            .await;

        let staged = body_json(
            app(state.clone())
                .oneshot(post("/v1/kem-key", &token, json!({})))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(staged["status"], "staged");
        let staged_key = staged["kemKey"].as_str().unwrap().to_string();

        let mut vms = BTreeMap::new();
        vms.insert("atproto".to_string(), signing.clone());
        vms.insert("atproto_kem".to_string(), staged_key.clone());
        let signer = repo_engine::CommitSigner::from_bytes(&device.private_key_bytes).unwrap();
        let op = crypto::build_did_plc_rotation_op(
            HEAD_CID,
            rotation_keys,
            vms,
            vec!["at://alice.example.com".to_string()],
            services(),
            |bytes| Ok(signer.sign(bytes)),
        )
        .unwrap();
        let operation: Value = serde_json::from_str(&op.signed_op_json).unwrap();

        let response = app(state.clone())
            .oneshot(post(
                "/v1/kem-key/complete",
                &token,
                json!({"operation": operation}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["status"], "published");

        let active = get_active_kem_key(&state.db, DID).await.unwrap().unwrap();
        assert_eq!(active.key_id, staged_key);
        assert_eq!(get_staged_kem_key(&state.db, DID).await.unwrap(), None);
        let cached = custos_db::dids::get_did_document(&state.db, DID)
            .await
            .unwrap()
            .unwrap();
        assert!(custos_core::kem::publishes(&cached, &active));
    }

    /// A Custos-hosted did:web publishes on stage, with nothing to complete.
    #[tokio::test]
    async fn hosted_did_web_publishes_at_stage() {
        let state = state_with_master_key().await;
        let did = "did:web:hosted.example.com";
        seed_account_with_signing_key(&state.db, did, "hosted.example.com").await;
        custos_db::dids::seed_did_document(
            &state.db,
            did,
            json!({"id": did, "verificationMethod": [
                {"id": "#atproto", "type": "Multikey", "controller": did, "publicKeyMultibase": "zSigning"}
            ]}),
        )
        .await;
        custos_db::dids::set_did_web_hosting(&state.db, did, true)
            .await
            .unwrap();
        let token = session_for(&state, did).await;

        let body = body_json(
            app(state.clone())
                .oneshot(post("/v1/kem-key", &token, json!({})))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["status"], "published");
        let active = get_active_kem_key(&state.db, did).await.unwrap().unwrap();
        assert_eq!(body["kemKey"], active.key_id);
        let served = custos_db::dids::get_did_document(&state.db, did)
            .await
            .unwrap()
            .unwrap();
        assert!(custos_core::kem::publishes(&served, &active));

        let complete = app(state)
            .oneshot(post("/v1/kem-key/complete", &token, json!({})))
            .await
            .unwrap();
        assert_eq!(complete.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn complete_without_a_staged_key_is_refused() {
        let state = state_with_master_key().await;
        let did = "did:web:selfhosted.example.com";
        seed_account_with_signing_key(&state.db, did, "selfhosted.example.com").await;
        let token = session_for(&state, did).await;
        let response = app(state)
            .oneshot(post("/v1/kem-key/complete", &token, json!({})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
