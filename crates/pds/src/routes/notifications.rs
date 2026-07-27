// pattern: Imperative Shell
//
// The account-holder's notification endpoints:
//
//   POST   /v1/notifications/register               — register this device for push
//   DELETE /v1/notifications/register/{deviceUuid}  — stop pushing to this device
//   GET    /v1/notifications/sender-keys            — the set of keys to pin
//
// Auth is `auth::extractors::authenticate_access` (the DPoP-binding seam every access-token
// verification must route through — `just auth-seam-check` enforces it), so these live on
// the same-origin `/v1/*` surface alongside the other wallet endpoints.
//
// Registration keys on `(did, device_uuid)` rather than the `devices` table: `devices` rows
// are deleted inside the DID-promotion transaction, so a registration anchored there would
// die exactly when the account starts mattering. `device_uuid` is app-generated and stable
// across reinstalls of the same install identity.
//
// The relay round trip is deliberately **not** in the request path. Registration is one of
// the first calls the wallet makes after promotion; making it wait on a third-party relay
// would put that relay's uptime in the onboarding critical path for a feature whose entire
// failure mode is a missed banner. The row is stored, the relay registration is enqueued,
// and the response says plainly which of the two happened.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, Method, Uri},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::extractors::authenticate_access;
use crate::db::notifications as store;
use crate::notify_relay_client::{NotifyJob, RegistrationOwner};
use crate::routes::notification_views::{
    require_notifications_enabled, sender_keys_response, validate_registration_fields,
    SenderKeysResponse,
};
use common::{ApiError, ErrorCode};

// ── POST /v1/notifications/register ───────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    /// App-generated stable device identifier. Survives DID promotion, unlike `devices.id`.
    pub device_uuid: String,
    /// The device's P-256 notification `did:key`. Payloads are sealed to this.
    pub notification_public_key: String,
    pub apns_token: String,
    pub apns_topic: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    /// Always `"pending"`: the row is stored, and the relay handle is being minted in the
    /// background. The app learns the outcome by re-reading, not by blocking here.
    pub status: &'static str,
}

pub async fn register_notifications(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    let user = authenticate_access(&headers, &method, &uri, &state)?;
    require_notifications_enabled(&state)?;

    if payload.device_uuid.is_empty() || payload.device_uuid.len() > MAX_DEVICE_UUID_LEN {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "deviceUuid must be between 1 and 128 characters",
        ));
    }
    validate_registration_fields(
        &payload.notification_public_key,
        &payload.apns_token,
        &payload.apns_topic,
    )?;

    store::upsert_registration(
        &state.db,
        &user.did,
        &payload.device_uuid,
        &payload.notification_public_key,
        &payload.apns_token,
        &payload.apns_topic,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to store a notification registration");
        ApiError::new(ErrorCode::InternalError, "failed to store the registration")
    })?;

    if let Some(sender) = state.notify_sender.as_ref() {
        sender.send(NotifyJob::RegisterHandle {
            owner: RegistrationOwner::Account {
                did: user.did.clone(),
                device_uuid: payload.device_uuid.clone(),
            },
            apns_token: payload.apns_token,
            apns_topic: payload.apns_topic,
        });
    }

    Ok(Json(RegisterResponse { status: "pending" }))
}

const MAX_DEVICE_UUID_LEN: usize = 128;

// ── DELETE /v1/notifications/register/{deviceUuid} ────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnregisterResponse {
    /// `"deleted"` when a registration existed, `"absent"` when there was nothing to remove.
    pub status: &'static str,
}

pub async fn unregister_notifications(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(device_uuid): Path<String>,
) -> Result<Json<UnregisterResponse>, ApiError> {
    let user = authenticate_access(&headers, &method, &uri, &state)?;

    // Deliberately *not* gated on `require_notifications_enabled`, unlike register and
    // sender-keys. An operator who removes the relay config leaves registrations behind; the
    // one thing a device should still be able to do is disown its own row and have the relay
    // told to drop the handle. Gating this would strand exactly the rows most worth removing.

    // Read the row before deleting so the relay handle can be dropped too — otherwise the
    // relay keeps forwarding to a device this account has explicitly disowned.
    let handle = store::list_registrations(&state.db, &user.did)
        .await
        .ok()
        .and_then(|rows| {
            rows.into_iter()
                .find(|r| r.device_id == device_uuid)
                .and_then(|r| r.push_handle)
        });

    let existed = store::delete_registration(&state.db, &user.did, &device_uuid)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to delete a notification registration");
            ApiError::new(
                ErrorCode::InternalError,
                "failed to delete the registration",
            )
        })?;

    if let (Some(handle), Some(sender)) = (handle, state.notify_sender.as_ref()) {
        sender.send(NotifyJob::DropHandle { handle });
    }

    Ok(Json(UnregisterResponse {
        // Idempotent: repeating a delete is a 200, not a 404. The app retries this on a flaky
        // network and must not have to distinguish "already gone" from "failed".
        status: if existed { "deleted" } else { "absent" },
    }))
}

// ── GET /v1/notifications/sender-keys ─────────────────────────────────────────

/// The account-holder's re-pin surface. The published set itself is built by
/// [`notification_views::sender_keys_response`], which the operator surface shares — the
/// sender keys belong to the instance, not to whoever is asking.
pub async fn get_sender_keys(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<SenderKeysResponse>, ApiError> {
    authenticate_access(&headers, &method, &uri, &state)?;
    require_notifications_enabled(&state)?;
    Ok(Json(sender_keys_response(&state).await?))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::app as build_router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::{json, Value};
    use std::sync::Arc;
    use tower::ServiceExt;

    /// A state with notifications configured but no live relay — enough to exercise every
    /// route, since the relay leg is asynchronous by design.
    async fn state_with_notifications() -> AppState {
        let mut state = crate::state::test_state().await;
        let mut config = (*state.config).clone();
        config.notifications.relay = Some("relay-node-id".to_string());
        config.signing_key_master_key =
            Some(common::Sensitive(zeroize::Zeroizing::new([0x7u8; 32])));
        state.config = Arc::new(config);
        state
    }

    async fn seed_account(state: &AppState, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'notif@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .expect("seed account");
    }

    /// A full-access HS256 access token, the shape `authenticate_access` verifies.
    fn token(state: &AppState, did: &str) -> String {
        #[derive(serde::Serialize)]
        struct Claims {
            sub: String,
            aud: String,
            exp: u64,
            scope: String,
        }
        let claims = Claims {
            sub: did.to_string(),
            aud: "did:plc:test".to_string(),
            exp: (chrono::Utc::now().timestamp() + 3600) as u64,
            scope: "com.atproto.access".to_string(),
        };
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(&state.jwt_secret),
        )
        .unwrap()
    }

    async fn call(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
        let response = build_router(state)
            .oneshot(request)
            .await
            .expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    fn device_key() -> String {
        crypto::generate_p256_keypair().unwrap().key_id.0
    }

    fn register_body(device_uuid: &str, key: &str) -> Value {
        json!({
            "deviceUuid": device_uuid,
            "notificationPublicKey": key,
            "apnsToken": "abcdef0123456789",
            "apnsTopic": "org.obsign.identitywallet",
        })
    }

    async fn register(state: AppState, did: &str, body: Value) -> (StatusCode, Value) {
        let auth = format!("Bearer {}", token(&state, did));
        call(
            state,
            Request::post("/v1/notifications/register")
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    #[tokio::test]
    async fn registering_stores_the_row_and_reports_it_pending() {
        let state = state_with_notifications().await;
        seed_account(&state, "did:plc:notifroutes").await;

        let (status, body) = register(
            state.clone(),
            "did:plc:notifroutes",
            register_body("device-1", &device_key()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "pending");

        let rows = store::list_registrations(&state.db, "did:plc:notifroutes")
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device_id, "device-1");
        assert_eq!(
            rows[0].push_handle, None,
            "the handle is minted by the worker, not the request path"
        );
    }

    #[tokio::test]
    async fn registration_requires_authentication() {
        let state = state_with_notifications().await;
        let (status, _) = call(
            state,
            Request::post("/v1/notifications/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    register_body("device-1", &device_key()).to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// A key we cannot decode now is a device we cannot reach later — reject at the boundary.
    #[tokio::test]
    async fn a_non_p256_did_key_is_refused() {
        let state = state_with_notifications().await;
        seed_account(&state, "did:plc:notifroutes").await;

        for bad in [
            "",
            "not-a-did-key",
            "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
        ] {
            let (status, _) = register(
                state.clone(),
                "did:plc:notifroutes",
                register_body("device-1", bad),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "accepted key: {bad:?}");
        }
    }

    #[tokio::test]
    async fn a_malformed_apns_token_or_topic_is_refused() {
        let state = state_with_notifications().await;
        seed_account(&state, "did:plc:notifroutes").await;
        let key = device_key();

        let mut body = register_body("device-1", &key);
        body["apnsToken"] = json!("not hex!");
        let (status, _) = register(state.clone(), "did:plc:notifroutes", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let mut body = register_body("device-1", &key);
        body["apnsTopic"] = json!("org.obsign/../../etc");
        let (status, _) = register(state.clone(), "did:plc:notifroutes", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// The whole feature must be absent, not merely quiet, when unconfigured.
    #[tokio::test]
    async fn the_routes_are_not_implemented_without_a_configured_relay() {
        let state = crate::state::test_state().await;
        seed_account(&state, "did:plc:notifroutes").await;

        let (status, _) = register(
            state.clone(),
            "did:plc:notifroutes",
            register_body("device-1", &device_key()),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);

        let auth = format!("Bearer {}", token(&state, "did:plc:notifroutes"));
        let (status, _) = call(
            state.clone(),
            Request::get("/v1/notifications/sender-keys")
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);

        let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_sender_keys")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(keys, 0);
    }

    #[tokio::test]
    async fn unregistering_is_idempotent() {
        let state = state_with_notifications().await;
        seed_account(&state, "did:plc:notifroutes").await;
        register(
            state.clone(),
            "did:plc:notifroutes",
            register_body("device-1", &device_key()),
        )
        .await;

        let delete = |state: AppState| async move {
            let auth = format!("Bearer {}", token(&state, "did:plc:notifroutes"));
            call(
                state,
                Request::delete("/v1/notifications/register/device-1")
                    .header("authorization", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
        };

        let (status, body) = delete(state.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "deleted");

        let (status, body) = delete(state.clone()).await;
        assert_eq!(status, StatusCode::OK, "a repeat delete must not 404");
        assert_eq!(body["status"], "absent");
    }

    /// One account must not be able to unregister another's device.
    #[tokio::test]
    async fn unregistering_only_touches_the_callers_own_devices() {
        let state = state_with_notifications().await;
        seed_account(&state, "did:plc:owner").await;
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:other', 'other@example.com', 'h', datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();
        register(
            state.clone(),
            "did:plc:owner",
            register_body("device-1", &device_key()),
        )
        .await;

        let auth = format!("Bearer {}", token(&state, "did:plc:other"));
        let (status, body) = call(
            state.clone(),
            Request::delete("/v1/notifications/register/device-1")
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "absent");
        assert_eq!(
            store::list_registrations(&state.db, "did:plc:owner")
                .await
                .unwrap()
                .len(),
            1,
            "the owner's registration must survive another account's delete"
        );
    }

    /// The re-pin contract, over the wire: a retired key is still published, a revoked one is
    /// not, and the newest active key leads.
    #[tokio::test]
    async fn sender_keys_publishes_active_and_retired_but_never_revoked() {
        let state = state_with_notifications().await;
        seed_account(&state, "did:plc:notifroutes").await;

        let master = [0x7u8; 32];
        let retired = crate::notifications::generate_sender_key(&state, &master)
            .await
            .unwrap()
            .0;
        let revoked = crate::notifications::generate_sender_key(&state, &master)
            .await
            .unwrap()
            .0;
        let active = crate::notifications::generate_sender_key(&state, &master)
            .await
            .unwrap()
            .0;
        store::retire_sender_key(&state.db, retired).await.unwrap();
        store::revoke_sender_key(&state.db, revoked).await.unwrap();

        let auth = format!("Bearer {}", token(&state, "did:plc:notifroutes"));
        let (status, body) = call(
            state.clone(),
            Request::get("/v1/notifications/sender-keys")
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let kids: Vec<i64> = body["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_i64().unwrap())
            .collect();
        assert_eq!(
            kids,
            vec![active, retired],
            "revoked must be gone; retired must remain"
        );

        // Every published key is a usable P-256 did:key, not an opaque string.
        for key in body["keys"].as_array().unwrap() {
            crypto::p256_public_key_from_did_key(key["publicKey"].as_str().unwrap())
                .expect("published key must decode");
        }
    }

    /// A relay configured without a master key cannot mint or unwrap sender keys. It must say
    /// so, rather than answer 200 with an empty set — a client that pinned nothing would then
    /// fail to verify every notification it received, with no way to tell why.
    #[tokio::test]
    async fn a_configured_instance_without_a_master_key_refuses_to_publish_an_empty_set() {
        let mut state = state_with_notifications().await;
        let mut config = (*state.config).clone();
        config.signing_key_master_key = None;
        state.config = Arc::new(config);
        seed_account(&state, "did:plc:notifroutes").await;

        let auth = format!("Bearer {}", token(&state, "did:plc:notifroutes"));
        let (status, body) = call(
            state.clone(),
            Request::get("/v1/notifications/sender-keys")
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        // 503, not the 501 an unconfigured instance returns: the operator *has* opted in, the
        // instance simply cannot serve the keys right now.
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("master key"),
            "the error must name the missing master key: {body}"
        );
    }

    /// The other route to an empty set: the master key is present, but the stored key material
    /// will not decrypt under it (a restored backup wrapped under a previous KEK, say). The
    /// client must be told, not handed an empty array it would pin as authoritative.
    #[tokio::test]
    async fn a_stored_key_that_will_not_unwrap_is_reported_rather_than_silently_dropped() {
        let state = state_with_notifications().await;
        seed_account(&state, "did:plc:notifroutes").await;

        // Ciphertext that is well-formed base64 but not decryptable under this master key —
        // exactly what a KEK mismatch leaves behind.
        store::insert_sender_key(&state.db, "bm90LWEtcmVhbC1jaXBoZXJ0ZXh0LWF0LWFsbA")
            .await
            .unwrap();

        let auth = format!("Bearer {}", token(&state, "did:plc:notifroutes"));
        let (status, body) = call(
            state.clone(),
            Request::get("/v1/notifications/sender-keys")
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "an unusable key set must not be served as an empty one: {body}"
        );
        assert!(
            body["keys"].is_null(),
            "no key array should be returned: {body}"
        );
    }

    /// An app that fetches the set before the instance has ever sent anything must still get
    /// a key to pin — otherwise it cannot verify the very first notification it receives.
    #[tokio::test]
    async fn the_first_fetch_mints_the_instances_first_sender_key() {
        let state = state_with_notifications().await;
        seed_account(&state, "did:plc:notifroutes").await;

        let auth = format!("Bearer {}", token(&state, "did:plc:notifroutes"));
        let (status, body) = call(
            state.clone(),
            Request::get("/v1/notifications/sender-keys")
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["keys"].as_array().unwrap().len(), 1);
    }
}
