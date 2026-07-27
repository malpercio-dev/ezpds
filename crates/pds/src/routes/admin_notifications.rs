// pattern: Imperative Shell
//
// The admin-companion's notification endpoints — the operator-alert analog of
// `routes/notifications.rs`:
//
//   POST /v1/admin/notifications/register    — register this admin device for push
//   GET  /v1/admin/notifications/sender-keys — the set of keys to pin
//
// Auth is `require_admin` (master token OR a device-signed envelope), not `authenticate_access`:
// an operator device authenticates *as a device*, never as an account.
//
// The registration is keyed by the authenticated device id, taken from the credential rather
// than the body. That is the whole security property of this route: a device can register a
// push key for itself and for nothing else, so a compromised operator device cannot redirect
// another device's alerts to itself. It follows that the master token — which authenticates
// no particular device — cannot register at all.

use axum::body::Bytes;
use axum::{
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::guards::{require_admin, require_admin_json, AdminActor};
use crate::db::notifications as store;
use crate::notify_relay_client::{NotifyJob, RegistrationOwner};
use crate::routes::notification_views::{
    require_notifications_enabled, sender_keys_response, validate_registration_fields,
};
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRegisterRequest {
    /// The device's P-256 notification `did:key`. One notification keypair per device, shared
    /// across every relay it is paired with (the admin key model).
    pub notification_public_key: String,
    pub apns_token: String,
    pub apns_topic: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRegisterResponse {
    /// Always `"pending"` — the relay handle is minted in the background, exactly as on the
    /// account surface.
    pub status: &'static str,
}

pub async fn register_admin_notifications(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let actor = match require_admin_json(method.as_str(), uri.path(), &headers, &body, &state).await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };

    // The master token is a break-glass credential belonging to no device, so there is no
    // device to register a push key for. Refusing is not a limitation — a token that could
    // register arbitrary devices' keys would be exactly the redirection this route prevents.
    let AdminActor::Device(device_id) = actor else {
        return ApiError::new(
            ErrorCode::InvalidRequest,
            "notification registration requires a device-signed request, not the master token",
        )
        .into_response();
    };

    if let Err(e) = require_notifications_enabled(&state) {
        return e.into_response();
    }

    let payload = match Json::<AdminRegisterRequest>::from_bytes(&body) {
        Ok(Json(payload)) => payload,
        Err(rejection) => return rejection.into_response(),
    };

    if let Err(e) = validate_registration_fields(
        &payload.notification_public_key,
        &payload.apns_token,
        &payload.apns_topic,
    ) {
        return e.into_response();
    }

    if let Err(e) = store::upsert_admin_registration(
        &state.db,
        &device_id,
        &payload.notification_public_key,
        &payload.apns_token,
        &payload.apns_topic,
    )
    .await
    {
        tracing::error!(error = %e, "failed to store an admin notification registration");
        return ApiError::new(ErrorCode::InternalError, "failed to store the registration")
            .into_response();
    }

    if let Some(sender) = state.notify_sender.as_ref() {
        let _ = sender.send(NotifyJob::RegisterHandle {
            owner: RegistrationOwner::AdminDevice {
                admin_device_id: device_id,
            },
            apns_token: payload.apns_token,
            apns_topic: payload.apns_topic,
        });
    }

    Json(AdminRegisterResponse { status: "pending" }).into_response()
}

/// The admin app's re-pin surface. Same published set as the account surface — the sender keys
/// belong to the instance, not to whoever is asking.
pub async fn get_admin_sender_keys(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = require_admin(method.as_str(), uri.path(), &headers, b"", &state).await {
        return e.into_response();
    }
    if let Err(e) = require_notifications_enabled(&state) {
        return e.into_response();
    }
    match sender_keys_response(&state).await {
        Ok(response) => Json(response).into_response(),
        Err(e) => e.into_response(),
    }
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

    async fn state_with_notifications() -> AppState {
        let mut state = crate::state::test_state().await;
        let mut config = (*state.config).clone();
        config.notifications.relay = Some("relay-node-id".to_string());
        config.admin_token = Some(common::Sensitive("admin-secret".to_string()));
        config.signing_key_master_key =
            Some(common::Sensitive(zeroize::Zeroizing::new([0x7u8; 32])));
        state.config = Arc::new(config);
        state
    }

    /// Register an admin device and return `(device_id, its signing key)`.
    async fn seed_device(state: &AppState, id: &str) -> crypto::P256Keypair {
        let keypair = crypto::generate_p256_keypair().unwrap();
        sqlx::query(
            "INSERT INTO admin_devices (id, label, public_key, platform, scopes, created_at) \
             VALUES (?, 'console', ?, 'ios', 'admin', datetime('now'))",
        )
        .bind(id)
        .bind(&keypair.key_id.0)
        .execute(&state.db)
        .await
        .expect("seed admin device");
        keypair
    }

    /// Build a device-signed request the `require_admin` guard will accept.
    fn signed(
        method: &str,
        path: &str,
        device_id: &str,
        keypair: &crypto::P256Keypair,
        body: &[u8],
        nonce: &str,
    ) -> Request<Body> {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};

        let timestamp = chrono::Utc::now().timestamp();
        let sign_string =
            crate::auth::guards::admin_request_sign_string(method, path, timestamp, nonce, body);
        let signing_key = SigningKey::from_slice(&*keypair.private_key_bytes).unwrap();
        let signature: Signature = signing_key.sign(sign_string.as_bytes());
        // Normalize to low-S, as a real admin device must. `SigningKey::sign` does not do this
        // for P-256, and the verifier rejects the high-S twin (ECDSA malleability: every
        // signature has one, and accepting both would let one signature yield two valid
        // requests). Omitting this makes the test a ~50/50 coin flip, not a clean failure.
        let signature = signature.normalize_s().unwrap_or(signature);
        let signature = data_encoding::BASE64URL_NOPAD.encode(&signature.to_bytes());

        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("X-Admin-Device", device_id)
            .header("X-Admin-Timestamp", timestamp.to_string())
            .header("X-Admin-Nonce", nonce)
            .header("X-Admin-Signature", signature);
        if !body.is_empty() {
            builder = builder.header("content-type", "application/json");
        }
        builder.body(Body::from(body.to_vec())).unwrap()
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
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    fn body_for(key: &str) -> Vec<u8> {
        json!({
            "notificationPublicKey": key,
            "apnsToken": "abcdef0123456789",
            "apnsTopic": "org.obsign.admincompanion",
        })
        .to_string()
        .into_bytes()
    }

    #[tokio::test]
    async fn a_device_registers_itself_for_push() {
        let state = state_with_notifications().await;
        let keypair = seed_device(&state, "adm-1").await;
        let key = crypto::generate_p256_keypair().unwrap().key_id.0;

        let body = body_for(&key);
        let (status, response) = call(
            state.clone(),
            signed(
                "POST",
                "/v1/admin/notifications/register",
                "adm-1",
                &keypair,
                &body,
                "nonce-1",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["status"], "pending");

        let rows = store::list_active_admin_registrations(&state.db)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device_id, "adm-1");
        assert_eq!(rows[0].notification_public_key, key);
    }

    /// The credential names the device — a body field never could, and this is what stops one
    /// compromised device from redirecting another's alerts.
    #[tokio::test]
    async fn the_master_token_cannot_register_a_device() {
        let state = state_with_notifications().await;
        seed_device(&state, "adm-1").await;
        let key = crypto::generate_p256_keypair().unwrap().key_id.0;

        let (status, _) = call(
            state.clone(),
            Request::post("/v1/admin/notifications/register")
                .header("authorization", "Bearer admin-secret")
                .header("content-type", "application/json")
                .body(Body::from(body_for(&key)))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(store::list_active_admin_registrations(&state.db)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn an_unsigned_request_is_refused() {
        let state = state_with_notifications().await;
        let key = crypto::generate_p256_keypair().unwrap().key_id.0;
        let (status, _) = call(
            state,
            Request::post("/v1/admin/notifications/register")
                .header("content-type", "application/json")
                .body(Body::from(body_for(&key)))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// Reading the pinned set is a plain admin read, so the master token is fine here — it is
    /// only *registration* that must name a device.
    #[tokio::test]
    async fn the_admin_app_can_fetch_the_sender_key_set() {
        let state = state_with_notifications().await;
        let (status, body) = call(
            state.clone(),
            Request::get("/v1/admin/notifications/sender-keys")
                .header("authorization", "Bearer admin-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["keys"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_admin_routes_are_not_implemented_without_a_configured_relay() {
        let mut state = crate::state::test_state().await;
        let mut config = (*state.config).clone();
        config.admin_token = Some(common::Sensitive("admin-secret".to_string()));
        state.config = Arc::new(config);

        let (status, _) = call(
            state,
            Request::get("/v1/admin/notifications/sender-keys")
                .header("authorization", "Bearer admin-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    }
}
