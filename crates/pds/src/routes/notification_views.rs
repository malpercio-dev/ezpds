// pattern: Imperative Shell
//
// Shared, handler-free support for the two notification surfaces — the account-holder's
// (`notifications.rs`) and the operator's (`admin_notifications.rs`). Routes may not import
// one another, so everything both need lives here: the registration field validators and the
// `sender-keys` response shape.
//
// Same non-handler-support-file pattern as `admin_subject_defs.rs` and `oauth_templates.rs`.

use serde::Serialize;

use crate::app::AppState;
use crate::auth::validation::validate_device_public_key;
use common::{ApiError, ErrorCode};

/// Reject when the operator has not configured a relay.
///
/// A 501 rather than a 404: the route exists, this instance has simply not opted into push.
/// A client reads that as "notifications unavailable here" and stops asking — the honest
/// answer for a self-hoster who never pointed at a relay.
pub(crate) fn require_notifications_enabled(state: &AppState) -> Result<(), ApiError> {
    if state.config.notifications.relay.is_none() {
        return Err(ApiError::new(
            ErrorCode::MethodNotImplemented,
            "this instance is not configured for push notifications",
        ));
    }
    Ok(())
}

/// Bound on an APNs device token / topic. Both are echoed to Apple by the relay.
const MAX_APNS_FIELD_LEN: usize = 200;

/// Validate everything a registration body carries, on both surfaces.
///
/// The public key is decoded, not merely length-checked: a key we cannot decode now is a
/// device we cannot reach later, and that failure would surface only at send time, far from
/// the request that caused it.
pub(crate) fn validate_registration_fields(
    notification_public_key: &str,
    apns_token: &str,
    apns_topic: &str,
) -> Result<(), ApiError> {
    let invalid = |msg: String| ApiError::new(ErrorCode::InvalidRequest, msg);

    validate_device_public_key(notification_public_key)
        .map_err(|e| invalid(e.replace("devicePublicKey", "notificationPublicKey")))?;
    crypto::p256_public_key_from_did_key(notification_public_key).map_err(|e| {
        invalid(format!(
            "notificationPublicKey must be a P-256 did:key ({e})"
        ))
    })?;

    if apns_token.is_empty() || apns_token.len() > MAX_APNS_FIELD_LEN {
        return Err(invalid(format!(
            "apnsToken must be between 1 and {MAX_APNS_FIELD_LEN} characters"
        )));
    }
    if !apns_token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("apnsToken must be hexadecimal".to_string()));
    }
    if apns_topic.is_empty() || apns_topic.len() > MAX_APNS_FIELD_LEN {
        return Err(invalid(format!(
            "apnsTopic must be between 1 and {MAX_APNS_FIELD_LEN} characters"
        )));
    }
    if !apns_topic
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(invalid("apnsTopic must be a bundle identifier".to_string()));
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SenderKey {
    /// Version. Every sealed payload's envelope names which key sealed it.
    pub kid: i64,
    /// The P-256 `did:key` to verify against.
    pub public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SenderKeysResponse {
    pub keys: Vec<SenderKey>,
}

/// The published sender-key set — a property of the instance, not of who is asking, so both
/// surfaces serve exactly this.
///
/// This is the re-pin surface: clients fetch it on every successful Custos contact, which is
/// what keeps the compromise window short. Revocation drops a key from the set immediately,
/// and the next contact is the last time a device will trust it. Retired keys stay, because a
/// payload sealed just before a rotation must still verify on a device that has re-pinned.
pub(crate) async fn sender_keys_response(state: &AppState) -> Result<SenderKeysResponse, ApiError> {
    let keys = crate::notifications::published_sender_keys(state)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to load notification sender keys");
            match e {
                // Distinct from the 501 above: the operator *has* opted into notifications,
                // but the instance cannot mint or unwrap the keys that make them verifiable.
                // A 503 says "configured but not currently able", which is the truth, and
                // keeps a client from pinning an empty set and silently trusting nothing.
                crate::notifications::SenderKeyError::NoMasterKey => ApiError::new(
                    ErrorCode::ServiceUnavailable,
                    "notifications are configured but the signing-key master key is not set",
                ),
                crate::notifications::SenderKeyError::NoUsableKey => ApiError::new(
                    ErrorCode::ServiceUnavailable,
                    "no usable notification sender key is available",
                ),
                crate::notifications::SenderKeyError::Db(_) => {
                    ApiError::new(ErrorCode::InternalError, "failed to load sender keys")
                }
            }
        })?;

    Ok(SenderKeysResponse {
        keys: keys
            .into_iter()
            .map(|(kid, public_key)| SenderKey { kid, public_key })
            .collect(),
    })
}
