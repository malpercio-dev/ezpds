//! The `ezpds/notify/0` wire protocol: one JSON request per bidirectional iroh stream,
//! one JSON response back, the stream's FIN delimiting each.
//!
//! There is deliberately no credential anywhere in these messages. The caller's identity
//! is the QUIC connection's `remote_id()` — an instance proves who it is by holding its
//! node secret key, which iroh has already verified before the first byte arrives.

use serde::{Deserialize, Serialize};

/// ALPN protocol identifier for the Custos↔relay notification channel. Bumped if the
/// wire protocol changes incompatibly. Distinct from the pds's `ezpds/iroh/0` tunnel.
pub const ALPN: &[u8] = b"ezpds/notify/0";

/// Upper bound on one request (bytes) — bounds server-side allocation against a peer that
/// streams forever.
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// A request from an instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Request {
    /// Ask to be enrolled. Idempotent. `claimCode` is required unless the relay runs
    /// open enrollment.
    #[serde(rename_all = "camelCase")]
    Enroll { claim_code: Option<String> },
    /// Register a device's APNs token, receiving an opaque handle for it.
    #[serde(rename_all = "camelCase")]
    RegisterHandle {
        apns_token: String,
        apns_topic: String,
    },
    /// Forget a handle. Idempotent.
    #[serde(rename_all = "camelCase")]
    DropHandle { handle: String },
    /// Deliver a sealed payload to the device behind `handle`.
    #[serde(rename_all = "camelCase")]
    Push {
        handle: String,
        /// Which of the instance's versioned sender keys sealed this payload. Opaque to
        /// the relay — it is echoed to the device, never interpreted.
        kid: u32,
        /// Base64url HPKE encapsulated key.
        enc: String,
        /// Base64url HPKE ciphertext.
        ct: String,
        #[serde(default)]
        priority: Option<u8>,
        #[serde(default)]
        ttl_secs: Option<u32>,
        #[serde(default)]
        ping: Option<bool>,
    },
}

/// What happened to a push. Reported inside a `pushed` response rather than as a
/// transport error, because every one of these is a normal outcome the sender acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PushOutcome {
    /// Apple accepted the notification.
    Delivered,
    /// APNs 410: the device token is dead. The instance deletes its registration.
    Unregistered,
    /// This node's push budget is exhausted.
    Throttled,
    /// The serialized APNs request would exceed Apple's cap.
    TooLarge,
    /// The node has not enrolled with this relay.
    NotEnrolled,
    /// No such handle — or it belongs to another node, which reads identically.
    UnknownHandle,
    /// Apple refused, or the relay could not reach it.
    ApnsError,
}

/// A response to an instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Response {
    /// The request succeeded and carries nothing else to say.
    Ok,
    /// A handle was minted (or rotated).
    #[serde(rename_all = "camelCase")]
    Handle { handle: String },
    /// A push finished, with its outcome.
    #[serde(rename_all = "camelCase")]
    Pushed { outcome: PushOutcome },
    /// Enrollment was refused: no code, or a code that was unknown, spent, or expired.
    /// One shape for all of them — an enrollment probe learns nothing about which codes
    /// this relay has minted.
    Denied,
    /// The node must enroll before making this request.
    NotEnrolled,
    /// This node's request budget is exhausted; retry later.
    Throttled,
    /// The request could not be understood. Carries a short, non-reflective reason.
    #[serde(rename_all = "camelCase")]
    BadRequest { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_versioned_and_distinct_from_the_pds_tunnel() {
        assert_eq!(ALPN, b"ezpds/notify/0");
    }

    #[test]
    fn requests_are_camel_case_tagged() {
        let json = r#"{"type":"registerHandle","apnsToken":"tok","apnsTopic":"org.obsign.app"}"#;
        assert_eq!(
            serde_json::from_str::<Request>(json).expect("parse"),
            Request::RegisterHandle {
                apns_token: "tok".into(),
                apns_topic: "org.obsign.app".into(),
            }
        );
    }

    #[test]
    fn an_enroll_without_a_code_parses_as_none() {
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"type":"enroll"}"#).expect("parse"),
            Request::Enroll { claim_code: None }
        );
    }

    #[test]
    fn push_outcomes_render_as_camel_case() {
        let json = serde_json::to_string(&Response::Pushed {
            outcome: PushOutcome::UnknownHandle,
        })
        .expect("serialize");
        assert_eq!(json, r#"{"type":"pushed","outcome":"unknownHandle"}"#);
    }
}
