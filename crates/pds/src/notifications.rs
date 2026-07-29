// pattern: Imperative Shell
//
// The sending side of the notification relay: turn a notification into one HPKE-sealed,
// length-quantized payload *per registered device* and hand each to the relay worker.
//
// Three properties this module is responsible for, in the order they matter:
//
// 1. **Confidentiality.** The relay and Apple both handle the payload, and neither may read
//    it. Every send is sealed to one specific device's notification public key.
// 2. **Authenticity.** HPKE `mode_auth` proves the payload came from this instance's sender
//    key. A malicious relay can drop or duplicate a push; it cannot author one that renders
//    as genuine.
// 3. **Metadata minimization.** Ciphertext length is visible to everyone on the path, and
//    notification *length* betrays notification *kind*. Every payload is padded up to a
//    bucket before sealing.
//
// Fan-out is one seal per registration, never one seal reused: HPKE seals to a single
// recipient key, and reusing an encapsulated key across devices would be a different (and
// weaker) protocol.
//
// Nothing here is fallible from a caller's perspective. Every path ends in an enqueue or a
// log line, because a notification is a courtesy: a missed banner is recovered the next time
// the app talks to Custos, whereas a trigger that fails because a push relay is unwell has
// turned a courtesy into an outage.

use serde::Serialize;
use zeroize::Zeroizing;

use crate::app::AppState;
use crate::db::notifications as store;
use crate::notify_relay_client::{NotifyJob, RegistrationOwner};

/// The plaintext a device's Notification Service Extension decrypts and renders.
///
/// Serialized camelCase, matching the wallet's decoder. `pad` is the length-quantizing
/// filler; it is meaningless to the reader and is the last field so the arithmetic below can
/// reason about it as a suffix.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPayload {
    /// Machine-readable kind, e.g. `agent_claim_pending`. The app routes on this.
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub title: String,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Spaces, sized so the serialized APNs body lands on a padding bucket.
    pub pad: String,
}

impl NotificationPayload {
    /// A payload with no padding yet — [`seal_for`] computes and applies it.
    pub fn new(kind: &'static str, title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            kind,
            title: title.into(),
            body: body.into(),
            data: None,
            pad: String::new(),
        }
    }

    /// Attach structured routing data (a claim attempt id, a subject DID, …).
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }
}

/// Notify every device registered to `did`.
///
/// Silent and harmless when notifications are unconfigured, when the account has no
/// registered devices, or when the relay is unreachable. Returns how many sealed payloads
/// were enqueued toward the relay — delivery stays fire-and-forget beyond that, but "zero
/// devices could even be attempted" is a fact some triggers branch on (the consent push
/// makes number matching mandatory only when a push actually went out).
pub async fn notify_device(state: &AppState, did: &str, payload: NotificationPayload) -> usize {
    let Some(sender) = state.notify_sender.as_ref() else {
        return 0;
    };
    let registrations = match store::list_registrations(&state.db, did).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "failed to load notification registrations");
            return 0;
        }
    };
    fan_out(state, sender, registrations, payload, |device_id| {
        RegistrationOwner::Account {
            did: did.to_string(),
            device_uuid: device_id,
        }
    })
    .await
}

/// Notify every *active* admin-companion device — the operator alert channel.
///
/// The registration and key-pinning halves ship here; the operator *triggers* that call this
/// (labeler flags, health alerts) land with admin-companion adoption, so nothing in-tree
/// invokes it yet. Kept rather than deferred because the admin registration route it serves
/// is already live — a stored registration nothing can ever send to would be the odder state.
#[allow(dead_code)]
pub async fn notify_admin_devices(state: &AppState, payload: NotificationPayload) {
    let Some(sender) = state.notify_sender.as_ref() else {
        return;
    };
    let registrations = match store::list_active_admin_registrations(&state.db).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "failed to load admin notification registrations");
            return;
        }
    };
    fan_out(state, sender, registrations, payload, |device_id| {
        RegistrationOwner::AdminDevice {
            admin_device_id: device_id,
        }
    })
    .await;
}

/// Seal-and-enqueue one payload per registration, returning how many jobs were enqueued.
async fn fan_out(
    state: &AppState,
    sender: &crate::notify_relay_client::NotifySender,
    registrations: Vec<store::RegistrationRow>,
    payload: NotificationPayload,
    owner_of: impl Fn(String) -> RegistrationOwner,
) -> usize {
    if registrations.is_empty() {
        return 0;
    }

    // Load the sealing key once for the whole fan-out. Doing it per device would mean a
    // rotation landing mid-fan-out seals some devices under the old key and some under the
    // new — both valid, but needlessly hard to reason about when debugging a delivery.
    let Some((kid, secret)) = active_sender_key(state).await else {
        return 0;
    };

    let mut enqueued = 0;
    for registration in registrations {
        // A registration with no handle has not completed its relay round trip yet (the
        // relay was down at registration time, or the job is still queued). There is nothing
        // to push to; the next registration attempt mints one.
        let Some(handle) = registration.push_handle.clone() else {
            continue;
        };

        let recipient =
            match crypto::p256_public_key_from_did_key(&registration.notification_public_key) {
                Ok(key) => key,
                Err(e) => {
                    // Registration validated this key, so reaching here means the stored row is
                    // corrupt — worth an error, not a silent skip.
                    tracing::error!(error = %e, "stored notification public key is unusable");
                    continue;
                }
            };

        let Some(sealed) = seal_for(kid, &secret, &recipient, &payload) else {
            continue;
        };

        // `send` fails only once every receiver is gone, i.e. the worker has stopped. Not
        // worth a per-device log line.
        sender.send(NotifyJob::Push {
            owner: owner_of(registration.device_id),
            handle,
            kid,
            enc: base64url(&sealed.enc),
            ct: base64url(&sealed.ct),
        });
        enqueued += 1;
    }
    enqueued
}

/// Pad, then seal, one payload for one recipient.
///
/// Returns `None` when the payload cannot be sent — which for v1 means only one thing: it is
/// too large for the top padding bucket. We refuse rather than degrade. Sending it unpadded
/// would leak the exact length that padding exists to hide, and truncating the body would
/// deliver a security notice that no longer says what happened; a dropped banner is the one
/// failure mode with no downside beyond the missed banner itself.
fn seal_for(
    kid: i64,
    sender_secret: &[u8; 32],
    recipient_public_key: &[u8],
    payload: &NotificationPayload,
) -> Option<crypto::SealedNotification> {
    let pad_len = pad_len_for(kid, payload)?;

    let mut padded = payload.clone();
    padded.pad = " ".repeat(pad_len);
    let plaintext = match serde_json::to_vec(&padded) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(error = %e, "failed to serialize a notification payload");
            return None;
        }
    };

    match crypto::seal_notification(sender_secret, recipient_public_key, &plaintext) {
        Ok(sealed) => Some(sealed),
        Err(e) => {
            tracing::error!(error = %e, "failed to seal a notification");
            None
        }
    }
}

/// How many pad bytes make this payload's APNs body land on a bucket.
///
/// The buckets are defined on the **serialized APNs request body**, because that is the only
/// length anyone on the path actually measures. So this models the exact body the relay will
/// build (via the shared [`notify_relay::protocol::apns_envelope`]) and works backwards
/// through base64url expansion. Sealing is deterministic in length — ciphertext is plaintext
/// plus a 16-byte tag, and `enc` is always a 65-byte point — so this needs no trial seal.
fn pad_len_for(kid: i64, payload: &NotificationPayload) -> Option<usize> {
    let unpadded_plaintext_len = serde_json::to_vec(payload).ok()?.len();
    let unpadded_ct_len = unpadded_plaintext_len + AEAD_TAG_LEN;

    // Placeholder strings of the right *length*: only the byte count reaches the arithmetic,
    // and JSON escaping never touches base64url's alphabet.
    let envelope = notify_relay::protocol::apns_envelope(
        kid as u32,
        &"A".repeat(crypto::base64url_len(P256_POINT_LEN)),
        &"A".repeat(crypto::base64url_len(unpadded_ct_len)),
    );
    let unpadded_serialized_len = serde_json::to_vec(&envelope).ok()?.len();

    let pad = crypto::plaintext_pad_len(unpadded_ct_len, unpadded_serialized_len);
    if pad.is_none() {
        tracing::error!(
            serialized_len = unpadded_serialized_len,
            "refusing to send a notification too large for any padding bucket; \
             sending it unpadded would leak the length padding exists to hide"
        );
    }
    pad
}

/// AES-GCM authentication tag, appended to every ciphertext.
const AEAD_TAG_LEN: usize = 16;

/// Uncompressed SEC1 P-256 point — the fixed wire length of the HPKE encapsulated key.
const P256_POINT_LEN: usize = 65;

/// The sender key to seal with, generating the instance's first one on demand.
///
/// Lazy generation rather than a startup step: an instance that has notifications configured
/// but never sends one should not mint key material, and the first send is the earliest
/// moment the key is genuinely needed.
async fn active_sender_key(state: &AppState) -> Option<(i64, Zeroizing<[u8; 32]>)> {
    let master_key = master_key(state)?;

    let existing = match store::get_active_sender_key(&state.db).await {
        Ok(row) => row,
        Err(e) => {
            tracing::warn!(error = %e, "failed to load the notification sender key");
            return None;
        }
    };

    if let Some(row) = existing {
        return match crypto::decrypt_secret_bytes(&row.secret_key_encrypted, master_key) {
            Ok(bytes) => to_scalar(&bytes).map(|scalar| (row.kid, scalar)),
            Err(e) => {
                tracing::error!(error = %e, kid = row.kid, "failed to unwrap a sender key");
                None
            }
        };
    }

    generate_sender_key(state, master_key).await
}

/// Mint, wrap, and store a fresh sender key.
pub(crate) async fn generate_sender_key(
    state: &AppState,
    master_key: &[u8; 32],
) -> Option<(i64, Zeroizing<[u8; 32]>)> {
    let keypair = match crypto::generate_p256_keypair() {
        Ok(keypair) => keypair,
        Err(e) => {
            tracing::error!(error = %e, "failed to generate a notification sender key");
            return None;
        }
    };
    // Stays in `Zeroizing` the whole way. The crypto crate deliberately hands back a wiped-on-
    // drop buffer, and copying out into a bare `[u8; 32]` would silently discard that — leaving
    // the instance's sender scalar in freed memory on every send.
    let secret = keypair.private_key_bytes.clone();
    let wrapped = match crypto::encrypt_secret_bytes(&*secret, master_key) {
        Ok(wrapped) => wrapped,
        Err(e) => {
            tracing::error!(error = %e, "failed to wrap a notification sender key");
            return None;
        }
    };
    match store::insert_sender_key(&state.db, &wrapped).await {
        Ok(kid) => {
            tracing::info!(kid, "generated a new notification sender key");
            Some((kid, secret))
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to store a notification sender key");
            None
        }
    }
}

/// The published sender-key set: `(kid, did:key)` for every key a device may verify against.
///
/// This is the re-pin surface both `sender-keys` routes serve. Generating the first key here
/// as well as on send matters for onboarding order: an app that fetches the set before the
/// instance has ever sent anything would otherwise pin an empty set and be unable to verify
/// the first notification it receives.
pub async fn published_sender_keys(state: &AppState) -> Result<Vec<(i64, String)>, SenderKeyError> {
    // No master key means no key can be minted *or* unwrapped, so the honest answer is an
    // error, not an empty set. Answering `200 {"keys": []}` would let a client conclude it has
    // successfully pinned nothing — and then fail to verify every notification it receives,
    // with only a server-side warning to explain it. This is a misconfiguration; it should be
    // as visible as one.
    let master_key = master_key(state).ok_or(SenderKeyError::NoMasterKey)?;

    let mut rows = store::list_publishable_sender_keys(&state.db).await?;
    if rows.is_empty() {
        generate_sender_key(state, master_key).await;
        rows = store::list_publishable_sender_keys(&state.db).await?;
    }

    let keys: Vec<(i64, String)> = rows
        .into_iter()
        .filter_map(|row| {
            // An individual row that will not unwrap is skipped rather than fatal: it is a
            // key this instance can no longer use, and dropping it from the published set is
            // exactly right — but it must not take the still-good keys down with it.
            let secret = crypto::decrypt_secret_bytes(&row.secret_key_encrypted, master_key)
                .ok()
                .and_then(|bytes| to_scalar(&bytes))
                .or_else(|| {
                    tracing::error!(kid = row.kid, "a stored sender key will not unwrap");
                    None
                })?;
            // Re-derive the public half rather than storing it: one stored secret cannot
            // disagree with a separately stored public key if there is no separately stored
            // public key.
            let keypair = crypto::p256_keypair_from_secret(&secret).ok()?;
            Some((row.kid, keypair.key_id.0))
        })
        .collect();

    // One invariant at the exit rather than a guard per failure path: **never publish an empty
    // set**. Several routes lead here — lazy generation failed, every stored key is unusable,
    // or some future path — and they all end the same way for a client, which pins nothing and
    // then cannot verify a single notification it receives. Checking the result instead of each
    // cause means a new failure mode is covered the day it appears.
    if keys.is_empty() {
        return Err(SenderKeyError::NoUsableKey);
    }
    Ok(keys)
}

/// Why the published sender-key set could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum SenderKeyError {
    #[error("notifications are configured but no signing-key master key is set")]
    NoMasterKey,
    /// A key could neither be minted nor unwrapped. Distinct from [`Self::NoMasterKey`] because
    /// the operator fix differs: the master key is present, so this is a generation failure or
    /// key material that no longer decrypts under it (both already logged with their cause).
    #[error("no usable notification sender key could be produced")]
    NoUsableKey,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// The master KEK, if configured. Callers report its absence — logging here would emit a line
/// per request on the read path, where the caller already turns it into a visible error.
fn master_key(state: &AppState) -> Option<&[u8; 32]> {
    state.config.signing_key_master_key.as_ref().map(|s| &*s.0)
}

/// Narrow a decrypted secret to a 32-byte scalar without leaving `Zeroizing`.
///
/// `decrypt_secret_bytes` returns a `Zeroizing<Vec<u8>>`; converting through a bare array
/// would drop the wipe-on-drop guarantee for the copy, so the result is re-wrapped instead.
fn to_scalar(bytes: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    <[u8; 32]>::try_from(bytes).ok().map(Zeroizing::new)
}

fn base64url(bytes: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipient() -> (crypto::P256Keypair, Vec<u8>) {
        let keypair = crypto::generate_p256_keypair().unwrap();
        let public = crypto::p256_public_key_from_did_key(&keypair.key_id.0).unwrap();
        (keypair, public)
    }

    /// The property the whole padding budget exists for: two notifications of very different
    /// natural length must produce APNs bodies of the *same* length.
    #[test]
    fn payloads_of_different_lengths_land_on_the_same_bucket() {
        let sender = crypto::generate_p256_keypair().unwrap();
        let (_, recipient_public) = recipient();

        let body_len = |payload: &NotificationPayload| {
            let sealed =
                seal_for(1, &sender.private_key_bytes, &recipient_public, payload).unwrap();
            let envelope = notify_relay::protocol::apns_envelope(
                1,
                &base64url(&sealed.enc),
                &base64url(&sealed.ct),
            );
            serde_json::to_vec(&envelope).unwrap().len()
        };

        let short = NotificationPayload::new("agent_claim_pending", "Custos", "hi");
        let long = NotificationPayload::new("agent_claim_pending", "Custos", "x".repeat(400))
            .with_data(serde_json::json!({ "claimAttemptId": "clm_0123456789" }));
        assert_ne!(
            serde_json::to_vec(&short).unwrap().len(),
            serde_json::to_vec(&long).unwrap().len(),
            "the two payloads must genuinely differ before padding"
        );

        assert_eq!(
            body_len(&short),
            body_len(&long),
            "padding must erase the length difference between notification kinds"
        );
    }

    #[test]
    fn every_sealed_body_stays_under_apples_cap() {
        let sender = crypto::generate_p256_keypair().unwrap();
        let (_, recipient_public) = recipient();

        for body_len in [0usize, 1, 50, 500, 1500, 2400] {
            let payload =
                NotificationPayload::new("agent_claim_pending", "Custos", "b".repeat(body_len));
            let sealed =
                seal_for(1, &sender.private_key_bytes, &recipient_public, &payload).unwrap();
            let envelope = notify_relay::protocol::apns_envelope(
                1,
                &base64url(&sealed.enc),
                &base64url(&sealed.ct),
            );
            let len = serde_json::to_vec(&envelope).unwrap().len();
            assert!(
                len <= *crypto::PADDING_BUCKETS.last().unwrap(),
                "body_len {body_len} produced a {len}-byte body, past the top bucket"
            );
            assert!(len < crypto::APNS_MAX_PAYLOAD_BYTES);
        }
    }

    /// The answer to "too big to pad" is refusal, not a degraded send.
    #[test]
    fn an_unpaddable_payload_is_refused_rather_than_sent_unpadded() {
        let sender = crypto::generate_p256_keypair().unwrap();
        let (_, recipient_public) = recipient();

        let payload = NotificationPayload::new("agent_claim_pending", "Custos", "x".repeat(4096));
        assert!(seal_for(1, &sender.private_key_bytes, &recipient_public, &payload).is_none());
    }

    /// The end-to-end crypto contract, from the device's point of view: the fixture "device"
    /// opens the payload and, in doing so, verifies it came from this instance's sender key.
    #[test]
    fn a_device_opens_the_payload_and_verifies_the_sender() {
        let sender = crypto::generate_p256_keypair().unwrap();
        let (recipient_keypair, recipient_public) = recipient();

        let payload = NotificationPayload::new(
            "agent_claim_pending",
            "Confirm agent access",
            "An agent is waiting for you to confirm it.",
        )
        .with_data(serde_json::json!({ "claimAttemptId": "clm_abc" }));
        let sealed = seal_for(3, &sender.private_key_bytes, &recipient_public, &payload).unwrap();

        let sender_public = crypto::public_key_for_secret(&sender.private_key_bytes).unwrap();
        let opened = crypto::open_notification(
            &recipient_keypair.private_key_bytes,
            &sender_public,
            &sealed.enc,
            &sealed.ct,
        )
        .unwrap();

        let decoded: serde_json::Value = serde_json::from_slice(&opened).unwrap();
        assert_eq!(decoded["type"], "agent_claim_pending");
        assert_eq!(decoded["title"], "Confirm agent access");
        assert_eq!(decoded["data"]["claimAttemptId"], "clm_abc");

        // Authenticity is not incidental: an impostor's key must not open it.
        let impostor = crypto::generate_p256_keypair().unwrap();
        let impostor_public = crypto::public_key_for_secret(&impostor.private_key_bytes).unwrap();
        assert!(crypto::open_notification(
            &recipient_keypair.private_key_bytes,
            &impostor_public,
            &sealed.enc,
            &sealed.ct
        )
        .is_err());
    }

    #[tokio::test]
    async fn sending_is_inert_when_no_relay_is_configured() {
        let state = crate::state::test_state().await;
        assert!(state.notify_sender.is_none());

        // No relay, no panic, no rows touched — the whole feature is absent.
        notify_device(
            &state,
            "did:plc:nobody",
            NotificationPayload::new("agent_claim_pending", "t", "b"),
        )
        .await;
        notify_admin_devices(&state, NotificationPayload::new("ops_alert", "t", "b")).await;

        let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_sender_keys")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(keys, 0, "an inert feature must not mint key material");
    }
}
