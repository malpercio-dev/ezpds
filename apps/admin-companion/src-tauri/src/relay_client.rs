// pattern: Imperative Shell
//
// The operator companion's HTTP client to the relay. Two things happen here:
//   1. Pairing — register this device's public key by claiming a pairing code
//      (`POST /v1/admin/devices`), self-signing the canonical registration message.
//   2. Signed requests — every later admin call attaches the `X-Admin-*` envelope so
//      the relay's `require_admin` guard accepts it (`POST /v1/accounts/claim-codes`
//      is Phase 7's concrete consumer / demo action).
//
// The request *construction* (which bytes get signed, which headers get attached) is
// factored into pure, synchronous `build_*` functions so it can be tested without a
// network: a test signs a request and verifies it with `crypto::verify_p256_signature`
// — the same function the relay's guard calls — proving the relay would accept it.
// Only the thin `send`/`pair`/`generate_claim_code` wrappers touch reqwest.

use serde::Serialize;

use crate::keychain::Pairing;
use crate::{device_key, keychain, signing};

/// Platform tag sent at registration and stored on the device row. Derived from the
/// build target so an Android build registers as `"android"`; iOS and the macOS host
/// (where tests run) both report `"ios"`.
#[cfg(target_os = "android")]
const PLATFORM: &str = "android";
#[cfg(not(target_os = "android"))]
const PLATFORM: &str = "ios";

/// Errors surfaced to the frontend, serialized as `{ "code": "SCREAMING_SNAKE_CASE", … }`
/// to match the device-key error convention. Distinct variants let the UI render honest,
/// specific states (unreachable vs revoked vs not-paired) instead of one generic failure.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelayClientError {
    /// A signed request was attempted before this device paired.
    #[error("device is not paired")]
    NotPaired,
    /// The device key could not be created, found, or used to sign.
    #[error("device key error: {message}")]
    DeviceKey { message: String },
    /// Keychain read/write failure while loading or storing pairing state.
    #[error("keychain error: {message}")]
    Keychain { message: String },
    /// The relay URL is not a valid absolute URL.
    #[error("invalid relay URL")]
    InvalidRelayUrl,
    /// Network/transport failure — the relay could not be reached.
    #[error("relay unreachable: {message}")]
    Unreachable { message: String },
    /// The relay returned a non-success status. `status` lets the UI distinguish a
    /// revoked device (403) from a generic auth failure (401, often clock skew).
    #[error("relay rejected the request (HTTP {status})")]
    RelayRejected { status: u16, message: String },
    /// A 2xx response whose body did not match the expected schema.
    #[error("unexpected relay response: {message}")]
    BadResponse { message: String },
}

impl From<device_key::DeviceKeyError> for RelayClientError {
    fn from(e: device_key::DeviceKeyError) -> Self {
        RelayClientError::DeviceKey {
            message: e.to_string(),
        }
    }
}

impl From<keychain::KeychainError> for RelayClientError {
    fn from(e: keychain::KeychainError) -> Self {
        RelayClientError::Keychain {
            message: e.to_string(),
        }
    }
}

// ── Registration (pairing) ───────────────────────────────────────────────────

/// The JSON body of `POST /v1/admin/devices`. Field names are camelCase to match the
/// relay's `RegisterDeviceRequest` (crates/pds/src/routes/admin_devices.rs).
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationBody {
    pub pairing_code: String,
    pub label: String,
    pub public_key: String,
    pub platform: String,
    pub timestamp: i64,
    pub signature: String,
}

/// Build the self-signed registration body for a pairing exchange.
///
/// Ensures the device key exists, signs the canonical registration message
/// (`pairing_code\npublic_key\ntimestamp`) with it, and assembles the camelCase body
/// the relay expects. Pure apart from the device-key read/sign (the in-memory store in
/// tests), so it is fully exercisable on the host software-key path.
pub fn build_registration(
    pairing_code: &str,
    label: &str,
    timestamp: i64,
) -> Result<RegistrationBody, RelayClientError> {
    let key = device_key::get_or_create()?;
    let message = signing::registration_sign_string(pairing_code, &key.key_id, timestamp);
    let signature = signing::encode_signature(&device_key::sign(message.as_bytes())?);
    Ok(RegistrationBody {
        pairing_code: pairing_code.to_string(),
        label: label.to_string(),
        public_key: key.key_id,
        platform: PLATFORM.to_string(),
        timestamp,
        signature,
    })
}

// ── Per-request signing ──────────────────────────────────────────────────────

/// A fully-signed request ready to hand to reqwest: where to send it, and the body and
/// `X-Admin-*` headers that authenticate it.
#[derive(Debug)]
pub struct SignedRequest {
    pub url: String,
    pub method: String,
    /// `(name, value)` pairs — the four `X-Admin-*` headers plus `Content-Type`.
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

/// Build a signed admin request for an already-paired device.
///
/// Signs the canonical envelope (`method\npath\ntimestamp\nnonce\nsha256_hex(body)`) with
/// the device key and attaches the `X-Admin-*` headers. The exact `body` bytes passed
/// here are the bytes whose hash is signed *and* the bytes sent on the wire, so the
/// relay's recomputed body hash always matches. `path` must be the URL path the relay
/// will see (no scheme/host/query).
pub fn build_signed_request(
    pairing: &Pairing,
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: i64,
    nonce: &str,
) -> Result<SignedRequest, RelayClientError> {
    let url = join_url(&pairing.relay_url, path)?;
    let sign_string = signing::request_sign_string(method, path, timestamp, nonce, body);
    let signature = signing::encode_signature(&device_key::sign(sign_string.as_bytes())?);
    let headers = vec![
        (signing::ADMIN_DEVICE_HEADER, pairing.device_id.clone()),
        (signing::ADMIN_TIMESTAMP_HEADER, timestamp.to_string()),
        (signing::ADMIN_NONCE_HEADER, nonce.to_string()),
        (signing::ADMIN_SIGNATURE_HEADER, signature),
        ("Content-Type", "application/json".to_string()),
    ];
    Ok(SignedRequest {
        url,
        method: method.to_string(),
        headers,
        body: body.to_vec(),
    })
}

// ── Async surface (thin reqwest wrappers) ────────────────────────────────────

/// Pair this device with `relay_url` by claiming `pairing_code`. On success, persists
/// the relay-assigned `device_id` and `relay_url`, and returns the `device_id`.
pub async fn pair(
    relay_url: &str,
    pairing_code: &str,
    label: &str,
) -> Result<String, RelayClientError> {
    let body = build_registration(pairing_code, label, unix_now())?;
    let url = join_url(relay_url, "/v1/admin/devices")?;

    let response = http_client()
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(unreachable)?;

    let device_id = parse_success::<RegisterDeviceResponse>(response)
        .await?
        .device_id;
    keychain::store_pairing(&device_id, relay_url, label)?;
    Ok(device_id)
}

/// Mint a single account claim code via a signed `POST /v1/accounts/claim-codes`.
/// The demo-lifesaver action: an operator generates a claim code from their phone.
pub async fn generate_claim_code() -> Result<String, RelayClientError> {
    let pairing = keychain::get_pairing()?.ok_or(RelayClientError::NotPaired)?;

    // Serialize the body once so the exact bytes we sign are the exact bytes we send.
    let body = serde_json::to_vec(&ClaimCodesRequestBody { count: 1 })
        .expect("ClaimCodesRequestBody serializes");
    let path = "/v1/accounts/claim-codes";
    let signed = build_signed_request(&pairing, "POST", path, &body, unix_now(), &fresh_nonce())?;

    let response = send(signed).await?;
    let codes = parse_success::<ClaimCodesResponseBody>(response)
        .await?
        .codes;
    codes
        .into_iter()
        .next()
        .ok_or_else(|| RelayClientError::BadResponse {
            message: "relay returned no claim codes".into(),
        })
}

/// The device's current pairing, or `None` if it has not paired yet. Lets the UI choose
/// between the Pair screen and the operator console on launch.
pub fn current_pairing() -> Result<Option<Pairing>, RelayClientError> {
    Ok(keychain::get_pairing()?)
}

/// Revoke this device on the relay, then forget the pairing locally — the Settings
/// "unpair" action. Sends a signed `POST /v1/admin/devices/:id/revoke` for this device's
/// **own** id (the relay's `require_admin` accepts a device revoking itself), so the admin
/// credential is dead server-side even if the phone is later lost. Local state is cleared
/// only *after* the relay confirms: a failed revoke leaves the pairing intact so the
/// operator can retry, or fall back to a local-only [`unpair`].
pub async fn revoke_self() -> Result<(), RelayClientError> {
    let pairing = keychain::get_pairing()?.ok_or(RelayClientError::NotPaired)?;
    let path = format!("/v1/admin/devices/{}/revoke", pairing.device_id);
    // The revoke endpoint takes no body. The signature still binds method + path, so a
    // signature minted to revoke this device cannot be replayed to revoke another.
    let signed = build_signed_request(&pairing, "POST", &path, b"", unix_now(), &fresh_nonce())?;
    ensure_success(send(signed).await?).await?;
    keychain::clear_pairing()?;
    Ok(())
}

/// Forget this device's pairing locally **without** contacting the relay. The fallback
/// when [`revoke_self`] can't reach the relay: the operator can still detach this phone,
/// accepting that the credential remains valid server-side until revoked another way. The
/// device key is preserved so a re-pair is recognised.
pub fn unpair() -> Result<(), RelayClientError> {
    keychain::clear_pairing()?;
    Ok(())
}

/// Send an already-built [`SignedRequest`] and return the raw response.
async fn send(req: SignedRequest) -> Result<reqwest::Response, RelayClientError> {
    let method = reqwest::Method::from_bytes(req.method.as_bytes()).map_err(|_| {
        RelayClientError::BadResponse {
            message: "invalid HTTP method".into(),
        }
    })?;
    let mut builder = http_client().request(method, &req.url).body(req.body);
    for (name, value) in &req.headers {
        builder = builder.header(*name, value);
    }
    builder.send().await.map_err(unreachable)
}

// ── Wire types (relay request/response bodies) ───────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClaimCodesRequestBody {
    count: u32,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterDeviceResponse {
    device_id: String,
}

#[derive(serde::Deserialize)]
struct ClaimCodesResponseBody {
    codes: Vec<String>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Shared reqwest client with explicit timeouts. The async client has **no** default
/// timeout, so without these a stalled or unreachable relay would hang a pairing or
/// claim-code IPC call indefinitely. The connect timeout bounds DNS/TCP/TLS setup; the
/// overall timeout bounds the whole request. Falls back to an untimed client only if the
/// builder fails to initialise the TLS backend (effectively never).
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Current Unix time in seconds. Clamps a pre-epoch clock to 0 (which the relay's ±60s
/// window rejects anyway) rather than panicking.
fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A fresh anti-replay nonce — a random UUID v4, unique per request.
fn fresh_nonce() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Join a relay base URL and an absolute path, validating the result is a real URL.
/// Assumes `relay_url` is an origin (no base path); a trailing slash is tolerated.
fn join_url(relay_url: &str, path: &str) -> Result<String, RelayClientError> {
    let trimmed = relay_url.trim().trim_end_matches('/');
    let candidate = format!("{trimmed}{path}");
    reqwest::Url::parse(&candidate)
        .map(|_| candidate)
        .map_err(|_| RelayClientError::InvalidRelayUrl)
}

fn unreachable(e: reqwest::Error) -> RelayClientError {
    RelayClientError::Unreachable {
        message: e.to_string(),
    }
}

/// Decode a 2xx JSON body, or map a non-2xx status to [`RelayClientError::RelayRejected`]
/// (best-effort extracting the relay's `{ "error": { "message" } }` text).
async fn parse_success<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, RelayClientError> {
    let status = response.status();
    let text = response.text().await.map_err(unreachable)?;
    if !status.is_success() {
        return Err(RelayClientError::RelayRejected {
            status: status.as_u16(),
            message: extract_error_message(&text),
        });
    }
    serde_json::from_str::<T>(&text).map_err(|e| RelayClientError::BadResponse {
        message: e.to_string(),
    })
}

/// Verify a response is 2xx, mapping a non-success status to [`RelayClientError::RelayRejected`]
/// (best-effort extracting the relay's error text). For calls whose success body we don't
/// need — e.g. revoke, which only has to land.
async fn ensure_success(response: reqwest::Response) -> Result<(), RelayClientError> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let text = response.text().await.map_err(unreachable)?;
    Err(RelayClientError::RelayRejected {
        status: status.as_u16(),
        message: extract_error_message(&text),
    })
}

/// Pull the human-readable message out of the relay's error envelope
/// (`{ "error": { "code", "message" } }`), falling back to the raw body.
fn extract_error_message(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"]["message"].as_str().map(str::to_string))
        .unwrap_or_else(|| body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use crypto::{verify_p256_signature, DidKeyUri};

    fn decode_sig(b64: &str) -> [u8; 64] {
        URL_SAFE_NO_PAD
            .decode(b64)
            .expect("base64url signature")
            .try_into()
            .expect("64-byte signature")
    }

    fn header<'a>(req: &'a SignedRequest, name: &str) -> &'a str {
        req.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("missing header {name}"))
    }

    #[test]
    fn build_registration_self_signature_verifies() {
        keychain::clear_for_test();
        let key = device_key::get_or_create().expect("device key");

        let body =
            build_registration("PAIR-CODE", "Operator iPhone", 1_700_000_000).expect("build");

        // The body advertises this device's public key and platform.
        assert_eq!(body.public_key, key.key_id);
        assert_eq!(body.platform, "ios");
        assert_eq!(body.pairing_code, "PAIR-CODE");
        assert_eq!(body.label, "Operator iPhone");

        // The self-signature verifies against the advertised key over the canonical
        // registration message — exactly what the relay's verify_device_self_signature does.
        let message =
            signing::registration_sign_string(&body.pairing_code, &body.public_key, body.timestamp);
        verify_p256_signature(
            &DidKeyUri(body.public_key.clone()),
            message.as_bytes(),
            &decode_sig(&body.signature),
        )
        .expect("registration self-signature must verify against the relay's verifier");
    }

    // The Phase 7 Definition of Done, proven without a live relay: a signed claim-code
    // request carries headers whose signature the relay's OWN verifier accepts over the
    // canonical envelope. If this passes, `require_admin` accepts the request end-to-end.
    #[test]
    fn signed_claim_code_request_is_accepted_by_relay_verifier() {
        keychain::clear_for_test();
        let key = device_key::get_or_create().expect("device key");
        keychain::store_pairing("device-xyz", "https://relay.example", "Operator iPhone")
            .expect("store pairing");
        let pairing = keychain::get_pairing().unwrap().unwrap();

        let body = br#"{"count":1}"#;
        let req = build_signed_request(
            &pairing,
            "POST",
            "/v1/accounts/claim-codes",
            body,
            1_700_000_000,
            "nonce-1",
        )
        .expect("build signed request");

        // Header envelope matches the stored pairing + provided inputs.
        assert_eq!(req.url, "https://relay.example/v1/accounts/claim-codes");
        assert_eq!(req.method, "POST");
        assert_eq!(header(&req, signing::ADMIN_DEVICE_HEADER), "device-xyz");
        assert_eq!(header(&req, signing::ADMIN_TIMESTAMP_HEADER), "1700000000");
        assert_eq!(header(&req, signing::ADMIN_NONCE_HEADER), "nonce-1");
        assert_eq!(header(&req, "Content-Type"), "application/json");
        assert_eq!(req.body, body);

        // Reconstruct exactly what the relay reconstructs, and verify with its verifier.
        let sign_string = signing::request_sign_string(
            "POST",
            "/v1/accounts/claim-codes",
            1_700_000_000,
            "nonce-1",
            body,
        );
        verify_p256_signature(
            &DidKeyUri(key.key_id),
            sign_string.as_bytes(),
            &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
        )
        .expect("the relay's verifier must accept this signed request");
    }

    // Phase 8 self-revoke, proven without a live relay: a signed `POST
    // /v1/admin/devices/:id/revoke` over an empty body carries a signature the relay's OWN
    // verifier accepts — and that signature is bound to the path (this device's id), so it
    // cannot be replayed to revoke a *different* device.
    #[test]
    fn signed_self_revoke_request_is_accepted_and_path_bound() {
        keychain::clear_for_test();
        let key = device_key::get_or_create().expect("device key");
        keychain::store_pairing("device-self", "https://relay.example", "Operator iPhone")
            .expect("store pairing");
        let pairing = keychain::get_pairing().unwrap().unwrap();

        let path = "/v1/admin/devices/device-self/revoke";
        let req = build_signed_request(&pairing, "POST", path, b"", 1_700_000_000, "nonce-rev")
            .expect("build signed revoke request");

        assert_eq!(
            req.url,
            "https://relay.example/v1/admin/devices/device-self/revoke"
        );
        assert_eq!(req.body, b"");
        assert_eq!(header(&req, signing::ADMIN_DEVICE_HEADER), "device-self");

        // The relay's verifier accepts the self-revoke over its canonical envelope.
        let sign_string =
            signing::request_sign_string("POST", path, 1_700_000_000, "nonce-rev", b"");
        verify_p256_signature(
            &DidKeyUri(key.key_id.clone()),
            sign_string.as_bytes(),
            &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
        )
        .expect("the relay's verifier must accept this self-revoke");

        // The same signature must NOT verify against a different device's revoke path —
        // the envelope binds the target id, so a self-revoke can't revoke another device.
        let other_path = "/v1/admin/devices/device-victim/revoke";
        let other_sign_string =
            signing::request_sign_string("POST", other_path, 1_700_000_000, "nonce-rev", b"");
        assert!(
            verify_p256_signature(
                &DidKeyUri(key.key_id),
                other_sign_string.as_bytes(),
                &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
            )
            .is_err(),
            "a revoke signature must be bound to its own device's path"
        );
    }

    #[test]
    fn build_signed_request_binds_body_so_tamper_is_detected() {
        keychain::clear_for_test();
        let key = device_key::get_or_create().expect("device key");
        keychain::store_pairing("device-xyz", "https://relay.example", "Operator iPhone").unwrap();
        let pairing = keychain::get_pairing().unwrap().unwrap();

        let req = build_signed_request(
            &pairing,
            "POST",
            "/v1/accounts/claim-codes",
            br#"{"count":1}"#,
            1_700_000_000,
            "nonce-1",
        )
        .unwrap();

        // Verifying the signature against a *different* body must fail — the envelope
        // commits to the body hash, so a tampered body is rejected by the relay.
        let tampered = signing::request_sign_string(
            "POST",
            "/v1/accounts/claim-codes",
            1_700_000_000,
            "nonce-1",
            br#"{"count":99}"#,
        );
        assert!(
            verify_p256_signature(
                &DidKeyUri(key.key_id),
                tampered.as_bytes(),
                &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
            )
            .is_err(),
            "a signature over the real body must not verify against a tampered body"
        );
    }

    #[test]
    fn join_url_tolerates_trailing_slash_and_rejects_garbage() {
        assert_eq!(
            join_url("https://relay.example/", "/v1/admin/devices").unwrap(),
            "https://relay.example/v1/admin/devices"
        );
        assert_eq!(
            join_url("https://relay.example", "/v1/admin/devices").unwrap(),
            "https://relay.example/v1/admin/devices"
        );
        assert!(matches!(
            join_url("not a url", "/x"),
            Err(RelayClientError::InvalidRelayUrl)
        ));
    }

    #[test]
    fn extract_error_message_reads_relay_envelope() {
        assert_eq!(
            extract_error_message(
                r#"{"error":{"code":"Unauthorized","message":"invalid admin request signature"}}"#
            ),
            "invalid admin request signature"
        );
        // Falls back to the raw body when it is not the expected envelope.
        assert_eq!(extract_error_message("plain text"), "plain text");
    }
}
