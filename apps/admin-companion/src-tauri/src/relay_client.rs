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

use crate::pairings::{self, Pairing, PairingsState};
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
    /// An id-addressed pairing operation referenced an id not present in the document
    /// (e.g. the entry was removed on another screen between load and tap).
    #[error("no such pairing")]
    NoSuchPairing,
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

impl From<pairings::NoSuchPairing> for RelayClientError {
    fn from(_: pairings::NoSuchPairing) -> Self {
        RelayClientError::NoSuchPairing
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
/// the pairing as a new entry in the pairing document and makes it active.
pub async fn pair(
    relay_url: &str,
    pairing_code: &str,
    label: &str,
    nickname: &str,
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
    let mut doc = keychain::load_pairings()?;
    doc.append(Pairing {
        id: uuid::Uuid::new_v4().to_string(),
        nickname: nickname.to_string(),
        relay_url: relay_url.to_string(),
        device_id: device_id.clone(),
        device_label: label.to_string(),
    });
    keychain::save_pairings(&doc)?;
    Ok(device_id)
}

/// Resolve the pairing that unqualified operator actions (claim-code mint) target.
/// `NotPaired` covers both "never paired" and "the active entry was removed without an
/// explicit re-pick" — in either case there is no server this device may safely act on.
fn resolve_active() -> Result<Pairing, RelayClientError> {
    keychain::load_pairings()?
        .active_pairing()
        .cloned()
        .ok_or(RelayClientError::NotPaired)
}

/// Mint a single account claim code via a signed `POST /v1/accounts/claim-codes`.
/// The demo-lifesaver action: an operator generates a claim code from their phone.
pub async fn generate_claim_code() -> Result<String, RelayClientError> {
    let pairing = resolve_active()?;

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

/// Everything the UI needs to render the switcher and Settings list. Local keychain
/// read only — never contacts a relay.
pub fn list_pairings() -> Result<PairingsState, RelayClientError> {
    Ok(keychain::load_pairings()?.into())
}

/// Select which pairing unqualified actions target. Local-only; the relays are never
/// told which of them is "active".
pub fn set_active_pairing(id: &str) -> Result<(), RelayClientError> {
    let mut doc = keychain::load_pairings()?;
    doc.set_active(id)?;
    keychain::save_pairings(&doc)?;
    Ok(())
}

/// Update a pairing's operator-chosen nickname. Local-only display state.
pub fn rename_pairing(id: &str, nickname: &str) -> Result<(), RelayClientError> {
    let mut doc = keychain::load_pairings()?;
    doc.rename(id, nickname)?;
    keychain::save_pairings(&doc)?;
    Ok(())
}

/// Revoke the given pairing's credential on ITS relay (a signed self-revoke against
/// that relay), then remove the entry locally. The signed request is built from the
/// addressed pairing — not the active one — so revoking a background server never
/// signs against the wrong relay. Local removal happens only after the relay confirms;
/// a failed revoke leaves the entry intact so the operator can retry or fall back to a
/// local-only [`unpair`].
pub async fn revoke_self(id: &str) -> Result<(), RelayClientError> {
    let doc = keychain::load_pairings()?;
    let pairing = doc
        .get(id)
        .cloned()
        .ok_or(RelayClientError::NoSuchPairing)?;
    let path = format!("/v1/admin/devices/{}/revoke", pairing.device_id);
    // The revoke endpoint takes no body. The signature still binds method + path, so a
    // signature minted to revoke this device cannot be replayed to revoke another.
    let signed = build_signed_request(&pairing, "POST", &path, b"", unix_now(), &fresh_nonce())?;
    ensure_success(send(signed).await?).await?;
    // Reload before mutating: the document may have gained entries during the network
    // round-trip, and a stale write would silently drop them.
    let mut doc = keychain::load_pairings()?;
    if doc.remove(id).is_ok() {
        keychain::save_pairings(&doc)?;
    }
    Ok(())
}

/// Forget the given pairing locally **without** contacting any relay — the fallback
/// when [`revoke_self`] can't reach that relay. The credential remains valid
/// server-side until revoked another way. The device key is preserved so a re-pair is
/// recognised by the same public key.
pub fn unpair(id: &str) -> Result<(), RelayClientError> {
    let mut doc = keychain::load_pairings()?;
    doc.remove(id)?;
    keychain::save_pairings(&doc)?;
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

    /// A document-backed pairing fixture. The golden envelope tests below predate the
    /// multi-relay document; only this setup changed when the legacy triple helpers were
    /// removed — every sign-string, header assertion, and relay-verifier call is
    /// unchanged, which is what pins the envelope.
    fn test_pairing(device_id: &str, relay_url: &str) -> Pairing {
        Pairing {
            id: "test-pairing-id".to_string(),
            nickname: "test".to_string(),
            relay_url: relay_url.to_string(),
            device_id: device_id.to_string(),
            device_label: "Operator iPhone".to_string(),
        }
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
        let pairing = test_pairing("device-xyz", "https://relay.example");

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

    // Self-revoke, proven without a live relay: a signed `POST
    // /v1/admin/devices/:id/revoke` over an empty body carries a signature the relay's OWN
    // verifier accepts — and that signature is bound to the path (this device's id), so it
    // cannot be replayed to revoke a *different* device.
    #[test]
    fn signed_self_revoke_request_is_accepted_and_path_bound() {
        keychain::clear_for_test();
        let key = device_key::get_or_create().expect("device key");
        let pairing = test_pairing("device-self", "https://relay.example");

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
        let pairing = test_pairing("device-xyz", "https://relay.example");

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
    fn unpair_removes_the_active_pairing_and_keeps_the_biometric_pref() {
        keychain::clear_for_test();
        keychain::set_biometric_enabled(false).expect("disable biometric");

        // Save a doc with one entry.
        let mut doc = crate::pairings::PairingDoc::empty();
        doc.append(crate::pairings::Pairing {
            id: "id-1".to_string(),
            nickname: "test".to_string(),
            relay_url: "https://relay.example".to_string(),
            device_id: "device-1".to_string(),
            device_label: "Operator iPhone".to_string(),
        });
        keychain::save_pairings(&doc).expect("save");

        // Unpair removes it.
        unpair("id-1").expect("unpair");
        let loaded = keychain::load_pairings().expect("load");
        assert_eq!(loaded.pairings().len(), 0, "no pairings after unpair");
        assert_eq!(loaded.active_id(), None, "no active after unpair");

        // Biometric pref still false.
        assert!(!keychain::get_biometric_enabled().expect("read biometric"));

        // Second unpair on the same id returns NoSuchPairing error.
        assert!(matches!(
            unpair("id-1"),
            Err(RelayClientError::NoSuchPairing)
        ));
    }

    #[test]
    fn unpair_with_two_remaining_clears_the_selection() {
        keychain::clear_for_test();
        // Three entries, active = third.
        let mut doc = crate::pairings::PairingDoc::empty();
        doc.append(crate::pairings::Pairing {
            id: "id-1".to_string(),
            nickname: "first".to_string(),
            relay_url: "https://relay-1.example".to_string(),
            device_id: "device-1".to_string(),
            device_label: "Operator iPhone".to_string(),
        });
        doc.append(crate::pairings::Pairing {
            id: "id-2".to_string(),
            nickname: "second".to_string(),
            relay_url: "https://relay-2.example".to_string(),
            device_id: "device-2".to_string(),
            device_label: "Operator iPhone".to_string(),
        });
        doc.append(crate::pairings::Pairing {
            id: "id-3".to_string(),
            nickname: "third".to_string(),
            relay_url: "https://relay-3.example".to_string(),
            device_id: "device-3".to_string(),
            device_label: "Operator iPhone".to_string(),
        });
        keychain::save_pairings(&doc).expect("save");

        // Unpair removes the active entry (id-3).
        unpair("id-3").expect("unpair");

        // The two remaining entries persist and active is None.
        let loaded = keychain::load_pairings().expect("load");
        assert_eq!(loaded.pairings().len(), 2, "two pairings remain");
        assert_eq!(loaded.pairings()[0].id, "id-1", "first entry unchanged");
        assert_eq!(loaded.pairings()[1].id, "id-2", "second entry unchanged");
        assert_eq!(
            loaded.active_id(),
            None,
            "active is None (UI must ask for explicit pick)"
        );
    }

    #[test]
    fn set_active_then_signed_request_targets_the_new_active_relay() {
        // AC2.1's substance, offline. Seed: A ("https://staging.example", "device-a"),
        // then B ("https://prod.example", "device-b") — append order makes B active.
        keychain::clear_for_test();
        let key = device_key::get_or_create().expect("device key");
        let mut doc = crate::pairings::PairingDoc::empty();
        doc.append(crate::pairings::Pairing {
            id: "id-a".to_string(),
            nickname: "staging".to_string(),
            relay_url: "https://staging.example".to_string(),
            device_id: "device-a".to_string(),
            device_label: "Operator iPhone".to_string(),
        });
        doc.append(crate::pairings::Pairing {
            id: "id-b".to_string(),
            nickname: "prod".to_string(),
            relay_url: "https://prod.example".to_string(),
            device_id: "device-b".to_string(),
            device_label: "Operator iPhone".to_string(),
        });
        keychain::save_pairings(&doc).expect("save");

        // Initially active is B (prod).
        assert_eq!(list_pairings().unwrap().active, Some("id-b".to_string()));

        // Set active to A (staging).
        set_active_pairing("id-a").expect("set active to A");
        assert_eq!(list_pairings().unwrap().active, Some("id-a".to_string()));

        // Build a request from resolve_active() — should target A's relay.
        let pairing = resolve_active().expect("resolve active");
        assert_eq!(pairing.id, "id-a");
        assert_eq!(pairing.relay_url, "https://staging.example");
        assert_eq!(pairing.device_id, "device-a");

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

        assert_eq!(req.url, "https://staging.example/v1/accounts/claim-codes");
        assert_eq!(header(&req, signing::ADMIN_DEVICE_HEADER), "device-a");

        // Verify the signature.
        let sign_string = signing::request_sign_string(
            "POST",
            "/v1/accounts/claim-codes",
            1_700_000_000,
            "nonce-1",
            body,
        );
        verify_p256_signature(
            &DidKeyUri(key.key_id.clone()),
            sign_string.as_bytes(),
            &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
        )
        .expect("A's signature must verify");

        // Now set active to B and verify the request targets B.
        set_active_pairing("id-b").expect("set active to B");
        let pairing_b = resolve_active().expect("resolve active");
        assert_eq!(pairing_b.id, "id-b");
        assert_eq!(pairing_b.relay_url, "https://prod.example");
        assert_eq!(pairing_b.device_id, "device-b");

        let req_b = build_signed_request(
            &pairing_b,
            "POST",
            "/v1/accounts/claim-codes",
            body,
            1_700_000_000,
            "nonce-1",
        )
        .expect("build signed request for B");

        assert_eq!(req_b.url, "https://prod.example/v1/accounts/claim-codes");
        assert_eq!(header(&req_b, signing::ADMIN_DEVICE_HEADER), "device-b");

        // B's signature verifies against B's key.
        let sign_string_b = signing::request_sign_string(
            "POST",
            "/v1/accounts/claim-codes",
            1_700_000_000,
            "nonce-1",
            body,
        );
        verify_p256_signature(
            &DidKeyUri(key.key_id),
            sign_string_b.as_bytes(),
            &decode_sig(header(&req_b, signing::ADMIN_SIGNATURE_HEADER)),
        )
        .expect("B's signature must verify");
    }

    #[test]
    fn resolve_active_is_not_paired_when_nothing_is_selected() {
        // Empty document: resolve_active() matches Err(RelayClientError::NotPaired).
        keychain::clear_for_test();
        let result = resolve_active();
        assert!(matches!(result, Err(RelayClientError::NotPaired)));
    }

    #[test]
    fn resolve_active_is_not_paired_after_ambiguous_removal() {
        // Seed A, B, C (active C). unpair(C.id) — two remain, selection cleared.
        keychain::clear_for_test();
        let mut doc = crate::pairings::PairingDoc::empty();
        doc.append(crate::pairings::Pairing {
            id: "id-a".to_string(),
            nickname: "a".to_string(),
            relay_url: "https://a.example".to_string(),
            device_id: "device-a".to_string(),
            device_label: "Operator iPhone".to_string(),
        });
        doc.append(crate::pairings::Pairing {
            id: "id-b".to_string(),
            nickname: "b".to_string(),
            relay_url: "https://b.example".to_string(),
            device_id: "device-b".to_string(),
            device_label: "Operator iPhone".to_string(),
        });
        doc.append(crate::pairings::Pairing {
            id: "id-c".to_string(),
            nickname: "c".to_string(),
            relay_url: "https://c.example".to_string(),
            device_id: "device-c".to_string(),
            device_label: "Operator iPhone".to_string(),
        });
        keychain::save_pairings(&doc).expect("save");

        // Active is C.
        assert_eq!(list_pairings().unwrap().active, Some("id-c".to_string()));

        // Unpair C.
        unpair("id-c").expect("unpair");

        // Active is now cleared, resolve_active() is NotPaired.
        assert_eq!(list_pairings().unwrap().active, None);
        let result = resolve_active();
        assert!(matches!(result, Err(RelayClientError::NotPaired)));
    }

    #[test]
    fn set_active_pairing_unknown_id_is_no_such_pairing_and_selection_is_kept() {
        // Seed A (active). set_active_pairing("nope") matches
        // Err(RelayClientError::NoSuchPairing); list_pairings().active is still A.id.
        keychain::clear_for_test();
        let mut doc = crate::pairings::PairingDoc::empty();
        doc.append(crate::pairings::Pairing {
            id: "id-a".to_string(),
            nickname: "a".to_string(),
            relay_url: "https://a.example".to_string(),
            device_id: "device-a".to_string(),
            device_label: "Operator iPhone".to_string(),
        });
        keychain::save_pairings(&doc).expect("save");

        assert_eq!(list_pairings().unwrap().active, Some("id-a".to_string()));

        let result = set_active_pairing("nope");
        assert!(matches!(result, Err(RelayClientError::NoSuchPairing)));

        // Active is still A.
        assert_eq!(list_pairings().unwrap().active, Some("id-a".to_string()));
    }

    #[test]
    fn rename_pairing_updates_only_the_nickname_locally() {
        // Seed A. rename_pairing(A.id, "prod") succeeds; list_pairings() shows the new
        // nickname with relay_url/device_id/device_label/id unchanged, and active
        // unchanged. rename_pairing("nope", "x") is Err(NoSuchPairing).
        keychain::clear_for_test();
        let mut doc = crate::pairings::PairingDoc::empty();
        doc.append(crate::pairings::Pairing {
            id: "id-a".to_string(),
            nickname: "original".to_string(),
            relay_url: "https://a.example".to_string(),
            device_id: "device-a".to_string(),
            device_label: "Operator iPhone".to_string(),
        });
        keychain::save_pairings(&doc).expect("save");

        rename_pairing("id-a", "prod").expect("rename");

        let state = list_pairings().expect("list");
        assert_eq!(state.active, Some("id-a".to_string()));
        assert_eq!(state.pairings.len(), 1);
        let p = &state.pairings[0];
        assert_eq!(p.id, "id-a");
        assert_eq!(p.nickname, "prod");
        assert_eq!(p.relay_url, "https://a.example");
        assert_eq!(p.device_id, "device-a");
        assert_eq!(p.device_label, "Operator iPhone");

        // Unknown id returns NoSuchPairing.
        let result = rename_pairing("nope", "x");
        assert!(matches!(result, Err(RelayClientError::NoSuchPairing)));

        // Nickname is unchanged.
        assert_eq!(list_pairings().unwrap().pairings[0].nickname, "prod");
    }

    #[test]
    fn revoke_request_for_a_non_active_pairing_binds_its_own_relay_and_path() {
        // AC6.2. Seed A (active, "https://staging.example") and B (non-active,
        // "https://prod.example", device "device-b"). Build the exact request
        // revoke_self(B.id) would send, from B (the doc's non-active entry, fetched via
        // keychain::load_pairings().get(B.id)):
        keychain::clear_for_test();
        let key = device_key::get_or_create().expect("device key");
        let mut doc = crate::pairings::PairingDoc::empty();
        doc.append(crate::pairings::Pairing {
            id: "id-b".to_string(),
            nickname: "prod".to_string(),
            relay_url: "https://prod.example".to_string(),
            device_id: "device-b".to_string(),
            device_label: "Operator iPhone".to_string(),
        });
        doc.append(crate::pairings::Pairing {
            id: "id-a".to_string(),
            nickname: "staging".to_string(),
            relay_url: "https://staging.example".to_string(),
            device_id: "device-a".to_string(),
            device_label: "Operator iPhone".to_string(),
        });
        keychain::save_pairings(&doc).expect("save");

        // A is active (appended last), B is not.
        assert_eq!(list_pairings().unwrap().active, Some("id-a".to_string()));

        // Fetch B (the non-active pairing).
        let doc = keychain::load_pairings().expect("load");
        let b = doc.get("id-b").cloned().expect("B exists");
        assert_eq!(b.relay_url, "https://prod.example");
        assert_eq!(b.device_id, "device-b");

        // Build the request that revoke_self(B.id) would send.
        let path = format!("/v1/admin/devices/{}/revoke", b.device_id);
        let req = build_signed_request(&b, "POST", &path, b"", 1_700_000_000, "nonce-rev")
            .expect("build revoke request");

        // URL and path are B's.
        assert_eq!(
            req.url,
            "https://prod.example/v1/admin/devices/device-b/revoke"
        );
        assert_eq!(req.body, b"");
        assert_eq!(header(&req, signing::ADMIN_DEVICE_HEADER), "device-b");

        // The relay's verifier accepts the signature over B's path.
        let sign_string =
            signing::request_sign_string("POST", &path, 1_700_000_000, "nonce-rev", b"");
        verify_p256_signature(
            &DidKeyUri(key.key_id.clone()),
            sign_string.as_bytes(),
            &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
        )
        .expect("B's revoke signature must verify");

        // The same signature must NOT verify against A's path — path-binding holds.
        let a_path = "/v1/admin/devices/device-a/revoke";
        let a_sign_string =
            signing::request_sign_string("POST", a_path, 1_700_000_000, "nonce-rev", b"");
        assert!(
            verify_p256_signature(
                &DidKeyUri(key.key_id),
                a_sign_string.as_bytes(),
                &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
            )
            .is_err(),
            "B's revoke signature must NOT verify against A's path"
        );
    }

    #[test]
    fn no_such_pairing_serializes_with_its_screaming_snake_code() {
        // serde_json::to_value(RelayClientError::NoSuchPairing)["code"]
        //   == "NO_SUCH_PAIRING" — the IPC contract Phase 3's classifyRelayError keys on.
        let error = RelayClientError::NoSuchPairing;
        let value = serde_json::to_value(&error).expect("serialize");
        assert_eq!(
            value.get("code").unwrap().as_str().unwrap(),
            "NO_SUCH_PAIRING"
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
