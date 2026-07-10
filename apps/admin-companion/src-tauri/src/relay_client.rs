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
    /// A remote revoke addressed this pairing's own registration. Refused: self-revoke
    /// is a distinct flow ([`revoke_self`]) that also removes the local pairing entry,
    /// and letting the remote path revoke self would strand a dead local pairing.
    #[error("target is this device's own registration")]
    SelfRevokeNotAllowed,
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

/// Resolve an id-addressed pairing, or `NoSuchPairing` when the entry was removed
/// (e.g. on another screen between load and tap).
fn resolve_pairing(id: &str) -> Result<Pairing, RelayClientError> {
    keychain::load_pairings()?
        .get(id)
        .cloned()
        .ok_or(RelayClientError::NoSuchPairing)
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
    let pairing = resolve_pairing(id)?;
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

// ── Device management (list / remote revoke) ─────────────────────────────────

/// Build the signed remote-revoke request for another device on `pairing`'s relay.
///
/// Refuses this pairing's own registration ([`RelayClientError::SelfRevokeNotAllowed`]):
/// self-revoke is [`revoke_self`], which also removes the local pairing entry. Pure
/// apart from the device-key sign, so the refusal and the path-binding are testable
/// without a network.
pub fn build_revoke_device_request(
    pairing: &Pairing,
    device_id: &str,
    timestamp: i64,
    nonce: &str,
) -> Result<SignedRequest, RelayClientError> {
    if device_id == pairing.device_id {
        return Err(RelayClientError::SelfRevokeNotAllowed);
    }
    let path = format!("/v1/admin/devices/{device_id}/revoke");
    // The revoke endpoint takes no body; the signature binds method + path, so a
    // signature minted to revoke this device cannot be replayed against another.
    build_signed_request(pairing, "POST", &path, b"", timestamp, nonce)
}

/// List every device registered on the given pairing's relay — active and revoked,
/// newest first — via a signed `GET /v1/admin/devices`. The devices screen's data
/// source; id-addressed so the list always comes from (and is signed for) the relay
/// the screen was opened for, never a concurrently-switched active pairing.
pub async fn list_devices(pairing_id: &str) -> Result<Vec<AdminDevice>, RelayClientError> {
    let pairing = resolve_pairing(pairing_id)?;
    let signed = build_signed_request(
        &pairing,
        "GET",
        "/v1/admin/devices",
        b"",
        unix_now(),
        &fresh_nonce(),
    )?;
    let response = send(signed).await?;
    Ok(parse_success::<ListDevicesResponseBody>(response)
        .await?
        .devices)
}

/// Revoke another device's registration on the given pairing's relay — the loss
/// response: kill a lost device's credential from this one. Self-targets are refused
/// (see [`build_revoke_device_request`]). Returns the device's post-revoke state as
/// the relay reports it.
pub async fn revoke_device(
    pairing_id: &str,
    device_id: &str,
) -> Result<AdminDevice, RelayClientError> {
    let pairing = resolve_pairing(pairing_id)?;
    let signed = build_revoke_device_request(&pairing, device_id, unix_now(), &fresh_nonce())?;
    let response = send(signed).await?;
    Ok(parse_success::<RevokeDeviceResponseBody>(response)
        .await?
        .device)
}

// ── Moderation (account takedown / restore) ──────────────────────────────────

/// The subject discriminant for account-level moderation — the only subject kind the
/// relay's `getSubjectStatus`/`updateSubjectStatus` implement.
const REPO_REF_TYPE: &str = "com.atproto.admin.defs#repoRef";

/// Build the signed status lookup (`GET /xrpc/com.atproto.admin.getSubjectStatus?did=…`).
///
/// The relay's guard verifies the signature over `uri.path()` only — the query string is
/// excluded from the canonical envelope — so the bare path is signed here and `did` is
/// appended to the URL *after* signing. Folding the query into the signed path would
/// fail verification.
pub fn build_get_subject_status_request(
    pairing: &Pairing,
    did: &str,
    timestamp: i64,
    nonce: &str,
) -> Result<SignedRequest, RelayClientError> {
    let mut req = build_signed_request(
        pairing,
        "GET",
        "/xrpc/com.atproto.admin.getSubjectStatus",
        b"",
        timestamp,
        nonce,
    )?;
    req.url = append_query(&req.url, &[("did", did)])?;
    Ok(req)
}

/// Build the signed takedown/restore write (`POST /xrpc/com.atproto.admin.updateSubjectStatus`).
/// `applied = true` takes the account down; `false` restores it. The body is serialized
/// once here so the exact bytes signed are the exact bytes sent.
pub fn build_update_subject_status_request(
    pairing: &Pairing,
    did: &str,
    applied: bool,
    timestamp: i64,
    nonce: &str,
) -> Result<SignedRequest, RelayClientError> {
    let body = serde_json::to_vec(&UpdateSubjectStatusRequestBody {
        subject: RepoRefBody {
            type_: REPO_REF_TYPE,
            did: did.to_string(),
        },
        takedown: StatusAttrBody { applied },
    })
    .expect("UpdateSubjectStatusRequestBody serializes");
    build_signed_request(
        pairing,
        "POST",
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        &body,
        timestamp,
        nonce,
    )
}

/// Report an account's current takedown status from the given pairing's relay via a
/// signed `GET`. Id-addressed like [`list_devices`], so a concurrent active-pairing
/// switch can never redirect which relay is asked (or signed for).
pub async fn get_subject_status(
    pairing_id: &str,
    did: &str,
) -> Result<SubjectStatus, RelayClientError> {
    let pairing = resolve_pairing(pairing_id)?;
    let signed = build_get_subject_status_request(&pairing, did, unix_now(), &fresh_nonce())?;
    let response = send(signed).await?;
    parse_success::<SubjectStatus>(response).await
}

/// Apply (`applied = true`) or clear (`false`) an account-level takedown on the given
/// pairing's relay via a signed `POST`. Idempotent server-side; the response reports
/// the resulting takedown state, which the screen re-renders as the relay's truth.
pub async fn update_subject_status(
    pairing_id: &str,
    did: &str,
    applied: bool,
) -> Result<SubjectStatus, RelayClientError> {
    let pairing = resolve_pairing(pairing_id)?;
    let signed =
        build_update_subject_status_request(&pairing, did, applied, unix_now(), &fresh_nonce())?;
    let response = send(signed).await?;
    parse_success::<SubjectStatus>(response).await
}

// ── Account metrics (usage / storage) ────────────────────────────────────────

/// Build the signed per-account metrics lookup (`GET /v1/accounts/{did}/usage` or
/// `…/storage`). Unlike the moderation lookup, the DID rides in the *path*, so it is
/// covered by the signed envelope — a signature minted for one account's metrics can
/// never be replayed against another account's.
pub fn build_account_metrics_request(
    pairing: &Pairing,
    did: &str,
    metric: &str,
    timestamp: i64,
    nonce: &str,
) -> Result<SignedRequest, RelayClientError> {
    let path = format!("/v1/accounts/{did}/{metric}");
    build_signed_request(pairing, "GET", &path, b"", timestamp, nonce)
}

/// Fetch an account's usage metrics (records/commits/blobs counts, total bytes,
/// last-active) from the given pairing's relay via a signed `GET`. Id-addressed like
/// [`get_subject_status`], so a concurrent active-pairing switch can never redirect
/// which relay is asked (or signed for).
pub async fn get_account_usage(
    pairing_id: &str,
    did: &str,
) -> Result<AccountUsage, RelayClientError> {
    let pairing = resolve_pairing(pairing_id)?;
    let signed = build_account_metrics_request(&pairing, did, "usage", unix_now(), &fresh_nonce())?;
    let response = send(signed).await?;
    parse_success::<AccountUsage>(response).await
}

/// Fetch an account's blob-storage metrics (blob count, bytes, configured quota +
/// used %, largest blob) from the given pairing's relay via a signed `GET`.
pub async fn get_account_storage(
    pairing_id: &str,
    did: &str,
) -> Result<AccountStorage, RelayClientError> {
    let pairing = resolve_pairing(pairing_id)?;
    let signed =
        build_account_metrics_request(&pairing, did, "storage", unix_now(), &fresh_nonce())?;
    let response = send(signed).await?;
    parse_success::<AccountStorage>(response).await
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

/// One registered companion device as the relay reports it — the shape of
/// `AdminDeviceView` in `crates/pds/src/routes/admin_devices.rs` (camelCase on the
/// wire; re-serialized camelCase over IPC). The `pds` crate is binary-only, so this
/// contract is shared by value, not import — a deserialization test pins it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminDevice {
    /// Relay-assigned id — the value a phone sends as `X-Admin-Device`. Matching this
    /// against a pairing's `device_id` identifies "this device" in the list.
    pub id: String,
    pub label: String,
    /// The device's P-256 public key as a `did:key:` URI.
    pub public_key: String,
    pub platform: String,
    pub scopes: String,
    /// `"active"` or `"revoked"`, derived server-side from `revoked_at`.
    pub status: String,
    pub created_at: String,
    pub last_seen_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(serde::Deserialize)]
struct ListDevicesResponseBody {
    devices: Vec<AdminDevice>,
}

#[derive(serde::Deserialize)]
struct RevokeDeviceResponseBody {
    device: AdminDevice,
}

#[derive(Serialize)]
struct UpdateSubjectStatusRequestBody {
    subject: RepoRefBody,
    takedown: StatusAttrBody,
}

/// `com.atproto.admin.defs#repoRef` as the relay's `RepoRefSubject` expects it — that
/// struct is `deny_unknown_fields`, so exactly `$type` + `did` and nothing else.
#[derive(Serialize)]
struct RepoRefBody {
    #[serde(rename = "$type")]
    type_: &'static str,
    did: String,
}

#[derive(Serialize)]
struct StatusAttrBody {
    applied: bool,
}

/// An account's takedown status as the relay reports it — the response shape of both
/// `getSubjectStatus` and `updateSubjectStatus` (`RepoRefView`/`StatusAttrView` in
/// crates/pds/src/routes/admin_subject_defs.rs; the `pds` crate is binary-only, so this
/// contract is shared by value, not import — a deserialization test pins it). The same
/// shape is re-serialized over IPC, `$type` key included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct SubjectStatus {
    pub subject: SubjectRepoRef,
    pub takedown: SubjectTakedown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct SubjectRepoRef {
    #[serde(rename = "$type")]
    pub type_: String,
    pub did: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct SubjectTakedown {
    pub applied: bool,
}

/// An account's usage metrics as the relay reports them — the response shape of
/// `GET /v1/accounts/{did}/usage` (`UsageResponse` in crates/pds/src/routes/
/// account_usage.rs; the `pds` crate is binary-only, so this contract is shared by
/// value, not import — a deserialization test pins it). Re-serialized camelCase over IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountUsage {
    pub records_count: i64,
    pub commits_count: i64,
    pub blobs_count: i64,
    pub storage_bytes: i64,
    pub last_active: String,
}

/// An account's blob-storage metrics as the relay reports them — the response shape
/// of `GET /v1/accounts/{did}/storage` (`StorageResponse` in crates/pds/src/routes/
/// account_storage.rs; shared by value like [`AccountUsage`], pinned by a
/// deserialization test). Re-serialized camelCase over IPC.
#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountStorage {
    pub blob_count: i64,
    pub total_bytes: i64,
    pub quota_bytes: i64,
    pub quota_used_pct: f64,
    pub largest_blob: Option<LargestBlob>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LargestBlob {
    pub cid: String,
    pub size: i64,
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

/// Append URL-encoded query parameters to an already-validated URL. Kept separate from
/// [`join_url`] because the canonical signing envelope covers the *path only* — callers
/// append the query after the request is built (and signed), never before.
fn append_query(url: &str, params: &[(&str, &str)]) -> Result<String, RelayClientError> {
    let mut parsed = reqwest::Url::parse(url).map_err(|_| RelayClientError::InvalidRelayUrl)?;
    parsed.query_pairs_mut().extend_pairs(params);
    Ok(parsed.to_string())
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

    // The device-list read, proven without a live relay: a signed `GET /v1/admin/devices`
    // over an empty body carries a signature the relay's OWN verifier accepts — the same
    // envelope gates reads and writes.
    #[test]
    fn signed_device_list_request_is_accepted_by_relay_verifier() {
        keychain::clear_for_test();
        let key = device_key::get_or_create().expect("device key");
        let pairing = test_pairing("device-xyz", "https://relay.example");

        let req = build_signed_request(
            &pairing,
            "GET",
            "/v1/admin/devices",
            b"",
            1_700_000_000,
            "nonce-list",
        )
        .expect("build signed list request");

        assert_eq!(req.url, "https://relay.example/v1/admin/devices");
        assert_eq!(req.method, "GET");
        assert_eq!(req.body, b"");
        assert_eq!(header(&req, signing::ADMIN_DEVICE_HEADER), "device-xyz");

        let sign_string = signing::request_sign_string(
            "GET",
            "/v1/admin/devices",
            1_700_000_000,
            "nonce-list",
            b"",
        );
        verify_p256_signature(
            &DidKeyUri(key.key_id),
            sign_string.as_bytes(),
            &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
        )
        .expect("the relay's verifier must accept this signed list request");
    }

    // Remote revoke of ANOTHER device (the loss response): the signature binds the
    // target's path, and a self-target is refused before anything is signed —
    // self-revoke is `revoke_self`, which also removes the local pairing.
    #[test]
    fn remote_revoke_request_is_path_bound_and_refuses_self_target() {
        keychain::clear_for_test();
        let key = device_key::get_or_create().expect("device key");
        let pairing = test_pairing("device-self", "https://relay.example");

        let req = build_revoke_device_request(&pairing, "device-lost", 1_700_000_000, "nonce-rev")
            .expect("build remote revoke request");

        // The request targets the LOST device's path, authenticated as THIS device.
        assert_eq!(
            req.url,
            "https://relay.example/v1/admin/devices/device-lost/revoke"
        );
        assert_eq!(req.body, b"");
        assert_eq!(header(&req, signing::ADMIN_DEVICE_HEADER), "device-self");

        let path = "/v1/admin/devices/device-lost/revoke";
        let sign_string =
            signing::request_sign_string("POST", path, 1_700_000_000, "nonce-rev", b"");
        verify_p256_signature(
            &DidKeyUri(key.key_id.clone()),
            sign_string.as_bytes(),
            &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
        )
        .expect("the relay's verifier must accept this remote revoke");

        // Path-binding: the same signature must NOT verify against another target.
        let other_path = "/v1/admin/devices/device-other/revoke";
        let other_sign_string =
            signing::request_sign_string("POST", other_path, 1_700_000_000, "nonce-rev", b"");
        assert!(
            verify_p256_signature(
                &DidKeyUri(key.key_id),
                other_sign_string.as_bytes(),
                &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
            )
            .is_err(),
            "a remote-revoke signature must be bound to its target's path"
        );

        // A self-target is refused before signing.
        assert!(matches!(
            build_revoke_device_request(&pairing, "device-self", 1_700_000_000, "nonce-rev"),
            Err(RelayClientError::SelfRevokeNotAllowed)
        ));
    }

    // The moderation lookup, proven without a live relay: the signature covers the BARE
    // path (the relay's guard verifies `uri.path()`, which never includes the query),
    // while the URL carries `?did=`. A signature minted over path+query must fail.
    #[test]
    fn signed_get_subject_status_request_signs_path_without_query() {
        keychain::clear_for_test();
        let key = device_key::get_or_create().expect("device key");
        let pairing = test_pairing("device-xyz", "https://relay.example");

        let req = build_get_subject_status_request(
            &pairing,
            "did:plc:abc123",
            1_700_000_000,
            "nonce-mod",
        )
        .expect("build signed status lookup");

        assert_eq!(
            req.url,
            "https://relay.example/xrpc/com.atproto.admin.getSubjectStatus?did=did%3Aplc%3Aabc123"
        );
        assert_eq!(req.method, "GET");
        assert_eq!(req.body, b"");
        assert_eq!(header(&req, signing::ADMIN_DEVICE_HEADER), "device-xyz");

        // The relay reconstructs the envelope from uri.path() — no query — and verifies.
        let path = "/xrpc/com.atproto.admin.getSubjectStatus";
        let sign_string =
            signing::request_sign_string("GET", path, 1_700_000_000, "nonce-mod", b"");
        verify_p256_signature(
            &DidKeyUri(key.key_id.clone()),
            sign_string.as_bytes(),
            &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
        )
        .expect("the relay's verifier must accept this status lookup");

        // Path+query is NOT what the relay verifies — the signature must not cover it.
        let with_query = signing::request_sign_string(
            "GET",
            "/xrpc/com.atproto.admin.getSubjectStatus?did=did%3Aplc%3Aabc123",
            1_700_000_000,
            "nonce-mod",
            b"",
        );
        assert!(
            verify_p256_signature(
                &DidKeyUri(key.key_id),
                with_query.as_bytes(),
                &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
            )
            .is_err(),
            "the signature must cover the bare path, not path+query"
        );
    }

    // The takedown write: the exact serialized body is pinned (the relay's
    // `RepoRefSubject` is deny_unknown_fields, so any extra or renamed field is a 400),
    // its hash is what the signature commits to, and the relay's own verifier accepts
    // the envelope. A restore differs only in `applied`, which changes the body hash —
    // a takedown signature can never be replayed as a restore or vice versa.
    #[test]
    fn signed_update_subject_status_request_pins_body_and_verifies() {
        keychain::clear_for_test();
        let key = device_key::get_or_create().expect("device key");
        let pairing = test_pairing("device-xyz", "https://relay.example");

        let req = build_update_subject_status_request(
            &pairing,
            "did:plc:abc123",
            true,
            1_700_000_000,
            "nonce-td",
        )
        .expect("build signed takedown");

        assert_eq!(
            req.url,
            "https://relay.example/xrpc/com.atproto.admin.updateSubjectStatus"
        );
        // `require_admin_json` refuses the request with 415 without this header.
        assert_eq!(header(&req, "Content-Type"), "application/json");
        assert_eq!(
            std::str::from_utf8(&req.body).unwrap(),
            r#"{"subject":{"$type":"com.atproto.admin.defs#repoRef","did":"did:plc:abc123"},"takedown":{"applied":true}}"#
        );

        let sign_string = signing::request_sign_string(
            "POST",
            "/xrpc/com.atproto.admin.updateSubjectStatus",
            1_700_000_000,
            "nonce-td",
            &req.body,
        );
        verify_p256_signature(
            &DidKeyUri(key.key_id),
            sign_string.as_bytes(),
            &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
        )
        .expect("the relay's verifier must accept this takedown request");

        // The restore body flips only `applied` — pinned so the two writes are distinct.
        let restore = build_update_subject_status_request(
            &pairing,
            "did:plc:abc123",
            false,
            1_700_000_000,
            "nonce-td",
        )
        .expect("build signed restore");
        assert_eq!(
            std::str::from_utf8(&restore.body).unwrap(),
            r#"{"subject":{"$type":"com.atproto.admin.defs#repoRef","did":"did:plc:abc123"},"takedown":{"applied":false}}"#
        );
        assert_ne!(
            header(&req, signing::ADMIN_SIGNATURE_HEADER),
            header(&restore, signing::ADMIN_SIGNATURE_HEADER),
            "a takedown signature must not be valid for a restore"
        );
    }

    // Pins the relay's subject-status wire shape by value (`RepoRefView`/`StatusAttrView`
    // in crates/pds/src/routes/admin_subject_defs.rs) and its IPC re-serialization —
    // the `$type` key survives the round trip.
    #[test]
    fn subject_status_deserializes_the_relay_shape() {
        let json = r#"{
            "subject": { "$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:abc123" },
            "takedown": { "applied": true }
        }"#;
        let status: SubjectStatus = serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            status,
            SubjectStatus {
                subject: SubjectRepoRef {
                    type_: "com.atproto.admin.defs#repoRef".to_string(),
                    did: "did:plc:abc123".to_string(),
                },
                takedown: SubjectTakedown { applied: true },
            }
        );

        let value = serde_json::to_value(&status).expect("serialize");
        assert_eq!(value["subject"]["$type"], "com.atproto.admin.defs#repoRef");
        assert_eq!(value["subject"]["did"], "did:plc:abc123");
        assert_eq!(value["takedown"]["applied"], true);
    }

    // Pins the relay's `AdminDeviceView` wire shape by value (the `pds` crate is
    // binary-only, so the contract can't be shared by import). If the relay renames or
    // retypes a field, this literal — and the screen consuming it — must change together.
    #[test]
    fn admin_device_deserializes_the_relay_camel_case_shape() {
        let json = r#"{
            "id": "dev-1",
            "label": "Operator iPhone",
            "publicKey": "did:key:zDnaexample",
            "platform": "ios",
            "scopes": "full",
            "status": "revoked",
            "createdAt": "2026-07-01 12:00:00",
            "lastSeenAt": null,
            "revokedAt": "2026-07-02 08:30:00"
        }"#;
        let device: AdminDevice = serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            device,
            AdminDevice {
                id: "dev-1".to_string(),
                label: "Operator iPhone".to_string(),
                public_key: "did:key:zDnaexample".to_string(),
                platform: "ios".to_string(),
                scopes: "full".to_string(),
                status: "revoked".to_string(),
                created_at: "2026-07-01 12:00:00".to_string(),
                last_seen_at: None,
                revoked_at: Some("2026-07-02 08:30:00".to_string()),
            }
        );

        // And it re-serializes camelCase for IPC — the frontend sees the relay's names.
        let value = serde_json::to_value(&device).expect("serialize");
        assert_eq!(value.get("publicKey").unwrap(), "did:key:zDnaexample");
        assert_eq!(value.get("lastSeenAt").unwrap(), &serde_json::Value::Null);
        assert_eq!(value.get("revokedAt").unwrap(), "2026-07-02 08:30:00");
    }

    // The account-metrics lookup: the DID rides in the PATH (unlike getSubjectStatus's
    // query), so it is inside the signed envelope — proven by verifying with the relay's
    // own verifier, then showing the same signature fails for another account's path.
    #[test]
    fn signed_account_metrics_request_binds_did_in_path() {
        keychain::clear_for_test();
        let key = device_key::get_or_create().expect("device key");
        let pairing = test_pairing("device-xyz", "https://relay.example");

        let req = build_account_metrics_request(
            &pairing,
            "did:plc:abc123",
            "usage",
            1_700_000_000,
            "nonce-usage",
        )
        .expect("build signed usage lookup");

        assert_eq!(
            req.url,
            "https://relay.example/v1/accounts/did:plc:abc123/usage"
        );
        assert_eq!(req.method, "GET");
        assert_eq!(req.body, b"");
        assert_eq!(header(&req, signing::ADMIN_DEVICE_HEADER), "device-xyz");

        let path = "/v1/accounts/did:plc:abc123/usage";
        let sign_string =
            signing::request_sign_string("GET", path, 1_700_000_000, "nonce-usage", b"");
        verify_p256_signature(
            &DidKeyUri(key.key_id.clone()),
            sign_string.as_bytes(),
            &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
        )
        .expect("the relay's verifier must accept this usage lookup");

        // DID-binding: the same signature must NOT verify for another account's path.
        let other_path = "/v1/accounts/did:plc:other/usage";
        let other_sign_string =
            signing::request_sign_string("GET", other_path, 1_700_000_000, "nonce-usage", b"");
        assert!(
            verify_p256_signature(
                &DidKeyUri(key.key_id),
                other_sign_string.as_bytes(),
                &decode_sig(header(&req, signing::ADMIN_SIGNATURE_HEADER)),
            )
            .is_err(),
            "an account-metrics signature must be bound to its account's path"
        );

        // The storage variant only changes the trailing path segment.
        let storage = build_account_metrics_request(
            &pairing,
            "did:plc:abc123",
            "storage",
            1_700_000_000,
            "nonce-storage",
        )
        .expect("build signed storage lookup");
        assert_eq!(
            storage.url,
            "https://relay.example/v1/accounts/did:plc:abc123/storage"
        );
    }

    // Pins the relay's usage/storage wire shapes by value (`UsageResponse` in
    // account_usage.rs, `StorageResponse` in account_storage.rs — binary-only crate,
    // so shared by value, not import) and their IPC re-serialization.
    #[test]
    fn account_metrics_deserialize_the_relay_shapes() {
        let usage: AccountUsage = serde_json::from_str(
            r#"{
                "recordsCount": 3,
                "commitsCount": 4,
                "blobsCount": 1,
                "storageBytes": 2048,
                "lastActive": "2026-07-01 12:00:00"
            }"#,
        )
        .expect("usage deserializes");
        assert_eq!(
            usage,
            AccountUsage {
                records_count: 3,
                commits_count: 4,
                blobs_count: 1,
                storage_bytes: 2048,
                last_active: "2026-07-01 12:00:00".to_string(),
            }
        );
        // Re-serializes camelCase for IPC — the frontend sees the relay's names.
        let value = serde_json::to_value(&usage).expect("serialize");
        assert_eq!(value.get("storageBytes").unwrap(), 2048);
        assert_eq!(value.get("lastActive").unwrap(), "2026-07-01 12:00:00");

        let storage: AccountStorage = serde_json::from_str(
            r#"{
                "blobCount": 2,
                "totalBytes": 1000,
                "quotaBytes": 1073741824,
                "quotaUsedPct": 0.0000931,
                "largestBlob": { "cid": "bafblobbig", "size": 900 }
            }"#,
        )
        .expect("storage deserializes");
        assert_eq!(storage.blob_count, 2);
        assert_eq!(storage.quota_bytes, 1_073_741_824);
        assert_eq!(
            storage.largest_blob,
            Some(LargestBlob {
                cid: "bafblobbig".to_string(),
                size: 900,
            })
        );

        // `largestBlob` is null for a blobless account — must stay Option, not default.
        let empty: AccountStorage = serde_json::from_str(
            r#"{
                "blobCount": 0,
                "totalBytes": 0,
                "quotaBytes": 1073741824,
                "quotaUsedPct": 0.0,
                "largestBlob": null
            }"#,
        )
        .expect("blobless storage deserializes");
        assert_eq!(empty.largest_blob, None);
        let value = serde_json::to_value(&empty).expect("serialize");
        assert_eq!(value.get("largestBlob").unwrap(), &serde_json::Value::Null);
    }

    // Pins the wrapper envelopes around `AdminDevice` — `{"devices":[…]}` for the list
    // and `{"device":{…}}` for the revoke response — so a relay-side wrapper-key rename
    // breaks here, not as a runtime `BadResponse`.
    #[test]
    fn device_response_envelopes_deserialize() {
        let device_json = r#"{
            "id": "dev-1",
            "label": "Operator iPhone",
            "publicKey": "did:key:zDnaexample",
            "platform": "ios",
            "scopes": "full",
            "status": "active",
            "createdAt": "2026-07-01 12:00:00",
            "lastSeenAt": "2026-07-02 08:30:00",
            "revokedAt": null
        }"#;

        let list: ListDevicesResponseBody =
            serde_json::from_str(&format!(r#"{{"devices":[{device_json}]}}"#))
                .expect("list envelope deserializes");
        assert_eq!(list.devices.len(), 1);
        assert_eq!(list.devices[0].id, "dev-1");

        let revoke: RevokeDeviceResponseBody =
            serde_json::from_str(&format!(r#"{{"device":{device_json}}}"#))
                .expect("revoke envelope deserializes");
        assert_eq!(revoke.device.id, "dev-1");
    }

    #[test]
    fn self_revoke_not_allowed_serializes_with_its_screaming_snake_code() {
        let value =
            serde_json::to_value(RelayClientError::SelfRevokeNotAllowed).expect("serialize");
        assert_eq!(
            value.get("code").unwrap().as_str().unwrap(),
            "SELF_REVOKE_NOT_ALLOWED"
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
