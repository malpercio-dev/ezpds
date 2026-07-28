// pattern: Mixed (Functional Core pin-store arithmetic; Imperative Shell commands + Keychain)
//
// The device half of the end-to-end-encrypted notification relay: the keys a Custos instance
// seals push payloads to, the registration that tells it where to send them, and the pinned
// sender-key set the Notification Service Extension verifies against.
//
//   register_for_notifications(did)         — POST /v1/notifications/register
//   refresh_notification_sender_keys(did)   — GET  /v1/notifications/sender-keys (the re-pin)
//   get_notification_diagnostics()          — what this device holds, for Settings
//
// Nothing here decrypts anything. The extension that does is a separate target (a later phase);
// this module's whole job is to leave the right material in the right Keychain slots under the
// right protection class, and to keep the pinned set fresh.
//
// # Why the material is device-global rather than per-DID
//
// A push arrives at the extension as `{v, kid, enc, ct}` and nothing else — no DID, no handle,
// no account hint, because naming one would hand the relay and Apple the metadata the whole
// design exists to withhold. So the recipient key cannot be per-identity: the extension would
// have no way to choose among several. One device, one notification keypair, one `device_uuid`;
// every identity on the device registers the same public key with its own host.
//
// # Why the pinned set is per-host anyway
//
// `kid` is an autoincrement column on *one* Custos instance. Two instances will both publish a
// `kid` of 1 for entirely unrelated keys, and this wallet routinely holds identities on more
// than one. So the pin store is a map from hosting server to that server's published set, and
// the extension tries every candidate key registered under the incoming `kid`. That costs
// nothing and cannot go wrong: HPKE Auth mode either authenticates against a given sender key
// or it does not, so a wrong candidate fails closed and the next is tried. A single flat set
// keyed by `kid` alone would instead have two instances silently overwriting each other.
//
// # Re-pinning is wholesale replacement
//
// A successful fetch replaces that host's entry entirely rather than merging into it. That one
// choice is what implements all three rotation semantics from the design: a new key appears, a
// retired key stays as long as the server keeps publishing it, and a *revoked* key vanishes from
// this device the first time it contacts its Custos. Merging would keep a compromised key
// pinned forever, which is precisely the window re-pin-on-every-contact exists to close.
//
// A failed fetch changes nothing. An instance that answers 501 has not revoked anything — it has
// switched the feature off, or was never configured — and a 503 means it could not read its own
// keys. Treating either as "revoke everything" would let one bad deploy strip the pins off every
// device that happened to check in during it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::identity_store::IdentityStore;
use crate::oauth_client::OAuthClient;
use crate::pds_client::PdsClient;
use crate::session_provider::{SessionError, SessionProvider, UnlockReason};

// ── Keychain accounts ────────────────────────────────────────────────────────

/// The device's stable notification identifier. App-generated and device-global: the server
/// keys registrations on `(did, device_uuid)` precisely because its own `devices` rows are
/// deleted at DID promotion, so this value must outlive every identity that uses it.
const DEVICE_UUID_ACCOUNT: &str = "notification-device-uuid";

/// The per-device P-256 notification private key (raw 32-byte scalar).
///
/// `AccessibleAfterFirstUnlock`, in the shared access group — the extension decrypts on a locked
/// screen and cannot present a biometric prompt. The relaxation is bounded: this key opens
/// notification *content* and signs nothing. It is not a rotation key, not a repo signing key,
/// and its loss costs unreadable banners, never an identity.
const NOTIFICATION_KEY_ACCOUNT: &str = "notification-key-priv";

/// The pinned sender-key sets, one per hosting server. Same protection class as the private
/// key: the extension needs both in the same moment, and a key it cannot read is a payload it
/// must render as unverified.
const PINNED_SENDER_KEYS_ACCOUNT: &str = "notification-sender-keys";

/// The APNs device token, lowercase hex. Ordinary protection — only the foreground app reads it,
/// to put it in a registration request.
const APNS_TOKEN_ACCOUNT: &str = "notification-apns-token";

/// Every account this module owns, so `keychain.rs`'s never-sync assertion is written against
/// the list rather than a copy of it — a new slot added here is covered without anyone
/// remembering to go and add it there too.
#[cfg(test)]
pub(crate) const NOTIFICATION_ACCOUNTS: &[&str] = &[
    DEVICE_UUID_ACCOUNT,
    NOTIFICATION_KEY_ACCOUNT,
    PINNED_SENDER_KEYS_ACCOUNT,
    APNS_TOKEN_ACCOUNT,
];

/// Version tag on the stored pin document, so a later shape change can be recognized rather
/// than mis-parsed.
const PIN_DOCUMENT_VERSION: u8 = 1;

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the notification commands.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }`, matching the sibling wallet error
/// enums. Note what is deliberately *absent*: there is no error for "this device has no APNs
/// token yet" or "this host does not do notifications". Both are ordinary states — a simulator
/// has no token, a claimed identity on bsky.social will never have a relay — and the commands
/// report them as outcomes, so onboarding has nothing to catch.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum NotificationsError {
    /// The identity's session could not be resolved without an unlock — the frontend's cue to
    /// run `unlockIdentity(did)` and retry.
    #[error("identity is locked and needs an unlock")]
    SessionLocked { reason: UnlockReason },
    /// The hosting PDS rate limited the request.
    #[error("rate limited")]
    RateLimited { retry_after: Option<String> },
    /// The DID is not registered in this wallet.
    #[error("identity not found: {message}")]
    IdentityNotFound { message: String },
    /// A notification key could not be generated.
    #[error("could not generate the notification key: {message}")]
    KeyGenerationFailed { message: String },
    /// The Keychain refused a read or a write.
    #[error("keychain error: {message}")]
    KeychainError { message: String },
    /// The hosting server refused for a non-connectivity reason. `status` is the HTTP code where
    /// there was one, and `None` for a session-lifecycle verdict that is not a transport failure.
    #[error("server error: {message}")]
    ServerError {
        status: Option<u16>,
        message: String,
    },
    /// A network / transport call failed.
    #[error("network error: {message}")]
    NetworkError { message: String },
}

/// Map a session-lifecycle failure onto this surface. Exhaustive on purpose: only a genuine
/// transport failure becomes `NetworkError`, so a server verdict or a Keychain fault is never
/// mislabelled "check your connection" (the same discipline as `app_passwords.rs`).
fn map_session_error(error: SessionError) -> NotificationsError {
    match error {
        SessionError::NeedsUnlock { reason } => NotificationsError::SessionLocked { reason },
        SessionError::RateLimited { retry_after } => {
            NotificationsError::RateLimited { retry_after }
        }
        SessionError::IdentityNotFound => NotificationsError::IdentityNotFound {
            message: "identity not found".to_string(),
        },
        SessionError::Offline { message } => NotificationsError::NetworkError { message },
        SessionError::ServerFailure { status } => NotificationsError::ServerError {
            status: Some(status),
            message: format!("session request failed with status {status}"),
        },
        SessionError::UnsupportedHost => NotificationsError::ServerError {
            status: None,
            message: "the identity's hosting server does not support session refresh".to_string(),
        },
        SessionError::Keychain { message } => NotificationsError::KeychainError { message },
        SessionError::InvalidResponse { message } => NotificationsError::ServerError {
            status: None,
            message: format!("invalid session response: {message}"),
        },
    }
}

fn keychain_err(e: crate::keychain::KeychainError) -> NotificationsError {
    NotificationsError::KeychainError {
        message: e.to_string(),
    }
}

// ── Wire + storage types ─────────────────────────────────────────────────────

/// One published sender key. Mirrors the server's `sender-keys` element exactly, so the
/// response deserializes straight into what gets pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SenderKey {
    /// The instance-scoped key id a sealed payload's envelope names.
    pub kid: i64,
    /// The P-256 `did:key` to verify the seal against.
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
struct SenderKeysResponse {
    keys: Vec<SenderKey>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterRequest<'a> {
    device_uuid: &'a str,
    notification_public_key: &'a str,
    apns_token: &'a str,
    apns_topic: &'a str,
}

/// The whole pin store: every hosting server this device has re-pinned against.
///
/// Read **fail-open** — an unreadable document is treated as empty. That is the opposite of
/// `ceremony-staging`'s fail-closed contract, and for the opposite reason: this holds public
/// keys the server will hand back on the next contact, so refusing to proceed would forfeit the
/// re-pin that repairs it in order to protect a copy of something already recoverable.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PinnedSenderKeys {
    version: u8,
    /// Hosting server (normalized by [`host_key`]) → that server's published set.
    hosts: BTreeMap<String, Vec<SenderKey>>,
}

/// Normalize a PDS base URL into a pin-store key, so `https://Pds.Example.com/` and
/// `https://pds.example.com` are one host. Same rule as `pds_capabilities`' cache key; kept
/// separate because that one is a process cache and this one is written to disk.
fn host_key(pds_url: &str) -> String {
    pds_url.trim().trim_end_matches('/').to_ascii_lowercase()
}

// ── Command results ──────────────────────────────────────────────────────────

/// What a registration attempt actually did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistrationStatus {
    /// The server stored the registration and is minting a relay handle for it.
    Registered,
    /// This device has no APNs token yet: the simulator never issues one, the user may not have
    /// granted permission, and even on a granted device the token arrives asynchronously after
    /// launch. Not a failure — the token-change callback re-registers when one shows up.
    AwaitingApnsToken,
    /// The identity's host serves no notification routes (it answered 501). A standard PDS
    /// always will, and so will a Custos whose operator configured no relay.
    Unsupported,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationOutcome {
    pub status: RegistrationStatus,
    /// The stable identifier this device registered under, echoed so the UI and the diagnostics
    /// export name the same thing the server row is keyed by.
    pub device_uuid: String,
    /// The device's notification `did:key`, or `None` when the attempt stopped before a key was
    /// needed.
    pub notification_key_id: Option<String>,
}

/// The outcome of a re-pin.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SenderKeyPinning {
    /// The host whose set was fetched (normalized).
    pub host: String,
    /// `true` when the server answered and the stored set was replaced; `false` when the host
    /// serves no notification routes and the stored set was left exactly as it was.
    pub pinned: bool,
    /// The set now pinned for this host — after a successful fetch, verbatim what the server
    /// published.
    pub keys: Vec<SenderKey>,
}

/// What this device holds, for the Settings diagnostics surface. Public keys and identifiers
/// only; the private scalar is reported as present, never returned.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationDiagnostics {
    pub device_uuid: Option<String>,
    pub notification_key_id: Option<String>,
    pub has_apns_token: bool,
    /// Pinned sender keys per host, newest-first as the server published them.
    pub pinned_hosts: BTreeMap<String, Vec<SenderKey>>,
}

// ── Device identity ──────────────────────────────────────────────────────────

/// The device's stable notification identifier, generated on first use.
///
/// Idempotent: every later call returns the same value, because the server's registration row is
/// keyed by it and a fresh one on each launch would accumulate a dead row (and a live relay
/// handle) per app start.
pub fn device_uuid() -> Result<String, NotificationsError> {
    match crate::keychain::get_item(DEVICE_UUID_ACCOUNT) {
        Ok(bytes) => {
            if let Ok(existing) = String::from_utf8(bytes) {
                if !existing.is_empty() {
                    return Ok(existing);
                }
            }
            // An unreadable identifier is not recoverable and not secret: mint a new one rather
            // than wedging registration forever. The stale server row ages out with the relay's
            // handle when APNs reports the token gone.
            tracing::warn!("notification device uuid is unreadable; minting a replacement");
            mint_device_uuid()
        }
        Err(e) if crate::keychain::is_not_found(&e) => mint_device_uuid(),
        Err(e) => Err(keychain_err(e)),
    }
}

/// Mint the device's identifier, **verifying it read back** before reporting it.
///
/// The same discipline the notification key and every Share 1 writer use, and for a sharper
/// reason here: a write that reports success without persisting is indistinguishable from never
/// having run, so the next launch mints another identifier and registers again — accumulating
/// exactly the dead row and live relay handle per app start that [`device_uuid`] exists to
/// prevent. Failing loudly costs one registration attempt; succeeding quietly costs one forever.
fn mint_device_uuid() -> Result<String, NotificationsError> {
    let uuid = uuid::Uuid::new_v4().to_string();
    crate::keychain::store_item(DEVICE_UUID_ACCOUNT, uuid.as_bytes()).map_err(keychain_err)?;
    match crate::keychain::get_item(DEVICE_UUID_ACCOUNT) {
        Ok(bytes) if bytes == uuid.as_bytes() => Ok(uuid),
        _ => Err(NotificationsError::KeychainError {
            message: "the device uuid did not read back after storing".to_string(),
        }),
    }
}

/// Load — or, on first use, generate — the device's notification keypair, returning its
/// `did:key`.
///
/// The private scalar is written under `AccessibleAfterFirstUnlock` and **read back before the
/// key is reported**, the same discipline every Share 1 writer uses. Here the failure it guards
/// is quiet by construction: a key the app believes it stored but the extension cannot find
/// turns every future notification into the unverified notice, with nothing anywhere saying why.
fn load_or_create_notification_key() -> Result<String, NotificationsError> {
    if let Some(scalar) = stored_notification_scalar()? {
        match crypto::p256_keypair_from_secret(&scalar) {
            Ok(keypair) => return Ok(keypair.key_id.0),
            // A stored 32-byte value that is not a valid scalar (zero, or past the curve order)
            // gets the same verdict as a wrong-length one: unreconstructable either way. Erroring
            // instead would refuse every future registration forever, since nothing else ever
            // overwrites this slot — and the only thing minting costs is payloads already sealed
            // to a key nobody can rebuild.
            Err(e) => tracing::warn!(
                error = %e,
                "stored notification key is unusable; minting a replacement"
            ),
        }
    }

    let keypair =
        crypto::generate_p256_keypair().map_err(|e| NotificationsError::KeyGenerationFailed {
            message: e.to_string(),
        })?;
    crate::keychain::store_item_after_first_unlock(
        NOTIFICATION_KEY_ACCOUNT,
        keypair.private_key_bytes.as_ref(),
    )
    .map_err(keychain_err)?;

    match stored_notification_scalar()? {
        Some(read_back) if read_back.as_ref() == keypair.private_key_bytes.as_ref() => {
            Ok(keypair.key_id.0)
        }
        _ => Err(NotificationsError::KeychainError {
            message: "the notification key did not read back after storing".to_string(),
        }),
    }
}

/// The stored notification private scalar, or `None` when none is stored.
///
/// A stored value of the wrong length is treated as absent so the caller mints a fresh key: the
/// only thing lost is the ability to open payloads sealed to a key nobody can reconstruct
/// anyway.
fn stored_notification_scalar() -> Result<Option<Zeroizing<[u8; 32]>>, NotificationsError> {
    match crate::keychain::get_item(NOTIFICATION_KEY_ACCOUNT) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(&bytes);
            Ok(Some(Zeroizing::new(scalar)))
        }
        Ok(_) => {
            tracing::warn!("notification key has an unexpected length; treating it as absent");
            Ok(None)
        }
        Err(e) if crate::keychain::is_not_found(&e) => Ok(None),
        Err(e) => Err(keychain_err(e)),
    }
}

// ── APNs token ───────────────────────────────────────────────────────────────

/// Record the APNs device token iOS handed us, reporting whether it actually changed.
///
/// Gated to iOS and tests because the only production caller is `apns.rs`, which iOS alone
/// compiles — the same shape `bg_backup.rs` uses for its scheduling payload.
///
/// `false` means the token is the one already stored, which is the common case: iOS delivers a
/// token on every launch, and re-registering every identity each time would spend a round trip
/// per identity per launch to write rows that already say this.
#[cfg(any(target_os = "ios", test))]
pub(crate) fn record_apns_token(token: &str) -> Result<bool, NotificationsError> {
    let token = token.to_ascii_lowercase();
    if stored_apns_token() == Some(token.clone()) {
        return Ok(false);
    }
    crate::keychain::store_item(APNS_TOKEN_ACCOUNT, token.as_bytes()).map_err(keychain_err)?;
    Ok(true)
}

/// The stored APNs device token, if this device has one.
fn stored_apns_token() -> Option<String> {
    match crate::keychain::get_item(APNS_TOKEN_ACCOUNT) {
        Ok(bytes) => String::from_utf8(bytes)
            .ok()
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty()),
        Err(e) if crate::keychain::is_not_found(&e) => None,
        Err(e) => {
            tracing::warn!(error = %e, "could not read the stored APNs token");
            None
        }
    }
}

/// Render a raw APNs device token into the lowercase hex the server validates.
///
/// Pure, so the iOS bridge's only untested part is getting the bytes out of `NSData`.
#[cfg(any(target_os = "ios", test))]
pub(crate) fn hex_encode_apns_token(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Pin store ────────────────────────────────────────────────────────────────

/// The pin store as it currently stands. Never fails: an unreadable document reads as empty
/// (see [`PinnedSenderKeys`]).
fn load_pins() -> PinnedSenderKeys {
    let raw = match crate::keychain::get_item(PINNED_SENDER_KEYS_ACCOUNT) {
        Ok(bytes) => bytes,
        Err(e) => {
            if !crate::keychain::is_not_found(&e) {
                tracing::warn!(error = %e, "could not read pinned sender keys; treating as empty");
            }
            return PinnedSenderKeys {
                version: PIN_DOCUMENT_VERSION,
                hosts: BTreeMap::new(),
            };
        }
    };
    match serde_json::from_slice::<PinnedSenderKeys>(&raw) {
        Ok(pins) if pins.version == PIN_DOCUMENT_VERSION => pins,
        Ok(pins) => {
            tracing::warn!(
                version = pins.version,
                "pinned sender keys were written by a different build; re-pinning from scratch"
            );
            PinnedSenderKeys {
                version: PIN_DOCUMENT_VERSION,
                hosts: BTreeMap::new(),
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "pinned sender keys are corrupt; re-pinning from scratch");
            PinnedSenderKeys {
                version: PIN_DOCUMENT_VERSION,
                hosts: BTreeMap::new(),
            }
        }
    }
}

/// Replace one host's pinned set, leaving every other host untouched.
///
/// Wholesale for the named host — that is the revocation mechanism — and surgical across hosts,
/// because a contact with one identity's Custos says nothing about another's.
/// One shared document means one writer at a time.
///
/// `+page.svelte` fires a registration per identity **without awaiting**, and each one re-pins on
/// the same contact, so two of these read-modify-writes genuinely overlap on Tauri's multi-thread
/// runtime. Losing the later write is not merely a stale entry: if the discarded pass was the
/// contact that dropped a *revoked* sender key, that host keeps trusting the revoked key until
/// its next contact — reopening the exact window the module header says re-pinning closes.
///
/// A `std::sync::Mutex` deliberately: the guard is taken and released entirely inside this
/// synchronous function and never crosses an `.await`.
static PIN_WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn store_pins_for_host(host: &str, keys: &[SenderKey]) -> Result<(), NotificationsError> {
    // A poisoned lock means some other thread panicked mid-write; the document is re-read below
    // either way, so recovering is strictly better than propagating the panic into a re-pin.
    let _guard = PIN_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut pins = load_pins();
    pins.version = PIN_DOCUMENT_VERSION;
    pins.hosts.insert(host.to_string(), keys.to_vec());

    let encoded = serde_json::to_vec(&pins).map_err(|e| NotificationsError::KeychainError {
        message: format!("could not encode pinned sender keys: {e}"),
    })?;
    crate::keychain::store_item_after_first_unlock(PINNED_SENDER_KEYS_ACCOUNT, &encoded)
        .map_err(keychain_err)
}

// ── Network cores (testable against httpmock) ────────────────────────────────

fn oauth_err(e: crate::oauth::OAuthError) -> NotificationsError {
    NotificationsError::NetworkError {
        message: e.to_string(),
    }
}

/// `POST /v1/notifications/register`. `Ok(false)` is the host's 501 — it serves no notification
/// routes — which the caller reports as `Unsupported` rather than an error.
async fn register_impl(
    client: &OAuthClient,
    request: &RegisterRequest<'_>,
) -> Result<bool, NotificationsError> {
    let resp = client
        .post("/v1/notifications/register", request)
        .await
        .map_err(oauth_err)?;
    match resp.status().as_u16() {
        200 => Ok(true),
        501 => Ok(false),
        429 => Err(NotificationsError::RateLimited {
            retry_after: resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
        }),
        other => Err(NotificationsError::ServerError {
            status: Some(other),
            message: server_message(resp, "registration was refused").await,
        }),
    }
}

/// `GET /v1/notifications/sender-keys`. `Ok(None)` is the 501; every other non-200 is an error,
/// including the 503 an instance returns when it cannot read its own keys — pinning nothing on
/// that basis would leave the device silently unable to verify anything it later receives.
async fn fetch_sender_keys_impl(
    client: &OAuthClient,
) -> Result<Option<Vec<SenderKey>>, NotificationsError> {
    let resp = client
        .get("/v1/notifications/sender-keys")
        .await
        .map_err(oauth_err)?;
    match resp.status().as_u16() {
        200 => {
            let body: SenderKeysResponse =
                resp.json()
                    .await
                    .map_err(|e| NotificationsError::ServerError {
                        status: Some(200),
                        message: format!("could not parse the sender-key set: {e}"),
                    })?;
            Ok(Some(body.keys))
        }
        501 => Ok(None),
        429 => Err(NotificationsError::RateLimited {
            retry_after: resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
        }),
        other => Err(NotificationsError::ServerError {
            status: Some(other),
            message: server_message(resp, "the sender-key set is unavailable").await,
        }),
    }
}

/// The server's own error message where it sent one, so the screen shows the real reason instead
/// of a status code.
async fn server_message(resp: reqwest::Response, fallback: &str) -> String {
    #[derive(Deserialize)]
    struct Envelope {
        error: Option<Inner>,
    }
    #[derive(Deserialize)]
    struct Inner {
        message: Option<String>,
    }
    resp.json::<Envelope>()
        .await
        .ok()
        .and_then(|e| e.error)
        .and_then(|e| e.message)
        .unwrap_or_else(|| fallback.to_string())
}

/// Resolve the DID's full-access session (restore / refresh, or `SessionLocked`).
async fn full_access_session(
    pds_client: &PdsClient,
    did: &str,
) -> Result<crate::session_provider::ActiveSession, NotificationsError> {
    // Not `NetworkError`: an unreadable clock is a local fault, and this module's rule is that
    // only a transport failure may be reported as one — otherwise the screen offers connectivity
    // advice for a problem connectivity cannot fix.
    let now = crate::sovereign_session::unix_timestamp().map_err(|_| {
        NotificationsError::ServerError {
            status: None,
            message: "system clock is unavailable".to_string(),
        }
    })?;
    SessionProvider
        .full_access_client(pds_client, &IdentityStore, did, now)
        .await
        .map_err(map_session_error)
}

// ── Tauri commands ───────────────────────────────────────────────────────────

/// Tauri command: register this device for push on the identity's hosting Custos.
///
/// Called at onboarding completion (post-promotion, so the account exists and can be
/// authenticated) and again whenever the APNs token changes. Idempotent on the server, which
/// upserts on `(did, device_uuid)`, so a repeat is free — which is what lets the caller fire it
/// without tracking whether it already has.
#[tauri::command]
pub async fn register_for_notifications(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<RegistrationOutcome, NotificationsError> {
    // The topic is the app's own bundle identifier, read from the running configuration rather
    // than restated as a constant here — APNs routes on the identifier the binary was actually
    // built with, and a rename that missed a hardcoded copy would fail at the relay, one hop
    // away from anything that could explain it.
    register_identity(&app.config().identifier, state.pds_client(), &did).await
}

/// Register one identity, given the APNs topic and a PDS client.
///
/// Split out from the command because the APNs token-change callback re-registers every managed
/// identity from a context that has no Tauri `State` — and a second implementation of the same
/// sequence is exactly how the two would drift.
pub(crate) async fn register_identity(
    apns_topic: &str,
    pds_client: &PdsClient,
    did: &str,
) -> Result<RegistrationOutcome, NotificationsError> {
    let device_uuid = device_uuid()?;

    // Checked before the key is generated or the session resolved: with no token there is
    // nothing to register, and minting key material for a registration that cannot happen would
    // pin this device to a key its host has never heard of.
    let Some(apns_token) = stored_apns_token() else {
        return Ok(RegistrationOutcome {
            status: RegistrationStatus::AwaitingApnsToken,
            device_uuid,
            notification_key_id: None,
        });
    };

    let notification_key_id = load_or_create_notification_key()?;
    let session = full_access_session(pds_client, did).await?;

    let registered = register_impl(
        &session.client,
        &RegisterRequest {
            device_uuid: &device_uuid,
            notification_public_key: &notification_key_id,
            apns_token: &apns_token,
            apns_topic,
        },
    )
    .await?;

    // The same contact re-pins. The registration is the first moment this device could receive
    // anything from this host, so it is also the first moment it needs the keys to verify it.
    if registered {
        if let Err(e) = pin_sender_keys(&session.client, &session.pds_url).await {
            tracing::warn!(error = ?e, "registered for push but could not pin sender keys");
        }
    }

    Ok(RegistrationOutcome {
        status: if registered {
            RegistrationStatus::Registered
        } else {
            RegistrationStatus::Unsupported
        },
        device_uuid,
        notification_key_id: Some(notification_key_id),
    })
}

/// Re-register every managed identity, after the APNs token changed under us.
///
/// Per identity rather than once: the registration lives on each identity's own hosting Custos,
/// which may be a different server (or no Custos at all). Failures are logged and stepped over —
/// one identity whose host is unreachable must not cost the others their new token, and the next
/// contact retries anyway.
#[cfg(target_os = "ios")]
pub(crate) async fn re_register_every_identity(apns_topic: &str, pds_client: &PdsClient) {
    let dids = match IdentityStore.list_identities() {
        Ok(dids) => dids,
        Err(e) => {
            tracing::warn!(error = ?e, "could not list identities to re-register for push");
            return;
        }
    };
    for did in dids {
        match register_identity(apns_topic, pds_client, &did).await {
            Ok(outcome) => {
                tracing::info!(did = %did, status = ?outcome.status, "re-registered for push")
            }
            Err(e) => tracing::warn!(did = %did, error = ?e, "could not re-register for push"),
        }
    }
}

/// Tauri command: re-fetch and re-pin the identity's host's sender-key set.
///
/// The frontend calls this on every successful contact with a Custos. That cadence is the
/// design's compromise-window property, not housekeeping: a sender key the operator revokes
/// stops being trusted on this device at the next contact, and nothing shorter than that is
/// available without a channel the relay could interfere with.
#[tauri::command]
pub async fn refresh_notification_sender_keys(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<SenderKeyPinning, NotificationsError> {
    let session = full_access_session(state.pds_client(), &did).await?;
    pin_sender_keys(&session.client, &session.pds_url).await
}

/// Fetch and store one host's set. Shared by the re-pin command and the registration path.
async fn pin_sender_keys(
    client: &OAuthClient,
    pds_url: &str,
) -> Result<SenderKeyPinning, NotificationsError> {
    let host = host_key(pds_url);
    match fetch_sender_keys_impl(client).await? {
        Some(keys) => {
            store_pins_for_host(&host, &keys)?;
            Ok(SenderKeyPinning {
                host,
                pinned: true,
                keys,
            })
        }
        None => {
            let keys = load_pins().hosts.get(&host).cloned().unwrap_or_default();
            Ok(SenderKeyPinning {
                host,
                pinned: false,
                keys,
            })
        }
    }
}

/// Tauri command: what this device holds. Read-only, no network, no identity required — it is
/// the Settings answer to "why am I not getting notifications", and it must work in exactly the
/// states where nothing else does.
#[tauri::command]
pub fn get_notification_diagnostics() -> NotificationDiagnostics {
    NotificationDiagnostics {
        device_uuid: crate::keychain::get_item(DEVICE_UUID_ACCOUNT)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .filter(|s| !s.is_empty()),
        notification_key_id: stored_notification_scalar()
            .ok()
            .flatten()
            .and_then(|scalar| crypto::p256_keypair_from_secret(&scalar).ok())
            .map(|keypair| keypair.key_id.0),
        has_apns_token: stored_apns_token().is_some(),
        pinned_hosts: load_pins().hosts,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::Accessibility;

    fn key(kid: i64) -> SenderKey {
        SenderKey {
            kid,
            public_key: crypto::generate_p256_keypair().unwrap().key_id.0,
        }
    }

    // ── device identity ──

    #[test]
    fn the_device_uuid_is_minted_once_and_then_reused() {
        crate::keychain::clear_for_test();

        let first = device_uuid().unwrap();
        assert!(!first.is_empty());
        assert_eq!(
            device_uuid().unwrap(),
            first,
            "a second uuid would leave a dead server row and a live relay handle per launch"
        );
    }

    #[test]
    fn an_unreadable_device_uuid_is_replaced_rather_than_wedging_registration() {
        crate::keychain::clear_for_test();
        crate::keychain::store_item(DEVICE_UUID_ACCOUNT, b"").unwrap();

        let minted = device_uuid().unwrap();
        assert!(!minted.is_empty());
        assert_eq!(device_uuid().unwrap(), minted);
    }

    // ── the notification key ──

    #[test]
    fn the_notification_key_is_generated_once_under_the_locked_screen_class() {
        crate::keychain::clear_for_test();

        let key_id = load_or_create_notification_key().unwrap();
        assert!(key_id.starts_with("did:key:z"));
        crypto::p256_public_key_from_did_key(&key_id)
            .expect("the registered key must decode as P-256 — the server decodes it too");

        assert_eq!(
            crate::keychain::accessibility_of(NOTIFICATION_KEY_ACCOUNT),
            Some(Accessibility::AfterFirstUnlock),
            "the extension decrypts on a locked screen; WhenUnlocked would make it unreachable"
        );

        assert_eq!(
            load_or_create_notification_key().unwrap(),
            key_id,
            "a second keypair would orphan every payload already sealed to the first"
        );
    }

    #[test]
    fn a_wrong_length_stored_key_is_replaced_not_used() {
        crate::keychain::clear_for_test();
        crate::keychain::store_item_after_first_unlock(NOTIFICATION_KEY_ACCOUNT, b"too short")
            .unwrap();

        let key_id = load_or_create_notification_key().unwrap();
        crypto::p256_public_key_from_did_key(&key_id).expect("a usable key must replace it");
    }

    /// The wedge that erroring here would create: nothing else ever overwrites this slot, so a
    /// stored value of the right *length* but the wrong *value* would refuse every registration
    /// for the life of the install. It gets the same verdict as a wrong-length slot.
    #[test]
    fn a_right_length_but_invalid_stored_scalar_is_replaced_not_fatal() {
        for invalid in [
            // The zero scalar — 32 bytes, not a valid private key.
            [0u8; 32],
            // Past the curve order (all-ones is well above P-256's n).
            [0xffu8; 32],
        ] {
            crate::keychain::clear_for_test();
            assert!(
                crypto::p256_keypair_from_secret(&invalid).is_err(),
                "the fixture must actually be rejected by the curve, or this proves nothing"
            );
            crate::keychain::store_item_after_first_unlock(NOTIFICATION_KEY_ACCOUNT, &invalid)
                .unwrap();

            let key_id = load_or_create_notification_key()
                .expect("an unusable stored scalar must not wedge registration forever");
            crypto::p256_public_key_from_did_key(&key_id).expect("a usable key must replace it");

            // And the replacement is durable, so the next launch reuses it rather than minting
            // a third key.
            assert_eq!(load_or_create_notification_key().unwrap(), key_id);
        }
    }

    /// The identifier's whole contract is that it never changes, so a write that cannot be read
    /// back is reported rather than papered over — a silent failure would mint a fresh uuid every
    /// launch and leave a dead server row (and a live relay handle) behind each one.
    #[test]
    fn a_minted_uuid_is_verified_durable_before_it_is_reported() {
        crate::keychain::clear_for_test();

        let uuid = device_uuid().unwrap();
        assert_eq!(
            crate::keychain::get_item(DEVICE_UUID_ACCOUNT).unwrap(),
            uuid.as_bytes(),
            "the reported uuid must be the one actually in the slot"
        );
    }

    // ── the APNs token ──

    #[test]
    fn recording_the_apns_token_reports_only_real_changes() {
        crate::keychain::clear_for_test();

        assert!(
            record_apns_token("AABBCC").unwrap(),
            "first token is a change"
        );
        assert_eq!(stored_apns_token(), Some("aabbcc".to_string()));
        assert!(
            !record_apns_token("aabbcc").unwrap(),
            "iOS hands over a token every launch; re-registering each time is a wasted round \
             trip per identity"
        );
        assert!(
            record_apns_token("ddeeff").unwrap(),
            "a rotated token is a change"
        );
        assert_eq!(stored_apns_token(), Some("ddeeff".to_string()));
    }

    #[test]
    fn the_hex_token_matches_what_the_server_validates() {
        // The server rejects anything that is not ASCII hex (`validate_registration_fields`).
        let hex = hex_encode_apns_token(&[0x00, 0x0f, 0xa0, 0xff]);
        assert_eq!(hex, "000fa0ff");
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    // ── the pin store ──

    #[test]
    fn pinning_replaces_a_hosts_set_wholesale() {
        crate::keychain::clear_for_test();
        let host = "https://pds.example.com";

        let (retired, revoked, fresh) = (key(1), key(2), key(3));
        store_pins_for_host(host, &[retired.clone(), revoked.clone()]).unwrap();
        assert_eq!(load_pins().hosts[host], vec![retired.clone(), revoked]);

        // The server rotated: a new key appears, the retired one is still published, and the
        // revoked one is simply gone from the response.
        store_pins_for_host(host, &[fresh.clone(), retired.clone()]).unwrap();
        assert_eq!(
            load_pins().hosts[host],
            vec![fresh, retired],
            "a revoked key must vanish on the next contact, not linger through a merge"
        );
    }

    #[test]
    fn pinning_one_host_leaves_the_others_alone() {
        crate::keychain::clear_for_test();

        // Two instances both start their kid sequence at 1 — the reason the store is per host.
        let (a, b) = (key(1), key(1));
        store_pins_for_host("https://a.example.com", std::slice::from_ref(&a)).unwrap();
        store_pins_for_host("https://b.example.com", std::slice::from_ref(&b)).unwrap();

        let pins = load_pins();
        assert_eq!(pins.hosts["https://a.example.com"], vec![a]);
        assert_eq!(pins.hosts["https://b.example.com"], vec![b]);

        store_pins_for_host("https://a.example.com", &[]).unwrap();
        let pins = load_pins();
        assert!(pins.hosts["https://a.example.com"].is_empty());
        assert_eq!(
            pins.hosts["https://b.example.com"].len(),
            1,
            "contacting one identity's Custos says nothing about another's"
        );
    }

    #[test]
    fn one_host_is_one_entry_however_its_url_is_spelled() {
        crate::keychain::clear_for_test();

        store_pins_for_host(&host_key("https://Pds.Example.com/"), &[key(1)]).unwrap();
        store_pins_for_host(&host_key("https://pds.example.com"), &[key(2), key(3)]).unwrap();

        let pins = load_pins();
        assert_eq!(pins.hosts.len(), 1, "spelling must not fork the pin store");
        assert_eq!(pins.hosts["https://pds.example.com"].len(), 2);
    }

    #[test]
    fn the_pinned_set_carries_the_locked_screen_class() {
        crate::keychain::clear_for_test();
        store_pins_for_host("https://pds.example.com", &[key(1)]).unwrap();

        assert_eq!(
            crate::keychain::accessibility_of(PINNED_SENDER_KEYS_ACCOUNT),
            Some(Accessibility::AfterFirstUnlock),
            "a key the extension cannot read is a payload it must call unverified"
        );
    }

    /// Fail-open, deliberately: the pins are public keys the server hands back on the next
    /// contact, so refusing to read them would forfeit the very re-pin that repairs them.
    #[test]
    fn a_corrupt_pin_document_reads_as_empty_and_is_repaired_by_the_next_pin() {
        crate::keychain::clear_for_test();
        crate::keychain::store_item_after_first_unlock(
            PINNED_SENDER_KEYS_ACCOUNT,
            b"{not json at all",
        )
        .unwrap();

        assert!(load_pins().hosts.is_empty());

        let fresh = key(7);
        store_pins_for_host("https://pds.example.com", std::slice::from_ref(&fresh)).unwrap();
        assert_eq!(load_pins().hosts["https://pds.example.com"], vec![fresh]);
    }

    #[test]
    fn a_pin_document_from_another_version_is_discarded_rather_than_misread() {
        crate::keychain::clear_for_test();
        crate::keychain::store_item_after_first_unlock(
            PINNED_SENDER_KEYS_ACCOUNT,
            br#"{"version":99,"hosts":{"https://pds.example.com":[{"kid":1,"publicKey":"x"}]}}"#,
        )
        .unwrap();

        assert!(load_pins().hosts.is_empty());
    }

    // ── diagnostics ──

    #[test]
    fn diagnostics_report_a_bare_device_without_inventing_state() {
        crate::keychain::clear_for_test();

        let empty = get_notification_diagnostics();
        assert_eq!(empty.device_uuid, None);
        assert_eq!(empty.notification_key_id, None);
        assert!(!empty.has_apns_token);
        assert!(empty.pinned_hosts.is_empty());
    }

    #[test]
    fn diagnostics_report_the_public_half_only() {
        crate::keychain::clear_for_test();
        let uuid = device_uuid().unwrap();
        let key_id = load_or_create_notification_key().unwrap();
        record_apns_token("abcdef").unwrap();
        store_pins_for_host("https://pds.example.com", &[key(1)]).unwrap();

        let diagnostics = get_notification_diagnostics();
        assert_eq!(diagnostics.device_uuid, Some(uuid));
        assert_eq!(diagnostics.notification_key_id, Some(key_id));
        assert!(diagnostics.has_apns_token);
        assert_eq!(diagnostics.pinned_hosts["https://pds.example.com"].len(), 1);

        let json = serde_json::to_string(&diagnostics).unwrap();
        assert!(
            !json.contains("privateKey") && !json.contains("abcdef"),
            "diagnostics are shareable; neither the scalar nor the raw APNs token may ride along"
        );
    }

    // ── error mapping ──

    #[test]
    fn needs_unlock_maps_to_session_locked() {
        assert!(matches!(
            map_session_error(SessionError::NeedsUnlock {
                reason: UnlockReason::NoRefreshChain
            }),
            NotificationsError::SessionLocked {
                reason: UnlockReason::NoRefreshChain
            }
        ));
    }

    /// Only a transport failure is a network error — the discipline `classify_xrpc_error` exists
    /// to enforce, restated here because a mislabelled cause is undiagnosable from the screen.
    #[test]
    fn session_verdicts_keep_their_nature() {
        assert!(matches!(
            map_session_error(SessionError::Offline {
                message: "timeout".to_string()
            }),
            NotificationsError::NetworkError { .. }
        ));
        assert!(matches!(
            map_session_error(SessionError::ServerFailure { status: 503 }),
            NotificationsError::ServerError {
                status: Some(503),
                ..
            }
        ));
        assert!(matches!(
            map_session_error(SessionError::UnsupportedHost),
            NotificationsError::ServerError { status: None, .. }
        ));
        assert!(matches!(
            map_session_error(SessionError::Keychain {
                message: "no slot".to_string()
            }),
            NotificationsError::KeychainError { .. }
        ));
    }

    #[test]
    fn errors_serialize_as_screaming_snake_codes_with_camel_fields() {
        let json = serde_json::to_value(NotificationsError::SessionLocked {
            reason: UnlockReason::HostChanged,
        })
        .unwrap();
        assert_eq!(json["code"], "SESSION_LOCKED");
        assert_eq!(json["reason"], "HOST_CHANGED");

        let json = serde_json::to_value(NotificationsError::RateLimited {
            retry_after: Some("30".to_string()),
        })
        .unwrap();
        assert_eq!(json["code"], "RATE_LIMITED");
        assert_eq!(json["retryAfter"], "30");

        let json = serde_json::to_value(NotificationsError::ServerError {
            status: None,
            message: "unsupported host".to_string(),
        })
        .unwrap();
        assert_eq!(json["code"], "SERVER_ERROR");
        assert_eq!(json["status"], serde_json::Value::Null);
    }

    #[test]
    fn outcomes_serialize_as_the_frontend_union() {
        let json = serde_json::to_value(RegistrationOutcome {
            status: RegistrationStatus::AwaitingApnsToken,
            device_uuid: "uuid".to_string(),
            notification_key_id: None,
        })
        .unwrap();
        assert_eq!(json["status"], "AWAITING_APNS_TOKEN");
        assert_eq!(json["deviceUuid"], "uuid");
        assert_eq!(json["notificationKeyId"], serde_json::Value::Null);

        let json = serde_json::to_value(SenderKeyPinning {
            host: "https://pds.example.com".to_string(),
            pinned: false,
            keys: vec![],
        })
        .unwrap();
        assert_eq!(json["pinned"], false);
    }

    // ── the network cores, against a mock host ──

    /// A Bearer client pointed at the mock server, carrying a far-future access token so no
    /// refresh fires ahead of the request under test (the `agents.rs` test-client shape).
    fn mock_client(base_url: &str) -> OAuthClient {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp}}}"#).as_bytes());

        OAuthClient::new_bearer(
            format!("{header}.{payload}.sig"),
            "refresh".to_string(),
            base_url.to_string(),
        )
        .expect("new_bearer must succeed")
    }

    #[tokio::test]
    async fn registration_sends_exactly_what_the_server_validates() {
        let server = httpmock::MockServer::start();
        let key_id = crypto::generate_p256_keypair().unwrap().key_id.0;

        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/v1/notifications/register")
                .json_body(serde_json::json!({
                    "deviceUuid": "device-1",
                    "notificationPublicKey": key_id,
                    "apnsToken": "aabbcc",
                    "apnsTopic": "dev.malpercio.identitywallet",
                }));
            then.status(200)
                .json_body(serde_json::json!({ "status": "pending" }));
        });

        let registered = register_impl(
            &mock_client(&server.base_url()),
            &RegisterRequest {
                device_uuid: "device-1",
                notification_public_key: &key_id,
                apns_token: "aabbcc",
                apns_topic: "dev.malpercio.identitywallet",
            },
        )
        .await
        .unwrap();

        assert!(registered);
        mock.assert();
    }

    /// A host with no relay configured is the ordinary case for a claimed identity elsewhere.
    /// It must not surface as a failure the onboarding screen has to explain.
    #[tokio::test]
    async fn a_host_without_notifications_is_reported_not_raised() {
        let server = httpmock::MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/v1/notifications/register");
            then.status(501);
        });

        let registered = register_impl(
            &mock_client(&server.base_url()),
            &RegisterRequest {
                device_uuid: "device-1",
                notification_public_key: "did:key:zdummy",
                apns_token: "aabbcc",
                apns_topic: "dev.malpercio.identitywallet",
            },
        )
        .await
        .unwrap();
        assert!(!registered);
    }

    #[tokio::test]
    async fn a_refused_registration_keeps_the_servers_own_reason() {
        let server = httpmock::MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/v1/notifications/register");
            then.status(400).json_body(serde_json::json!({
                "error": { "message": "apnsToken must be hexadecimal" }
            }));
        });

        let err = register_impl(
            &mock_client(&server.base_url()),
            &RegisterRequest {
                device_uuid: "device-1",
                notification_public_key: "did:key:zdummy",
                apns_token: "not hex!",
                apns_topic: "dev.malpercio.identitywallet",
            },
        )
        .await
        .unwrap_err();

        match err {
            NotificationsError::ServerError { status, message } => {
                assert_eq!(status, Some(400));
                assert_eq!(message, "apnsToken must be hexadecimal");
            }
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_fetched_set_replaces_the_pinned_one() {
        crate::keychain::clear_for_test();
        let server = httpmock::MockServer::start();
        let stale = key(1);
        store_pins_for_host(&host_key(&server.base_url()), std::slice::from_ref(&stale)).unwrap();

        let published = key(2);
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/v1/notifications/sender-keys");
            then.status(200).json_body(serde_json::json!({
                "keys": [{ "kid": published.kid, "publicKey": published.public_key }]
            }));
        });

        let pinning = pin_sender_keys(&mock_client(&server.base_url()), &server.base_url())
            .await
            .unwrap();

        assert!(pinning.pinned);
        assert_eq!(pinning.keys, vec![published.clone()]);
        assert_eq!(
            load_pins().hosts[&host_key(&server.base_url())],
            vec![published],
            "the key the server stopped publishing is the one it revoked"
        );
    }

    /// A host that switched notifications off has not revoked anything. Clearing the pins on a
    /// 501 would let one misconfigured deploy strip every device that checked in during it.
    #[tokio::test]
    async fn a_501_leaves_the_pinned_set_exactly_as_it_was() {
        crate::keychain::clear_for_test();
        let server = httpmock::MockServer::start();
        let pinned = key(5);
        store_pins_for_host(&host_key(&server.base_url()), std::slice::from_ref(&pinned)).unwrap();

        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/v1/notifications/sender-keys");
            then.status(501);
        });

        let pinning = pin_sender_keys(&mock_client(&server.base_url()), &server.base_url())
            .await
            .unwrap();

        assert!(!pinning.pinned);
        assert_eq!(pinning.keys, vec![pinned.clone()]);
        assert_eq!(
            load_pins().hosts[&host_key(&server.base_url())],
            vec![pinned]
        );
    }

    /// The 503 an instance returns when it cannot unwrap its own keys is an error, not an empty
    /// set: pinning nothing would leave this device unable to verify anything, with no signal.
    #[tokio::test]
    async fn an_unusable_key_set_is_an_error_and_changes_nothing() {
        crate::keychain::clear_for_test();
        let server = httpmock::MockServer::start();
        let pinned = key(5);
        store_pins_for_host(&host_key(&server.base_url()), std::slice::from_ref(&pinned)).unwrap();

        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/v1/notifications/sender-keys");
            then.status(503).json_body(serde_json::json!({
                "error": { "message": "no usable notification sender key is available" }
            }));
        });

        let err = pin_sender_keys(&mock_client(&server.base_url()), &server.base_url())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            NotificationsError::ServerError {
                status: Some(503),
                ..
            }
        ));
        assert_eq!(
            load_pins().hosts[&host_key(&server.base_url())],
            vec![pinned]
        );
    }
}
