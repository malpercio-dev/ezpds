// pattern: Imperative Shell
//
// Gathers: a selected DID's persisted `oauth-tokens` record, current DID discovery,
//          and a per-DID coalescing lock
// Processes: restore a still-valid session, or rotate a near-expiry one via
//            `com.atproto.server.refreshSession` and atomically persist the new pair
// Returns: a ready full-access Bearer client, or a typed lifecycle error whose
//          `NEEDS_UNLOCK` variant hands off to the biometric sovereign login

//! Per-DID full-access session lifecycle.
//!
//! [`SessionProvider::full_access_client`] is the seam every authenticated wallet
//! operation on a Custos-hosted identity goes through. It replaces the single
//! global in-memory `oauth_session` with an on-demand, per-DID resolver:
//!
//! 1. Load the selected DID's versioned [`SovereignTokenRecord`].
//! 2. If the access JWT is still valid, hand back a Bearer client directly — no
//!    network, so a restart (or an offline launch) with a live token needs no prompt.
//! 3. If it is expired/near-expiry but the refresh chain is alive, confirm the DID
//!    still resolves to the same host, then rotate exactly once via
//!    `refreshSession` and atomically persist the returned pair.
//! 4. If no usable refresh chain remains, return [`SessionError::NeedsUnlock`] — the
//!    frontend surfaces a passwordless "Unlock identity" action that runs the
//!    biometric-gated [`crate::sovereign_session::sovereign_login`].
//!
//! Concurrent callers for one DID coalesce behind a per-DID async lock: the first
//! rotates and persists, later callers re-read the freshly-stored record and reuse
//! it, so a refresh token can never be raced into replay detection.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::identity_store::{IdentityStore, IdentityStoreError, SovereignTokenRecord};
use crate::oauth_client::OAuthClient;
use crate::pds_client::{PdsClient, PdsClientError};
use crate::sovereign_session::{audience_matches_server, bearer_jwt_claims};

/// Seconds of headroom before an access token's `exp` at which it is treated as
/// already stale and proactively rotated. Covers clock skew plus the duration of
/// the operation the caller is about to perform, so a token cannot expire mid-flight.
const ACCESS_REFRESH_MARGIN_SECS: i64 = 120;

/// Why a managed identity cannot produce a full-access client without a passwordless
/// unlock (a fresh device-key sovereign login).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnlockReason {
    /// No token record exists, the refresh token has itself expired, or the stored
    /// record is unusable (malformed or bound to another DID/host).
    NoRefreshChain,
    /// The hosting server rejected the refresh token (revoked/replayed). The dead
    /// record has been discarded.
    RefreshRevoked,
    /// The DID now resolves to a different PDS than the stored credentials' audience.
    /// The old-audience record has been discarded.
    HostChanged,
}

/// Outcome of trying to obtain a full-access client for a managed DID.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }` to match `OAuthError` /
/// `IdentityStoreError` / `SovereignLoginError`. Each variant is a distinct terminal
/// classification — the provider never loops refresh/login retries.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum SessionError {
    #[error("identity not found")]
    IdentityNotFound,
    #[error("identity is locked and needs a passwordless unlock")]
    NeedsUnlock { reason: UnlockReason },
    #[error("the hosting server rate limited the refresh")]
    RateLimited { retry_after: Option<String> },
    #[error("the identity's hosting server does not support session refresh")]
    UnsupportedHost,
    #[error("offline or transport failure: {message}")]
    Offline { message: String },
    #[error("hosting server failure: {status}")]
    ServerFailure { status: u16 },
    #[error("keychain failure: {message}")]
    Keychain { message: String },
    #[error("invalid session response: {message}")]
    InvalidResponse { message: String },
}

/// A resolved, ready-to-use full-access session for one managed DID.
///
/// `client` is the authenticated XRPC vehicle for the downstream operation; the
/// summary fields let a thin Tauri command report status to the frontend without
/// exposing the client across the IPC boundary.
pub struct ActiveSession {
    pub client: OAuthClient,
    pub did: String,
    pub pds_url: String,
    pub access_expires_at: u64,
    pub refresh_expires_at: Option<u64>,
    /// `true` if this call rotated an expired/near-expiry pair; `false` on the
    /// still-valid fast path. Surfaced for observability, not authorization.
    pub rotated: bool,
}

/// Serializable session status for the frontend pre-flight (`ensure_identity_session`).
/// Drops the `OAuthClient`, which cannot cross the IPC boundary.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionReady {
    pub did: String,
    pub pds_url: String,
    pub access_expires_at: u64,
    pub refresh_expires_at: Option<u64>,
    pub rotated: bool,
}

impl From<&ActiveSession> for SessionReady {
    fn from(session: &ActiveSession) -> Self {
        Self {
            did: session.did.clone(),
            pds_url: session.pds_url.clone(),
            access_expires_at: session.access_expires_at,
            refresh_expires_at: session.refresh_expires_at,
            rotated: session.rotated,
        }
    }
}

/// Bearer-mode rotation response from `com.atproto.server.refreshSession`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefreshSessionResponse {
    access_jwt: String,
    refresh_jwt: String,
    did: String,
}

/// Per-DID full-access session resolver.
///
/// Zero-sized, like [`IdentityStore`]: its only state is a process-global registry
/// of per-DID coalescing locks, so it is cheap to construct anywhere a resolve is
/// needed (Tauri commands, downstream operation modules, tests).
#[derive(Default)]
pub struct SessionProvider;

/// Return the coalescing lock for a DID, creating it on first use.
///
/// Different DIDs get independent locks (their sessions resolve concurrently); every
/// caller for one DID shares a single `tokio::Mutex`, held across the refresh await
/// so only one rotation is ever in flight. The registry map is guarded by a std
/// mutex held only long enough to clone the `Arc` — never across an await.
fn did_lock(did: &str) -> Arc<tokio::sync::Mutex<()>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
        OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = registry.lock().unwrap();
    map.entry(did.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

fn map_store_error(error: IdentityStoreError) -> SessionError {
    match error {
        IdentityStoreError::IdentityNotFound => SessionError::IdentityNotFound,
        IdentityStoreError::KeychainError { message } => SessionError::Keychain { message },
        other => SessionError::Keychain {
            message: other.to_string(),
        },
    }
}

/// Map a DID-discovery failure to a session-lifecycle error. A transport failure
/// (offline, PDS unreachable) is [`SessionError::Offline`]; a resolution failure
/// (DID or PDS metadata absent) is [`SessionError::UnsupportedHost`].
fn map_discovery_error(error: PdsClientError) -> SessionError {
    match error {
        PdsClientError::PdsUnreachable { reason } => SessionError::Offline { message: reason },
        PdsClientError::NetworkError { message } => SessionError::Offline { message },
        PdsClientError::DidNotFound | PdsClientError::InvalidResponse { .. } => {
            SessionError::UnsupportedHost
        }
        other => SessionError::Offline {
            message: other.to_string(),
        },
    }
}

/// Whether two PDS URLs identify the same host (trailing slash is not significant).
fn pds_urls_match(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

impl SessionProvider {
    /// Obtain a ready full-access client for `did`, refreshing or reporting a needed
    /// unlock as required. `now` is the current Unix time in seconds (injected so the
    /// expiry ladder is deterministic in tests).
    ///
    /// The entire decision runs under the DID's coalescing lock, and the token record
    /// is re-read *inside* the lock so a caller that waited on an in-flight rotation
    /// observes the freshly-persisted pair instead of racing a second refresh.
    pub async fn full_access_client(
        &self,
        pds_client: &PdsClient,
        store: &IdentityStore,
        did: &str,
        now: i64,
    ) -> Result<ActiveSession, SessionError> {
        let lock = did_lock(did);
        let _guard = lock.lock().await;

        let Some(record) = store.load_oauth_tokens(did).map_err(map_store_error)? else {
            return Err(SessionError::NeedsUnlock {
                reason: UnlockReason::NoRefreshChain,
            });
        };

        // The stored access JWT must be readable and bound to this DID + host, or the
        // record is corrupt/foreign and only a fresh mint can recover it.
        let Some(access) = bearer_jwt_claims(&record.access_jwt) else {
            store.delete_oauth_tokens(did).map_err(map_store_error)?;
            return Err(SessionError::NeedsUnlock {
                reason: UnlockReason::NoRefreshChain,
            });
        };
        if access.sub != did
            || !audience_matches_server(&access.aud, &record.server_did, &record.pds_url)
        {
            store.delete_oauth_tokens(did).map_err(map_store_error)?;
            return Err(SessionError::NeedsUnlock {
                reason: UnlockReason::NoRefreshChain,
            });
        }

        // Fast path: a still-valid access token is usable directly — no discovery, no
        // network — which is what lets a restart (or an offline launch) skip the prompt.
        if (access.exp as i64) > now + ACCESS_REFRESH_MARGIN_SECS {
            return active_session_from_record(did, record, false);
        }

        // Rotation is needed. Without a live refresh token there is no chain to rotate.
        let refresh_exp = record
            .refresh_expires_at
            .or_else(|| bearer_jwt_claims(&record.refresh_jwt).map(|c| c.exp));
        if refresh_exp.is_none_or(|exp| (exp as i64) <= now) {
            return Err(SessionError::NeedsUnlock {
                reason: UnlockReason::NoRefreshChain,
            });
        }

        // Validate the DID still resolves to this record's host before sending the
        // refresh token — a migrated/changed host means the stored credential is for a
        // stale audience and must be discarded rather than presented.
        let (current_pds, _doc) = pds_client
            .discover_pds(did)
            .await
            .map_err(map_discovery_error)?;
        if !pds_urls_match(&current_pds, &record.pds_url) {
            store.delete_oauth_tokens(did).map_err(map_store_error)?;
            return Err(SessionError::NeedsUnlock {
                reason: UnlockReason::HostChanged,
            });
        }

        rotate_and_persist(pds_client, store, did, &record, now).await
    }
}

/// Tauri command: pre-flight a managed identity's full-access session for the UI.
///
/// Restores or rotates the selected DID's session and reports its status, discarding
/// the resolved client (an [`OAuthClient`] cannot cross the IPC boundary). The
/// frontend calls this when showing an identity so a `NEEDS_UNLOCK` result can render
/// the passwordless "Unlock identity" action before the user attempts an operation.
#[tauri::command]
pub async fn ensure_identity_session(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<SessionReady, SessionError> {
    let now =
        crate::sovereign_session::unix_timestamp().map_err(|_| SessionError::InvalidResponse {
            message: "system clock is unavailable".into(),
        })?;
    let session = SessionProvider
        .full_access_client(state.pds_client(), &IdentityStore, &did, now)
        .await?;
    Ok(SessionReady::from(&session))
}

/// Rebuild a Bearer [`OAuthClient`] plus its status summary from a token record.
/// Shared by the still-valid fast path and the post-rotation path.
fn active_session_from_record(
    did: &str,
    record: SovereignTokenRecord,
    rotated: bool,
) -> Result<ActiveSession, SessionError> {
    let access =
        bearer_jwt_claims(&record.access_jwt).ok_or_else(|| SessionError::InvalidResponse {
            message: "stored accessJwt is malformed".into(),
        })?;
    let client = OAuthClient::new_bearer(
        record.access_jwt.clone(),
        record.refresh_jwt.clone(),
        record.pds_url.clone(),
    )
    .map_err(|e| SessionError::Keychain {
        message: e.to_string(),
    })?;
    Ok(ActiveSession {
        client,
        did: did.to_string(),
        pds_url: record.pds_url,
        access_expires_at: access.exp,
        refresh_expires_at: record.refresh_expires_at,
        rotated,
    })
}

/// Rotate a near-expiry pair via `com.atproto.server.refreshSession` and atomically
/// persist the returned pair. Exactly one network attempt — no retry loop.
async fn rotate_and_persist(
    pds_client: &PdsClient,
    store: &IdentityStore,
    did: &str,
    record: &SovereignTokenRecord,
    now: i64,
) -> Result<ActiveSession, SessionError> {
    let url = format!(
        "{}/xrpc/com.atproto.server.refreshSession",
        record.pds_url.trim_end_matches('/')
    );
    let response = pds_client
        .client()
        .post(url)
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", record.refresh_jwt),
        )
        .send()
        .await
        .map_err(|e| SessionError::Offline {
            message: e.to_string(),
        })?;

    let status = response.status();
    if !status.is_success() {
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        return Err(classify_refresh_failure(
            status.as_u16(),
            retry_after,
            store,
            did,
        )?);
    }

    let refreshed: RefreshSessionResponse =
        response
            .json()
            .await
            .map_err(|e| SessionError::InvalidResponse {
                message: e.to_string(),
            })?;

    // Bind the rotated pair to the same DID and hosting server the record was minted
    // for — a rotation must never silently re-audience the session.
    if refreshed.did != did {
        return Err(SessionError::InvalidResponse {
            message: "refreshSession returned a different DID".into(),
        });
    }
    let access =
        bearer_jwt_claims(&refreshed.access_jwt).ok_or_else(|| SessionError::InvalidResponse {
            message: "rotated accessJwt is missing valid claims".into(),
        })?;
    let refresh =
        bearer_jwt_claims(&refreshed.refresh_jwt).ok_or_else(|| SessionError::InvalidResponse {
            message: "rotated refreshJwt is missing valid claims".into(),
        })?;
    if access.sub != did || refresh.sub != did {
        return Err(SessionError::InvalidResponse {
            message: "rotated tokens are bound to a different DID".into(),
        });
    }
    if !audience_matches_server(&access.aud, &record.server_did, &record.pds_url)
        || !audience_matches_server(&refresh.aud, &record.server_did, &record.pds_url)
    {
        return Err(SessionError::InvalidResponse {
            message: "rotated tokens are bound to a different host".into(),
        });
    }

    let stored_at = u64::try_from(now).map_err(|_| SessionError::InvalidResponse {
        message: "negative timestamp cannot be persisted".into(),
    })?;
    let new_record = SovereignTokenRecord {
        version: SovereignTokenRecord::VERSION,
        access_jwt: refreshed.access_jwt,
        refresh_jwt: refreshed.refresh_jwt,
        pds_url: record.pds_url.clone(),
        server_did: record.server_did.clone(),
        access_expires_at: Some(access.exp),
        refresh_expires_at: Some(refresh.exp),
        stored_at,
    };
    store
        .store_oauth_tokens(did, &new_record)
        .map_err(map_store_error)?;

    active_session_from_record(did, new_record, true)
}

/// Classify a non-success `refreshSession` response into a distinct terminal error.
///
/// A rejected refresh token (400/401) is revoked/replayed — the dead record is
/// discarded and the identity falls back to a passwordless unlock. Rate limiting,
/// an unsupported host, and other server failures each stay recognizable so the UI
/// (and downstream callers) never collapse them into one another. Returns `Err` only
/// if discarding the dead record itself fails.
fn classify_refresh_failure(
    status: u16,
    retry_after: Option<String>,
    store: &IdentityStore,
    did: &str,
) -> Result<SessionError, SessionError> {
    Ok(match status {
        400 | 401 => {
            store.delete_oauth_tokens(did).map_err(map_store_error)?;
            SessionError::NeedsUnlock {
                reason: UnlockReason::RefreshRevoked,
            }
        }
        404 | 405 => SessionError::UnsupportedHost,
        429 => SessionError::RateLimited { retry_after },
        other => SessionError::ServerFailure { status: other },
    })
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use httpmock::{Method::GET, Method::HEAD, Method::POST, Mock, MockServer};
    use serde_json::json;

    use super::*;

    const DID: &str = "did:plc:abcdefghijklmnopqrstuvwx";
    const OTHER_DID: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
    const SERVER_DID: &str = "did:web:pds.example.com";

    /// Build an unsigned Bearer JWT carrying the given `exp`/`sub`/`aud` claims.
    fn jwt(exp: i64, sub: &str, aud: &str) -> String {
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({ "exp": exp, "sub": sub, "aud": aud })).unwrap());
        format!("e30.{payload}.sig")
    }

    fn record_for(
        access_exp: i64,
        refresh_exp: i64,
        pds_url: &str,
        server_did: &str,
    ) -> SovereignTokenRecord {
        SovereignTokenRecord {
            version: SovereignTokenRecord::VERSION,
            access_jwt: jwt(access_exp, DID, server_did),
            refresh_jwt: jwt(refresh_exp, DID, server_did),
            pds_url: pds_url.into(),
            server_did: server_did.into(),
            access_expires_at: Some(access_exp as u64),
            refresh_expires_at: Some(refresh_exp as u64),
            stored_at: 1_000,
        }
    }

    /// Register `did` fresh and store `record` under it. Clears the (thread-local test)
    /// Keychain first so scenarios do not bleed into one another.
    fn seed(did: &str, record: &SovereignTokenRecord) {
        crate::keychain::clear_for_test();
        IdentityStore.add_identity(did).unwrap();
        IdentityStore.store_oauth_tokens(did, record).unwrap();
    }

    /// Mock the two calls `discover_pds` makes — the PLC document (pointing the PDS
    /// service at `pds_base`) and the reachability HEAD.
    async fn discovery_mocks<'a>(server: &'a MockServer, did: &str, pds_base: &str) -> Mock<'a> {
        let did_path = format!("/{did}");
        let pds_base = pds_base.to_string();
        let did_owned = did.to_string();
        let plc = server
            .mock_async(move |when, then| {
                when.method(GET).path(did_path);
                then.status(200).json_body(json!({
                    "id": did_owned,
                    "alsoKnownAs": ["at://alice.example.com"],
                    "verificationMethod": [],
                    "service": [{
                        "id": "#atproto_pds",
                        "type": "AtprotoPersonalDataServer",
                        "serviceEndpoint": pds_base,
                    }],
                }));
            })
            .await;
        server
            .mock_async(|when, then| {
                when.method(HEAD).path("/");
                then.status(200);
            })
            .await;
        plc
    }

    fn now() -> i64 {
        1_720_000_000
    }

    // ── Restart: a still-valid access token needs no prompt and no network ─────────

    #[tokio::test]
    async fn valid_access_restores_without_network() {
        let record = record_for(
            now() + 3_600,
            now() + 86_400,
            "https://pds.example.com",
            SERVER_DID,
        );
        seed(DID, &record);

        // An unroutable plc.directory: reaching the network at all would error, so a
        // success proves the fast path never touched it.
        let client = PdsClient::new_for_test("http://127.0.0.1:9".into());
        let session = SessionProvider
            .full_access_client(&client, &IdentityStore, DID, now())
            .await
            .expect("valid access token restores");

        assert!(!session.rotated, "a valid token must not rotate");
        assert_eq!(session.pds_url, "https://pds.example.com");
        assert_eq!(session.access_expires_at, (now() + 3_600) as u64);
    }

    // ── Refresh rotation: one refresh, new pair persisted ─────────────────────────

    #[tokio::test]
    async fn expired_access_rotates_once_and_persists() {
        let server = MockServer::start_async().await;
        let record = record_for(now() - 10, now() + 86_400, &server.base_url(), SERVER_DID);
        seed(DID, &record);
        let _plc = discovery_mocks(&server, DID, &server.base_url()).await;
        let new_access = jwt(now() + 3_600, DID, SERVER_DID);
        let new_refresh = jwt(now() + 172_800, DID, SERVER_DID);
        // The rotation must present the *refresh* token as the Bearer credential.
        let expected_auth = format!("Bearer {}", jwt(now() + 86_400, DID, SERVER_DID));
        let refresh = server
            .mock_async({
                let new_access = new_access.clone();
                let new_refresh = new_refresh.clone();
                move |when, then| {
                    when.method(POST)
                        .path("/xrpc/com.atproto.server.refreshSession")
                        .header("Authorization", expected_auth.as_str());
                    then.status(200).json_body(json!({
                        "accessJwt": new_access,
                        "refreshJwt": new_refresh,
                        "did": DID,
                        "handle": "alice.example.com",
                    }));
                }
            })
            .await;

        let client = PdsClient::new_for_test(server.base_url());
        let session = SessionProvider
            .full_access_client(&client, &IdentityStore, DID, now())
            .await
            .expect("rotation succeeds");

        refresh.assert_async().await;
        assert!(session.rotated, "an expired token must rotate");
        assert_eq!(session.access_expires_at, (now() + 3_600) as u64);
        let stored = IdentityStore.load_oauth_tokens(DID).unwrap().unwrap();
        assert_eq!(stored.access_jwt, new_access, "new pair must be persisted");
        assert_eq!(stored.refresh_jwt, new_refresh);
        assert_eq!(stored.refresh_expires_at, Some((now() + 172_800) as u64));
    }

    // ── Concurrency: two callers coalesce into a single refresh ───────────────────

    #[tokio::test]
    async fn concurrent_callers_refresh_only_once() {
        let server = MockServer::start_async().await;
        let record = record_for(now() - 10, now() + 86_400, &server.base_url(), SERVER_DID);
        seed(DID, &record);
        let _plc = discovery_mocks(&server, DID, &server.base_url()).await;
        let refresh = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/xrpc/com.atproto.server.refreshSession");
                then.status(200).json_body(json!({
                    "accessJwt": jwt(now() + 3_600, DID, SERVER_DID),
                    "refreshJwt": jwt(now() + 172_800, DID, SERVER_DID),
                    "did": DID,
                }));
            })
            .await;

        let client = PdsClient::new_for_test(server.base_url());
        let (a, b) = tokio::join!(
            SessionProvider.full_access_client(&client, &IdentityStore, DID, now()),
            SessionProvider.full_access_client(&client, &IdentityStore, DID, now()),
        );

        assert!(a.is_ok() && b.is_ok(), "both callers get a session");
        assert_eq!(
            refresh.calls(),
            1,
            "the refresh token must be spent exactly once, never raced"
        );
    }

    // ── Host change: credentials for the old audience are discarded ───────────────

    #[tokio::test]
    async fn host_change_discards_credentials_and_needs_unlock() {
        let server = MockServer::start_async().await;
        // Stored host differs from where the DID now resolves (the mock server).
        let record = record_for(
            now() - 10,
            now() + 86_400,
            "https://old.example.com",
            SERVER_DID,
        );
        seed(DID, &record);
        let _plc = discovery_mocks(&server, DID, &server.base_url()).await;
        let refresh = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/xrpc/com.atproto.server.refreshSession");
                then.status(200).json_body(json!({ "did": DID }));
            })
            .await;

        let client = PdsClient::new_for_test(server.base_url());
        let result = SessionProvider
            .full_access_client(&client, &IdentityStore, DID, now())
            .await;

        assert!(matches!(
            result,
            Err(SessionError::NeedsUnlock {
                reason: UnlockReason::HostChanged
            })
        ));
        assert_eq!(
            refresh.calls(),
            0,
            "no refresh token is sent to the stale host"
        );
        assert_eq!(
            IdentityStore.load_oauth_tokens(DID).unwrap(),
            None,
            "the old-audience record must be discarded"
        );
    }

    // ── Revoked refresh: distinct classification, dead record discarded ───────────

    #[tokio::test]
    async fn revoked_refresh_needs_unlock_and_discards() {
        let server = MockServer::start_async().await;
        let record = record_for(now() - 10, now() + 86_400, &server.base_url(), SERVER_DID);
        seed(DID, &record);
        let _plc = discovery_mocks(&server, DID, &server.base_url()).await;
        let _refresh = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/xrpc/com.atproto.server.refreshSession");
                then.status(401)
                    .json_body(json!({ "error": "ExpiredToken" }));
            })
            .await;

        let client = PdsClient::new_for_test(server.base_url());
        let result = SessionProvider
            .full_access_client(&client, &IdentityStore, DID, now())
            .await;

        assert!(matches!(
            result,
            Err(SessionError::NeedsUnlock {
                reason: UnlockReason::RefreshRevoked
            })
        ));
        assert_eq!(IdentityStore.load_oauth_tokens(DID).unwrap(), None);
    }

    #[tokio::test]
    async fn rate_limited_refresh_is_distinct_and_keeps_record() {
        let server = MockServer::start_async().await;
        let record = record_for(now() - 10, now() + 86_400, &server.base_url(), SERVER_DID);
        seed(DID, &record);
        let _plc = discovery_mocks(&server, DID, &server.base_url()).await;
        let _refresh = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/xrpc/com.atproto.server.refreshSession");
                then.status(429).header("Retry-After", "30");
            })
            .await;

        let client = PdsClient::new_for_test(server.base_url());
        let result = SessionProvider
            .full_access_client(&client, &IdentityStore, DID, now())
            .await;

        assert!(matches!(
            result,
            Err(SessionError::RateLimited { retry_after: Some(v) }) if v == "30"
        ));
        assert!(
            IdentityStore.load_oauth_tokens(DID).unwrap().is_some(),
            "a rate limit must not discard a still-valid refresh chain"
        );
    }

    // ── Offline: transport failure stays distinct from a server verdict ───────────

    #[tokio::test]
    async fn offline_during_discovery_is_distinct() {
        let record = record_for(
            now() - 10,
            now() + 86_400,
            "https://pds.example.com",
            SERVER_DID,
        );
        seed(DID, &record);

        // Expired access forces the refresh path, but discovery cannot reach the network.
        let client = PdsClient::new_for_test("http://127.0.0.1:9".into());
        let result = SessionProvider
            .full_access_client(&client, &IdentityStore, DID, now())
            .await;

        assert!(matches!(result, Err(SessionError::Offline { .. })));
    }

    // ── Dead / missing chains need an unlock ──────────────────────────────────────

    #[tokio::test]
    async fn missing_record_needs_unlock() {
        crate::keychain::clear_for_test();
        IdentityStore.add_identity(DID).unwrap();

        let client = PdsClient::new_for_test("http://127.0.0.1:9".into());
        let result = SessionProvider
            .full_access_client(&client, &IdentityStore, DID, now())
            .await;

        assert!(matches!(
            result,
            Err(SessionError::NeedsUnlock {
                reason: UnlockReason::NoRefreshChain
            })
        ));
    }

    #[tokio::test]
    async fn expired_refresh_needs_unlock_without_network() {
        let record = record_for(
            now() - 100,
            now() - 10,
            "https://pds.example.com",
            SERVER_DID,
        );
        seed(DID, &record);

        // Unroutable plc.directory: reaching it would error, so a clean NeedsUnlock
        // proves the dead-chain short-circuit precedes any discovery.
        let client = PdsClient::new_for_test("http://127.0.0.1:9".into());
        let result = SessionProvider
            .full_access_client(&client, &IdentityStore, DID, now())
            .await;

        assert!(matches!(
            result,
            Err(SessionError::NeedsUnlock {
                reason: UnlockReason::NoRefreshChain
            })
        ));
    }

    // ── Multi-DID isolation: independent sessions, independent hosts ──────────────

    #[tokio::test]
    async fn two_identities_hold_independent_sessions() {
        crate::keychain::clear_for_test();
        let alice_record = record_for(
            now() + 3_600,
            now() + 86_400,
            "https://alice-pds.example.com",
            SERVER_DID,
        );
        let bob_record = record_for(
            now() + 3_600,
            now() + 86_400,
            "https://bob-pds.example.com",
            "did:web:bob.example.com",
        );
        IdentityStore.add_identity(DID).unwrap();
        IdentityStore.add_identity(OTHER_DID).unwrap();
        // record_for hardcodes DID as the subject; rebuild bob's tokens under its own DID.
        let bob_record = SovereignTokenRecord {
            access_jwt: jwt(now() + 3_600, OTHER_DID, "did:web:bob.example.com"),
            refresh_jwt: jwt(now() + 86_400, OTHER_DID, "did:web:bob.example.com"),
            ..bob_record
        };
        IdentityStore
            .store_oauth_tokens(DID, &alice_record)
            .unwrap();
        IdentityStore
            .store_oauth_tokens(OTHER_DID, &bob_record)
            .unwrap();

        let client = PdsClient::new_for_test("http://127.0.0.1:9".into());
        let alice = SessionProvider
            .full_access_client(&client, &IdentityStore, DID, now())
            .await
            .expect("alice restores");
        let bob = SessionProvider
            .full_access_client(&client, &IdentityStore, OTHER_DID, now())
            .await
            .expect("bob restores");

        assert_eq!(alice.pds_url, "https://alice-pds.example.com");
        assert_eq!(bob.pds_url, "https://bob-pds.example.com");
        assert_ne!(
            alice.pds_url, bob.pds_url,
            "each identity's session must stay bound to its own host"
        );
    }

    #[test]
    fn session_error_serializes_needs_unlock_with_reason() {
        let json = serde_json::to_string(&SessionError::NeedsUnlock {
            reason: UnlockReason::HostChanged,
        })
        .unwrap();
        assert!(json.contains(r#""code":"NEEDS_UNLOCK""#));
        assert!(json.contains(r#""reason":"HOST_CHANGED""#));
    }
}
