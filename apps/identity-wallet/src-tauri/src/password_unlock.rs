// pattern: Imperative Shell

//! The second resolution of [`crate::session_provider::SessionError::NeedsUnlock`].
//!
//! Every authenticated wallet operation goes through
//! [`SessionProvider::full_access_client`](crate::session_provider::SessionProvider::full_access_client),
//! which resolves a session from the DID's persisted `{did}:oauth-tokens` record. Until now
//! that record had exactly one origin: the biometric, passwordless
//! [`sovereign_login`](crate::sovereign_session::sovereign_login), which only a host
//! advertising `sovereignSessions` can serve. So a claimed identity hosted on bsky.social or
//! the reference PDS had no way to obtain one, and every feature built on that seam — app
//! passwords, change handle, identity removal, blob restore — was dark for it despite being
//! pure standard lexicon.
//!
//! This module supplies the missing origin. A password `createSession` (the machinery
//! [`crate::source_login`] already runs transiently for the claim and migration source logins)
//! produces the same full-access JWT pair, which is persisted into the **same** versioned
//! record. From that write on, the provider's ladder — restore, rotate via `refreshSession`,
//! discard on host change — owns the session and behaves identically regardless of which
//! unlock minted it. Nothing in `session_provider.rs` changes.
//!
//! Two postures carry over from the claim flow unchanged: the full session is required
//! because a `transition:generic` OAuth token cannot drive identity operations (ADR-0021),
//! and the password is used only in `createSession` requests (including the email-2FA
//! retry with `authFactorToken`) and never stored.
//!
//! [`get_identity_unlock_route`] decides which unlock a screen should offer
//! (`UnlockRoute { method, pdsUrl, handle }`, method `SOVEREIGN` | `PASSWORD`) by
//! discovering the DID's current host and reading `pds_capabilities::probe`. **An
//! unreached probe routes to `SOVEREIGN`, not `PASSWORD`**: `reached: false` means the
//! question could not be put to the host, and demanding a password on that basis would
//! both misstate a fact about the user's server and change behavior for every Custos
//! identity whose launch happens to be offline. That rule covers the capability probe
//! only: when `discover_pds` itself fails, no route can be answered at all and the
//! command surfaces the plain `NETWORK_ERROR`.
//! [`unlock_identity_with_password`] validates the returned pair's `sub`/`aud` against
//! this DID and host before persisting, and answers with the provider's `SessionReady`.
//!
//! Deliberately NOT biometric-gated: the password is itself the presence proof and
//! nothing here is device-key-signed; the irreversible operations a session unlocks
//! keep their own gates. [`UnlockError`] (IDENTITY_NOT_FOUND, UNSUPPORTED_HOST,
//! TWO_FACTOR_REQUIRED, INVALID_CREDENTIALS, ACCOUNT_MISMATCH, INSECURE_HOST_URL,
//! RATE_LIMITED, SERVER_ERROR, NETWORK_ERROR, KEYCHAIN, INVALID_RESPONSE) serializes
//! as `{ code: "SCREAMING_SNAKE_CASE" }` with camelCase fields.

use serde::Serialize;

use crate::identity_store::{IdentityStore, IdentityStoreError, SovereignTokenRecord};
use crate::pds_client::{PdsClient, PdsClientError};
use crate::session_provider::SessionReady;
use crate::source_login::{create_source_session, SourceLoginError};
use crate::sovereign_session::{audience_matches_server, bearer_jwt_claims};

/// How a given identity's host can turn a locked identity back into a live session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnlockMethod {
    /// The host advertises `sovereignSessions`: a device-key proof mints the session with no
    /// password, behind the biometric gate.
    Sovereign,
    /// The host serves only the standard lexicon: the account's password opens the session.
    Password,
}

/// Which unlock a screen should offer for one identity, plus what the prompt needs to say.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockRoute {
    pub method: UnlockMethod,
    /// The identity's current hosting PDS — named in the password prompt so the user knows
    /// whose password is being asked for.
    pub pds_url: String,
    /// The account's handle from its DID document, offered as the prefilled `identifier`.
    /// `None` when the document carries no `at://` alias; the DID itself is then the fallback
    /// identifier, which `createSession` accepts.
    pub handle: Option<String>,
}

/// Why a password unlock could not produce a session.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }` alongside `SessionError` /
/// `ClaimError` / `MigrationError`. The credential-shaped variants mirror the claim flow's,
/// because they are the same `createSession` failures seen from a different screen.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum UnlockError {
    #[error("identity not found")]
    IdentityNotFound,
    #[error("the identity's hosting server could not be resolved")]
    UnsupportedHost,
    /// The account has email two-factor enabled; the host has emailed a code and the caller
    /// re-invokes with `auth_factor_token`.
    #[error("a two-factor code is required")]
    TwoFactorRequired,
    #[error("the hosting server did not accept that password")]
    InvalidCredentials { message: String },
    /// The credentials signed in to a different account than the one being unlocked.
    #[error("those credentials are for a different account")]
    AccountMismatch,
    /// The hosting endpoint from the DID document is not HTTPS, so the password is refused
    /// rather than sent in cleartext.
    #[error("the hosting server's endpoint is not secure")]
    InsecureHostUrl,
    #[error("the hosting server rate limited the sign-in")]
    RateLimited { retry_after: Option<String> },
    /// A non-2xx the wallet doesn't model specially. `message` is the host's own error text
    /// (mapped from [`SourceLoginError::ServerError`]) — server-quoted per ADR-0031, so the
    /// dialog may render it behind explicit attribution.
    #[error("hosting server failure: {message}")]
    ServerError { message: String },
    #[error("offline or transport failure: {message}")]
    NetworkError { message: String },
    #[error("keychain failure: {message}")]
    Keychain { message: String },
    #[error("invalid session response: {message}")]
    InvalidResponse { message: String },
}

impl From<SourceLoginError> for UnlockError {
    fn from(error: SourceLoginError) -> Self {
        match error {
            SourceLoginError::TwoFactorRequired => Self::TwoFactorRequired,
            SourceLoginError::SourceAuthFailed { message } => Self::InvalidCredentials { message },
            SourceLoginError::AccountMismatch => Self::AccountMismatch,
            SourceLoginError::InsecureSourceUrl => Self::InsecureHostUrl,
            SourceLoginError::RateLimited { retry_after } => Self::RateLimited { retry_after },
            SourceLoginError::ServerError { message } => Self::ServerError { message },
            SourceLoginError::NetworkError { message } => Self::NetworkError { message },
        }
    }
}

fn map_store_error(error: IdentityStoreError) -> UnlockError {
    match error {
        IdentityStoreError::IdentityNotFound => UnlockError::IdentityNotFound,
        IdentityStoreError::KeychainError { message } => UnlockError::Keychain { message },
        other => UnlockError::Keychain {
            message: other.to_string(),
        },
    }
}

/// Map a DID-discovery failure. A transport failure is a connectivity problem; anything that
/// means the DID or its PDS metadata could not be read leaves us with no host to sign in to.
fn map_discovery_error(error: PdsClientError) -> UnlockError {
    match error {
        PdsClientError::PdsUnreachable { reason } => UnlockError::NetworkError { message: reason },
        PdsClientError::NetworkError { message } => UnlockError::NetworkError { message },
        PdsClientError::RateLimited { retry_after, .. } => UnlockError::RateLimited { retry_after },
        other => {
            tracing::warn!(error = %other, "could not resolve the identity's hosting server");
            UnlockError::UnsupportedHost
        }
    }
}

/// The account's handle from its DID document's first `at://` alias.
fn handle_from_also_known_as(also_known_as: &[String]) -> Option<String> {
    also_known_as
        .iter()
        .find_map(|alias| alias.strip_prefix("at://"))
        .map(str::to_string)
}

/// Decide which unlock the identity's host can serve.
///
/// A host that advertises `sovereignSessions` gets the passwordless path. A host that answered
/// and advertises nothing gets the password path. A host that **could not be asked** also gets
/// the sovereign path: an unreached probe means the network blinked, not that the server lacks
/// the capability, and demanding a password on that basis would both be a false statement about
/// their server and a change in behavior for every Custos identity whose launch happens to be
/// offline.
pub async fn unlock_route(
    pds_client: &PdsClient,
    store: &IdentityStore,
    did: &str,
) -> Result<UnlockRoute, UnlockError> {
    // Registration is what `store_oauth_tokens` requires, so an unmanaged DID must fail here
    // rather than after the user has typed a password.
    if !store
        .list_identities()
        .map_err(map_store_error)?
        .iter()
        .any(|managed| managed == did)
    {
        return Err(UnlockError::IdentityNotFound);
    }

    let (pds_url, doc) = pds_client
        .discover_pds(did)
        .await
        .map_err(map_discovery_error)?;
    let capabilities = crate::pds_capabilities::probe(pds_client, &pds_url).await;
    let method = if capabilities.reached && !capabilities.sovereign_sessions() {
        UnlockMethod::Password
    } else {
        UnlockMethod::Sovereign
    };

    Ok(UnlockRoute {
        method,
        pds_url,
        handle: handle_from_also_known_as(&doc.also_known_as),
    })
}

/// Mint a full-access session with the account's password and persist it as this DID's
/// `{did}:oauth-tokens` record.
///
/// The returned pair is bound to this DID and this host before it is stored: a JWT whose `sub`
/// is another account, or whose `aud` is another server, would be a credential the provider
/// would later hand to operations acting on *this* identity. The provider re-checks the same
/// binding on every read, so a record that fails here would be discarded there anyway — failing
/// at the write keeps the user's error honest ("that didn't sign you in") instead of surfacing
/// later as an unexplained re-lock.
pub async fn unlock_with_password(
    pds_client: &PdsClient,
    store: &IdentityStore,
    did: &str,
    identifier: &str,
    password: &str,
    auth_factor_token: Option<&str>,
    now: i64,
) -> Result<SessionReady, UnlockError> {
    let (pds_url, _doc) = pds_client
        .discover_pds(did)
        .await
        .map_err(map_discovery_error)?;
    let server = pds_client
        .describe_server(&pds_url)
        .await
        .map_err(map_discovery_error)?;

    let session = create_source_session(
        pds_client,
        &pds_url,
        did,
        identifier,
        password,
        auth_factor_token,
    )
    .await?;

    let access =
        bearer_jwt_claims(&session.access_jwt).ok_or_else(|| UnlockError::InvalidResponse {
            message: "accessJwt is missing valid exp, sub, or aud claims".into(),
        })?;
    let refresh =
        bearer_jwt_claims(&session.refresh_jwt).ok_or_else(|| UnlockError::InvalidResponse {
            message: "refreshJwt is missing valid exp, sub, or aud claims".into(),
        })?;
    if access.sub != did || refresh.sub != did {
        return Err(UnlockError::AccountMismatch);
    }
    if !audience_matches_server(&access.aud, &server.did, &pds_url)
        || !audience_matches_server(&refresh.aud, &server.did, &pds_url)
    {
        return Err(UnlockError::InvalidResponse {
            message: "the session is bound to a different host".into(),
        });
    }

    let stored_at = u64::try_from(now).map_err(|_| UnlockError::InvalidResponse {
        message: "negative timestamp cannot be persisted".into(),
    })?;
    let record = SovereignTokenRecord {
        version: SovereignTokenRecord::VERSION,
        access_jwt: session.access_jwt,
        refresh_jwt: session.refresh_jwt,
        pds_url: pds_url.clone(),
        server_did: server.did,
        access_expires_at: Some(access.exp),
        refresh_expires_at: Some(refresh.exp),
        stored_at,
    };
    store
        .store_oauth_tokens(did, &record)
        .map_err(map_store_error)?;

    Ok(SessionReady {
        did: did.to_string(),
        pds_url,
        access_expires_at: access.exp,
        refresh_expires_at: Some(refresh.exp),
        // A freshly minted pair is not a rotation of an existing one.
        rotated: false,
    })
}

/// Tauri command: which unlock should this identity's screen offer?
#[tauri::command]
pub async fn get_identity_unlock_route(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<UnlockRoute, UnlockError> {
    unlock_route(state.pds_client(), &IdentityStore, &did).await
}

/// Tauri command: open a locked identity with the account's password.
///
/// Deliberately **not** biometric-gated: the password the user just typed is itself the
/// presence proof, and this signs nothing with the device key. The irreversible operations
/// downstream (mint an app password, change a handle, remove an identity, restore blobs) keep
/// their own gates, exactly as they do after a sovereign unlock.
#[tauri::command]
pub async fn unlock_identity_with_password(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    identifier: String,
    password: String,
    auth_factor_token: Option<String>,
) -> Result<SessionReady, UnlockError> {
    let now =
        crate::sovereign_session::unix_timestamp().map_err(|_| UnlockError::InvalidResponse {
            message: "system clock is unavailable".into(),
        })?;
    unlock_with_password(
        state.pds_client(),
        &IdentityStore,
        &did,
        &identifier,
        &password,
        auth_factor_token.as_deref(),
        now,
    )
    .await
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use httpmock::{Method::GET, Method::HEAD, Method::POST, MockServer};
    use serde_json::json;

    use super::*;

    const DID: &str = "did:plc:abcdefghijklmnopqrstuvwx";

    fn now() -> i64 {
        1_720_000_000
    }

    fn jwt(exp: i64, sub: &str, aud: &str) -> String {
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({ "exp": exp, "sub": sub, "aud": aud })).unwrap());
        format!("e30.{payload}.sig")
    }

    /// Mock the DID document + reachability HEAD that `discover_pds` performs.
    async fn discovery_mocks(server: &MockServer, did: &str, pds_base: &str) {
        let did_path = format!("/{did}");
        let pds_base = pds_base.to_string();
        let did_owned = did.to_string();
        server
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
    }

    /// `describeServer`, optionally carrying the `custos` capability extension.
    async fn describe_mock(server: &MockServer, custos: Option<serde_json::Value>) {
        let mut body = json!({ "did": "did:web:pds.example.com", "availableUserDomains": [] });
        if let Some(custos) = custos {
            body["custos"] = custos;
        }
        server
            .mock_async(move |when, then| {
                when.method(GET)
                    .path("/xrpc/com.atproto.server.describeServer");
                then.status(200).json_body(body.clone());
            })
            .await;
    }

    fn register(did: &str) {
        crate::keychain::clear_for_test();
        crate::pds_capabilities::clear_for_test();
        IdentityStore.add_identity(did).unwrap();
    }

    // ── Route selection ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_host_advertising_sovereign_sessions_keeps_the_passwordless_route() {
        let server = MockServer::start_async().await;
        register(DID);
        discovery_mocks(&server, DID, &server.base_url()).await;
        describe_mock(
            &server,
            Some(json!({ "version": "0.8.1", "capabilities": ["sovereignSessions"] })),
        )
        .await;

        let client = PdsClient::new_for_test(server.base_url());
        let route = unlock_route(&client, &IdentityStore, DID).await.unwrap();

        assert_eq!(route.method, UnlockMethod::Sovereign);
        assert_eq!(route.handle.as_deref(), Some("alice.example.com"));
    }

    #[tokio::test]
    async fn a_standard_lexicon_host_routes_to_the_password_prompt() {
        let server = MockServer::start_async().await;
        register(DID);
        discovery_mocks(&server, DID, &server.base_url()).await;
        // A reference PDS answers describeServer with no `custos` object at all.
        describe_mock(&server, None).await;

        let client = PdsClient::new_for_test(server.base_url());
        let route = unlock_route(&client, &IdentityStore, DID).await.unwrap();

        assert_eq!(route.method, UnlockMethod::Password);
        assert_eq!(route.pds_url, server.base_url());
    }

    #[tokio::test]
    async fn a_host_that_could_not_be_asked_is_not_demoted_to_the_password_prompt() {
        let server = MockServer::start_async().await;
        register(DID);
        discovery_mocks(&server, DID, &server.base_url()).await;
        // describeServer fails: the probe is unreached, which says nothing about the host.
        server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/xrpc/com.atproto.server.describeServer");
                then.status(503);
            })
            .await;

        let client = PdsClient::new_for_test(server.base_url());
        let route = unlock_route(&client, &IdentityStore, DID).await.unwrap();

        assert_eq!(
            route.method,
            UnlockMethod::Sovereign,
            "a transient outage must not be read as 'this host has no sovereign sessions'"
        );
    }

    #[tokio::test]
    async fn an_unmanaged_did_is_refused_before_any_prompt() {
        crate::keychain::clear_for_test();
        crate::pds_capabilities::clear_for_test();

        let client = PdsClient::new_for_test("http://127.0.0.1:9".into());
        let result = unlock_route(&client, &IdentityStore, DID).await;

        assert!(matches!(result, Err(UnlockError::IdentityNotFound)));
    }

    // ── Password unlock ───────────────────────────────────────────────────────────

    async fn create_session_mock(server: &MockServer, body: serde_json::Value, status: u16) {
        server
            .mock_async(move |when, then| {
                when.method(POST)
                    .path("/xrpc/com.atproto.server.createSession");
                then.status(status).json_body(body.clone());
            })
            .await;
    }

    #[tokio::test]
    async fn a_password_unlock_persists_the_pair_the_provider_reads() {
        let server = MockServer::start_async().await;
        register(DID);
        discovery_mocks(&server, DID, &server.base_url()).await;
        describe_mock(&server, None).await;
        let access = jwt(now() + 3_600, DID, "did:web:pds.example.com");
        let refresh = jwt(now() + 86_400, DID, "did:web:pds.example.com");
        create_session_mock(
            &server,
            json!({
                "accessJwt": access,
                "refreshJwt": refresh,
                "did": DID,
                "handle": "alice.example.com",
            }),
            200,
        )
        .await;

        let client = PdsClient::new_for_test(server.base_url());
        let ready = unlock_with_password(
            &client,
            &IdentityStore,
            DID,
            "alice.example.com",
            "hunter2",
            None,
            now(),
        )
        .await
        .expect("a valid password mints a session");

        assert_eq!(ready.access_expires_at, (now() + 3_600) as u64);
        let stored = IdentityStore.load_oauth_tokens(DID).unwrap().unwrap();
        assert_eq!(stored.access_jwt, access);
        assert_eq!(stored.refresh_jwt, refresh);
        assert_eq!(stored.refresh_expires_at, Some((now() + 86_400) as u64));
        assert_eq!(stored.server_did, "did:web:pds.example.com");

        // The whole point: the provider's fast path now restores this identity with no
        // network and no prompt, exactly as it would after a sovereign login.
        let offline = PdsClient::new_for_test("http://127.0.0.1:9".into());
        let session = crate::session_provider::SessionProvider
            .full_access_client(&offline, &IdentityStore, DID, now())
            .await
            .expect("the persisted pair restores through the unchanged provider ladder");
        assert!(!session.rotated);
        assert_eq!(session.pds_url, server.base_url());
    }

    #[tokio::test]
    async fn email_two_factor_is_distinct_from_a_wrong_password() {
        let server = MockServer::start_async().await;
        register(DID);
        discovery_mocks(&server, DID, &server.base_url()).await;
        describe_mock(&server, None).await;
        create_session_mock(
            &server,
            json!({ "error": "AuthFactorTokenRequired", "message": "code sent" }),
            401,
        )
        .await;

        let client = PdsClient::new_for_test(server.base_url());
        let result = unlock_with_password(
            &client,
            &IdentityStore,
            DID,
            "alice.example.com",
            "hunter2",
            None,
            now(),
        )
        .await;

        assert!(matches!(result, Err(UnlockError::TwoFactorRequired)));
        assert_eq!(
            IdentityStore.load_oauth_tokens(DID).unwrap(),
            None,
            "a 2FA challenge must not leave a partial record"
        );
    }

    #[tokio::test]
    async fn credentials_for_another_account_never_become_this_identitys_session() {
        let server = MockServer::start_async().await;
        register(DID);
        discovery_mocks(&server, DID, &server.base_url()).await;
        describe_mock(&server, None).await;
        create_session_mock(
            &server,
            json!({
                "accessJwt": jwt(now() + 3_600, "did:plc:someone-else", "did:web:pds.example.com"),
                "refreshJwt": jwt(now() + 86_400, "did:plc:someone-else", "did:web:pds.example.com"),
                "did": "did:plc:someone-else",
                "handle": "mallory.example.com",
            }),
            200,
        )
        .await;

        let client = PdsClient::new_for_test(server.base_url());
        let result = unlock_with_password(
            &client,
            &IdentityStore,
            DID,
            "mallory.example.com",
            "hunter2",
            None,
            now(),
        )
        .await;

        assert!(matches!(result, Err(UnlockError::AccountMismatch)));
        assert_eq!(IdentityStore.load_oauth_tokens(DID).unwrap(), None);
    }

    #[tokio::test]
    async fn a_session_bound_to_another_host_is_refused() {
        let server = MockServer::start_async().await;
        register(DID);
        discovery_mocks(&server, DID, &server.base_url()).await;
        describe_mock(&server, None).await;
        // `createSession` answers for the right DID but audiences the pair elsewhere.
        create_session_mock(
            &server,
            json!({
                "accessJwt": jwt(now() + 3_600, DID, "did:web:elsewhere.example.com"),
                "refreshJwt": jwt(now() + 86_400, DID, "did:web:elsewhere.example.com"),
                "did": DID,
                "handle": "alice.example.com",
            }),
            200,
        )
        .await;

        let client = PdsClient::new_for_test(server.base_url());
        let result = unlock_with_password(
            &client,
            &IdentityStore,
            DID,
            "alice.example.com",
            "hunter2",
            None,
            now(),
        )
        .await;

        assert!(matches!(result, Err(UnlockError::InvalidResponse { .. })));
        assert_eq!(IdentityStore.load_oauth_tokens(DID).unwrap(), None);
    }

    #[test]
    fn errors_serialize_with_the_shared_coded_shape() {
        let json = serde_json::to_string(&UnlockError::RateLimited {
            retry_after: Some("30".into()),
        })
        .unwrap();
        assert!(json.contains(r#""code":"RATE_LIMITED""#));
        assert!(json.contains(r#""retryAfter":"30""#));

        let route = serde_json::to_string(&UnlockRoute {
            method: UnlockMethod::Password,
            pds_url: "https://bsky.social".into(),
            handle: Some("alice.bsky.social".into()),
        })
        .unwrap();
        assert!(route.contains(r#""method":"PASSWORD""#));
        assert!(route.contains(r#""pdsUrl":"https://bsky.social""#));
    }

    #[test]
    fn the_handle_comes_from_the_first_at_uri_alias() {
        assert_eq!(
            handle_from_also_known_as(&[
                "https://alice.example.com".into(),
                "at://alice.example.com".into(),
            ]),
            Some("alice.example.com".into())
        );
        assert_eq!(handle_from_also_known_as(&[]), None);
    }
}
