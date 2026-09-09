// pattern: Imperative Shell

//! Per-DID Custos sovereign login: passwordless full-access session issuance proven by
//! the identity's own device key.
//!
//! The network ceremony (discover the DID's hosting PDS, sign the shared canonical proof
//! envelope, exchange it at `POST /v1/sessions/sovereign`, validate the response DID and the
//! returned JWT's subject/audience against this DID and host) lives in
//! `custos_client::sovereign_session::sovereign_login` — it only needs a [`PdsClient`], the
//! per-DID device key's public id, and a signing closure, none of which name this app. This
//! module resolves those from [`IdentityStore`] and persists the result into a versioned
//! `SovereignTokenRecord` in the `{did}:oauth-tokens` Keychain record — the same record
//! `password_unlock` writes and `session_provider` reads, so restore, rotate, and
//! host-change-discard behave identically whichever unlock minted the session.
//!
//! [`sovereign_login`] is the narrow Tauri command; the typed frontend
//! `sovereignLogin(did)` wrapper performs the biometric gate before invoking it, so a
//! cancelled prompt signs and sends nothing. [`stored_bearer_client`] rebuilds an
//! authenticated Bearer client from the stored record for XRPC helpers. The re-exported
//! [`bearer_jwt_claims`] and [`audience_matches_server`] are the single source of the
//! sub/aud binding check, reused by `session_provider` and `password_unlock`. `fresh_nonce`
//! and `unix_timestamp` are also re-exported here — several other device-key-signed
//! ceremonies (`agents`, `app_passwords`, `identity_removal`, `migration_orchestrator`, and
//! more) reuse them as `crate::sovereign_session::{fresh_nonce, unix_timestamp}` for their
//! own request envelopes, not just this module's own ceremony.
//! `SovereignLoginError` serializes as `{ code: "SCREAMING_SNAKE_CASE" }` with camelCase
//! fields — this app's own enum, distinct from (and a superset of, for pre-flight failures)
//! `custos_client::sovereign_session::SovereignLoginError`.

use serde::Serialize;

use crate::identity_store::{
    IdentityStore, IdentityStoreError, PerDidSignError, SovereignTokenRecord,
};
use crate::oauth::AppState;
use crate::oauth_client::OAuthClient;
use crate::pds_client::PdsClient;

pub(crate) use custos_client::sovereign_session::{
    audience_matches_server, bearer_jwt_claims, fresh_nonce, unix_timestamp,
};

#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum SovereignLoginError {
    #[error("identity not found")]
    IdentityNotFound,
    #[error("the identity's hosting server does not support Custos sovereign login")]
    UnsupportedHost,
    #[error("the hosting server rejected the device-key proof")]
    AuthorizationFailed,
    #[error("the hosting server rate limited the login")]
    RateLimited { retry_after: Option<String> },
    /// `message` is diagnostic only (ADR-0031) — a transport failure is never the server's
    /// words.
    #[error("transport failure: {message}")]
    TransportFailure { message: String },
    /// `message` is diagnostic only (ADR-0031) — a local Keychain failure is never the
    /// server's words.
    #[error("keychain failure: {message}")]
    KeychainFailure { message: String },
    /// The signer closure (device key / Secure Enclave) failed — a **local** failure, the same
    /// one [`custos_client::sovereign_session::SovereignLoginError::SigningFailed`] documents.
    /// `message` is diagnostic only (ADR-0031 rule 4's producer contract).
    #[error("signing failure: {message}")]
    SigningFailed { message: String },
    #[error("the discovered DID document did not match the selected identity")]
    DidMismatch,
    #[error("invalid hosting server identity")]
    ServerMismatch,
    /// `message` is diagnostic only (ADR-0031) — it describes this client's read of the
    /// response, not a reason the server stated.
    #[error("invalid sovereign-session response: {message}")]
    InvalidResponse { message: String },
    #[error("hosting server failure: {status}")]
    ServerFailure { status: u16 },
}

/// Map the crate's network/validation error into this app's superset enum.
impl From<custos_client::sovereign_session::SovereignLoginError> for SovereignLoginError {
    fn from(error: custos_client::sovereign_session::SovereignLoginError) -> Self {
        use custos_client::sovereign_session::SovereignLoginError as Crate;
        match error {
            Crate::UnsupportedHost => Self::UnsupportedHost,
            Crate::AuthorizationFailed => Self::AuthorizationFailed,
            Crate::RateLimited { retry_after } => Self::RateLimited { retry_after },
            Crate::TransportFailure { message } => Self::TransportFailure { message },
            Crate::SigningFailed { message } => Self::SigningFailed { message },
            Crate::DidMismatch => Self::DidMismatch,
            Crate::ServerMismatch => Self::ServerMismatch,
            Crate::InvalidResponse { message } => Self::InvalidResponse { message },
            Crate::ServerFailure { status } => Self::ServerFailure { status },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SovereignLoginResult {
    pub did: String,
    pub pds_url: String,
    pub access_expires_at: u64,
    pub refresh_expires_at: u64,
}

fn map_store_error(error: IdentityStoreError) -> SovereignLoginError {
    match error {
        IdentityStoreError::IdentityNotFound => SovereignLoginError::IdentityNotFound,
        IdentityStoreError::KeychainError { message } => {
            SovereignLoginError::KeychainFailure { message }
        }
        other => SovereignLoginError::KeychainFailure {
            message: other.to_string(),
        },
    }
}

/// Mint and persist a full-access session for one managed DID.
#[tauri::command]
pub async fn sovereign_login(
    state: tauri::State<'_, AppState>,
    did: String,
) -> Result<SovereignLoginResult, SovereignLoginError> {
    let nonce = fresh_nonce();
    let timestamp = unix_timestamp()?;
    sovereign_login_impl(state.pds_client(), &IdentityStore, &did, timestamp, &nonce).await
}

pub(crate) async fn sovereign_login_impl(
    pds_client: &PdsClient,
    store: &IdentityStore,
    did: &str,
    timestamp: i64,
    nonce: &str,
) -> Result<SovereignLoginResult, SovereignLoginError> {
    // Resolve the key before any request to the hosting PDS. This both enforces
    // managed-DID membership and guarantees the selected DID's key is the signer.
    let device_key = store
        .get_or_create_device_key(did)
        .map_err(map_store_error)?;
    let signer = crate::identity_store::per_did_sign_closure(did).map_err(|error| match error {
        PerDidSignError::DeviceKeyNotFound { message }
        | PerDidSignError::SigningSetupFailed { message } => {
            SovereignLoginError::SigningFailed { message }
        }
    })?;
    let sign = move |data: &[u8]| signer(data).map_err(|e| e.to_string());

    let response = custos_client::sovereign_session::sovereign_login(
        pds_client,
        did,
        &device_key.key_id,
        timestamp,
        nonce,
        sign,
    )
    .await?;

    let stored_at = u64::try_from(timestamp).map_err(|_| SovereignLoginError::InvalidResponse {
        message: "negative timestamp cannot be persisted".into(),
    })?;
    let record = SovereignTokenRecord {
        version: SovereignTokenRecord::VERSION,
        access_jwt: response.access_jwt,
        refresh_jwt: response.refresh_jwt,
        pds_url: response.pds_url.clone(),
        server_did: response.server_did,
        access_expires_at: Some(response.access_expires_at),
        refresh_expires_at: Some(response.refresh_expires_at),
        stored_at,
    };
    store
        .store_oauth_tokens(did, &record)
        .map_err(map_store_error)?;

    Ok(SovereignLoginResult {
        did: did.into(),
        pds_url: response.pds_url,
        access_expires_at: response.access_expires_at,
        refresh_expires_at: response.refresh_expires_at,
    })
}

/// Restore a selected DID's persisted full-access session as an authenticated XRPC client.
pub fn stored_bearer_client(did: &str) -> Result<Option<OAuthClient>, SovereignLoginError> {
    let Some(record) = IdentityStore
        .load_oauth_tokens(did)
        .map_err(map_store_error)?
    else {
        return Ok(None);
    };
    let access = bearer_jwt_claims(&record.access_jwt).ok_or_else(|| {
        SovereignLoginError::InvalidResponse {
            message: "stored accessJwt is malformed".into(),
        }
    })?;
    let refresh = bearer_jwt_claims(&record.refresh_jwt).ok_or_else(|| {
        SovereignLoginError::InvalidResponse {
            message: "stored refreshJwt is malformed".into(),
        }
    })?;
    if access.sub != did || refresh.sub != did {
        return Err(SovereignLoginError::DidMismatch);
    }
    if !audience_matches_server(&access.aud, &record.server_did, &record.pds_url)
        || !audience_matches_server(&refresh.aud, &record.server_did, &record.pds_url)
    {
        return Err(SovereignLoginError::ServerMismatch);
    }
    OAuthClient::new_bearer_with_observer(
        record.access_jwt,
        record.refresh_jwt,
        record.pds_url,
        crate::oauth_client::diagnostics_observer(),
    )
    .map(Some)
    .map_err(|e| SovereignLoginError::KeychainFailure {
        message: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use httpmock::{Method::GET, Method::HEAD, Method::POST, Mock, MockServer};
    use serde_json::json;

    use super::*;
    use crate::device_key::DevicePublicKey;

    const DID: &str = "did:plc:abcdefghijklmnopqrstuvwx";
    const OTHER_DID: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
    const SERVER_DID: &str = "did:web:pds.example.com";
    const TIMESTAMP: i64 = 1_720_000_000;
    const NONCE_BYTES: usize = 32;

    fn jwt(exp: u64) -> String {
        jwt_for(exp, DID, SERVER_DID)
    }

    fn jwt_for(exp: u64, sub: &str, aud: &str) -> String {
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({ "exp": exp, "sub": sub, "aud": aud })).unwrap());
        format!("e30.{payload}.signature")
    }

    fn reset_identity(did: &str) -> DevicePublicKey {
        crate::keychain::clear_for_test();
        IdentityStore.add_identity(did).unwrap();
        IdentityStore.get_or_create_device_key(did).unwrap()
    }

    async fn discovery_mocks<'a>(
        server: &'a MockServer,
        did: &str,
        document_did: &str,
        server_did: &str,
    ) -> (Mock<'a>, Mock<'a>, Mock<'a>) {
        let did_path = format!("/{did}");
        let pds_url = server.base_url();
        let document_did = document_did.to_string();
        let plc = server
            .mock_async(move |when, then| {
                when.method(GET).path(did_path);
                then.status(200).json_body(json!({
                    "id": document_did,
                    "alsoKnownAs": ["at://alice.example.com"],
                    "verificationMethod": [],
                    "service": [{
                        "id": "#atproto_pds",
                        "type": "AtprotoPersonalDataServer",
                        "serviceEndpoint": pds_url,
                    }],
                }));
            })
            .await;
        let head = server
            .mock_async(|when, then| {
                when.method(HEAD).path("/");
                then.status(200);
            })
            .await;
        let server_did = server_did.to_string();
        let describe = server
            .mock_async(move |when, then| {
                when.method(GET)
                    .path("/xrpc/com.atproto.server.describeServer");
                then.status(200).json_body(json!({
                    "did": server_did,
                    "availableUserDomains": [".example.com"],
                }));
            })
            .await;
        (plc, head, describe)
    }

    #[tokio::test]
    async fn sends_exact_per_did_signed_request_and_persists_session() {
        let key = reset_identity(DID);
        let server = MockServer::start_async().await;
        let (_plc, _head, _describe) = discovery_mocks(&server, DID, DID, SERVER_DID).await;
        let nonce = URL_SAFE_NO_PAD.encode([7u8; NONCE_BYTES]);
        let envelope = crypto::encode_sovereign_session_envelope(
            SERVER_DID,
            DID,
            &key.key_id,
            TIMESTAMP,
            &nonce,
        );
        let signature =
            crate::identity_store::per_did_sign_closure(DID).unwrap()(&envelope).unwrap();
        let access_jwt = jwt(1_720_003_600);
        let refresh_jwt = jwt(1_720_086_400);
        let request = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(crypto::SOVEREIGN_SESSION_PATH)
                    .json_body(json!({
                        "did": DID,
                        "signingKey": key.key_id,
                        "timestamp": TIMESTAMP,
                        "nonce": nonce,
                        "signature": URL_SAFE_NO_PAD.encode(signature),
                    }));
                then.status(200).json_body(json!({
                    "accessJwt": access_jwt,
                    "refreshJwt": refresh_jwt,
                    "handle": "alice.example.com",
                    "did": DID,
                    "email": null,
                }));
            })
            .await;

        let client = crate::pds_client::new_for_test(server.base_url());
        let result = sovereign_login_impl(&client, &IdentityStore, DID, TIMESTAMP, &nonce)
            .await
            .unwrap();

        request.assert_async().await;
        assert_eq!(result.did, DID);
        let stored = IdentityStore.load_oauth_tokens(DID).unwrap().unwrap();
        assert_eq!(stored.pds_url, server.base_url());
        assert_eq!(stored.access_expires_at, Some(1_720_003_600));
        assert_eq!(stored.refresh_expires_at, Some(1_720_086_400));
        assert!(stored_bearer_client(DID).unwrap().is_some());
    }

    #[tokio::test]
    async fn response_did_mismatch_does_not_persist_tokens() {
        reset_identity(DID);
        let server = MockServer::start_async().await;
        let (_plc, _head, _describe) = discovery_mocks(&server, DID, DID, SERVER_DID).await;
        let _request = server
            .mock_async(|when, then| {
                when.method(POST).path(crypto::SOVEREIGN_SESSION_PATH);
                then.status(200).json_body(json!({
                    "accessJwt": jwt(1_720_003_600),
                    "refreshJwt": jwt(1_720_086_400),
                    "did": OTHER_DID,
                }));
            })
            .await;
        let nonce = URL_SAFE_NO_PAD.encode([8u8; NONCE_BYTES]);

        let result = sovereign_login_impl(
            &crate::pds_client::new_for_test(server.base_url()),
            &IdentityStore,
            DID,
            TIMESTAMP,
            &nonce,
        )
        .await;

        assert!(matches!(result, Err(SovereignLoginError::DidMismatch)));
        assert_eq!(IdentityStore.load_oauth_tokens(DID).unwrap(), None);
    }

    #[tokio::test]
    async fn malformed_success_does_not_persist_tokens() {
        reset_identity(DID);
        let server = MockServer::start_async().await;
        let (_plc, _head, _describe) = discovery_mocks(&server, DID, DID, SERVER_DID).await;
        let _request = server
            .mock_async(|when, then| {
                when.method(POST).path(crypto::SOVEREIGN_SESSION_PATH);
                then.status(200).json_body(json!({ "did": DID }));
            })
            .await;
        let nonce = URL_SAFE_NO_PAD.encode([9u8; NONCE_BYTES]);

        let result = sovereign_login_impl(
            &crate::pds_client::new_for_test(server.base_url()),
            &IdentityStore,
            DID,
            TIMESTAMP,
            &nonce,
        )
        .await;

        assert!(matches!(
            result,
            Err(SovereignLoginError::InvalidResponse { .. })
        ));
        assert_eq!(IdentityStore.load_oauth_tokens(DID).unwrap(), None);
    }

    #[tokio::test]
    async fn token_server_audience_mismatch_does_not_persist_tokens() {
        reset_identity(DID);
        let server = MockServer::start_async().await;
        let (_plc, _head, _describe) = discovery_mocks(&server, DID, DID, SERVER_DID).await;
        let _request = server
            .mock_async(|when, then| {
                when.method(POST).path(crypto::SOVEREIGN_SESSION_PATH);
                then.status(200).json_body(json!({
                    "accessJwt": jwt_for(1_720_003_600, DID, "did:web:other.example.com"),
                    "refreshJwt": jwt_for(1_720_086_400, DID, "did:web:other.example.com"),
                    "did": DID,
                }));
            })
            .await;
        let nonce = URL_SAFE_NO_PAD.encode([10u8; NONCE_BYTES]);

        let result = sovereign_login_impl(
            &crate::pds_client::new_for_test(server.base_url()),
            &IdentityStore,
            DID,
            TIMESTAMP,
            &nonce,
        )
        .await;

        assert!(matches!(result, Err(SovereignLoginError::ServerMismatch)));
        assert_eq!(IdentityStore.load_oauth_tokens(DID).unwrap(), None);
    }

    #[tokio::test]
    async fn public_pds_url_is_accepted_as_the_legacy_session_audience() {
        reset_identity(DID);
        let server = MockServer::start_async().await;
        let (_plc, _head, _describe) = discovery_mocks(&server, DID, DID, SERVER_DID).await;
        let pds_url = server.base_url();
        let access_jwt = jwt_for(1_720_003_600, DID, &pds_url);
        let refresh_jwt = jwt_for(1_720_086_400, DID, &pds_url);
        let _request = server
            .mock_async(|when, then| {
                when.method(POST).path(crypto::SOVEREIGN_SESSION_PATH);
                then.status(200).json_body(json!({
                    "accessJwt": access_jwt,
                    "refreshJwt": refresh_jwt,
                    "did": DID,
                }));
            })
            .await;
        let nonce = URL_SAFE_NO_PAD.encode([11u8; NONCE_BYTES]);

        sovereign_login_impl(
            &crate::pds_client::new_for_test(server.base_url()),
            &IdentityStore,
            DID,
            TIMESTAMP,
            &nonce,
        )
        .await
        .unwrap();

        assert!(stored_bearer_client(DID).unwrap().is_some());
    }

    #[tokio::test]
    async fn host_and_server_errors_remain_distinguishable() {
        for (status, expected) in [
            (404, "unsupported"),
            (401, "authorization"),
            (429, "rate_limit"),
            (503, "server"),
        ] {
            reset_identity(DID);
            let server = MockServer::start_async().await;
            let (_plc, _head, _describe) = discovery_mocks(&server, DID, DID, SERVER_DID).await;
            let _request = server
                .mock_async(move |when, then| {
                    when.method(POST).path(crypto::SOVEREIGN_SESSION_PATH);
                    then.status(status).header("Retry-After", "12");
                })
                .await;
            let nonce = URL_SAFE_NO_PAD.encode([status as u8; NONCE_BYTES]);
            let result = sovereign_login_impl(
                &crate::pds_client::new_for_test(server.base_url()),
                &IdentityStore,
                DID,
                TIMESTAMP,
                &nonce,
            )
            .await;
            assert!(match (expected, result) {
                ("unsupported", Err(SovereignLoginError::UnsupportedHost)) => true,
                ("authorization", Err(SovereignLoginError::AuthorizationFailed)) => true,
                (
                    "rate_limit",
                    Err(SovereignLoginError::RateLimited {
                        retry_after: Some(value),
                    }),
                ) if value == "12" => true,
                ("server", Err(SovereignLoginError::ServerFailure { status: 503 })) => true,
                _ => false,
            });
            assert_eq!(IdentityStore.load_oauth_tokens(DID).unwrap(), None);
        }
    }
}
