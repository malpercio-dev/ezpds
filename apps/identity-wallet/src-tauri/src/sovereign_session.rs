// pattern: Imperative Shell
//
// Gathers: managed DID, current hosting PDS/server DID, per-DID device key
// Processes: canonical proof signing, sovereign-session exchange, response validation
// Returns: a persisted per-DID Bearer session and a client constructor for XRPC callers

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::identity_store::{
    IdentityStore, IdentityStoreError, PerDidSignError, SovereignTokenRecord,
};
use crate::oauth::AppState;
use crate::oauth_client::OAuthClient;
use crate::pds_client::{PdsClient, PdsClientError};

const NONCE_BYTES: usize = 32;

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
    #[error("transport failure: {message}")]
    TransportFailure { message: String },
    #[error("keychain failure: {message}")]
    KeychainFailure { message: String },
    #[error("signing failure: {message}")]
    SigningFailed { message: String },
    #[error("the discovered DID document did not match the selected identity")]
    DidMismatch,
    #[error("invalid hosting server identity")]
    ServerMismatch,
    #[error("invalid sovereign-session response: {message}")]
    InvalidResponse { message: String },
    #[error("hosting server failure: {status}")]
    ServerFailure { status: u16 },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SovereignLoginResult {
    pub did: String,
    pub pds_url: String,
    pub access_expires_at: u64,
    pub refresh_expires_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SovereignSessionRequest<'a> {
    did: &'a str,
    signing_key: &'a str,
    timestamp: i64,
    nonce: &'a str,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SovereignSessionResponse {
    access_jwt: String,
    refresh_jwt: String,
    did: String,
}

#[derive(Deserialize)]
struct BearerJwtClaims {
    exp: u64,
    sub: String,
    aud: String,
}

fn bearer_jwt_claims(token: &str) -> Option<BearerJwtClaims> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn audience_matches_server(audience: &str, server_did: &str, pds_url: &str) -> bool {
    audience == server_did || audience.trim_end_matches('/') == pds_url.trim_end_matches('/')
}

/// Generate a fresh 32-byte canonical base64url nonce for a sovereign-session proof.
pub(crate) fn fresh_nonce() -> String {
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce_bytes);
    URL_SAFE_NO_PAD.encode(nonce_bytes)
}

pub(crate) fn unix_timestamp() -> Result<i64, SovereignLoginError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| SovereignLoginError::InvalidResponse {
            message: format!("system clock is before Unix epoch: {e}"),
        })?
        .as_secs();
    i64::try_from(seconds).map_err(|_| SovereignLoginError::InvalidResponse {
        message: "system timestamp exceeds supported range".into(),
    })
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

fn map_discovery_error(error: PdsClientError) -> SovereignLoginError {
    match error {
        PdsClientError::DidNotFound | PdsClientError::InvalidResponse { .. } => {
            SovereignLoginError::UnsupportedHost
        }
        PdsClientError::PdsUnreachable { reason } => {
            SovereignLoginError::TransportFailure { message: reason }
        }
        PdsClientError::NetworkError { message } => {
            SovereignLoginError::TransportFailure { message }
        }
        other => SovereignLoginError::TransportFailure {
            message: other.to_string(),
        },
    }
}

fn pds_url_is_safe(url: &str) -> bool {
    let Ok(url) = url::Url::parse(url) else {
        return false;
    };
    url.scheme() == "https"
        || (url.scheme() == "http"
            && matches!(
                url.host_str(),
                Some("localhost") | Some("127.0.0.1") | Some("::1") | Some("[::1]")
            ))
}

/// Mint and persist a full-access session for one managed DID.
#[tauri::command]
pub async fn sovereign_login(
    state: tauri::State<'_, AppState>,
    did: String,
) -> Result<SovereignLoginResult, SovereignLoginError> {
    let nonce = fresh_nonce();
    sovereign_login_impl(
        state.pds_client(),
        &IdentityStore,
        &did,
        unix_timestamp()?,
        &nonce,
    )
    .await
}

pub(crate) async fn sovereign_login_impl(
    pds_client: &PdsClient,
    store: &IdentityStore,
    did: &str,
    timestamp: i64,
    nonce: &str,
) -> Result<SovereignLoginResult, SovereignLoginError> {
    let decoded_nonce = URL_SAFE_NO_PAD.decode(nonce).ok();
    if decoded_nonce.as_deref().map(<[u8]>::len) != Some(NONCE_BYTES)
        || decoded_nonce
            .as_deref()
            .is_some_and(|bytes| URL_SAFE_NO_PAD.encode(bytes) != nonce)
    {
        return Err(SovereignLoginError::InvalidResponse {
            message: "nonce must be 32 canonical base64url bytes".into(),
        });
    }

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

    let (pds_url, did_doc) = pds_client
        .discover_pds(did)
        .await
        .map_err(map_discovery_error)?;
    if did_doc.did != did {
        return Err(SovereignLoginError::DidMismatch);
    }
    if !pds_url_is_safe(&pds_url) {
        return Err(SovereignLoginError::UnsupportedHost);
    }
    let server = pds_client
        .describe_server(&pds_url)
        .await
        .map_err(map_discovery_error)?;
    if !server.did.starts_with("did:") || server.did.chars().any(char::is_whitespace) {
        return Err(SovereignLoginError::ServerMismatch);
    }

    let envelope = crypto::encode_sovereign_session_envelope(
        &server.did,
        did,
        &device_key.key_id,
        timestamp,
        nonce,
    );
    let signature = signer(&envelope).map_err(|e| SovereignLoginError::SigningFailed {
        message: e.to_string(),
    })?;
    let request = SovereignSessionRequest {
        did,
        signing_key: &device_key.key_id,
        timestamp,
        nonce,
        signature: URL_SAFE_NO_PAD.encode(signature),
    };

    let url = format!(
        "{}{}",
        pds_url.trim_end_matches('/'),
        crypto::SOVEREIGN_SESSION_PATH
    );
    let response = pds_client
        .client()
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|e| SovereignLoginError::TransportFailure {
            message: e.to_string(),
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(match status.as_u16() {
            401 | 403 => SovereignLoginError::AuthorizationFailed,
            404 | 405 => SovereignLoginError::UnsupportedHost,
            429 => SovereignLoginError::RateLimited {
                retry_after: response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
            },
            status => SovereignLoginError::ServerFailure { status },
        });
    }

    let response: SovereignSessionResponse =
        response
            .json()
            .await
            .map_err(|e| SovereignLoginError::InvalidResponse {
                message: e.to_string(),
            })?;
    if response.did != did {
        return Err(SovereignLoginError::DidMismatch);
    }
    let access_claims = bearer_jwt_claims(&response.access_jwt).ok_or_else(|| {
        SovereignLoginError::InvalidResponse {
            message: "accessJwt is missing valid exp, sub, or aud claims".into(),
        }
    })?;
    let refresh_claims = bearer_jwt_claims(&response.refresh_jwt).ok_or_else(|| {
        SovereignLoginError::InvalidResponse {
            message: "refreshJwt is missing valid exp, sub, or aud claims".into(),
        }
    })?;
    if access_claims.sub != did || refresh_claims.sub != did {
        return Err(SovereignLoginError::DidMismatch);
    }
    if !audience_matches_server(&access_claims.aud, &server.did, &pds_url)
        || !audience_matches_server(&refresh_claims.aud, &server.did, &pds_url)
    {
        return Err(SovereignLoginError::ServerMismatch);
    }
    let access_expires_at = access_claims.exp;
    let refresh_expires_at = refresh_claims.exp;
    let stored_at = u64::try_from(timestamp).map_err(|_| SovereignLoginError::InvalidResponse {
        message: "negative timestamp cannot be persisted".into(),
    })?;
    let record = SovereignTokenRecord {
        version: SovereignTokenRecord::VERSION,
        access_jwt: response.access_jwt,
        refresh_jwt: response.refresh_jwt,
        pds_url: pds_url.clone(),
        server_did: server.did,
        access_expires_at: Some(access_expires_at),
        refresh_expires_at: Some(refresh_expires_at),
        stored_at,
    };
    store
        .store_oauth_tokens(did, &record)
        .map_err(map_store_error)?;

    Ok(SovereignLoginResult {
        did: did.into(),
        pds_url,
        access_expires_at,
        refresh_expires_at,
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
    OAuthClient::new_bearer(record.access_jwt, record.refresh_jwt, record.pds_url)
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

    #[test]
    fn wallet_uses_the_shared_canonical_envelope_vector() {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Vector {
            server_did: String,
            account_did: String,
            signing_key_did: String,
            timestamp: i64,
            nonce: String,
            envelope: String,
        }
        let vector: Vector = serde_json::from_str(include_str!(
            "../../../../test-vectors/sovereign-session-envelope-v1.json"
        ))
        .unwrap();
        let actual = crypto::encode_sovereign_session_envelope(
            &vector.server_did,
            &vector.account_did,
            &vector.signing_key_did,
            vector.timestamp,
            &vector.nonce,
        );
        assert_eq!(String::from_utf8(actual).unwrap(), vector.envelope);
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

        let client = PdsClient::new_for_test(server.base_url());
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
            &PdsClient::new_for_test(server.base_url()),
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
            &PdsClient::new_for_test(server.base_url()),
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
            &PdsClient::new_for_test(server.base_url()),
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
            &PdsClient::new_for_test(server.base_url()),
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
                &PdsClient::new_for_test(server.base_url()),
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
