// pattern: Imperative Shell

//! Custos sovereign login: passwordless full-access session issuance proven by an
//! identity's own device key.
//!
//! [`sovereign_login`] discovers the DID's current hosting PDS and server DID (via
//! [`PdsClient`]), exchanges a caller-signed proof envelope at `POST
//! {pds_url}{crypto::SOVEREIGN_SESSION_PATH}`, and validates the response DID and the
//! returned JWTs' subject/audience against the DID and host before returning. It does not
//! know about Keychains or per-DID key storage: the caller resolves the signing key and
//! passes a signing closure plus the key's public `device_key_id` (a did:key string).
//! Persisting the returned session is the caller's job too (this crate has no concept of
//! "the app's session record format").
//!
//! [`bearer_jwt_claims`] and [`audience_matches_server`] are the pure JWT helpers apps reuse
//! to validate a restored/rotated session against the DID and hosting server it was issued
//! for — the single source of the sub/aud binding check.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::PdsClientError;
use crate::pds_client::PdsClient;

const NONCE_BYTES: usize = 32;

/// Error type for the sovereign-login network ceremony. Callers with their own pre-flight
/// steps (key resolution, persistence) map their own failures into their own error type,
/// wrapping this one for the network/validation portion.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum SovereignLoginError {
    #[error("the identity's hosting server does not support Custos sovereign login")]
    UnsupportedHost,
    #[error("the hosting server rejected the device-key proof")]
    AuthorizationFailed,
    #[error("the hosting server rate limited the login")]
    RateLimited { retry_after: Option<String> },
    #[error("transport failure: {message}")]
    TransportFailure { message: String },
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

/// A successful sovereign login, carrying everything a caller needs both to persist the
/// session and to report a summary to its own frontend.
#[derive(Debug, Clone)]
pub struct SovereignLoginResponse {
    pub pds_url: String,
    pub server_did: String,
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub access_expires_at: u64,
    pub refresh_expires_at: u64,
    pub also_known_as: Vec<String>,
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

/// A JWT's unverified `exp`/`sub`/`aud` claims.
#[derive(Deserialize)]
pub struct BearerJwtClaims {
    pub exp: u64,
    pub sub: String,
    pub aud: String,
}

/// Decode a Bearer JWT's unverified payload into its `exp`/`sub`/`aud` claims.
///
/// The signature is NOT checked — the claims are only used for session-lifecycle
/// decisions (expiry) and to bind a restored/rotated session to the DID and hosting
/// server it was issued for, never as authorization data.
pub fn bearer_jwt_claims(token: &str) -> Option<BearerJwtClaims> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Whether a JWT `aud` claim identifies the hosting server, accepting either the
/// server DID or the PDS URL (some issuers set the public URL as the audience).
pub fn audience_matches_server(audience: &str, server_did: &str, pds_url: &str) -> bool {
    audience == server_did || audience.trim_end_matches('/') == pds_url.trim_end_matches('/')
}

/// Generate a fresh 32-byte canonical base64url nonce for a sovereign-session proof.
pub fn fresh_nonce() -> String {
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce_bytes);
    URL_SAFE_NO_PAD.encode(nonce_bytes)
}

/// The current Unix timestamp, for a sovereign-session proof.
pub fn unix_timestamp() -> Result<i64, SovereignLoginError> {
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

/// Mint a full-access session for one DID via Custos sovereign login.
///
/// `device_key_id` is the signing key's public did:key identifier (not the key material —
/// this function never touches key storage). `sign` produces the raw signature over the
/// canonical envelope bytes; the caller resolves it (e.g. against a per-DID Keychain key)
/// and reduces its own error type to a message string.
pub async fn sovereign_login(
    pds_client: &PdsClient,
    did: &str,
    device_key_id: &str,
    timestamp: i64,
    nonce: &str,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
) -> Result<SovereignLoginResponse, SovereignLoginError> {
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
        device_key_id,
        timestamp,
        nonce,
    );
    let signature =
        sign(&envelope).map_err(|message| SovereignLoginError::SigningFailed { message })?;
    let request = SovereignSessionRequest {
        did,
        signing_key: device_key_id,
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

    Ok(SovereignLoginResponse {
        pds_url,
        server_did: server.did,
        access_jwt: response.access_jwt,
        refresh_jwt: response.refresh_jwt,
        access_expires_at: access_claims.exp,
        refresh_expires_at: refresh_claims.exp,
        also_known_as: did_doc.also_known_as,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::{Method::GET, Method::HEAD, Method::POST, Mock, MockServer};
    use serde_json::json;

    const DID: &str = "did:plc:abcdefghijklmnopqrstuvwx";
    const OTHER_DID: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
    const SERVER_DID: &str = "did:web:pds.example.com";
    const SIGNING_KEY: &str = "did:key:zDnaeTHfhmSaQKBk94sne3DXpk4pbNs4LBfjSAwSKAvNXbAZ8";
    const TIMESTAMP: i64 = 1_720_000_000;

    fn jwt(exp: u64) -> String {
        jwt_for(exp, DID, SERVER_DID)
    }

    fn jwt_for(exp: u64, sub: &str, aud: &str) -> String {
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({ "exp": exp, "sub": sub, "aud": aud })).unwrap());
        format!("e30.{payload}.signature")
    }

    fn sign_ok(_data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(vec![0u8; 64])
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
    fn envelope_matches_the_shared_canonical_vector() {
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
            "../../../test-vectors/sovereign-session-envelope-v1.json"
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
    async fn sends_exact_signed_request_and_returns_the_session() {
        let server = MockServer::start_async().await;
        let (_plc, _head, _describe) = discovery_mocks(&server, DID, DID, SERVER_DID).await;
        let nonce = URL_SAFE_NO_PAD.encode([7u8; NONCE_BYTES]);
        let expected_signature = URL_SAFE_NO_PAD.encode(vec![0u8; 64]);
        let access_jwt = jwt(1_720_003_600);
        let refresh_jwt = jwt(1_720_086_400);
        let request = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(crypto::SOVEREIGN_SESSION_PATH)
                    .json_body(json!({
                        "did": DID,
                        "signingKey": SIGNING_KEY,
                        "timestamp": TIMESTAMP,
                        "nonce": nonce,
                        "signature": expected_signature,
                    }));
                then.status(200).json_body(json!({
                    "accessJwt": access_jwt,
                    "refreshJwt": refresh_jwt,
                    "did": DID,
                }));
            })
            .await;

        let client = PdsClient::new_for_test(server.base_url());
        let result = sovereign_login(&client, DID, SIGNING_KEY, TIMESTAMP, &nonce, sign_ok)
            .await
            .unwrap();

        request.assert_async().await;
        assert_eq!(result.pds_url, server.base_url());
        assert_eq!(result.server_did, SERVER_DID);
        assert_eq!(result.access_expires_at, 1_720_003_600);
        assert_eq!(result.refresh_expires_at, 1_720_086_400);
    }

    #[tokio::test]
    async fn response_did_mismatch_is_rejected() {
        let server = MockServer::start_async().await;
        let (_plc, _head, _describe) = discovery_mocks(&server, DID, DID, SERVER_DID).await;
        server
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

        let client = PdsClient::new_for_test(server.base_url());
        let result = sovereign_login(&client, DID, SIGNING_KEY, TIMESTAMP, &nonce, sign_ok).await;

        assert!(matches!(result, Err(SovereignLoginError::DidMismatch)));
    }

    #[tokio::test]
    async fn malformed_success_is_rejected() {
        let server = MockServer::start_async().await;
        let (_plc, _head, _describe) = discovery_mocks(&server, DID, DID, SERVER_DID).await;
        server
            .mock_async(|when, then| {
                when.method(POST).path(crypto::SOVEREIGN_SESSION_PATH);
                then.status(200).json_body(json!({ "did": DID }));
            })
            .await;
        let nonce = URL_SAFE_NO_PAD.encode([9u8; NONCE_BYTES]);

        let client = PdsClient::new_for_test(server.base_url());
        let result = sovereign_login(&client, DID, SIGNING_KEY, TIMESTAMP, &nonce, sign_ok).await;

        assert!(matches!(
            result,
            Err(SovereignLoginError::InvalidResponse { .. })
        ));
    }

    #[tokio::test]
    async fn token_server_audience_mismatch_is_rejected() {
        let server = MockServer::start_async().await;
        let (_plc, _head, _describe) = discovery_mocks(&server, DID, DID, SERVER_DID).await;
        server
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

        let client = PdsClient::new_for_test(server.base_url());
        let result = sovereign_login(&client, DID, SIGNING_KEY, TIMESTAMP, &nonce, sign_ok).await;

        assert!(matches!(result, Err(SovereignLoginError::ServerMismatch)));
    }

    #[tokio::test]
    async fn public_pds_url_is_accepted_as_the_legacy_session_audience() {
        let server = MockServer::start_async().await;
        let (_plc, _head, _describe) = discovery_mocks(&server, DID, DID, SERVER_DID).await;
        let pds_url = server.base_url();
        let access_jwt = jwt_for(1_720_003_600, DID, &pds_url);
        let refresh_jwt = jwt_for(1_720_086_400, DID, &pds_url);
        server
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

        let client = PdsClient::new_for_test(server.base_url());
        let result = sovereign_login(&client, DID, SIGNING_KEY, TIMESTAMP, &nonce, sign_ok)
            .await
            .unwrap();

        assert_eq!(result.access_jwt, access_jwt);
    }

    #[tokio::test]
    async fn host_and_server_errors_remain_distinguishable() {
        for (status, expected) in [
            (404, "unsupported"),
            (401, "authorization"),
            (429, "rate_limit"),
            (503, "server"),
        ] {
            let server = MockServer::start_async().await;
            let (_plc, _head, _describe) = discovery_mocks(&server, DID, DID, SERVER_DID).await;
            server
                .mock_async(move |when, then| {
                    when.method(POST).path(crypto::SOVEREIGN_SESSION_PATH);
                    then.status(status).header("Retry-After", "12");
                })
                .await;
            let nonce = URL_SAFE_NO_PAD.encode([status as u8; NONCE_BYTES]);

            let client = PdsClient::new_for_test(server.base_url());
            let result =
                sovereign_login(&client, DID, SIGNING_KEY, TIMESTAMP, &nonce, sign_ok).await;

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
        }
    }
}
