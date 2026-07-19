// pattern: Imperative Shell
//
// Gathers: the selected identity's DID, its hosting PDS + server DID, its per-DID device key
// Processes: fetches a pending OAuth authorization for preview; on confirm, signs the canonical
//            consent envelope with the device key and submits the approve/deny decision
// Returns: the preview a wallet screen renders, and the recorded decision
//
// The wallet-confirmed OAuth consent client (Phase A). Mirrors `sovereign_session.rs`: the same
// device-key-signed canonical envelope shape (`crypto::encode_oauth_consent_envelope`), the same
// per-DID discovery + safety checks. The biometric gate lives in the frontend, in front of
// `confirm_oauth_consent`, so a cancelled prompt signs and sends nothing.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::identity_store::{IdentityStore, IdentityStoreError, PerDidSignError};
use crate::oauth::AppState;
use crate::pds_client::{PdsClient, PdsClientError};
use crate::sovereign_session::{fresh_nonce, unix_timestamp};

#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum ConsentError {
    #[error("identity not found")]
    IdentityNotFound,
    #[error("the identity's hosting server does not support wallet-confirmed consent")]
    UnsupportedHost,
    #[error("no pending authorization matches that code")]
    RequestNotFound,
    #[error("the hosting server rejected the consent approval")]
    ApprovalRejected,
    #[error("the authorization request was already resolved")]
    AlreadyResolved,
    #[error("the hosting server rate limited the request")]
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
    #[error("invalid response: {message}")]
    InvalidResponse { message: String },
    #[error("hosting server failure: {status}")]
    ServerFailure { status: u16 },
}

/// The pending authorization a wallet screen previews before the biometric gate. Mirrors the
/// server's `ConsentRequestPreview`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentPreview {
    pub request_id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uri: String,
    pub origin: Option<String>,
    pub ip: Option<String>,
    pub requested_scope: Vec<String>,
    pub login_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentDecision {
    pub status: String,
    pub did: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalRequest<'a> {
    did: &'a str,
    signing_key: &'a str,
    request_id: &'a str,
    decision: &'a str,
    granted_scope: &'a str,
    timestamp: i64,
    nonce: &'a str,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalResponse {
    status: String,
    did: String,
}

fn map_store_error(error: IdentityStoreError) -> ConsentError {
    match error {
        IdentityStoreError::IdentityNotFound => ConsentError::IdentityNotFound,
        IdentityStoreError::KeychainError { message } => ConsentError::KeychainFailure { message },
        other => ConsentError::KeychainFailure {
            message: other.to_string(),
        },
    }
}

fn map_discovery_error(error: PdsClientError) -> ConsentError {
    match error {
        PdsClientError::DidNotFound | PdsClientError::InvalidResponse { .. } => {
            ConsentError::UnsupportedHost
        }
        PdsClientError::PdsUnreachable { reason } => {
            ConsentError::TransportFailure { message: reason }
        }
        PdsClientError::NetworkError { message } => ConsentError::TransportFailure { message },
        other => ConsentError::TransportFailure {
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

/// Resolve the selected DID's hosting PDS URL, verifying the DID document matches and the endpoint
/// is safe to send a request to.
async fn resolve_safe_pds(pds_client: &PdsClient, did: &str) -> Result<String, ConsentError> {
    let (pds_url, did_doc) = pds_client
        .discover_pds(did)
        .await
        .map_err(map_discovery_error)?;
    if did_doc.did != did {
        return Err(ConsentError::DidMismatch);
    }
    if !pds_url_is_safe(&pds_url) {
        return Err(ConsentError::UnsupportedHost);
    }
    Ok(pds_url)
}

/// Preview a pending authorization by its typed `user_code`, resolved against the selected DID's
/// hosting PDS. The typed path — the guaranteed fallback (no camera / accessibility).
#[tauri::command]
pub async fn preview_oauth_consent(
    state: tauri::State<'_, AppState>,
    did: String,
    user_code: String,
) -> Result<ConsentPreview, ConsentError> {
    preview_oauth_consent_impl(state.pds_client(), did, "user_code", user_code).await
}

/// Preview a pending authorization by its high-entropy `request_id`, resolved against the selected
/// DID's hosting PDS. The QR-scan path (Phase B): the wallet extracts only the `request_id` from the
/// scanned QR and re-fetches the client/origin/scope from the server's record here — it never trusts
/// the QR contents for what it displays. Otherwise identical to the typed path (same approval flow).
#[tauri::command]
pub async fn preview_oauth_consent_by_request_id(
    state: tauri::State<'_, AppState>,
    did: String,
    request_id: String,
) -> Result<ConsentPreview, ConsentError> {
    preview_oauth_consent_impl(state.pds_client(), did, "request_id", request_id).await
}

/// Shared preview core. `query_key` selects the server's lookup dimension (`user_code` for the typed
/// path, `request_id` for the scan/handoff path); the server resolves the same pending request and
/// returns the identical `ConsentRequestPreview` either way, so the wallet screen is unchanged.
pub(crate) async fn preview_oauth_consent_impl(
    pds_client: &PdsClient,
    did: impl AsRef<str>,
    query_key: &str,
    query_value: impl AsRef<str>,
) -> Result<ConsentPreview, ConsentError> {
    let did = did.as_ref();
    let pds_url = resolve_safe_pds(pds_client, did).await?;
    let url = format!(
        "{}/oauth/authorize/consent-request?{}={}",
        pds_url.trim_end_matches('/'),
        query_key,
        urlencoding::encode(query_value.as_ref())
    );
    let response =
        pds_client
            .client()
            .get(url)
            .send()
            .await
            .map_err(|e| ConsentError::TransportFailure {
                message: e.to_string(),
            })?;
    let status = response.status();
    if !status.is_success() {
        return Err(match status.as_u16() {
            404 => ConsentError::RequestNotFound,
            405 => ConsentError::UnsupportedHost,
            429 => ConsentError::RateLimited {
                retry_after: response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
            },
            status => ConsentError::ServerFailure { status },
        });
    }
    response
        .json::<ConsentPreview>()
        .await
        .map_err(|e| ConsentError::InvalidResponse {
            message: e.to_string(),
        })
}

/// Sign and submit a decision (approve/deny) for a previewed authorization. `granted_scope` is the
/// space-joined scope set the wallet chose (empty for a denial). The signed envelope binds the
/// `request_id`, `client_id`, decision, and granted-scope hash to the account's device key.
#[tauri::command]
pub async fn confirm_oauth_consent(
    state: tauri::State<'_, AppState>,
    did: String,
    request_id: String,
    client_id: String,
    decision: String,
    granted_scope: String,
) -> Result<ConsentDecision, ConsentError> {
    let nonce = fresh_nonce();
    let timestamp = unix_timestamp().map_err(|_| ConsentError::InvalidResponse {
        message: "system clock is before Unix epoch".into(),
    })?;
    confirm_oauth_consent_impl(
        state.pds_client(),
        &IdentityStore,
        &did,
        &request_id,
        &client_id,
        &decision,
        &granted_scope,
        timestamp,
        &nonce,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn confirm_oauth_consent_impl(
    pds_client: &PdsClient,
    store: &IdentityStore,
    did: &str,
    request_id: &str,
    client_id: &str,
    decision: &str,
    granted_scope: &str,
    timestamp: i64,
    nonce: &str,
) -> Result<ConsentDecision, ConsentError> {
    if decision != crypto::OAUTH_CONSENT_DECISION_APPROVE
        && decision != crypto::OAUTH_CONSENT_DECISION_DENY
    {
        return Err(ConsentError::InvalidResponse {
            message: "decision must be approve or deny".into(),
        });
    }

    // Resolve the signing key before any request — enforces managed-DID membership and guarantees
    // the selected DID's device key is the signer.
    let device_key = store
        .get_or_create_device_key(did)
        .map_err(map_store_error)?;
    let signer = crate::identity_store::per_did_sign_closure(did).map_err(|error| match error {
        PerDidSignError::DeviceKeyNotFound { message }
        | PerDidSignError::SigningSetupFailed { message } => {
            ConsentError::SigningFailed { message }
        }
    })?;

    let pds_url = resolve_safe_pds(pds_client, did).await?;
    let server = pds_client
        .describe_server(&pds_url)
        .await
        .map_err(map_discovery_error)?;
    if !server.did.starts_with("did:") || server.did.chars().any(char::is_whitespace) {
        return Err(ConsentError::ServerMismatch);
    }

    let envelope = crypto::encode_oauth_consent_envelope(
        &server.did,
        did,
        &device_key.key_id,
        request_id,
        client_id,
        decision,
        granted_scope,
        timestamp,
        nonce,
    );
    let signature = signer(&envelope).map_err(|e| ConsentError::SigningFailed {
        message: e.to_string(),
    })?;
    let request = ApprovalRequest {
        did,
        signing_key: &device_key.key_id,
        request_id,
        decision,
        granted_scope,
        timestamp,
        nonce,
        signature: URL_SAFE_NO_PAD.encode(signature),
    };

    let url = format!(
        "{}{}",
        pds_url.trim_end_matches('/'),
        crypto::OAUTH_CONSENT_APPROVE_PATH
    );
    let response = pds_client
        .client()
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|e| ConsentError::TransportFailure {
            message: e.to_string(),
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(match status.as_u16() {
            400 => ConsentError::AlreadyResolved,
            401 | 403 => ConsentError::ApprovalRejected,
            404 => ConsentError::RequestNotFound,
            405 => ConsentError::UnsupportedHost,
            429 => ConsentError::RateLimited {
                retry_after: response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
            },
            status => ConsentError::ServerFailure { status },
        });
    }

    let response: ApprovalResponse =
        response
            .json()
            .await
            .map_err(|e| ConsentError::InvalidResponse {
                message: e.to_string(),
            })?;
    if response.did != did {
        return Err(ConsentError::DidMismatch);
    }
    // The recorded outcome must match the decision we signed: an approval reports `approved`, a
    // denial `denied`. Anything else is a malformed/unexpected response, not a success to display.
    let expected_status = if decision == crypto::OAUTH_CONSENT_DECISION_APPROVE {
        "approved"
    } else {
        "denied"
    };
    if response.status != expected_status {
        return Err(ConsentError::InvalidResponse {
            message: "server returned a decision status that did not match the submitted decision"
                .into(),
        });
    }
    Ok(ConsentDecision {
        status: response.status,
        did: did.into(),
    })
}

#[cfg(test)]
mod tests {
    use httpmock::{Method::GET, Method::HEAD, Method::POST, Mock, MockServer};
    use serde_json::json;

    use super::*;
    use crate::device_key::DevicePublicKey;

    const DID: &str = "did:plc:abcdefghijklmnopqrstuvwx";
    const SERVER_DID: &str = "did:web:pds.example.com";
    const CLIENT_ID: &str = "https://app.example.com/client-metadata.json";
    const REQUEST_ID: &str = "poauth_test";
    const TIMESTAMP: i64 = 1_720_000_000;

    fn reset_identity(did: &str) -> DevicePublicKey {
        crate::keychain::clear_for_test();
        IdentityStore.add_identity(did).unwrap();
        IdentityStore.get_or_create_device_key(did).unwrap()
    }

    async fn discovery_mocks<'a>(server: &'a MockServer) -> (Mock<'a>, Mock<'a>, Mock<'a>) {
        let did_path = format!("/{DID}");
        let pds_url = server.base_url();
        let plc = server
            .mock_async(move |when, then| {
                when.method(GET).path(did_path);
                then.status(200).json_body(json!({
                    "id": DID,
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
        let describe = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/xrpc/com.atproto.server.describeServer");
                then.status(200).json_body(json!({
                    "did": SERVER_DID,
                    "availableUserDomains": [".example.com"],
                }));
            })
            .await;
        (plc, head, describe)
    }

    #[tokio::test]
    async fn preview_returns_the_pending_request() {
        reset_identity(DID);
        let server = MockServer::start_async().await;
        let (_plc, _head, _describe) = discovery_mocks(&server).await;
        let preview = server
            .mock_async(|when, then| {
                when.method(GET).path("/oauth/authorize/consent-request");
                then.status(200).json_body(json!({
                    "requestId": REQUEST_ID,
                    "clientId": CLIENT_ID,
                    "clientName": "Test App",
                    "redirectUri": "https://app.example.com/callback",
                    "origin": "https://app.example.com",
                    "ip": "203.0.113.5",
                    "requestedScope": ["atproto", "transition:generic"],
                    "loginHint": null,
                }));
            })
            .await;

        let client = PdsClient::new_for_test(server.base_url());
        let result = preview_oauth_consent_impl(&client, DID, "user_code", "ABCD-2345")
            .await
            .unwrap();

        preview.assert_async().await;
        assert_eq!(result.request_id, REQUEST_ID);
        assert_eq!(result.client_name.as_deref(), Some("Test App"));
        assert_eq!(
            result.requested_scope,
            vec!["atproto", "transition:generic"]
        );
    }

    #[tokio::test]
    async fn preview_by_request_id_queries_the_request_id_dimension() {
        reset_identity(DID);
        let server = MockServer::start_async().await;
        let (_plc, _head, _describe) = discovery_mocks(&server).await;
        // The scan path re-fetches the request server-side by request_id — never trusting the QR
        // contents for display. Assert the query rides on the `request_id` dimension.
        let preview = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/oauth/authorize/consent-request")
                    .query_param("request_id", REQUEST_ID);
                then.status(200).json_body(json!({
                    "requestId": REQUEST_ID,
                    "clientId": CLIENT_ID,
                    "clientName": "Test App",
                    "redirectUri": "https://app.example.com/callback",
                    "origin": "https://app.example.com",
                    "ip": "203.0.113.5",
                    "requestedScope": ["atproto", "transition:generic"],
                    "loginHint": null,
                }));
            })
            .await;

        let client = PdsClient::new_for_test(server.base_url());
        let result = preview_oauth_consent_impl(&client, DID, "request_id", REQUEST_ID)
            .await
            .unwrap();

        preview.assert_async().await;
        assert_eq!(result.request_id, REQUEST_ID);
        assert_eq!(result.client_name.as_deref(), Some("Test App"));
    }

    #[tokio::test]
    async fn preview_maps_404_to_request_not_found() {
        reset_identity(DID);
        let server = MockServer::start_async().await;
        let (_plc, _head, _describe) = discovery_mocks(&server).await;
        let _preview = server
            .mock_async(|when, then| {
                when.method(GET).path("/oauth/authorize/consent-request");
                then.status(404)
                    .json_body(json!({ "error": { "code": "NotFound" } }));
            })
            .await;

        let result = preview_oauth_consent_impl(
            &PdsClient::new_for_test(server.base_url()),
            DID,
            "user_code",
            "NOPE-0000",
        )
        .await;
        assert!(matches!(result, Err(ConsentError::RequestNotFound)));
    }

    #[tokio::test]
    async fn confirm_sends_the_signed_envelope_and_returns_status() {
        let key = reset_identity(DID);
        let server = MockServer::start_async().await;
        let (_plc, _head, _describe) = discovery_mocks(&server).await;
        let nonce = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let envelope = crypto::encode_oauth_consent_envelope(
            SERVER_DID,
            DID,
            &key.key_id,
            REQUEST_ID,
            CLIENT_ID,
            "approve",
            "atproto transition:generic",
            TIMESTAMP,
            &nonce,
        );
        let signature =
            crate::identity_store::per_did_sign_closure(DID).unwrap()(&envelope).unwrap();
        // Clone the values the matcher closure consumes so `nonce` stays live for the call below.
        let nonce_body = nonce.clone();
        let signing_key = key.key_id.clone();
        let approve = server
            .mock_async(move |when, then| {
                when.method(POST)
                    .path("/oauth/authorize/approve")
                    .json_body(json!({
                        "did": DID,
                        "signingKey": signing_key,
                        "requestId": REQUEST_ID,
                        "decision": "approve",
                        "grantedScope": "atproto transition:generic",
                        "timestamp": TIMESTAMP,
                        "nonce": nonce_body,
                        "signature": URL_SAFE_NO_PAD.encode(signature),
                    }));
                then.status(200)
                    .json_body(json!({ "status": "approved", "did": DID }));
            })
            .await;

        let client = PdsClient::new_for_test(server.base_url());
        let result = confirm_oauth_consent_impl(
            &client,
            &IdentityStore,
            DID,
            REQUEST_ID,
            CLIENT_ID,
            "approve",
            "atproto transition:generic",
            TIMESTAMP,
            &nonce,
        )
        .await
        .unwrap();

        approve.assert_async().await;
        assert_eq!(result.status, "approved");
        assert_eq!(result.did, DID);
    }

    #[tokio::test]
    async fn confirm_maps_status_codes_to_typed_errors() {
        for (status, want_already_resolved) in [(400, true), (401, false), (404, false)] {
            reset_identity(DID);
            let server = MockServer::start_async().await;
            let (_plc, _head, _describe) = discovery_mocks(&server).await;
            let _approve = server
                .mock_async(move |when, then| {
                    when.method(POST).path("/oauth/authorize/approve");
                    then.status(status);
                })
                .await;
            let nonce = URL_SAFE_NO_PAD.encode([status as u8; 32]);
            let result = confirm_oauth_consent_impl(
                &PdsClient::new_for_test(server.base_url()),
                &IdentityStore,
                DID,
                REQUEST_ID,
                CLIENT_ID,
                "approve",
                "atproto",
                TIMESTAMP,
                &nonce,
            )
            .await;
            if want_already_resolved {
                assert!(matches!(result, Err(ConsentError::AlreadyResolved)));
            } else {
                assert!(result.is_err());
            }
        }
    }
}
