// pattern: Imperative Shell

//! The claim trio: typed XRPC methods over an authenticated [`OAuthClient`] for the atproto
//! identity ceremony (`com.atproto.identity.*`). No wallet-specific side effects — each method
//! is a single request/response round trip; the caller sequences them and interprets the result.

use serde::{Deserialize, Serialize};

use crate::error::{xrpc_json, xrpc_ok, PdsClientError, TransportObserver};
use crate::oauth_client::OAuthClient;

/// Request body for `signPlcOperation`.
///
/// Serializes to frontend with `#[serde(rename_all = "camelCase")]`.
/// Optional fields are skipped if None.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignPlcOperationRequest {
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_methods: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<serde_json::Value>,
}

/// Response from `signPlcOperation`.
///
/// Returned from `POST /xrpc/com.atproto.identity.signPlcOperation`.
#[derive(Debug, Deserialize)]
pub struct SignPlcOperationResponse {
    pub operation: serde_json::Value,
}

/// Recommended credentials for a DID.
///
/// Returned from `GET /xrpc/com.atproto.identity.getRecommendedDidCredentials`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedCredentials {
    pub rotation_keys: Option<Vec<String>>,
    pub also_known_as: Option<Vec<String>>,
    pub verification_methods: Option<serde_json::Value>,
    pub services: Option<serde_json::Value>,
}

/// Request a PLC operation signature from the PDS.
///
/// Triggers email verification on the PDS. `requestPlcOperationSignature` is a
/// no-input procedure: the request must carry NO body — a spec-strict PDS
/// (bsky.social) rejects `{}` with `InvalidRequest: A request body was provided
/// when none was expected` (our own route is laxer, which is how the `{}` shipped).
pub async fn request_plc_operation_signature(
    client: &OAuthClient,
    observer: &dyn TransportObserver,
) -> Result<(), PdsClientError> {
    let resp = client
        .post_no_body("/xrpc/com.atproto.identity.requestPlcOperationSignature")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("request_plc_operation_signature failed: {}", e),
        })?;

    xrpc_ok("requestPlcOperationSignature", resp, observer)
        .await
        .map(|_| ())
}

/// Sign a PLC operation with credentials from the PDS.
pub async fn sign_plc_operation(
    client: &OAuthClient,
    request: &SignPlcOperationRequest,
    observer: &dyn TransportObserver,
) -> Result<SignPlcOperationResponse, PdsClientError> {
    let resp = client
        .post("/xrpc/com.atproto.identity.signPlcOperation", request)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("sign_plc_operation failed: {}", e),
        })?;

    xrpc_json("signPlcOperation", resp, observer).await
}

/// Fetch recommended credentials for the DID from the PDS.
pub async fn get_recommended_did_credentials(
    client: &OAuthClient,
    observer: &dyn TransportObserver,
) -> Result<RecommendedCredentials, PdsClientError> {
    let resp = client
        .get("/xrpc/com.atproto.identity.getRecommendedDidCredentials")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("get_recommended_did_credentials failed: {}", e),
        })?;

    xrpc_json("getRecommendedDidCredentials", resp, observer).await
}
