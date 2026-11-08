// pattern: Imperative Shell

//! The claim trio: typed XRPC methods over an authenticated [`OAuthClient`] for the atproto
//! identity ceremony (`com.atproto.identity.*`). No wallet-specific side effects — each method
//! is a single request/response round trip; the caller sequences them and interprets the result.

use serde::{Deserialize, Serialize};

use crate::error::{xrpc_json, xrpc_ok, PdsClientError};
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
pub async fn request_plc_operation_signature(client: &OAuthClient) -> Result<(), PdsClientError> {
    let resp = client
        .post_no_body("/xrpc/com.atproto.identity.requestPlcOperationSignature")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("request_plc_operation_signature failed: {}", e),
        })?;

    xrpc_ok("requestPlcOperationSignature", resp, client.observer())
        .await
        .map(|_| ())
}

/// Sign a PLC operation with credentials from the PDS.
pub async fn sign_plc_operation(
    client: &OAuthClient,
    request: &SignPlcOperationRequest,
) -> Result<SignPlcOperationResponse, PdsClientError> {
    let resp = client
        .post("/xrpc/com.atproto.identity.signPlcOperation", request)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("sign_plc_operation failed: {}", e),
        })?;

    xrpc_json("signPlcOperation", resp, client.observer()).await
}

/// Fetch recommended credentials for the DID from the PDS.
pub async fn get_recommended_did_credentials(
    client: &OAuthClient,
) -> Result<RecommendedCredentials, PdsClientError> {
    let resp = client
        .get("/xrpc/com.atproto.identity.getRecommendedDidCredentials")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("get_recommended_did_credentials failed: {}", e),
        })?;

    xrpc_json("getRecommendedDidCredentials", resp, client.observer()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    #[test]
    fn test_sign_plc_operation_request_skip_none_fields() {
        let req = SignPlcOperationRequest {
            token: "test_token".to_string(),
            rotation_keys: None,
            also_known_as: None,
            verification_methods: None,
            services: None,
        };

        let json = serde_json::to_string(&req).expect("serialization failed");
        // Verify that None fields are skipped
        assert!(!json.contains("rotationKeys"));
        assert!(!json.contains("alsoKnownAs"));
        assert!(json.contains("token"));
    }

    /// request_plc_operation_signature sends correct request
    #[tokio::test]
    async fn test_request_plc_operation_signature_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.requestPlcOperationSignature")
                .header("Authorization", "Bearer test_access_token")
                // No-input procedure: a spec-strict PDS rejects any body or Content-Type.
                .is_true(|req| req.body_ref().is_empty())
                .is_true(|req| {
                    !req.headers_vec()
                        .iter()
                        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                });
            then.status(200).json_body(serde_json::json!({}));
        });

        // Create a test session and OAuthClient
        let oauth_client = OAuthClient::new_bearer(
            "test_access_token".to_string(),
            String::new(),
            mock_server.base_url(),
        )
        .unwrap();

        let result = request_plc_operation_signature(&oauth_client).await;
        assert!(result.is_ok());
    }

    /// request_plc_operation_signature handles error
    #[tokio::test]
    async fn test_request_plc_operation_signature_error() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.requestPlcOperationSignature");
            then.status(401).json_body(serde_json::json!({
                "error": "Unauthorized"
            }));
        });

        let oauth_client = OAuthClient::new_bearer(
            "test_access_token".to_string(),
            String::new(),
            mock_server.base_url(),
        )
        .unwrap();

        let result = request_plc_operation_signature(&oauth_client).await;
        assert!(result.is_err());
        // A 401 is classified as Unauthorized, not folded into a generic NetworkError.
        match result.unwrap_err() {
            PdsClientError::Unauthorized { .. } => {
                // Expected
            }
            e => panic!("Expected Unauthorized, got: {:?}", e),
        }
    }

    /// sign_plc_operation sends token and rotation keys
    #[tokio::test]
    async fn test_sign_plc_operation_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation")
                .header("Authorization", "Bearer test_access_token");
            then.status(200).json_body(serde_json::json!({
                "operation": {
                    "type": "plc_operation",
                    "prev": "bafytest123"
                }
            }));
        });

        let oauth_client = OAuthClient::new_bearer(
            "test_access_token".to_string(),
            String::new(),
            mock_server.base_url(),
        )
        .unwrap();

        let request = SignPlcOperationRequest {
            token: "test_email_token".to_string(),
            rotation_keys: Some(vec!["did:key:zQ3test1".to_string()]),
            also_known_as: None,
            verification_methods: None,
            services: None,
        };

        let result = sign_plc_operation(&oauth_client, &request).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.operation.get("type").is_some());
    }

    /// sign_plc_operation omits optional null fields
    #[tokio::test]
    async fn test_sign_plc_operation_omits_none_fields() {
        let mock_server = MockServer::start();

        let mock = mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation");
            then.status(200).json_body(serde_json::json!({
                "operation": {}
            }));
        });

        let oauth_client = OAuthClient::new_bearer(
            "test_access_token".to_string(),
            String::new(),
            mock_server.base_url(),
        )
        .unwrap();

        let request = SignPlcOperationRequest {
            token: "test_token".to_string(),
            rotation_keys: None,
            also_known_as: None,
            verification_methods: None,
            services: None,
        };

        let result = sign_plc_operation(&oauth_client, &request).await;
        assert!(result.is_ok());

        // Verify the mock was hit (request was made)
        assert_eq!(mock.calls(), 1);
    }

    /// get_recommended_did_credentials returns credentials
    #[tokio::test]
    async fn test_get_recommended_did_credentials_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials")
                .header("Authorization", "Bearer test_access_token");
            then.status(200).json_body(serde_json::json!({
                "rotationKeys": ["did:key:zQ3test1"],
                "alsoKnownAs": ["at://alice.test"]
            }));
        });

        let oauth_client = OAuthClient::new_bearer(
            "test_access_token".to_string(),
            String::new(),
            mock_server.base_url(),
        )
        .unwrap();

        let result = get_recommended_did_credentials(&oauth_client).await;
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert!(creds.rotation_keys.is_some());
        assert!(creds.also_known_as.is_some());
    }

    /// XRPC get_recommended_did_credentials error: returns NetworkError on 403
    #[tokio::test]
    async fn test_get_recommended_did_credentials_error() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials");
            then.status(403).json_body(serde_json::json!({
                "error": "Forbidden"
            }));
        });

        let oauth_client = OAuthClient::new_bearer(
            "test_access_token".to_string(),
            String::new(),
            mock_server.base_url(),
        )
        .unwrap();

        let result = get_recommended_did_credentials(&oauth_client).await;
        assert!(result.is_err());
        // A 403 is a classified server rejection: XrpcError carrying status + error code.
        match result.unwrap_err() {
            PdsClientError::XrpcError { status: 403, .. } => {
                // Expected
            }
            e => panic!("Expected XrpcError(403), got: {:?}", e),
        }
    }

    /// sign_plc_operation surfaces an HTTP error through classify_xrpc_response: a non-nonce 400
    /// becomes a structured XrpcError carrying the server's status + error code, not a flattened
    /// NetworkError. (The DPoP OAuthClient does not swallow non-`use_dpop_nonce` 400s.)
    #[tokio::test]
    async fn test_sign_plc_operation_error() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation");
            then.status(400).json_body(serde_json::json!({
                "error": "invalid_token"
            }));
        });

        let oauth_client = OAuthClient::new_bearer(
            "test_access_token".to_string(),
            String::new(),
            mock_server.base_url(),
        )
        .unwrap();

        let request = SignPlcOperationRequest {
            token: "test_email_token".to_string(),
            rotation_keys: None,
            also_known_as: None,
            verification_methods: None,
            services: None,
        };

        let result = sign_plc_operation(&oauth_client, &request).await;
        assert!(result.is_err());
        // The 400 `invalid_token` reaches classify_xrpc_response intact, so it is classified as an
        // XrpcError that preserves the server's status and atproto error code — the whole point of
        // surfacing (rather than swallowing) a non-nonce 400 in the DPoP client.
        match result.unwrap_err() {
            PdsClientError::XrpcError { status, error, .. } => {
                assert_eq!(status, 400, "status must be preserved");
                assert_eq!(
                    error.as_deref(),
                    Some("invalid_token"),
                    "the atproto error code must be preserved"
                );
            }
            e => panic!("Expected XrpcError(400, invalid_token), got: {:?}", e),
        }
    }
}
