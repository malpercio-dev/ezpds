use super::oauth::par_rejection_message;
use super::*;
use crate::error::NoopObserver;
use httpmock::prelude::*;

/// A caller-supplied redirect URI; this crate never derives one (see `pds_par`).
const REDIRECT_URI: &str = "org.example.client:/oauth/callback";

/// A failed PAR surfaces the AS's own error/error_description; non-OAuth bodies
/// fall back to the raw status + body.
#[test]
fn par_rejection_message_extracts_oauth_error() {
    let status = reqwest::StatusCode::BAD_REQUEST;
    assert_eq!(
        par_rejection_message(
            status,
            r#"{"error":"invalid_redirect_uri","error_description":"scheme mismatch"}"#
        ),
        "invalid_redirect_uri: scheme mismatch"
    );
    assert_eq!(
        par_rejection_message(status, r#"{"error":"invalid_request"}"#),
        "invalid_request"
    );
    assert_eq!(
        par_rejection_message(status, "<html>gateway error</html>"),
        "PAR returned 400 Bad Request: <html>gateway error</html>"
    );
}

// A did:web document carries absolute-form ids ("did:web:host#atproto_pds"), unlike
// plc.directory's bare fragments ("#atproto_pds"). Both must key the services map by
// the fragment alone, or `discover_pds` reports "missing atproto_pds service" for a
// perfectly valid did:web document.
#[test]
fn test_into_plc_doc_keys_services_by_fragment_for_absolute_ids() {
    let did = "did:web:rehearsal.example";
    let w3c_doc: W3cDidDocument = serde_json::from_value(serde_json::json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "alsoKnownAs": ["at://rehearsal.example"],
        "verificationMethod": [
            {
                "id": format!("{did}#device"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": "zDnaDevice"
            },
            {
                "id": format!("{did}#atproto"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": "zDnaRepo"
            }
        ],
        "service": [{
            "id": format!("{did}#atproto_pds"),
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": "https://pds.example"
        }]
    }))
    .expect("document deserializes");

    let doc = w3c_doc.into_plc_doc();
    let pds = doc
        .services
        .get("atproto_pds")
        .expect("service keyed by fragment, not the absolute id");
    assert_eq!(pds.endpoint, "https://pds.example");
    assert_eq!(doc.verification_methods["atproto"], "zDnaRepo");
    assert_eq!(doc.verification_methods["device"], "zDnaDevice");
}

// ============================================================================
// HTTP fallback resolution tests
// ============================================================================

/// HTTP fallback resolves handle to DID
#[tokio::test]
async fn test_try_resolve_http_success() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/.well-known/atproto-did");
        then.status(200).body("did:plc:test123");
    });

    let client = reqwest::Client::new();
    let url = format!("{}/.well-known/atproto-did", mock_server.base_url());
    let result = try_resolve_http(&client, &url, &NoopObserver).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Some("did:plc:test123".to_string()));
}

/// HTTP fallback handles response body with whitespace
#[tokio::test]
async fn test_try_resolve_http_with_whitespace() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/.well-known/atproto-did");
        then.status(200).body("  did:plc:test123\n  ");
    });

    let client = reqwest::Client::new();
    let url = format!("{}/.well-known/atproto-did", mock_server.base_url());
    let result = try_resolve_http(&client, &url, &NoopObserver).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Some("did:plc:test123".to_string()));
}

/// HTTP fallback returns Ok(None) on 404 client error
#[tokio::test]
async fn test_try_resolve_http_not_found() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/.well-known/atproto-did");
        then.status(404);
    });

    let client = reqwest::Client::new();
    let url = format!("{}/.well-known/atproto-did", mock_server.base_url());
    let result = try_resolve_http(&client, &url, &NoopObserver).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), None);
}

/// HTTP fallback returns NetworkError on 500 server error
#[tokio::test]
async fn test_try_resolve_http_server_error() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/.well-known/atproto-did");
        then.status(500);
    });

    let client = reqwest::Client::new();
    let url = format!("{}/.well-known/atproto-did", mock_server.base_url());
    let result = try_resolve_http(&client, &url, &NoopObserver).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        PdsClientError::NetworkError { .. } => {
            // Expected: 5xx is a server error, not a missing handle
        }
        e => panic!("Expected NetworkError on 5xx, got: {:?}", e),
    }
}

/// `PdsClient::new_for_test`'s default field values.
#[test]
fn test_pds_client_default() {
    let client = PdsClient::default();
    assert_eq!(client.plc_directory_url(), "https://plc.directory");
}

/// A plc.directory 429 on the audit-log read classifies as RateLimited (with the pacing
/// hint), not as a connectivity failure.
#[tokio::test]
async fn fetch_audit_log_429_is_rate_limited_not_network_error() {
    let mock_server = MockServer::start();
    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/did:plc:throttled/log/audit");
        then.status(429)
            .header("Retry-After", "30")
            .body(r#"{"message":"rate limit exceeded"}"#);
    });

    let client = PdsClient::new_for_test(mock_server.base_url());
    let err = client
        .fetch_audit_log("did:plc:throttled")
        .await
        .unwrap_err();
    match err {
        PdsClientError::RateLimited { retry_after, .. } => {
            assert_eq!(retry_after.as_deref(), Some("30"));
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

/// A plc.directory 5xx on the audit-log read is the directory's verdict — a status-classified
/// error, not NetworkError ("check your connection").
#[tokio::test]
async fn fetch_audit_log_500_is_status_classified_not_network_error() {
    let mock_server = MockServer::start();
    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/did:plc:outage/log/audit");
        then.status(500).body("upstream exploded");
    });

    let client = PdsClient::new_for_test(mock_server.base_url());
    let err = client.fetch_audit_log("did:plc:outage").await.unwrap_err();
    match err {
        PdsClientError::XrpcError { status, .. } => assert_eq!(status, 500),
        other => panic!("expected XrpcError, got {other:?}"),
    }
}

/// A plc.directory 404 keeps its dedicated DidNotFound classification.
#[tokio::test]
async fn fetch_audit_log_404_stays_did_not_found() {
    let mock_server = MockServer::start();
    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/did:plc:ghost/log/audit");
        then.status(404);
    });

    let client = PdsClient::new_for_test(mock_server.base_url());
    let err = client.fetch_audit_log("did:plc:ghost").await.unwrap_err();
    assert!(matches!(err, PdsClientError::DidNotFound));
}

/// A plc.directory 429 on an operation submit surfaces as RateLimited; a 400 rejection keeps
/// the InvalidResponse "rejected operation" shape callers rely on.
#[tokio::test]
async fn post_plc_operation_classifies_throttle_but_keeps_rejection_shape() {
    let mock_server = MockServer::start();
    mock_server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/did:plc:busy");
        then.status(429).header("Retry-After", "7").body("{}");
    });
    mock_server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/did:plc:badop");
        then.status(400).body(r#"{"message":"invalid prev"}"#);
    });

    let client = PdsClient::new_for_test(mock_server.base_url());
    let op = serde_json::json!({});
    match client
        .post_plc_operation("did:plc:busy", &op)
        .await
        .unwrap_err()
    {
        PdsClientError::RateLimited { retry_after, .. } => {
            assert_eq!(retry_after.as_deref(), Some("7"));
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
    match client
        .post_plc_operation("did:plc:badop", &op)
        .await
        .unwrap_err()
    {
        PdsClientError::InvalidResponse { message } => {
            assert!(message.contains("rejected operation"), "got: {message}");
        }
        other => panic!("expected InvalidResponse, got {other:?}"),
    }
}

/// PDS endpoint is extracted from DID document
#[tokio::test]
async fn test_discover_pds_extracts_endpoint() {
    let mock_server = MockServer::start();
    let pds_endpoint = format!("{}/pds", mock_server.base_url());

    // W3C DID Document format (what plc.directory actually returns)
    let did_doc_json = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": "did:plc:test123",
        "alsoKnownAs": ["at://alice.example.com"],
        "verificationMethod": [{
            "id": "did:plc:test123#atproto",
            "type": "Multikey",
            "controller": "did:plc:test123",
            "publicKeyMultibase": "zQ3test1"
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": pds_endpoint
        }]
    });

    // Mock the plc.directory GET request
    mock_server.mock(|when, then| {
        when.method(GET).path("/did:plc:test123");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(did_doc_json);
    });

    // Mock the PDS reachability check (HEAD request for the service endpoint)
    mock_server.mock(|when, then| {
        when.method(httpmock::Method::HEAD).path("/pds");
        then.status(200);
    });

    let client = PdsClient::new_for_test(mock_server.base_url());
    let result = client.discover_pds("did:plc:test123").await;

    assert!(result.is_ok());
    let (pds_url, doc) = result.unwrap();
    assert!(pds_url.contains("/pds"));
    assert_eq!(doc.did, "did:plc:test123");
    assert_eq!(doc.also_known_as, vec!["at://alice.example.com"]);
    // W3C DID Document doesn't include rotation keys — they come from the audit log
    assert!(doc.rotation_keys.is_empty());
    // Service array converted to HashMap keyed by id (without '#' prefix)
    assert!(doc.services.contains_key("atproto_pds"));
    // verificationMethod array converted to { "atproto": "zQ3test1" }
    assert_eq!(doc.verification_methods["atproto"], "zQ3test1");
}

/// DID_NOT_FOUND error when plc.directory returns 404
#[tokio::test]
async fn test_discover_pds_did_not_found() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(GET).path("/did:plc:nonexistent");
        then.status(404);
    });

    let client = PdsClient::new_for_test(mock_server.base_url());
    let result = client.discover_pds("did:plc:nonexistent").await;

    assert!(result.is_err());
    match result.unwrap_err() {
        PdsClientError::DidNotFound => {
            // Expected
        }
        e => panic!("Expected DidNotFound, got: {:?}", e),
    }
}

/// PDS_UNREACHABLE error when PDS endpoint is down
#[tokio::test]
async fn test_discover_pds_pds_unreachable() {
    let mock_server = MockServer::start();

    let did_doc_json = serde_json::json!({
        "id": "did:plc:test123",
        "alsoKnownAs": [],
        "verificationMethod": [],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": "http://127.0.0.1:1"
        }]
    });

    mock_server.mock(|when, then| {
        when.method(GET).path("/did:plc:test123");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(did_doc_json);
    });

    let client = PdsClient::new_for_test(mock_server.base_url());
    let result = client.discover_pds("did:plc:test123").await;

    assert!(result.is_err());
    match result.unwrap_err() {
        PdsClientError::PdsUnreachable { .. } => {
            // Expected
        }
        e => panic!("Expected PdsUnreachable, got: {:?}", e),
    }
}

/// InvalidResponse error when atproto_pds service is missing
#[tokio::test]
async fn test_discover_pds_missing_service() {
    let mock_server = MockServer::start();

    let did_doc_json = serde_json::json!({
        "id": "did:plc:test123",
        "alsoKnownAs": [],
        "verificationMethod": [],
        "service": []
    });

    mock_server.mock(|when, then| {
        when.method(GET).path("/did:plc:test123");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(did_doc_json);
    });

    let client = PdsClient::new_for_test(mock_server.base_url());
    let result = client.discover_pds("did:plc:test123").await;

    assert!(result.is_err());
    match result.unwrap_err() {
        PdsClientError::InvalidResponse { .. } => {
            // Expected
        }
        e => panic!("Expected InvalidResponse, got: {:?}", e),
    }
}

/// Auth server metadata is fetched and validated
#[tokio::test]
async fn test_discover_auth_server_success() {
    let mock_server = MockServer::start();

    let metadata_json = serde_json::json!({
        "issuer": "https://pds.example.com",
        "authorization_endpoint": "https://pds.example.com/oauth/authorize",
        "token_endpoint": "https://pds.example.com/oauth/token",
        "pushed_authorization_request_endpoint": "https://pds.example.com/oauth/par",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "scopes_supported": ["atproto", "transition:generic"]
    });

    mock_server.mock(|when, then| {
        when.method(GET)
            .path("/.well-known/oauth-authorization-server");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(metadata_json);
    });

    let client = PdsClient::new();
    let result = client.discover_auth_server(&mock_server.base_url()).await;

    assert!(result.is_ok());
    let metadata = result.unwrap();
    assert_eq!(metadata.issuer, "https://pds.example.com");
    assert_eq!(
        metadata.authorization_endpoint,
        "https://pds.example.com/oauth/authorize"
    );
    assert_eq!(
        metadata.token_endpoint,
        "https://pds.example.com/oauth/token"
    );
    assert!(metadata
        .response_types_supported
        .contains(&"code".to_string()));
    assert!(metadata
        .code_challenge_methods_supported
        .contains(&"S256".to_string()));
}

/// discover_auth_server rejects missing S256
#[tokio::test]
async fn test_discover_auth_server_missing_s256() {
    let mock_server = MockServer::start();

    let metadata_json = serde_json::json!({
        "issuer": "https://pds.example.com",
        "authorization_endpoint": "https://pds.example.com/oauth/authorize",
        "token_endpoint": "https://pds.example.com/oauth/token",
        "pushed_authorization_request_endpoint": "https://pds.example.com/oauth/par",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["plain"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "scopes_supported": ["atproto"]
    });

    mock_server.mock(|when, then| {
        when.method(GET)
            .path("/.well-known/oauth-authorization-server");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(metadata_json);
    });

    let client = PdsClient::new();
    let result = client.discover_auth_server(&mock_server.base_url()).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        PdsClientError::InvalidResponse { message } => {
            assert!(message.contains("S256"));
        }
        e => panic!("Expected InvalidResponse, got: {:?}", e),
    }
}

/// discover_auth_server rejects missing "code" response type
#[tokio::test]
async fn test_discover_auth_server_missing_code_response_type() {
    let mock_server = MockServer::start();

    let metadata_json = serde_json::json!({
        "issuer": "https://pds.example.com",
        "authorization_endpoint": "https://pds.example.com/oauth/authorize",
        "token_endpoint": "https://pds.example.com/oauth/token",
        "pushed_authorization_request_endpoint": "https://pds.example.com/oauth/par",
        "response_types_supported": ["id_token"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "scopes_supported": ["atproto"]
    });

    mock_server.mock(|when, then| {
        when.method(GET)
            .path("/.well-known/oauth-authorization-server");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(metadata_json);
    });

    let client = PdsClient::new();
    let result = client.discover_auth_server(&mock_server.base_url()).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        PdsClientError::InvalidResponse { message } => {
            assert!(message.contains("code"));
        }
        e => panic!("Expected InvalidResponse, got: {:?}", e),
    }
}

/// discover_auth_server returns InvalidResponse on HTTP error
#[tokio::test]
async fn test_discover_auth_server_pds_unreachable() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(GET)
            .path("/.well-known/oauth-authorization-server");
        then.status(500);
    });

    let client = PdsClient::new();
    let result = client.discover_auth_server(&mock_server.base_url()).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        PdsClientError::InvalidResponse { .. } => {
            // Expected: HTTP errors are InvalidResponse, not PdsUnreachable
        }
        e => panic!("Expected InvalidResponse, got: {:?}", e),
    }
}

/// DNS TXT resolution (integration test, ignored for CI)
///
/// This requires real DNS access and tests against a known public handle.
/// Run manually with `cargo test -- --ignored --nocapture` if DNS is available.
#[tokio::test]
#[ignore]
async fn test_resolve_handle_dns_txt_integration() {
    // This test requires real DNS and uses a stable handle
    let result = try_resolve_dns("jay.bsky.team", &NoopObserver).await;

    match result {
        Ok(Some(did)) => {
            assert!(did.starts_with("did:plc:") || did.starts_with("did:key:"));
        }
        Ok(None) => {
            panic!("DNS lookup returned None for known handle");
        }
        Err(e) => {
            panic!("DNS lookup failed: {}", e);
        }
    }
}

/// PAR sends correct request with PKCE, DPoP, and optional login_hint
#[tokio::test]
async fn test_pds_par_sends_correct_request() {
    let mock_server = MockServer::start();

    let mock_par = mock_server.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/oauth/par")
            .header_exists("DPoP");
        then.status(200).json_body(serde_json::json!({
            "request_uri": "urn:ietf:params:oauth:request_uri:test",
            "expires_in": 60
        }));
    });

    let metadata = AuthServerMetadata {
        issuer: mock_server.base_url(),
        authorization_endpoint: format!("{}/oauth/authorize", mock_server.base_url()),
        token_endpoint: format!("{}/oauth/token", mock_server.base_url()),
        pushed_authorization_request_endpoint: Some(format!(
            "{}/oauth/par",
            mock_server.base_url()
        )),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        dpop_signing_alg_values_supported: Some(vec!["ES256".to_string()]),
        scopes_supported: Some(vec!["atproto".to_string()]),
    };

    let client = PdsClient::new();
    let result = client
        .pds_par(
            &metadata,
            PdsParRequest {
                pkce_challenge: "test_pkce_challenge",
                state_param: "test_state",
                dpop_proof: "test_dpop_proof",
                dpop_jkt: "test_dpop_jkt",
                login_hint: Some("user@example.com"),
                client_id: "https://test.example.com/oauth/client-metadata.json",
                redirect_uri: REDIRECT_URI,
            },
        )
        .await;

    assert!(result.is_ok());
    let par_response = result.unwrap();
    assert_eq!(
        par_response.request_uri,
        "urn:ietf:params:oauth:request_uri:test"
    );
    assert_eq!(par_response.expires_in, 60);
    assert_eq!(mock_par.calls(), 1);
}

/// PAR without login_hint
#[tokio::test]
async fn test_pds_par_without_login_hint() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/oauth/par");
        then.status(200).json_body(serde_json::json!({
            "request_uri": "urn:ietf:params:oauth:request_uri:test2",
            "expires_in": 120
        }));
    });

    let metadata = AuthServerMetadata {
        issuer: mock_server.base_url(),
        authorization_endpoint: format!("{}/oauth/authorize", mock_server.base_url()),
        token_endpoint: format!("{}/oauth/token", mock_server.base_url()),
        pushed_authorization_request_endpoint: Some(format!(
            "{}/oauth/par",
            mock_server.base_url()
        )),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        dpop_signing_alg_values_supported: None,
        scopes_supported: None,
    };

    let client = PdsClient::new();
    let result = client
        .pds_par(
            &metadata,
            PdsParRequest {
                pkce_challenge: "challenge",
                state_param: "state",
                dpop_proof: "proof",
                dpop_jkt: "jkt",
                login_hint: None,
                client_id: "https://test.example.com/oauth/client-metadata.json",
                redirect_uri: REDIRECT_URI,
            },
        )
        .await;

    assert!(result.is_ok());
}

/// PAR failure returns OauthFailed
#[tokio::test]
async fn test_pds_par_failure() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/oauth/par");
        then.status(400).json_body(serde_json::json!({
            "error": "invalid_request",
            "error_description": "missing code_challenge"
        }));
    });

    let metadata = AuthServerMetadata {
        issuer: mock_server.base_url(),
        authorization_endpoint: format!("{}/oauth/authorize", mock_server.base_url()),
        token_endpoint: format!("{}/oauth/token", mock_server.base_url()),
        pushed_authorization_request_endpoint: Some(format!(
            "{}/oauth/par",
            mock_server.base_url()
        )),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        dpop_signing_alg_values_supported: None,
        scopes_supported: None,
    };

    let client = PdsClient::new();
    let result = client
        .pds_par(
            &metadata,
            PdsParRequest {
                pkce_challenge: "challenge",
                state_param: "state",
                dpop_proof: "proof",
                dpop_jkt: "jkt",
                login_hint: None,
                client_id: "https://test.example.com/oauth/client-metadata.json",
                redirect_uri: REDIRECT_URI,
            },
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        PdsClientError::OauthFailed { .. } => {
            // Expected
        }
        e => panic!("Expected OauthFailed, got: {:?}", e),
    }
}

/// Token exchange sends correct request
#[tokio::test]
async fn test_pds_token_exchange_sends_correct_request() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/oauth/token")
            .header_exists("DPoP");
        then.status(200).json_body(serde_json::json!({
            "access_token": "test_access_token",
            "token_type": "DPoP",
            "expires_in": 300,
            "refresh_token": "test_refresh_token",
            "scope": "atproto transition:generic"
        }));
    });

    let metadata = AuthServerMetadata {
        issuer: mock_server.base_url(),
        authorization_endpoint: format!("{}/oauth/authorize", mock_server.base_url()),
        token_endpoint: format!("{}/oauth/token", mock_server.base_url()),
        pushed_authorization_request_endpoint: None,
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        dpop_signing_alg_values_supported: None,
        scopes_supported: None,
    };

    let client = PdsClient::new();
    let result = client
        .pds_token_exchange(
            &metadata,
            PdsTokenExchangeRequest {
                code: "test_code",
                pkce_verifier: "test_verifier",
                dpop_proof: "test_dpop_proof",
                client_id: "https://test.example.com/oauth/client-metadata.json",
                redirect_uri: REDIRECT_URI,
            },
        )
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status().as_u16(), 200);
}

/// Token exchange returns raw response on non-2xx
#[tokio::test]
async fn test_pds_token_exchange_returns_raw_response_on_error() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/oauth/token");
        then.status(400).json_body(serde_json::json!({
            "error": "use_dpop_nonce",
            "error_description": "nonce required"
        }));
    });

    let metadata = AuthServerMetadata {
        issuer: mock_server.base_url(),
        authorization_endpoint: format!("{}/oauth/authorize", mock_server.base_url()),
        token_endpoint: format!("{}/oauth/token", mock_server.base_url()),
        pushed_authorization_request_endpoint: None,
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        dpop_signing_alg_values_supported: None,
        scopes_supported: None,
    };

    let client = PdsClient::new();
    let result = client
        .pds_token_exchange(
            &metadata,
            PdsTokenExchangeRequest {
                code: "test_code",
                pkce_verifier: "test_verifier",
                dpop_proof: "test_dpop_proof",
                client_id: "https://test.example.com/oauth/client-metadata.json",
                redirect_uri: REDIRECT_URI,
            },
        )
        .await;

    // Should return Ok(Response) with 400 status — caller handles error interpretation.
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status().as_u16(), 400);
}

/// Token exchange to unreachable endpoint returns OauthFailed
#[tokio::test]
async fn test_pds_token_exchange_unreachable_endpoint() {
    let metadata = AuthServerMetadata {
        issuer: "http://127.0.0.1:1".to_string(),
        authorization_endpoint: "http://127.0.0.1:1/oauth/authorize".to_string(),
        token_endpoint: "http://127.0.0.1:1/oauth/token".to_string(),
        pushed_authorization_request_endpoint: None,
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        dpop_signing_alg_values_supported: None,
        scopes_supported: None,
    };

    let client = PdsClient::new();
    let result = client
        .pds_token_exchange(
            &metadata,
            PdsTokenExchangeRequest {
                code: "test_code",
                pkce_verifier: "test_verifier",
                dpop_proof: "test_dpop_proof",
                client_id: "https://test.example.com/oauth/client-metadata.json",
                redirect_uri: REDIRECT_URI,
            },
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        PdsClientError::OauthFailed { .. } => {
            // Expected
        }
        e => panic!("Expected OauthFailed, got: {:?}", e),
    }
}

/// build_pds_authorize_url constructs correct URL
#[test]
fn test_build_pds_authorize_url_with_login_hint() {
    let metadata = AuthServerMetadata {
        issuer: "https://pds.example.com".to_string(),
        authorization_endpoint: "https://pds.example.com/oauth/authorize".to_string(),
        token_endpoint: "https://pds.example.com/oauth/token".to_string(),
        pushed_authorization_request_endpoint: None,
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        dpop_signing_alg_values_supported: None,
        scopes_supported: None,
    };

    let url = PdsClient::build_pds_authorize_url(
        &metadata,
        "urn:ietf:params:oauth:request_uri:test",
        Some("user@example.com"),
        "https://test.example.com/oauth/client-metadata.json",
    );

    assert!(url.contains("client_id=https%3A%2F%2Ftest.example.com%2Foauth%2Fclient-metadata.json"));
    assert!(url.contains("request_uri="));
    assert!(url.contains("login_hint="));
    assert!(url.starts_with("https://pds.example.com/oauth/authorize?"));
}

/// build_pds_authorize_url without login_hint
#[test]
fn test_build_pds_authorize_url_without_login_hint() {
    let metadata = AuthServerMetadata {
        issuer: "https://pds.example.com".to_string(),
        authorization_endpoint: "https://pds.example.com/oauth/authorize".to_string(),
        token_endpoint: "https://pds.example.com/oauth/token".to_string(),
        pushed_authorization_request_endpoint: None,
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        dpop_signing_alg_values_supported: None,
        scopes_supported: None,
    };

    let url = PdsClient::build_pds_authorize_url(
        &metadata,
        "urn:ietf:params:oauth:request_uri:test2",
        None,
        "https://test.example.com/oauth/client-metadata.json",
    );

    assert!(url.contains("client_id=https%3A%2F%2Ftest.example.com%2Foauth%2Fclient-metadata.json"));
    assert!(url.contains("request_uri="));
    assert!(!url.contains("login_hint="));
    assert!(url.starts_with("https://pds.example.com/oauth/authorize?"));
}

/// resolve_handle returns HandleNotFound when both DNS and HTTP fail
/// This test uses a nonexistent .test TLD which DNS will reject, then attempts HTTP
/// which will fail due to inability to connect. Both failures result in HandleNotFound.
#[tokio::test]
async fn test_resolve_handle_orchestration_nonexistent() {
    let client = PdsClient::new();
    // Use a nonexistent handle on .test TLD (reserved, non-routable domain)
    // DNS will fail (no records found) and HTTP to https://.../.well-known/atproto-did
    // will fail (unable to resolve/connect). Both failures return HandleNotFound.
    let result = client
        .resolve_handle("this-handle-definitely-does-not-exist-12345.test")
        .await;

    assert!(result.is_err());
    // The error could be HandleNotFound if DNS+HTTP both fail, or NetworkError
    // if the HTTP request itself fails before we can determine there's no record.
    // We accept both as evidence that the handle cannot be resolved.
    match result.unwrap_err() {
        PdsClientError::HandleNotFound | PdsClientError::NetworkError { .. } => {
            // Expected: either no handle found or network failure during resolution
        }
        e => panic!("Expected HandleNotFound or NetworkError, got: {:?}", e),
    }
}

/// fetch_audit_log returns the raw JSON audit log array on success
#[tokio::test]
async fn test_fetch_audit_log_success() {
    let mock_server = MockServer::start();

    let audit_log_json = serde_json::json!([
        {
            "did": "did:plc:test123",
            "cid": "bafy123456789",
            "createdAt": "2024-01-01T00:00:00Z",
            "nullified": false,
            "operation": {
                "sig": "test_sig",
                "prev": serde_json::json!(null),
                "type": "plc_operation",
                "rotationKeys": ["did:key:z123"],
                "verificationMethods": {},
                "alsoKnownAs": [],
                "services": {}
            }
        }
    ]);

    mock_server.mock(|when, then| {
        when.method(GET).path("/did:plc:test123/log/audit");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(audit_log_json.clone());
    });

    let client = PdsClient::new_for_test(mock_server.base_url());
    let result = client.fetch_audit_log("did:plc:test123").await;

    assert!(result.is_ok());
    let json_str = result.unwrap();
    // Verify it parses as valid JSON array
    let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(&json_str);
    assert!(parsed.is_ok());
    assert_eq!(parsed.unwrap().len(), 1);
}

/// fetch_audit_log returns DidNotFound on 404
#[tokio::test]
async fn test_fetch_audit_log_not_found() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(GET).path("/did:plc:notfound/log/audit");
        then.status(404);
    });

    let client = PdsClient::new_for_test(mock_server.base_url());
    let result = client.fetch_audit_log("did:plc:notfound").await;

    assert!(result.is_err());
    match result.unwrap_err() {
        PdsClientError::DidNotFound => {
            // Expected
        }
        e => panic!("Expected DidNotFound, got: {:?}", e),
    }
}

/// post_plc_operation succeeds with 200 response
#[tokio::test]
async fn test_post_plc_operation_success() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/did:plc:test123");
        then.status(200);
    });

    let client = PdsClient::new_for_test(mock_server.base_url());
    let operation = serde_json::json!({
        "type": "plc_operation",
        "prev": "bafy123",
        "rotationKeys": ["did:key:z123"]
    });

    let result = client
        .post_plc_operation("did:plc:test123", &operation)
        .await;

    assert!(result.is_ok());
}

/// post_plc_operation returns InvalidResponse with error body on non-2xx
#[tokio::test]
async fn test_post_plc_operation_conflict() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/did:plc:test123");
        then.status(409).body("Conflicting operation");
    });

    let client = PdsClient::new_for_test(mock_server.base_url());
    let operation = serde_json::json!({
        "type": "plc_operation"
    });

    let result = client
        .post_plc_operation("did:plc:test123", &operation)
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        PdsClientError::InvalidResponse { message } => {
            assert!(message.contains("Conflicting operation"));
        }
        e => panic!("Expected InvalidResponse, got: {:?}", e),
    }
}

/// fetch_repo_car requests correct endpoint without auth and returns CAR bytes
#[tokio::test]
async fn test_fetch_repo_car_success() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getRepo")
            .query_param("did", "did:plc:test123")
            // This endpoint is auth:none — the request must carry no Authorization header.
            .is_true(|req| {
                !req.headers_vec()
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            });
        then.status(200)
            .header("content-type", "application/vnd.ipld.car")
            .body("CAR header and data");
    });

    let client = PdsClient::new();
    let result = client
        .fetch_repo_car(&mock_server.base_url(), "did:plc:test123")
        .await;

    assert!(result.is_ok());
    let bytes = result.unwrap();
    assert_eq!(bytes, "CAR header and data".as_bytes());
}

/// fetch_repo_car returns NetworkError on non-2xx status
#[tokio::test]
async fn test_fetch_repo_car_error() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getRepo")
            .query_param("did", "did:plc:notfound");
        then.status(404).body("not found");
    });

    let client = PdsClient::new();
    let result = client
        .fetch_repo_car(&mock_server.base_url(), "did:plc:notfound")
        .await;

    assert!(result.is_err());
    // A 404 is a classified server response, carrying the status and body message.
    match result.unwrap_err() {
        PdsClientError::XrpcError {
            status: 404,
            message,
            ..
        } => {
            assert!(message.contains("not found"));
        }
        e => panic!("Expected XrpcError(404), got: {:?}", e),
    }
}

/// fetch_blob requests correct endpoint without auth and returns blob bytes
#[tokio::test]
async fn test_fetch_blob_success() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getBlob")
            .query_param("did", "did:plc:test123")
            .query_param("cid", "bafy123")
            // This endpoint is auth:none — the request must carry no Authorization header.
            .is_true(|req| {
                !req.headers_vec()
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            });
        then.status(200)
            .header("content-type", "application/octet-stream")
            .body("blob data");
    });

    let client = PdsClient::new();
    let result = client
        .fetch_blob(&mock_server.base_url(), "did:plc:test123", "bafy123")
        .await;

    assert!(result.is_ok());
    let bytes = result.unwrap();
    assert_eq!(bytes, "blob data".as_bytes());
}

/// fetch_blob returns NetworkError on non-2xx status
#[tokio::test]
async fn test_fetch_blob_error() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getBlob")
            .query_param("did", "did:plc:test123")
            .query_param("cid", "bafy_notfound");
        then.status(404).body("blob not found");
    });

    let client = PdsClient::new();
    let result = client
        .fetch_blob(&mock_server.base_url(), "did:plc:test123", "bafy_notfound")
        .await;

    assert!(result.is_err());
    // A 404 is a classified server response, carrying the status and body message.
    match result.unwrap_err() {
        PdsClientError::XrpcError {
            status: 404,
            message,
            ..
        } => {
            assert!(message.contains("blob not found"));
        }
        e => panic!("Expected XrpcError(404), got: {:?}", e),
    }
}

/// reserve_signing_key POSTs {"did": did} and parses signingKey response
#[tokio::test]
async fn test_reserve_signing_key_success() {
    let mock_server = MockServer::start();
    let signing_key = "did:key:z6Mkq2r...";

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.reserveSigningKey")
            .body_includes("did:plc:test123");
        then.status(200).json_body(serde_json::json!({
            "signingKey": signing_key
        }));
    });

    let client = PdsClient::new();
    let result = client
        .reserve_signing_key(&mock_server.base_url(), Some("did:plc:test123"))
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), signing_key);
}

/// reserve_signing_key returns NetworkError on non-2xx status
#[tokio::test]
async fn test_reserve_signing_key_error() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.reserveSigningKey");
        then.status(400).body("invalid did");
    });

    let client = PdsClient::new();
    let result = client
        .reserve_signing_key(&mock_server.base_url(), Some("invalid"))
        .await;

    assert!(result.is_err());
    // A 400 is a classified server rejection: XrpcError carrying the status.
    match result.unwrap_err() {
        PdsClientError::XrpcError { status: 400, .. } => {
            // Expected
        }
        e => panic!("Expected XrpcError(400), got: {:?}", e),
    }
}

/// describe_server parses the response correctly
#[tokio::test]
async fn test_describe_server_success() {
    let mock_server = MockServer::start();

    let response = serde_json::json!({
        "did": "did:web:dest.example.com",
        "availableUserDomains": [".dest.example.com"]
    });

    mock_server.mock(|when, then| {
        when.method(GET)
            .path("/xrpc/com.atproto.server.describeServer");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(response);
    });

    let client = PdsClient::new();
    let result = client.describe_server(&mock_server.base_url()).await;

    assert!(result.is_ok());
    let desc = result.unwrap();
    assert_eq!(desc.did, "did:web:dest.example.com");
    assert_eq!(desc.available_user_domains, vec![".dest.example.com"]);
}

/// describe_server maps non-2xx to PdsUnreachable
#[tokio::test]
async fn test_describe_server_non_2xx() {
    let mock_server = MockServer::start();

    mock_server.mock(|when, then| {
        when.method(GET)
            .path("/xrpc/com.atproto.server.describeServer");
        then.status(500);
    });

    let client = PdsClient::new();
    let result = client.describe_server(&mock_server.base_url()).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        PdsClientError::PdsUnreachable { .. } => {
            // Expected
        }
        e => panic!("Expected PdsUnreachable, got: {:?}", e),
    }
}
