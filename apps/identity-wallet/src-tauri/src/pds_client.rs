// pattern: Mixed (unavoidable)

//! Re-exports [`custos_client::PdsClient`] — discovery/auth/XRPC against *arbitrary* PDS
//! endpoints and plc.directory — under this module's historical path, plus
//! [`new_with_diagnostics`] (wires this app's diagnostics + `pds_capabilities` observers) and
//! [`try_resolve_dns`] (same, for the change-handle DNS pre-flight). See
//! `custos_client::pds_client`'s module doc for `PdsClient`'s own behavior and method
//! inventory.
//!
//! **The wallet's OAuth identity** also lives here: [`CANONICAL_CLIENT_ID`],
//! [`REDIRECT_URI`], [`CALLBACK_SCHEME`], [`client_id_for_pds`] (fixed canonical URL except
//! a loopback base, which derives its own). The redirect scheme is the client_id host in
//! reverse-FQDN order — the constants' docs carry the spec rule and the sync requirement
//! with the Custos client-metadata route and the V042-seeded `oauth_clients` row. This stays
//! here rather than in `custos-client`: it names the wallet app itself, not a thing another
//! app could share — `PdsClient::pds_par`/`pds_token_exchange` take `client_id`/
//! `redirect_uri` as plain parameters instead of deriving them.
//!
//! **Module-level XRPC helpers** take an `&OAuthClient` instead of being `PdsClient`
//! methods — they need an authenticated client the plain one cannot provide, keeping
//! `PdsClient` focused on unauthenticated work: the claim trio
//! (`request_plc_operation_signature`, `sign_plc_operation`,
//! `get_recommended_did_credentials`); the migration set (`get_service_auth`,
//! `create_account_migration` — HTTP 409 → `DidAlreadyExists` for resume — `import_repo`,
//! `upload_blob`, `list_missing_blobs`, `get_preferences`, `put_preferences`,
//! `check_account_status`, `activate_account`, `deactivate_account`,
//! `request_account_delete`); the app-password trio (`create_app_password`,
//! `list_app_passwords`, `revoke_app_password`). All three groups are thin same-signature
//! wrappers over `custos_client::{identity,migration,app_passwords}` — the request/response
//! logic and types live there; this file supplies this app's diagnostics observer.
//!
//! **Error reachability.** `PdsClientError` serializes as `{ code: "SCREAMING_SNAKE_CASE" }`
//! (`PdsUnreachable.reason` is serde-skipped). The discovery/resolve variants
//! (`HandleNotFound`, `DidNotFound`, `PdsUnreachable`, `NetworkError`, `InvalidResponse`,
//! `OauthFailed`) can reach the frontend directly; the status-classified trio
//! (`RateLimited`, `Unauthorized`, `XrpcError`) is mapped into each command's own error
//! enum first (e.g. `ClaimError`); `DidAlreadyExists` is migration-internal; and
//! `InvalidCredentials`/`AuthFactorTokenRequired`/`InsecurePdsUrl` are claim-flow-internal,
//! mapped by `authenticate_source_pds`. [`PlcDidDocument`] and [`PlcService`] derive
//! `Clone` so claim state can be cloned out of the tokio mutex before network calls.

use std::sync::Arc;

/// OAuth client metadata path — the canonical client_id's path, also appended to a
/// loopback Custos base URL by the local-development exception in [`client_id_for_pds`].
const CLIENT_METADATA_PATH: &str = "/oauth/client-metadata.json";

/// The wallet's canonical OAuth client_id: its client-metadata document, served by the
/// production Custos at a stable wallet-owned host. The atproto OAuth spec requires a
/// native client's private-use redirect scheme to be the client_id host's FQDN in
/// reverse order — `identitywallet.obsign.org` ⇄ `org.obsign.identitywallet:` — and
/// third-party authorization servers (bsky.social) enforce it. Must stay in sync with
/// [`REDIRECT_URI`]/[`CALLBACK_SCHEME`], the Custos client-metadata route, and the
/// V042-seeded `oauth_clients` row.
pub const CANONICAL_CLIENT_ID: &str =
    "https://identitywallet.obsign.org/oauth/client-metadata.json";

/// OAuth redirect URI. The private-use scheme is the canonical client_id host reversed;
/// its scheme must match the `CFBundleURLTypes` entry in `src-tauri/Info.ios.plist`.
pub const REDIRECT_URI: &str = "org.obsign.identitywallet:/oauth/callback";

/// The redirect URI's scheme — what the auth-session plugin matches the callback on.
pub const CALLBACK_SCHEME: &str = "org.obsign.identitywallet";

/// The wallet's OAuth client_id.
///
/// This is the fixed [`CANONICAL_CLIENT_ID`]: the OAuth client is the wallet app, so
/// its identity does not vary with the Custos instance the user configured. The one
/// exception is a loopback Custos (local development), which serves a self-referencing
/// localhost document — there the client_id derives from the configured base so the
/// authorization server's fetch-and-match resolution still succeeds.
pub fn client_id_for_pds(custos_base_url: &str) -> String {
    if url_is_loopback(custos_base_url) {
        format!(
            "{}{}",
            custos_base_url.trim_end_matches('/'),
            CLIENT_METADATA_PATH
        )
    } else {
        CANONICAL_CLIENT_ID.to_string()
    }
}

/// Whether a URL string's host is loopback (unparseable → false).
fn url_is_loopback(base: &str) -> bool {
    let Ok(parsed) = url::Url::parse(base) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Error type for PDS client operations. Defined in `custos-client` (see its module doc for
/// the classification contract); re-exported here so the ~20 call sites across this app that
/// `use crate::pds_client::PdsClientError` are unaffected by the extraction.
pub use custos_client::PdsClientError;

// `PdsClient` itself (discovery/plc.directory/describeServer/createSession/OAuth-against-an-
// arbitrary-AS) moved to `custos-client`, alongside its request/response types. Re-exported
// here so this app's ~20 external references (`claim.rs`, `migration_orchestrator.rs`,
// `handle_change.rs`, etc.) are unaffected by the extraction.
pub use custos_client::pds_client::{
    rotation_keys_from_audit_log, AuthServerMetadata, CreateSessionResponse, CustosExtension,
    DeleteAccountProof, DeleteCredential, DescribeServerObserver, DescribeServerResponse,
    ListedBlobs, NoopDescribeServerObserver, PdsClient, PdsParRequest, PdsParResponse,
    PlcDidDocument, PlcService,
};

// The claim-trio and migration-set request/response types moved to
// `custos_client::identity`/`custos_client::migration` alongside the XRPC methods that use
// them; re-exported here so the wallet's existing `pds_client::{Type}` references (this
// file's own wrapper functions below, plus `claim.rs`/`migration_orchestrator.rs`) are
// unaffected.
pub use custos_client::identity::{
    RecommendedCredentials, SignPlcOperationRequest, SignPlcOperationResponse,
};
pub use custos_client::migration::{
    AccountStatus, CreateAccountMigrationRequest, CreateAccountResponse, MissingBlob, MissingBlobs,
    ServiceAuthToken, UploadBlobResponse,
};

/// Build a [`PdsClient`] wired to this app's diagnostics and `pds_capabilities` observers,
/// with the default plc.directory URL. The one production instance lives in `AppState`.
pub(crate) fn new_with_diagnostics() -> PdsClient {
    PdsClient::new_with_observers(
        Arc::new(crate::oauth::WalletTransportObserver),
        Arc::new(crate::oauth::WalletDescribeServerObserver),
    )
}

/// [`PdsClient`] wired to this app's real observers, with a caller-chosen plc.directory URL
/// (a mock server, in every current caller). Unlike `custos_client::PdsClient::new_for_test`
/// (which defaults to no-op observers, correct for a Tauri-free crate with nothing of its own
/// to record), this app's tests need the real `pds_capabilities` observer wired even in a test
/// fixture: `pds_capabilities::probe` reads its cache rather than `describe_server`'s return
/// value directly, so a no-op describe-observer silently starves it and any test exercising
/// capability-gated routing (see `password_unlock`/`share_recovery`) breaks quietly.
/// `#[cfg(test)]`, unlike the crate's own `new_for_test`: every caller of this one is inside
/// this crate's own test code, where `#[cfg(test)]` visibility applies normally (the
/// cross-crate restriction only bites when a *dependent* crate's test build needs to see a
/// *dependency's* `#[cfg(test)]` item).
#[cfg(test)]
pub(crate) fn new_for_test(plc_directory_url: String) -> PdsClient {
    new_with_diagnostics().with_plc_directory_url(plc_directory_url)
}

/// [`custos_client::pds_client::try_resolve_dns`], wired to this app's diagnostics observer.
/// Used by the change-handle DNS pre-flight to report this wallet-side vantage separately
/// from the hosting PDS's own resolution.
pub(crate) async fn try_resolve_dns(handle: &str) -> Result<Option<String>, PdsClientError> {
    custos_client::pds_client::try_resolve_dns(handle, &crate::oauth::WalletTransportObserver).await
}

// ============================================================================
// XRPC methods (require DPoP-authenticated OAuthClient)
// ============================================================================
//
// The typed methods themselves now live in `custos_client::{identity,app_passwords,migration}`
// — pure request/response wrappers with no wallet-specific side effects, so the move only
// needed each call site to gain this wallet's diagnostics observer. These are same-signature
// forwarding wrappers (no new parameter) so every existing caller in this app is unaffected.

/// Request a PLC operation signature from the PDS.
pub async fn request_plc_operation_signature(
    client: &crate::oauth_client::OAuthClient,
) -> Result<(), PdsClientError> {
    custos_client::identity::request_plc_operation_signature(
        client,
        &crate::oauth::WalletTransportObserver,
    )
    .await
}

/// Sign a PLC operation with credentials from the PDS.
pub async fn sign_plc_operation(
    client: &crate::oauth_client::OAuthClient,
    request: &SignPlcOperationRequest,
) -> Result<SignPlcOperationResponse, PdsClientError> {
    custos_client::identity::sign_plc_operation(
        client,
        request,
        &crate::oauth::WalletTransportObserver,
    )
    .await
}

/// Fetch recommended credentials for the DID from the PDS.
pub async fn get_recommended_did_credentials(
    client: &crate::oauth_client::OAuthClient,
) -> Result<RecommendedCredentials, PdsClientError> {
    custos_client::identity::get_recommended_did_credentials(
        client,
        &crate::oauth::WalletTransportObserver,
    )
    .await
}

// ============================================================================
// App-password management (full-access session required)
// ============================================================================

pub use custos_client::app_passwords::{AppPasswordCreated, AppPasswordEntry};

/// Mint a named app password on the hosting PDS.
pub async fn create_app_password(
    client: &crate::oauth_client::OAuthClient,
    name: &str,
    privileged: bool,
    personal_details: bool,
) -> Result<AppPasswordCreated, PdsClientError> {
    custos_client::app_passwords::create_app_password(
        client,
        name,
        privileged,
        personal_details,
        &crate::oauth::WalletTransportObserver,
    )
    .await
}

/// List the account's app passwords (names, creation times, privilege — never secrets).
pub async fn list_app_passwords(
    client: &crate::oauth_client::OAuthClient,
) -> Result<Vec<AppPasswordEntry>, PdsClientError> {
    custos_client::app_passwords::list_app_passwords(client, &crate::oauth::WalletTransportObserver)
        .await
}

/// Revoke a named app password (and, server-side, its sessions/refresh tokens atomically).
pub async fn revoke_app_password(
    client: &crate::oauth_client::OAuthClient,
    name: &str,
) -> Result<(), PdsClientError> {
    custos_client::app_passwords::revoke_app_password(
        client,
        name,
        &crate::oauth::WalletTransportObserver,
    )
    .await
}

// ============================================================================
// Migration XRPC helpers (Task 3, 4, 5)
// ============================================================================

/// Get service auth token for migration from the SOURCE PDS.
pub async fn get_service_auth(
    client: &crate::oauth_client::OAuthClient,
    aud: &str,
    lxm: &str,
) -> Result<ServiceAuthToken, PdsClientError> {
    custos_client::migration::get_service_auth(
        client,
        aud,
        lxm,
        &crate::oauth::WalletTransportObserver,
    )
    .await
}

/// Create account in migration mode on the destination PDS.
pub async fn create_account_migration(
    client: &crate::oauth_client::OAuthClient,
    req: &CreateAccountMigrationRequest,
) -> Result<CreateAccountResponse, PdsClientError> {
    custos_client::migration::create_account_migration(
        client,
        req,
        &crate::oauth::WalletTransportObserver,
    )
    .await
}

/// Import a CAR into the destination PDS repository.
pub async fn import_repo(
    client: &crate::oauth_client::OAuthClient,
    car: Vec<u8>,
) -> Result<(), PdsClientError> {
    custos_client::migration::import_repo(client, car, &crate::oauth::WalletTransportObserver).await
}

/// Upload a blob to the destination PDS.
pub async fn upload_blob(
    client: &crate::oauth_client::OAuthClient,
    mime: &str,
    bytes: Vec<u8>,
) -> Result<UploadBlobResponse, PdsClientError> {
    custos_client::migration::upload_blob(
        client,
        mime,
        bytes,
        &crate::oauth::WalletTransportObserver,
    )
    .await
}

/// List missing blobs on the destination PDS (one page).
pub async fn list_missing_blobs(
    client: &crate::oauth_client::OAuthClient,
    cursor: Option<&str>,
) -> Result<MissingBlobs, PdsClientError> {
    custos_client::migration::list_missing_blobs(
        client,
        cursor,
        &crate::oauth::WalletTransportObserver,
    )
    .await
}

/// Get the user's preferences.
pub async fn get_preferences(
    client: &crate::oauth_client::OAuthClient,
) -> Result<serde_json::Value, PdsClientError> {
    custos_client::migration::get_preferences(client, &crate::oauth::WalletTransportObserver).await
}

/// Put the user's preferences.
pub async fn put_preferences(
    client: &crate::oauth_client::OAuthClient,
    prefs: &serde_json::Value,
) -> Result<(), PdsClientError> {
    custos_client::migration::put_preferences(client, prefs, &crate::oauth::WalletTransportObserver)
        .await
}

/// Check the account status on the destination PDS.
pub async fn check_account_status(
    client: &crate::oauth_client::OAuthClient,
) -> Result<AccountStatus, PdsClientError> {
    custos_client::migration::check_account_status(client, &crate::oauth::WalletTransportObserver)
        .await
}

/// Activate the account on the destination PDS.
pub async fn activate_account(
    client: &crate::oauth_client::OAuthClient,
) -> Result<(), PdsClientError> {
    custos_client::migration::activate_account(client, &crate::oauth::WalletTransportObserver).await
}

/// Deactivate the account on the destination PDS.
pub async fn deactivate_account(
    client: &crate::oauth_client::OAuthClient,
    delete_after: Option<&str>,
) -> Result<(), PdsClientError> {
    custos_client::migration::deactivate_account(
        client,
        delete_after,
        &crate::oauth::WalletTransportObserver,
    )
    .await
}

/// Request permanent deletion of the authenticated account: mints and emails a single-use code.
pub async fn request_account_delete(
    client: &crate::oauth_client::OAuthClient,
) -> Result<(), PdsClientError> {
    custos_client::migration::request_account_delete(client, &crate::oauth::WalletTransportObserver)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    #[test]
    fn test_pds_client_default() {
        let client = PdsClient::default();
        assert_eq!(client.plc_directory_url(), "https://plc.directory");
    }

    /// The client_id is the fixed canonical URL for every non-loopback Custos — the
    /// app's OAuth identity must not vary with the configured server.
    #[test]
    fn client_id_is_canonical_for_public_custos() {
        assert_eq!(
            client_id_for_pds("https://pds.obsign.org"),
            CANONICAL_CLIENT_ID
        );
        assert_eq!(
            client_id_for_pds("https://ezpds-staging.up.railway.app/"),
            CANONICAL_CLIENT_ID
        );
    }

    /// Loopback dev exception: a local Custos serves a self-referencing localhost
    /// document, so the client_id derives from the configured base.
    #[test]
    fn client_id_derives_from_loopback_custos() {
        assert_eq!(
            client_id_for_pds("http://localhost:8080"),
            "http://localhost:8080/oauth/client-metadata.json"
        );
        assert_eq!(
            client_id_for_pds("http://127.0.0.1:8080/"),
            "http://127.0.0.1:8080/oauth/client-metadata.json"
        );
    }

    /// The redirect scheme is the canonical client_id host in reverse order — the
    /// pairing third-party authorization servers enforce.
    #[test]
    fn redirect_scheme_reverses_canonical_client_id_host() {
        let host = url::Url::parse(CANONICAL_CLIENT_ID)
            .unwrap()
            .host_str()
            .unwrap()
            .to_string();
        let reversed = host.split('.').rev().collect::<Vec<_>>().join(".");
        assert_eq!(REDIRECT_URI, format!("{reversed}:/oauth/callback"));
        assert_eq!(CALLBACK_SCHEME, reversed);
    }

    // `par_rejection_message` (a private PAR-error-formatting helper) and the pure XRPC
    // classification/`xrpc_json` unit tests now live in `custos_client`'s own test suite,
    // alongside the code they test.

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

        let client = crate::pds_client::new_for_test(mock_server.base_url());
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

        let client = crate::pds_client::new_for_test(mock_server.base_url());
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

        let client = crate::pds_client::new_for_test(mock_server.base_url());
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

        let client = crate::pds_client::new_for_test(mock_server.base_url());
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

    // ============================================================================
    // discover_pds and discover_auth_server tests
    // ============================================================================

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

        let client = crate::pds_client::new_for_test(mock_server.base_url());
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

    // `test_into_plc_doc_keys_services_by_fragment_for_absolute_ids` (tests the private
    // `W3cDidDocument::into_plc_doc`) moved to `custos_client`'s own test suite.

    /// DID_NOT_FOUND error when plc.directory returns 404
    #[tokio::test]
    async fn test_discover_pds_did_not_found() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(GET).path("/did:plc:nonexistent");
            then.status(404);
        });

        let client = crate::pds_client::new_for_test(mock_server.base_url());
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

        let client = crate::pds_client::new_for_test(mock_server.base_url());
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

        let client = crate::pds_client::new_for_test(mock_server.base_url());
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

    // ============================================================================
    // resolve_handle tests
    // ============================================================================

    /// HANDLE_NOT_FOUND error is returned correctly
    #[test]
    fn test_pds_client_error_handle_not_found() {
        let error = PdsClientError::HandleNotFound;
        assert_eq!(format!("{}", error), "handle not found");
    }

    /// DNS TXT resolution (integration test, ignored for CI)
    ///
    /// This requires real DNS access and tests against a known public handle.
    /// Run manually with `cargo test -- --ignored --nocapture` if DNS is available.
    #[tokio::test]
    #[ignore]
    async fn test_resolve_handle_dns_txt_integration() {
        // This test requires real DNS and uses a stable handle
        let result = try_resolve_dns("jay.bsky.team").await;

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

    // The `try_resolve_http` unit tests (a private PdsClient helper) moved to
    // `custos_client`'s own test suite, alongside the code they test.

    // ============================================================================
    // PAR and token exchange tests
    // ============================================================================

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
                "test_code",
                "test_verifier",
                "test_dpop_proof",
                "https://test.example.com/oauth/client-metadata.json",
                REDIRECT_URI,
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
                "test_code",
                "test_verifier",
                "test_dpop_proof",
                "https://test.example.com/oauth/client-metadata.json",
                REDIRECT_URI,
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
                "test_code",
                "test_verifier",
                "test_dpop_proof",
                "https://test.example.com/oauth/client-metadata.json",
                REDIRECT_URI,
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

        assert!(
            url.contains("client_id=https%3A%2F%2Ftest.example.com%2Foauth%2Fclient-metadata.json")
        );
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

        assert!(
            url.contains("client_id=https%3A%2F%2Ftest.example.com%2Foauth%2Fclient-metadata.json")
        );
        assert!(url.contains("request_uri="));
        assert!(!url.contains("login_hint="));
        assert!(url.starts_with("https://pds.example.com/oauth/authorize?"));
    }

    // ============================================================================
    // XRPC identity method tests
    // ============================================================================

    /// request_plc_operation_signature sends correct request
    #[tokio::test]
    async fn test_request_plc_operation_signature_success() {
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.requestPlcOperationSignature")
                .header_exists("Authorization")
                .header_exists("DPoP")
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
        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::test_dpop_keypair().expect("keypair must exist");
        let oauth_client =
            crate::oauth_client::new_for_test(keypair, session, mock_server.base_url());

        let result = request_plc_operation_signature(&oauth_client).await;
        assert!(result.is_ok());
    }

    /// request_plc_operation_signature handles error
    #[tokio::test]
    async fn test_request_plc_operation_signature_error() {
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.requestPlcOperationSignature");
            then.status(401).json_body(serde_json::json!({
                "error": "Unauthorized"
            }));
        });

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::test_dpop_keypair().expect("keypair must exist");
        let oauth_client =
            crate::oauth_client::new_for_test(keypair, session, mock_server.base_url());

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
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation")
                .header_exists("Authorization")
                .header_exists("DPoP");
            then.status(200).json_body(serde_json::json!({
                "operation": {
                    "type": "plc_operation",
                    "prev": "bafytest123"
                }
            }));
        });

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::test_dpop_keypair().expect("keypair must exist");
        let oauth_client =
            crate::oauth_client::new_for_test(keypair, session, mock_server.base_url());

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
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        let mock = mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation");
            then.status(200).json_body(serde_json::json!({
                "operation": {}
            }));
        });

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::test_dpop_keypair().expect("keypair must exist");
        let oauth_client =
            crate::oauth_client::new_for_test(keypair, session, mock_server.base_url());

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
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials")
                .header_exists("Authorization")
                .header_exists("DPoP");
            then.status(200).json_body(serde_json::json!({
                "rotationKeys": ["did:key:zQ3test1"],
                "alsoKnownAs": ["at://alice.test"]
            }));
        });

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::test_dpop_keypair().expect("keypair must exist");
        let oauth_client =
            crate::oauth_client::new_for_test(keypair, session, mock_server.base_url());

        let result = get_recommended_did_credentials(&oauth_client).await;
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert!(creds.rotation_keys.is_some());
        assert!(creds.also_known_as.is_some());
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

    /// HandleNotFound error serializes with code "HANDLE_NOT_FOUND"
    #[test]
    fn test_pds_client_error_handle_not_found_serialization() {
        let error = PdsClientError::HandleNotFound;
        let json = serde_json::to_string(&error).expect("serialization failed");
        assert!(json.contains("\"code\":\"HANDLE_NOT_FOUND\""));
    }

    /// DidNotFound error serializes with code "DID_NOT_FOUND"
    #[test]
    fn test_pds_client_error_did_not_found_serialization() {
        let error = PdsClientError::DidNotFound;
        let json = serde_json::to_string(&error).expect("serialization failed");
        assert!(json.contains("\"code\":\"DID_NOT_FOUND\""));
    }

    /// PdsUnreachable error serializes with code "PDS_UNREACHABLE"
    /// and does NOT include "reason" (because it's #[serde(skip)])
    #[test]
    fn test_pds_client_error_pds_unreachable_serialization() {
        let error = PdsClientError::PdsUnreachable {
            reason: "test".into(),
        };
        let json = serde_json::to_string(&error).expect("serialization failed");
        assert!(json.contains("\"code\":\"PDS_UNREACHABLE\""));
        // Verify "reason" field is NOT serialized (it's #[serde(skip)])
        assert!(!json.contains("\"reason\""));
        assert!(!json.contains("test"));
    }

    /// XRPC get_recommended_did_credentials error: returns NetworkError on 403
    #[tokio::test]
    async fn test_get_recommended_did_credentials_error() {
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials");
            then.status(403).json_body(serde_json::json!({
                "error": "Forbidden"
            }));
        });

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::test_dpop_keypair().expect("keypair must exist");
        let oauth_client =
            crate::oauth_client::new_for_test(keypair, session, mock_server.base_url());

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

    /// NetworkError error serializes with code "NETWORK_ERROR"
    #[test]
    fn test_pds_client_error_network_error_serialization() {
        let error = PdsClientError::NetworkError {
            message: "connection refused".to_string(),
        };
        let json = serde_json::to_string(&error).expect("serialization failed");
        assert!(json.contains("\"code\":\"NETWORK_ERROR\""));
    }

    /// InvalidResponse error serializes with code "INVALID_RESPONSE"
    #[test]
    fn test_pds_client_error_invalid_response_serialization() {
        let error = PdsClientError::InvalidResponse {
            message: "missing required field".to_string(),
        };
        let json = serde_json::to_string(&error).expect("serialization failed");
        assert!(json.contains("\"code\":\"INVALID_RESPONSE\""));
    }

    /// OauthFailed error serializes with code "OAUTH_FAILED"
    #[test]
    fn test_pds_client_error_oauth_failed_serialization() {
        let error = PdsClientError::OauthFailed {
            message: "invalid_grant".to_string(),
        };
        let json = serde_json::to_string(&error).expect("serialization failed");
        assert!(json.contains("\"code\":\"OAUTH_FAILED\""));
    }

    /// sign_plc_operation surfaces an HTTP error through classify_xrpc_response: a non-nonce 400
    /// becomes a structured XrpcError carrying the server's status + error code, not a flattened
    /// NetworkError. (The DPoP OAuthClient does not swallow non-`use_dpop_nonce` 400s.)
    #[tokio::test]
    async fn test_sign_plc_operation_error() {
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation");
            then.status(400).json_body(serde_json::json!({
                "error": "invalid_token"
            }));
        });

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::test_dpop_keypair().expect("keypair must exist");
        let oauth_client =
            crate::oauth_client::new_for_test(keypair, session, mock_server.base_url());

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

        let client = crate::pds_client::new_for_test(mock_server.base_url());
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

        let client = crate::pds_client::new_for_test(mock_server.base_url());
        let result = client.fetch_audit_log("did:plc:notfound").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::DidNotFound => {
                // Expected
            }
            e => panic!("Expected DidNotFound, got: {:?}", e),
        }
    }

    // ============================================================================
    // post_plc_operation tests
    // ============================================================================

    /// post_plc_operation succeeds with 200 response
    #[tokio::test]
    async fn test_post_plc_operation_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST).path("/did:plc:test123");
            then.status(200);
        });

        let client = crate::pds_client::new_for_test(mock_server.base_url());
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

        let client = crate::pds_client::new_for_test(mock_server.base_url());
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

    // ============================================================================
    // Migration XRPC method tests
    // ============================================================================

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

    // Helper: create a valid Bearer test JWT with a distant expiry
    fn make_bearer_jwt(exp: u64) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, exp).as_bytes());
        // Dummy signature; jwt_exp_claim never verifies it
        let sig = "dummy_signature";
        format!("{}.{}.{}", header, payload, sig)
    }

    // ============================================================================
    // Task 3: get_service_auth and create_account_migration
    // ============================================================================

    /// get_service_auth issues GET with aud and lxm query params and parses token
    #[tokio::test]
    async fn test_get_service_auth_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.getServiceAuth")
                .query_param("aud", "did:web:dest.example.com")
                .query_param("lxm", "com.atproto.server.createAccount");
            then.status(200).json_body(serde_json::json!({
                "token": "eyJhbGc..."
            }));
        });

        let jwt = make_bearer_jwt(9999999999); // Far future expiry
        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            jwt,
            "test_refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = get_service_auth(
            &test_client,
            "did:web:dest.example.com",
            "com.atproto.server.createAccount",
        )
        .await;

        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.token, "eyJhbGc...");
    }

    /// get_service_auth returns NetworkError on non-2xx status
    #[tokio::test]
    async fn test_get_service_auth_error() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.getServiceAuth");
            then.status(401).body("unauthorized");
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = get_service_auth(
            &test_client,
            "did:web:dest",
            "com.atproto.server.createAccount",
        )
        .await;

        assert!(result.is_err());
        // A 401 is classified as Unauthorized, not a generic NetworkError.
        match result.unwrap_err() {
            PdsClientError::Unauthorized { .. } => {
                // Expected
            }
            e => panic!("Expected Unauthorized, got: {:?}", e),
        }
    }

    /// create_account_migration POSTs camelCase body and parses response
    #[tokio::test]
    async fn test_create_account_migration_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAccount")
                // The body must be the camelCase {handle,email,did}; a serde-rename regression
                // (e.g. snake_case, or a dropped field) must fail this test.
                .body_includes("\"handle\":\"user.example.com\"")
                .body_includes("\"email\":\"user@example.com\"")
                .body_includes("\"did\":\"did:plc:abc123\"")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "accessJwt": "access...",
                "refreshJwt": "refresh...",
                "handle": "user.example.com",
                "did": "did:plc:abc123"
            }));
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_jwt".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let req = CreateAccountMigrationRequest {
            handle: "user.example.com".to_string(),
            email: "user@example.com".to_string(),
            did: "did:plc:abc123".to_string(),
            invite_code: None,
        };
        let result = create_account_migration(&test_client, &req).await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.access_jwt, "access...");
        assert_eq!(resp.refresh_jwt, "refresh...");
        assert_eq!(resp.handle, "user.example.com");
        assert_eq!(resp.did, "did:plc:abc123");
    }

    /// create_account_migration maps 409 to DidAlreadyExists
    #[tokio::test]
    async fn test_create_account_migration_409() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAccount");
            then.status(409).body("account already exists");
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_jwt".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let req = CreateAccountMigrationRequest {
            handle: "existing.example.com".to_string(),
            email: "existing@example.com".to_string(),
            did: "did:plc:xyz789".to_string(),
            invite_code: None,
        };
        let result = create_account_migration(&test_client, &req).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PdsClientError::DidAlreadyExists => {
                // Expected
            }
            e => panic!("Expected DidAlreadyExists, got: {:?}", e),
        }
    }

    // ============================================================================
    // Task 4: import_repo, upload_blob, list_missing_blobs, get+put_preferences
    // ============================================================================

    /// import_repo sends CAR bytes with correct Content-Type and returns Ok on 200
    #[tokio::test]
    async fn test_import_repo_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.importRepo")
                .header("content-type", "application/vnd.ipld.car")
                // The exact CAR bytes must reach the server unchanged.
                .body("CAR bytes content")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let car_bytes = b"CAR bytes content".to_vec();
        let result = import_repo(&test_client, car_bytes).await;

        assert!(result.is_ok());
    }

    /// upload_blob sends raw bytes with provided MIME type and parses blob response
    #[tokio::test]
    async fn test_upload_blob_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.uploadBlob")
                .header("content-type", "image/jpeg")
                // The exact blob bytes must reach the server unchanged.
                .body("JPEG data")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "blob": {
                    "$type": "com.atproto.sync.blob",
                    "mimeType": "image/jpeg",
                    "size": 1234,
                    "ref": { "$link": "bafy123" }
                }
            }));
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let blob_bytes = b"JPEG data".to_vec();
        let result = upload_blob(&test_client, "image/jpeg", blob_bytes).await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        // Assert the fields the migration flow actually consumes from the blob ref, not just $type.
        assert_eq!(resp.blob["ref"]["$link"], "bafy123");
        assert_eq!(resp.blob["mimeType"], "image/jpeg");
        assert_eq!(resp.blob["size"], 1234);
    }

    /// list_missing_blobs without cursor issues base path; with cursor includes ?cursor=
    #[tokio::test]
    async fn test_list_missing_blobs_no_cursor() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "blobs": [
                    { "cid": "bafy1", "recordUri": "at://did/record1" },
                    { "cid": "bafy2", "recordUri": "at://did/record2" }
                ]
            }));
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = list_missing_blobs(&test_client, None).await;

        assert!(result.is_ok());
        let blobs = result.unwrap();
        assert_eq!(blobs.blobs.len(), 2);
        assert_eq!(blobs.blobs[0].cid, "bafy1");
    }

    /// list_missing_blobs with cursor includes it in query params
    #[tokio::test]
    async fn test_list_missing_blobs_with_cursor() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param("cursor", "next_page_token")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "blobs": [
                    { "cid": "bafy3", "recordUri": "at://did/record3" }
                ],
                "cursor": "another_token"
            }));
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = list_missing_blobs(&test_client, Some("next_page_token")).await;

        assert!(result.is_ok());
        let blobs = result.unwrap();
        assert_eq!(blobs.blobs.len(), 1);
        assert_eq!(blobs.cursor, Some("another_token".to_string()));
    }

    /// get_preferences parses full preferences object
    #[tokio::test]
    async fn test_get_preferences_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/app.bsky.actor.getPreferences")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "preferences": [
                    { "feed": "pinned", "value": "at://feed1" }
                ]
            }));
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = get_preferences(&test_client).await;

        assert!(result.is_ok());
        let prefs = result.unwrap();
        assert!(prefs["preferences"].is_array());
    }

    /// put_preferences POSTs the preferences object back and treats 200 as success
    #[tokio::test]
    async fn test_put_preferences_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/app.bsky.actor.putPreferences")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let prefs = serde_json::json!({
            "preferences": [
                { "feed": "pinned", "value": "at://feed1" }
            ]
        });
        let result = put_preferences(&test_client, &prefs).await;

        assert!(result.is_ok());
    }

    // ============================================================================
    // Task 5: check_account_status, activate_account, deactivate_account
    // ============================================================================

    /// check_account_status parses all fields including storedBlocks
    #[tokio::test]
    async fn test_check_account_status_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.checkAccountStatus")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "activated": true,
                "validDid": true,
                "storedBlocks": 12345,
                "indexedRecords": 100,
                "privateStateValues": 5,
                "expectedBlobs": 50,
                "importedBlobs": 48
            }));
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = check_account_status(&test_client).await;

        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(status.activated);
        assert!(status.valid_did);
        assert_eq!(status.stored_blocks, 12345);
        assert_eq!(status.indexed_records, 100);
        assert_eq!(status.expected_blobs, 50);
        assert_eq!(status.imported_blobs, 48);
    }

    /// activate_account POSTs a genuinely empty body and treats 200 as success.
    /// The real handler rejects any non-whitespace body with 400, so the empty-body
    /// assertion below is the actual server contract (a `{}` body would be a bug).
    #[tokio::test]
    async fn test_activate_account_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.activateAccount")
                .is_true(|req| req.body_ref().is_empty())
                // No-input procedure: no Content-Type either (the old post_bytes
                // workaround still sent one with zero bytes).
                .is_true(|req| {
                    !req.headers_vec()
                        .iter()
                        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                })
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = activate_account(&test_client).await;

        assert!(result.is_ok());
    }

    /// deactivate_account without deleteAfter sends {} body
    #[tokio::test]
    async fn test_deactivate_account_no_delete_after() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.deactivateAccount")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = deactivate_account(&test_client, None).await;

        assert!(result.is_ok());
    }

    /// deactivate_account with deleteAfter includes it in request body
    #[tokio::test]
    async fn test_deactivate_account_with_delete_after() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.deactivateAccount")
                .body_includes("deleteAfter")
                .body_includes("2026-07-08")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = deactivate_account(&test_client, Some("2026-07-08T00:00:00.000Z")).await;

        assert!(result.is_ok());
    }

    // ============================================================================
    // describe_server tests
    // ============================================================================

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

    // ============================================================================
    // App-password management wrappers
    // ============================================================================

    fn bearer_client_for(server: &MockServer) -> crate::oauth_client::OAuthClient {
        crate::oauth_client::OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            "refresh".to_string(),
            server.base_url(),
        )
        .expect("new_bearer must succeed")
    }

    /// create_app_password POSTs name+privileged and parses the one-time secret response.
    #[tokio::test]
    async fn test_create_app_password_success() {
        let mock_server = MockServer::start();

        // Assembled from fragments so secret scanners don't flag a literal credential.
        let expected_password = ["abcd", "efgh", "ijkl", "mnop"].join("-");

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAppPassword")
                .json_body(serde_json::json!({
                    "name": "Bluesky app",
                    "privileged": false,
                    "personalDetails": false
                }));
            // The response deliberately omits `personalDetails` — a non-Custos PDS's shape —
            // so this also pins the serde default of the grant field to false.
            then.status(200).json_body(serde_json::json!({
                "name": "Bluesky app",
                "password": expected_password.clone(),
                "createdAt": "2026-07-17T00:00:00.000Z",
                "privileged": false
            }));
        });

        let created = create_app_password(
            &bearer_client_for(&mock_server),
            "Bluesky app",
            false,
            false,
        )
        .await
        .unwrap();
        assert_eq!(created.name, "Bluesky app");
        assert_eq!(created.password, expected_password);
        assert!(!created.privileged);
        assert!(
            !created.personal_details,
            "an absent personalDetails field must read back as not granted"
        );
    }

    /// A duplicate name surfaces as XrpcError with the 409 status preserved.
    #[tokio::test]
    async fn test_create_app_password_duplicate_is_409_xrpc_error() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAppPassword");
            then.status(409).json_body(serde_json::json!({
                "error": "Conflict",
                "message": "an app password with this name already exists"
            }));
        });

        let err = create_app_password(
            &bearer_client_for(&mock_server),
            "Bluesky app",
            false,
            false,
        )
        .await
        .unwrap_err();
        match err {
            PdsClientError::XrpcError { status: 409, .. } => {}
            e => panic!("Expected XrpcError 409, got: {:?}", e),
        }
    }

    /// list_app_passwords unwraps the passwords array (metadata only, no secret field).
    #[tokio::test]
    async fn test_list_app_passwords_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(GET)
                .path("/xrpc/com.atproto.server.listAppPasswords");
            then.status(200).json_body(serde_json::json!({
                "passwords": [
                    {
                        "name": "Bluesky app",
                        "createdAt": "2026-07-17T00:00:00.000Z",
                        "privileged": false
                    },
                    {
                        "name": "Chat client",
                        "createdAt": "2026-07-16T00:00:00.000Z",
                        "privileged": true
                    }
                ]
            }));
        });

        let passwords = list_app_passwords(&bearer_client_for(&mock_server))
            .await
            .unwrap();
        assert_eq!(passwords.len(), 2);
        assert_eq!(passwords[0].name, "Bluesky app");
        assert!(passwords[1].privileged);
    }

    /// revoke_app_password POSTs the name and treats a 2xx as done.
    #[tokio::test]
    async fn test_revoke_app_password_success() {
        let mock_server = MockServer::start();

        let mock = mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.revokeAppPassword")
                .json_body(serde_json::json!({ "name": "Bluesky app" }));
            then.status(200).json_body(serde_json::json!({}));
        });

        revoke_app_password(&bearer_client_for(&mock_server), "Bluesky app")
            .await
            .unwrap();
        mock.assert();
    }

    /// A 429 on the app-password surface is classified as RateLimited with Retry-After.
    #[tokio::test]
    async fn test_list_app_passwords_rate_limited() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(GET)
                .path("/xrpc/com.atproto.server.listAppPasswords");
            then.status(429)
                .header("retry-after", "30")
                .json_body(serde_json::json!({
                    "error": "RateLimitExceeded",
                    "message": "too many requests"
                }));
        });

        let err = list_app_passwords(&bearer_client_for(&mock_server))
            .await
            .unwrap_err();
        match err {
            PdsClientError::RateLimited { retry_after, .. } => {
                assert_eq!(retry_after.as_deref(), Some("30"));
            }
            e => panic!("Expected RateLimited, got: {:?}", e),
        }
    }

    /// A pure transport failure (connection refused) must leave a breadcrumb in the exportable
    /// diagnostics log. This is the regression guard for the gap that made the re-key
    /// `NETWORK_ERROR` invisible: `fetch_audit_log`'s `.send()` never yields a server verdict, so
    /// it never reaches `classify_xrpc_response` — the breadcrumb has to be recorded at the
    /// transport site itself. Also proves the recorded line stays redacted (the DID in the request
    /// path must not appear).
    #[tokio::test]
    async fn transport_failure_records_a_diagnostics_breadcrumb() {
        // Port 1 on loopback refuses immediately: a connect-class transport failure, no server.
        let client = crate::pds_client::new_for_test("http://127.0.0.1:1".to_string());
        let err = client
            .fetch_audit_log("did:plc:diagbreadcrumb")
            .await
            .unwrap_err();
        assert!(
            matches!(err, PdsClientError::NetworkError { .. }),
            "expected NetworkError, got {err:?}"
        );

        let report = crate::diagnostics::export();
        assert!(
            report.contains("fetch_audit_log"),
            "op name missing from report:\n{report}"
        );
        assert!(
            report.contains("transport"),
            "transport origin missing from report:\n{report}"
        );
        assert!(
            !report.contains("diagbreadcrumb"),
            "DID leaked into the redacted report:\n{report}"
        );
    }
}
