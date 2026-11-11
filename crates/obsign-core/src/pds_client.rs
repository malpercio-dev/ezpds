// pattern: Mixed (unavoidable)

//! Re-exports [`custos_client::PdsClient`] — discovery/auth/XRPC against *arbitrary* PDS
//! endpoints and plc.directory — under this module's historical path, plus
//! [`new_with_diagnostics`] (wires this app's diagnostics + `pds_capabilities` observers). See
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
//! `list_app_passwords`, `revoke_app_password`). All three groups are re-exported from
//! `custos_client::{identity,migration,app_passwords}`; each records breadcrumbs into the
//! observer of the `OAuthClient` it is called on.
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
// here so this app's ~20 external references (`claim.rs`, `migration_orchestrator/`,
// `handle_change.rs`, etc.) are unaffected by the extraction.
pub use custos_client::pds_client::{
    rotation_keys_from_audit_log, AuthServerMetadata, CreateSessionResponse, CustosExtension,
    DeleteAccountProof, DeleteCredential, DescribeServerObserver, DescribeServerResponse,
    ListedBlobs, NoopDescribeServerObserver, PdsClient, PdsParRequest, PdsParResponse,
    PdsTokenExchangeRequest, PlcDidDocument, PlcService,
};

// The claim-trio and migration-set request/response types moved to
// `custos_client::identity`/`custos_client::migration` alongside the XRPC methods that use
// them; re-exported here so the wallet's existing `pds_client::{Type}` references (`claim.rs`,
// `migration_orchestrator/`) are unaffected.
pub use custos_client::identity::{
    RecommendedCredentials, SignPlcOperationRequest, SignPlcOperationResponse,
};
pub use custos_client::migration::{
    AccountStatus, CreateAccountMigrationRequest, CreateAccountResponse, MissingBlob, MissingBlobs,
    ServiceAuthToken, UploadBlobResponse,
};

/// Build a [`PdsClient`] wired to this app's diagnostics and `pds_capabilities` observers,
/// with the default plc.directory URL. The one production instance lives in `AppState`.
pub fn new_with_diagnostics() -> PdsClient {
    PdsClient::new_with_observers(
        Arc::new(crate::diagnostics::WalletTransportObserver),
        Arc::new(crate::pds_capabilities::WalletDescribeServerObserver),
    )
}

/// [`PdsClient`] wired to this app's real observers, with a caller-chosen plc.directory URL
/// (a mock server, in every current caller). Unlike `custos_client::PdsClient::new_for_test`
/// (which defaults to no-op observers, correct for a Tauri-free crate with nothing of its own
/// to record), this app's tests need the real `pds_capabilities` observer wired even in a test
/// fixture: `pds_capabilities::probe` reads its cache rather than `describe_server`'s return
/// value directly, so a no-op describe-observer silently starves it and any test exercising
/// capability-gated routing (see `password_unlock`/`share_recovery`) breaks quietly.
/// `#[cfg(any(test, feature = "test-support"))]`, unlike the crate's own `new_for_test`: every caller of this one is inside
/// this crate's own test code, where `#[cfg(any(test, feature = "test-support"))]` visibility applies normally (the
/// cross-crate restriction only bites when a *dependent* crate's test build needs to see a
/// *dependency's* `#[cfg(any(test, feature = "test-support"))]` item).
#[cfg(any(test, feature = "test-support"))]
pub fn new_for_test(plc_directory_url: String) -> PdsClient {
    new_with_diagnostics().with_plc_directory_url(plc_directory_url)
}

// The typed XRPC methods (claim trio, app passwords, migration set) read the diagnostics
// observer from the `OAuthClient` they are called on, so they are re-exported as-is.
pub use custos_client::app_passwords::{
    create_app_password, list_app_passwords, revoke_app_password, AppPasswordCreated,
    AppPasswordEntry,
};
pub use custos_client::identity::{
    get_recommended_did_credentials, request_plc_operation_signature, sign_plc_operation,
};
pub use custos_client::migration::{
    activate_account, check_account_status, create_account_migration, deactivate_account,
    get_preferences, get_service_auth, import_repo, list_missing_blobs, put_preferences,
    request_account_delete, upload_blob,
};

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

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

    /// `new_for_test`'s real `WalletDescribeServerObserver` wiring (the same wiring
    /// `new_with_diagnostics` uses in production) is what lets `pds_capabilities::probe` see
    /// anything at all — it reads its own cache rather than `describe_server`'s return value,
    /// so a no-op describe-observer silently starves it (the regression this crate's own
    /// AGENTS.md Boundaries section names). This pins that a successful `describe_server` call
    /// actually warms the cache, not just returns a parsed value.
    #[tokio::test]
    async fn describe_server_through_new_for_test_warms_the_capabilities_cache() {
        let mock_server = MockServer::start();
        mock_server.mock(|when, then| {
            when.method(GET)
                .path("/xrpc/com.atproto.server.describeServer");
            then.status(200).json_body(serde_json::json!({
                "did": "did:web:cap.example.com",
                "availableUserDomains": [],
                "custos": { "version": "0.16.0", "capabilities": ["didWebHosting"] }
            }));
        });

        let client = crate::pds_client::new_for_test(mock_server.base_url());
        client
            .describe_server(&mock_server.base_url())
            .await
            .expect("describe_server succeeds");

        let cached = crate::pds_capabilities::cached(&mock_server.base_url())
            .expect("a successful describeServer must warm the cache");
        assert!(cached.reached);
        assert!(cached.has(crate::pds_capabilities::capability::DID_WEB_HOSTING));
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
