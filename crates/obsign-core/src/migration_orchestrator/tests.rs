use super::*;
use httpmock::MockServer;

// Phase too low returns MigrationNotReady
#[test]
fn test_ensure_phase_did_phase_too_low() {
    let state = Some(OutboundMigrationState {
        did: "did:plc:abc123".into(),
        source_pds_url: "https://source.pds".into(),
        dest_pds_url: "https://dest.pds".into(),
        dest_did: "did:web:dest".into(),
        handle: "alice.test".into(),
        source_client: None,
        dest_client: None,
        phase: MigrationPhase::SourceAuthed,
        accepted_blob_loss: Vec::new(),
        recovery: false,
    });

    let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::RepoTransferred);
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
}

// DID mismatch returns MigrationNotReady
#[test]
fn test_ensure_phase_did_did_mismatch() {
    let state = Some(OutboundMigrationState {
        did: "did:plc:abc123".into(),
        source_pds_url: "https://source.pds".into(),
        dest_pds_url: "https://dest.pds".into(),
        dest_did: "did:web:dest".into(),
        handle: "alice.test".into(),
        source_client: None,
        dest_client: None,
        phase: MigrationPhase::Resolved,
        accepted_blob_loss: Vec::new(),
        recovery: false,
    });

    let result = ensure_phase_did(&state, "did:plc:different", MigrationPhase::Resolved);
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
}

// None state returns MigrationNotReady
#[test]
fn test_ensure_phase_did_no_state() {
    let result = ensure_phase_did(&None, "did:plc:abc123", MigrationPhase::Resolved);
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
}

// Happy path — state present, DID matches, phase sufficient
#[test]
fn test_ensure_phase_did_success() {
    let state = Some(OutboundMigrationState {
        did: "did:plc:abc123".into(),
        source_pds_url: "https://source.pds".into(),
        dest_pds_url: "https://dest.pds".into(),
        dest_did: "did:web:dest".into(),
        handle: "alice.test".into(),
        source_client: None,
        dest_client: None,
        phase: MigrationPhase::RepoTransferred,
        accepted_blob_loss: Vec::new(),
        recovery: false,
    });

    let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::SourceAuthed);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().phase, MigrationPhase::RepoTransferred);
}

// MigrationError serialization — MigrationNotReady
#[test]
fn test_migration_error_serialization_not_ready() {
    let err = MigrationError::MigrationNotReady {
        message: "test message".into(),
    };
    let json = serde_json::to_value(&err).unwrap();
    assert_eq!(json["code"], "MIGRATION_NOT_READY");
    assert_eq!(json["message"], "test message");
}

// MigrationError serialization — VerificationIncomplete
#[test]
fn test_migration_error_serialization_verification_incomplete() {
    let err = MigrationError::VerificationIncomplete {
        imported: 5,
        expected: 10,
    };
    let json = serde_json::to_value(&err).unwrap();
    assert_eq!(json["code"], "VERIFICATION_INCOMPLETE");
    assert_eq!(json["imported"], 5);
    assert_eq!(json["expected"], 10);
}

// MigrationError serialization — BlobDrainIncomplete carries the loss manifest with camelCase
// fields and a lowercase direction, the exact shape the wallet's `BlobLoss` type consumes.
#[test]
fn test_migration_error_serialization_blob_drain_incomplete() {
    let err = MigrationError::BlobDrainIncomplete {
        losses: vec![
            BlobLoss {
                cid: "bafyfetch".into(),
                record_uri: "at://did:plc:abc/app.bsky.feed.post/1".into(),
                direction: BlobTransferDirection::Source,
                reason: "server error (500)".into(),
            },
            BlobLoss {
                cid: "bafyupload".into(),
                record_uri: "at://did:plc:abc/app.bsky.feed.post/2".into(),
                direction: BlobTransferDirection::Destination,
                reason: "rejected".into(),
            },
        ],
    };
    let json = serde_json::to_value(&err).unwrap();
    assert_eq!(json["code"], "BLOB_DRAIN_INCOMPLETE");
    assert_eq!(json["losses"][0]["cid"], "bafyfetch");
    assert_eq!(
        json["losses"][0]["recordUri"],
        "at://did:plc:abc/app.bsky.feed.post/1"
    );
    assert_eq!(json["losses"][0]["direction"], "source");
    assert_eq!(json["losses"][0]["reason"], "server error (500)");
    assert_eq!(json["losses"][1]["direction"], "destination");
}

// MigrationError serialization — DestinationUnreachable
#[test]
fn test_migration_error_serialization_destination_unreachable() {
    let err = MigrationError::DestinationUnreachable {
        message: "connection refused".into(),
    };
    let json = serde_json::to_value(&err).unwrap();
    assert_eq!(json["code"], "DESTINATION_UNREACHABLE");
    assert_eq!(json["message"], "connection refused");
}

// MigrationError serialization — SourceAuthFailed
#[test]
fn test_migration_error_serialization_source_auth_failed() {
    let err = MigrationError::SourceAuthFailed {
        message: "invalid grant".into(),
    };
    let json = serde_json::to_value(&err).unwrap();
    assert_eq!(json["code"], "SOURCE_AUTH_FAILED");
    assert_eq!(json["message"], "invalid grant");
}

// MigrationError serialization — DestinationConflict
#[test]
fn test_migration_error_serialization_destination_conflict() {
    let err = MigrationError::DestinationConflict {
        message: "account exists but session was lost".into(),
    };
    let json = serde_json::to_value(&err).unwrap();
    assert_eq!(json["code"], "DESTINATION_CONFLICT");
    assert_eq!(json["message"], "account exists but session was lost");
}

// ── Task 5 tests: source-PDS password login ────────────────────────────

// authenticate_migration_source with the wrong DID returns MIGRATION_NOT_READY (pure gate)
#[test]
fn test_authenticate_migration_source_did_mismatch_gate() {
    let state = Some(OutboundMigrationState {
        did: "did:plc:abc123".into(),
        source_pds_url: "https://source.pds".into(),
        dest_pds_url: "https://dest.pds".into(),
        dest_did: "did:web:dest".into(),
        handle: "alice.test".into(),
        source_client: None,
        dest_client: None,
        phase: MigrationPhase::Resolved,
        accepted_blob_loss: Vec::new(),
        recovery: false,
    });

    let result = ensure_phase_did(&state, "did:plc:different", MigrationPhase::Resolved);
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
}

// authenticate_migration_source gates at phase >= Resolved. Resolved is the first phase, so a
// "phase too low" case is impossible; the only gate failures are no-state and did-mismatch.
#[test]
fn test_authenticate_migration_source_no_state_gate() {
    // No state → gate fails
    let result = ensure_phase_did(&None, "did:plc:abc123", MigrationPhase::Resolved);
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
}

// ── source-login error mapping ──────────────────────────────────────────────

/// The shared `createSession` body + account-match guard now live in `source_login`, tested
/// once there against a mock PDS. What remains migration-specific is the
/// `From<SourceLoginError>` mapping into `MigrationError`; this unit test pins that contract so
/// a variant can't silently remap. `authenticate_migration_source_impl` is a thin
/// `.map_err(MigrationError::from)` over the shared core, so the mapping is the only
/// migration-owned behavior left to cover.
#[test]
fn test_source_login_error_maps_to_migration_error() {
    use crate::source_login::SourceLoginError as S;

    assert!(matches!(
        MigrationError::from(S::TwoFactorRequired),
        MigrationError::TwoFactorRequired
    ));
    assert!(matches!(
        MigrationError::from(S::AccountMismatch),
        MigrationError::AccountMismatch
    ));
    assert!(matches!(
        MigrationError::from(S::InsecureSourceUrl),
        MigrationError::InsecureSourceUrl
    ));
    assert!(matches!(
        MigrationError::from(S::SourceAuthFailed {
            message: "createSession rejected the credentials (401)".to_string()
        }),
        MigrationError::SourceAuthFailed { message } if message == "createSession rejected the credentials (401)"
    ));
    assert!(matches!(
        MigrationError::from(S::RateLimited {
            retry_after: Some("120".to_string())
        }),
        MigrationError::RateLimited { retry_after: Some(r) } if r == "120"
    ));
    assert!(matches!(
        MigrationError::from(S::ServerError {
            message: "handle is required".to_string()
        }),
        MigrationError::ServerRejected { message } if message == "handle is required"
    ));
    assert!(matches!(
        MigrationError::from(S::NetworkError {
            message: "connection refused".to_string()
        }),
        MigrationError::NetworkError { message } if message == "connection refused"
    ));
}

// Serialization of the password-login error variants (frontend switches on these codes).
#[test]
fn test_migration_error_serialization_two_factor_required() {
    let json = serde_json::to_value(MigrationError::TwoFactorRequired).unwrap();
    assert_eq!(json["code"], "TWO_FACTOR_REQUIRED");
}

#[test]
fn test_migration_error_serialization_account_mismatch() {
    let json = serde_json::to_value(MigrationError::AccountMismatch).unwrap();
    assert_eq!(json["code"], "ACCOUNT_MISMATCH");
}

#[test]
fn test_migration_error_serialization_insecure_source_url() {
    let json = serde_json::to_value(MigrationError::InsecureSourceUrl).unwrap();
    assert_eq!(json["code"], "INSECURE_SOURCE_URL");
}

#[test]
fn test_migration_error_serialization_rate_limited() {
    let json = serde_json::to_value(MigrationError::RateLimited {
        retry_after: Some("30".into()),
    })
    .unwrap();
    assert_eq!(json["code"], "RATE_LIMITED");
    // Serialized as camelCase `retryAfter`, matching the frontend MigrationError union.
    assert_eq!(json["retryAfter"], "30");
}

#[test]
fn test_migration_error_serialization_server_error() {
    let json = serde_json::to_value(MigrationError::ServerRejected {
        message: "handle is required".into(),
    })
    .unwrap();
    assert_eq!(json["code"], "SERVER_REJECTED");
    assert_eq!(json["message"], "handle is required");
}

// `prepare_migration` returns this to the source-auth screen; the frontend `PreparedMigration`
// type reads `handle` + `sourcePdsUrl`, so the camelCase rename must stay exact.
#[test]
fn test_prepared_migration_serializes_camel_case() {
    let json = serde_json::to_value(PreparedMigration {
        handle: "alice.test".into(),
        source_pds_url: "https://source.pds".into(),
    })
    .unwrap();
    assert_eq!(json["handle"], "alice.test");
    assert_eq!(json["sourcePdsUrl"], "https://source.pds");
}

// ── Task 6 tests: Account creation idempotence + gating ───────────────

/// A JWT whose `exp` is `exp`. Bearer test clients need a future-exp token, else `new_bearer`
/// sets expires_at=0 and a proactive refresh fires before the request under test.
fn make_bearer_jwt(exp: u64) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#);
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, exp));
    format!("{}.{}.sig", header, payload)
}

// create_destination_account_impl with an existing dest_client returns it (idempotent
// re-establish) WITHOUT any network — the fast path short-circuits before reserve/serviceAuth/
// createAccount, so this also covers "409-with-existing is tolerated" (createAccount is never
// reached when a client is held). No #[ignore] needed: no socket is bound.
#[tokio::test]
async fn test_create_destination_account_impl_idempotent_with_existing_client() {
    let existing = Arc::new(
        OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            String::new(),
            "https://dest.pds".into(),
        )
        .unwrap(),
    );
    // Dummy deps that must never be touched (unreachable URLs prove the fast path took over).
    let pds_client = crate::pds_client::PdsClient::new();
    let source_client = Arc::new(
        OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            String::new(),
            "http://127.0.0.1:1".into(),
        )
        .unwrap(),
    );

    let result = create_destination_account_impl(
        &pds_client,
        &source_client,
        "http://127.0.0.1:1",
        "did:web:dest",
        "did:plc:abc123",
        "alice.test",
        "alice@example.com",
        None,
        Some(existing.clone()),
    )
    .await;

    assert!(result.is_ok());
    assert!(
        Arc::ptr_eq(&result.unwrap(), &existing),
        "must return the exact cached client without hitting the network"
    );
}

// createAccount 409 with NO existing dest_client → DESTINATION_CONFLICT (session lost).
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_create_destination_account_impl_409_no_existing_is_conflict() {
    let source = MockServer::start();
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.server.getServiceAuth");
        then.status(200)
            .json_body(serde_json::json!({ "token": make_bearer_jwt(9999999999) }));
    });
    let dest = MockServer::start();
    dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.reserveSigningKey");
        then.status(200)
            .json_body(serde_json::json!({ "signingKey": "did:key:zDest" }));
    });
    dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.createAccount");
        then.status(409).body("account already exists");
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let source_client = Arc::new(
        OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            String::new(),
            source.base_url(),
        )
        .unwrap(),
    );

    let result = create_destination_account_impl(
        &pds_client,
        &source_client,
        &dest.base_url(),
        "did:web:dest",
        "did:plc:abc123",
        "alice.test",
        "alice@example.com",
        None,
        None, // no existing client → conflict
    )
    .await;

    assert!(matches!(
        result,
        Err(MigrationError::DestinationConflict { .. })
    ));
}

// Happy path: reserveSigningKey → getServiceAuth → createAccount(200) → dest Bearer client.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_create_destination_account_impl_happy_path() {
    let source = MockServer::start();
    let sa_mock = source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.server.getServiceAuth");
        then.status(200)
            .json_body(serde_json::json!({ "token": make_bearer_jwt(9999999999) }));
    });
    let dest = MockServer::start();
    let reserve_mock = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.reserveSigningKey");
        then.status(200)
            .json_body(serde_json::json!({ "signingKey": "did:key:zDest" }));
    });
    let create_mock = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.createAccount");
        then.status(200).json_body(serde_json::json!({
            "accessJwt": make_bearer_jwt(9999999999),
            "refreshJwt": "refresh_jwt",
            "handle": "alice.test",
            "did": "did:plc:abc123"
        }));
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let source_client = Arc::new(
        OAuthClient::new_bearer(
            make_bearer_jwt(9999999999),
            String::new(),
            source.base_url(),
        )
        .unwrap(),
    );

    let result = create_destination_account_impl(
        &pds_client,
        &source_client,
        &dest.base_url(),
        "did:web:dest",
        "did:plc:abc123",
        "alice.test",
        "alice@example.com",
        None,
        None,
    )
    .await;

    assert!(result.is_ok(), "happy path must return a dest client");
    // Each leg was exercised exactly once, in order.
    assert_eq!(reserve_mock.calls(), 1);
    assert_eq!(sa_mock.calls(), 1);
    assert_eq!(create_mock.calls(), 1);
}

// create_destination_account before SourceAuthed phase returns MIGRATION_NOT_READY
#[test]
fn test_create_destination_account_phase_gate() {
    let state = Some(OutboundMigrationState {
        did: "did:plc:abc123".into(),
        source_pds_url: "https://source.pds".into(),
        dest_pds_url: "https://dest.pds".into(),
        dest_did: "did:web:dest".into(),
        handle: "alice.test".into(),
        source_client: None,
        dest_client: None,
        phase: MigrationPhase::Resolved, // Too early!
        accepted_blob_loss: Vec::new(),
        recovery: false,
    });

    let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::SourceAuthed);
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
}

// Helper test: extract_handle_from_also_known_as
#[test]
fn test_extract_handle_from_also_known_as_valid() {
    let entries = vec!["at://alice.test".to_string()];
    let result = extract_handle_from_also_known_as(&entries);
    assert_eq!(result, Some("alice.test".to_string()));
}

#[test]
fn test_extract_handle_from_also_known_as_multiple_entries() {
    let entries = vec![
        "https://example.com/user/alice".to_string(),
        "at://alice.test".to_string(),
    ];
    let result = extract_handle_from_also_known_as(&entries);
    assert_eq!(result, Some("alice.test".to_string()));
}

#[test]
fn test_extract_handle_from_also_known_as_empty() {
    let entries: Vec<String> = vec![];
    let result = extract_handle_from_also_known_as(&entries);
    assert_eq!(result, None);
}

// Only non-at:// entries present → None.
#[test]
fn test_extract_handle_from_also_known_as_no_at_uri() {
    let entries = vec![
        "https://example.com/user/alice".to_string(),
        "mailto:alice@example.com".to_string(),
    ];
    let result = extract_handle_from_also_known_as(&entries);
    assert_eq!(result, None);
}

#[test]
fn test_preferred_login_identifier_skips_did_alias_for_handle() {
    let entries = vec![
        "at://did:plc:abc123".to_string(),
        "at://alice.test".to_string(),
    ];

    assert_eq!(
        preferred_login_identifier(&entries, "did:plc:abc123"),
        "alice.test"
    );
}

#[test]
fn test_preferred_login_identifier_falls_back_to_did() {
    let entries = vec!["at://did:plc:abc123".to_string()];

    assert_eq!(
        preferred_login_identifier(&entries, "did:plc:abc123"),
        "did:plc:abc123"
    );
}

// ── Task 1 tests: transfer_repo ────────────────────────────────────────

// transfer_repo fetches source CAR and imports to dest, advances phase.
// (Pure gate test: phase < RepoTransferred returns MIGRATION_NOT_READY)
#[test]
fn test_transfer_repo_phase_gate() {
    let state = Some(OutboundMigrationState {
        did: "did:plc:abc123".into(),
        source_pds_url: "https://source.pds".into(),
        dest_pds_url: "https://dest.pds".into(),
        dest_did: "did:web:dest".into(),
        handle: "alice.test".into(),
        source_client: None,
        dest_client: None,
        phase: MigrationPhase::SourceAuthed, // Too early!
        accepted_blob_loss: Vec::new(),
        recovery: false,
    });

    let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::DestCreated);
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
}

// transfer_repo phase gate (pure test, no network)
#[test]
fn test_transfer_repo_phase_too_low() {
    let state = Some(OutboundMigrationState {
        did: "did:plc:abc123".into(),
        source_pds_url: "https://source.pds".into(),
        dest_pds_url: "https://dest.pds".into(),
        dest_did: "did:web:dest".into(),
        handle: "alice.test".into(),
        source_client: None,
        dest_client: None,
        phase: MigrationPhase::SourceAuthed, // Too early!
        accepted_blob_loss: Vec::new(),
        recovery: false,
    });

    let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::DestCreated);
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
}

// ── Task 2 tests: transfer_blobs ───────────────────────────────────────

// transfer_blobs phase gate (pure test, no network)
#[test]
fn test_transfer_blobs_phase_too_low() {
    let state = Some(OutboundMigrationState {
        did: "did:plc:abc123".into(),
        source_pds_url: "https://source.pds".into(),
        dest_pds_url: "https://dest.pds".into(),
        dest_did: "did:web:dest".into(),
        handle: "alice.test".into(),
        source_client: None,
        dest_client: None,
        phase: MigrationPhase::DestCreated, // Too early for transfer_blobs!
        accepted_blob_loss: Vec::new(),
        recovery: false,
    });

    let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::RepoTransferred);
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
}

// Build a Bearer dest client (future-exp so no proactive refresh fires) at `base_url`.
fn bearer_client_at(base_url: String) -> OAuthClient {
    OAuthClient::new_bearer(make_bearer_jwt(9999999999), String::new(), base_url).unwrap()
}

// ── Task 1 mock tests: transfer_repo_impl ──────────────────────────────

// Fetch the source CAR and POST the exact bytes to the destination importRepo.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_transfer_repo_impl_success() {
    let source = MockServer::start();
    let get_repo = source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getRepo")
            .query_param("did", "did:plc:abc123");
        then.status(200).body("CAR-DATA-BYTES");
    });
    let dest = MockServer::start();
    let import = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.repo.importRepo")
            .header("content-type", "application/vnd.ipld.car")
            .body("CAR-DATA-BYTES"); // the exact source bytes must round-trip
        then.status(200);
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let dest_client = bearer_client_at(dest.base_url());

    let result = transfer_repo_impl(
        &pds_client,
        &dest_client,
        &source.base_url(),
        "did:plc:abc123",
        None,
    )
    .await;

    assert!(result.is_ok());
    assert_eq!(get_repo.calls(), 1);
    assert_eq!(import.calls(), 1);
}

// Failure case: a dest importRepo 500 → RepoTransferFailed (command leaves phase un-advanced).
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_transfer_repo_impl_import_failure() {
    let source = MockServer::start();
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getRepo");
        then.status(200).body("CAR");
    });
    let dest = MockServer::start();
    dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.repo.importRepo");
        then.status(500).body("server error");
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let dest_client = bearer_client_at(dest.base_url());

    let result = transfer_repo_impl(
        &pds_client,
        &dest_client,
        &source.base_url(),
        "did:plc:abc123",
        None,
    )
    .await;

    assert!(matches!(
        result,
        Err(MigrationError::RepoTransferFailed { .. })
    ));
}

// The payoff: the source PDS can't serve getRepo, but the wallet has a validated iCloud snapshot
// for the DID — the transfer recovers the repo from the mirror and imports it, so a dead source
// repo is a non-event for a backed-up user.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_transfer_repo_falls_back_to_local_mirror_on_source_failure() {
    let did = "did:plc:repomirrorfallback";

    // Seed a local mirror with a valid snapshot, as a completed repo-backup pass would leave it.
    let mirror = tempfile::tempdir().unwrap();
    let car = crate::repo_backup::seed_mirror_repo_for_test(mirror.path(), did).await;

    // The source PDS permanently 500s getRepo (the repo twin of the observed migration fault).
    let source = MockServer::start();
    let get_repo = source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getRepo");
        then.status(500).body("repo bytes are gone");
    });
    // The destination importRepo must succeed — reached only via the mirror fallback.
    let dest = MockServer::start();
    let import = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.repo.importRepo");
        then.status(200);
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let dest_client = bearer_client_at(dest.base_url());

    let result = transfer_repo_impl(
        &pds_client,
        &dest_client,
        &source.base_url(),
        did,
        Some(mirror.path()),
    )
    .await;

    assert!(
        result.is_ok(),
        "the repo was recovered from the iCloud mirror after the source getRepo failure"
    );
    assert!(
        get_repo.calls() >= 1,
        "the source was tried before falling back"
    );
    assert_eq!(
        import.calls(),
        1,
        "the mirror's validated snapshot was imported to the destination"
    );
    // Sanity: the seeded snapshot is a real, non-empty CAR (it is what got imported).
    assert!(!car.is_empty());
}

// A 429 is pacing, not a dead source: the transfer surfaces RATE_LIMITED with the server's
// Retry-After and never imports the (possibly older) mirror snapshot.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_transfer_repo_rate_limited_never_falls_back_to_mirror() {
    let did = "did:plc:repomirrorratelimit";
    let mirror = tempfile::tempdir().unwrap();
    crate::repo_backup::seed_mirror_repo_for_test(mirror.path(), did).await;

    let source = MockServer::start();
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getRepo");
        then.status(429)
            .header("Retry-After", "1800")
            .json_body(serde_json::json!({ "error": "RateLimitExceeded", "message": "slow down" }));
    });
    let dest = MockServer::start();
    let import = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.repo.importRepo");
        then.status(200);
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let dest_client = bearer_client_at(dest.base_url());
    let result = transfer_repo_impl(
        &pds_client,
        &dest_client,
        &source.base_url(),
        did,
        Some(mirror.path()),
    )
    .await;

    assert!(
        matches!(
            result,
            Err(MigrationError::RateLimited { retry_after: Some(ref r) }) if r == "1800"
        ),
        "got {result:?}"
    );
    assert_eq!(
        import.calls(),
        0,
        "the mirror snapshot must not be imported"
    );
}

// The fallback never masks a genuine failure: with the mirror empty (no snapshot for the DID),
// a source getRepo failure is surfaced unchanged as REPO_TRANSFER_FAILED and no import happens.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_transfer_repo_preserves_source_failure_with_empty_mirror() {
    let did = "did:plc:repomirrormiss";

    // An empty mirror (no snapshot seeded for this DID).
    let mirror = tempfile::tempdir().unwrap();

    let source = MockServer::start();
    let get_repo = source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getRepo");
        then.status(500).body("gone");
    });
    let dest = MockServer::start();
    let import = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.repo.importRepo");
        then.status(200);
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let dest_client = bearer_client_at(dest.base_url());

    let result = transfer_repo_impl(
        &pds_client,
        &dest_client,
        &source.base_url(),
        did,
        Some(mirror.path()),
    )
    .await;

    assert!(
        matches!(result, Err(MigrationError::RepoTransferFailed { .. })),
        "an empty mirror preserves the original source failure unchanged"
    );
    assert!(get_repo.calls() >= 1);
    assert_eq!(
        import.calls(),
        0,
        "no import is attempted when the mirror has no valid snapshot"
    );
}

// ── Task 2 mock tests: drain_missing_blobs ─────────────────────────────

// An empty first page completes immediately with no getBlob/uploadBlob calls.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_drain_missing_blobs_empty_first_page() {
    let dest = MockServer::start();
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs")
            .query_param_missing("cursor");
        then.status(200)
            .json_body(serde_json::json!({ "blobs": [], "cursor": null }));
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let dest_client = bearer_client_at(dest.base_url());

    // Source URL is unreachable; if the drain tried to fetch a blob it would error, proving
    // the empty-page short-circuit did not touch the source.
    let result = drain_missing_blobs(
        &pds_client,
        &dest_client,
        Some("http://127.0.0.1:1"),
        "did:plc:abc123",
        None,
    )
    .await;

    assert!(result.is_ok());
}

// Walk two cursor pages, fetch every missing CID from source and upload to dest
// once each, terminating on the empty page.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_drain_missing_blobs_multi_page() {
    let source = MockServer::start();
    let get_a = source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getBlob")
            .query_param("cid", "cid_a");
        then.status(200).body("blob-a");
    });
    let get_b = source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getBlob")
            .query_param("cid", "cid_b");
        then.status(200).body("blob-b");
    });
    let get_c = source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getBlob")
            .query_param("cid", "cid_c");
        then.status(200).body("blob-c");
    });

    let dest = MockServer::start();
    // Page 1 (no cursor): two blobs, cursor c1.
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs")
            .query_param_missing("cursor");
        then.status(200).json_body(serde_json::json!({
            "blobs": [
                { "cid": "cid_a", "recordUri": "at://did:plc:abc123/app.bsky.feed.post/1" },
                { "cid": "cid_b", "recordUri": "at://did:plc:abc123/app.bsky.feed.post/2" }
            ],
            "cursor": "c1"
        }));
    });
    // Page 2 (cursor=c1): one blob, cursor c2.
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs")
            .query_param("cursor", "c1");
        then.status(200).json_body(serde_json::json!({
            "blobs": [
                { "cid": "cid_c", "recordUri": "at://did:plc:abc123/app.bsky.feed.post/3" }
            ],
            "cursor": "c2"
        }));
    });
    // Page 3 (cursor=c2): drained → empty, terminates the loop.
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs")
            .query_param("cursor", "c2");
        then.status(200)
            .json_body(serde_json::json!({ "blobs": [], "cursor": null }));
    });
    let upload = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.repo.uploadBlob");
        then.status(200)
            .json_body(serde_json::json!({ "blob": { "$type": "blob" } }));
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let dest_client = bearer_client_at(dest.base_url());

    let result = drain_missing_blobs(
        &pds_client,
        &dest_client,
        Some(&source.base_url()),
        "did:plc:abc123",
        None,
    )
    .await;

    assert!(result.is_ok());
    assert_eq!(get_a.calls(), 1, "cid_a fetched once");
    assert_eq!(get_b.calls(), 1, "cid_b fetched once");
    assert_eq!(get_c.calls(), 1, "cid_c fetched once");
    assert_eq!(upload.calls(), 3, "each of the 3 blobs uploaded once");
}

// A permanently-failing source getBlob no longer aborts the drain. The blob is retried,
// given up on, and returned in the loss manifest (direction=Source) — the drain still completes.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_drain_missing_blobs_records_loss_instead_of_aborting() {
    let source = MockServer::start();
    let get = source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getBlob");
        then.status(500).body("blob fetch error");
    });
    let dest = MockServer::start();
    // Stateless mock: keeps re-reporting cid_a as missing. The drain's give-up set must still
    // converge the loop and return the loss.
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs");
        then.status(200).json_body(serde_json::json!({
            "blobs": [ { "cid": "cid_a", "recordUri": "at://did:plc:abc123/x/1" } ],
            "cursor": null
        }));
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let dest_client = bearer_client_at(dest.base_url());

    let losses = drain_missing_blobs(
        &pds_client,
        &dest_client,
        Some(&source.base_url()),
        "did:plc:abc123",
        None,
    )
    .await
    .expect("drain degrades per-blob rather than erroring");

    assert_eq!(losses.len(), 1, "the one dead blob is on the manifest");
    assert_eq!(losses[0].cid, "cid_a");
    assert_eq!(losses[0].direction, BlobTransferDirection::Source);
    assert_eq!(losses[0].record_uri, "at://did:plc:abc123/x/1");
    assert_eq!(
        get.calls(),
        BLOB_TRANSFER_ATTEMPTS as usize,
        "fetch retried up to the cap"
    );
}

// A good blob is transferred while a dead one is skipped onto the manifest — one bad
// blob doesn't take the healthy ones down with it.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_drain_missing_blobs_mixed_good_and_bad() {
    let source = MockServer::start();
    let get_good = source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getBlob")
            .query_param("cid", "cid_good");
        then.status(200).body("good-bytes");
    });
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getBlob")
            .query_param("cid", "cid_bad");
        then.status(500).body("gone");
    });
    let dest = MockServer::start();
    // Page 1 (no cursor): both blobs, cursor c1. Page 2 (c1): empty — a real server drops the
    // uploaded good blob from the missing set, so the drain advances to the empty page and
    // returns with only the given-up bad blob on the manifest.
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs")
            .query_param_missing("cursor");
        then.status(200).json_body(serde_json::json!({
            "blobs": [
                { "cid": "cid_good", "recordUri": "at://did:plc:abc123/x/1" },
                { "cid": "cid_bad", "recordUri": "at://did:plc:abc123/x/2" }
            ],
            "cursor": "c1"
        }));
    });
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs")
            .query_param("cursor", "c1");
        then.status(200)
            .json_body(serde_json::json!({ "blobs": [], "cursor": null }));
    });
    let upload = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.repo.uploadBlob");
        then.status(200)
            .json_body(serde_json::json!({ "blob": { "$type": "blob" } }));
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let dest_client = bearer_client_at(dest.base_url());

    let losses = drain_missing_blobs(
        &pds_client,
        &dest_client,
        Some(&source.base_url()),
        "did:plc:abc123",
        None,
    )
    .await
    .expect("drain completes with a partial loss");

    assert_eq!(get_good.calls(), 1, "the good blob is fetched once");
    assert_eq!(upload.calls(), 1, "only the good blob is uploaded");
    assert_eq!(losses.len(), 1, "only the bad blob is on the manifest");
    assert_eq!(losses[0].cid, "cid_bad");
}

// The payoff: a blob the source PDS can't serve is recovered from the local mirror instead of
// being recorded as lost. The mirror holds a verified copy; the drain uploads it to the
// destination and the loss manifest stays empty.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_drain_falls_back_to_local_mirror_on_source_failure() {
    let did = "did:plc:mirrorfallback";
    let blob = b"media the source PDS lost but the wallet backed up".to_vec();

    // Seed a local mirror with the verified blob, as a completed backup pass would leave it.
    let mirror = tempfile::tempdir().unwrap();
    let cid =
        crate::blob_backup::seed_mirror_blob_for_test(mirror.path(), did, &blob, "image/png").await;

    // The source PDS permanently 500s getBlob for this CID (the observed real-migration fault).
    let source = MockServer::start();
    let get = source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getBlob");
        then.status(500).body("blob bytes are gone");
    });

    // Two pages: page 1 lists the CID, page 2 is empty so the loop terminates after the
    // mirror-sourced upload removes it from the destination's missing set.
    let dest = MockServer::start();
    dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param_missing("cursor");
            then.status(200).json_body(serde_json::json!({
                "blobs": [ { "cid": cid, "recordUri": "at://did:plc:mirrorfallback/app.bsky.feed.post/1" } ],
                "cursor": "c1"
            }));
        });
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs")
            .query_param("cursor", "c1");
        then.status(200)
            .json_body(serde_json::json!({ "blobs": [], "cursor": null }));
    });
    let upload = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.repo.uploadBlob")
            .body(std::str::from_utf8(&blob).unwrap());
        then.status(200)
            .json_body(serde_json::json!({ "blob": { "$type": "blob" } }));
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let dest_client = bearer_client_at(dest.base_url());

    let losses = drain_missing_blobs(
        &pds_client,
        &dest_client,
        Some(&source.base_url()),
        did,
        Some(mirror.path()),
    )
    .await
    .expect("drain completes by recovering the blob from the mirror");

    assert!(
        losses.is_empty(),
        "the blob was recovered from the mirror, not lost"
    );
    assert_eq!(
        get.calls(),
        BLOB_TRANSFER_ATTEMPTS as usize,
        "the source was tried up to the retry cap before falling back"
    );
    assert_eq!(
        upload.calls(),
        1,
        "the mirror's verified bytes were uploaded to the destination"
    );
}

// The fallback never masks a genuine loss: when the mirror is present but doesn't hold the
// failing blob, the drain still records it (direction=Source) rather than silently succeeding.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_drain_records_loss_when_mirror_lacks_the_blob() {
    let did = "did:plc:mirrormiss";

    // An empty mirror (no manifest entry for the failing CID).
    let mirror = tempfile::tempdir().unwrap();

    let source = MockServer::start();
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getBlob");
        then.status(500).body("gone");
    });
    let dest = MockServer::start();
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs");
        then.status(200).json_body(serde_json::json!({
            "blobs": [ { "cid": "cid_absent", "recordUri": "at://did:plc:mirrormiss/x/1" } ],
            "cursor": null
        }));
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let dest_client = bearer_client_at(dest.base_url());

    let losses = drain_missing_blobs(
        &pds_client,
        &dest_client,
        Some(&source.base_url()),
        did,
        Some(mirror.path()),
    )
    .await
    .expect("drain degrades per-blob rather than erroring");

    assert_eq!(losses.len(), 1, "the blob the mirror lacks is still lost");
    assert_eq!(losses[0].cid, "cid_absent");
    assert_eq!(losses[0].direction, BlobTransferDirection::Source);
}

// Failing to even enumerate the missing set is a hard error (no manifest is possible),
// so the drain still aborts with BlobTransferFailed and the phase never advances.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_drain_missing_blobs_list_failure_is_hard_error() {
    let dest = MockServer::start();
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs");
        then.status(500).body("cannot list");
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let dest_client = bearer_client_at(dest.base_url());

    let result = drain_missing_blobs(
        &pds_client,
        &dest_client,
        Some("http://127.0.0.1:1"),
        "did:plc:abc123",
        None,
    )
    .await;

    assert!(matches!(
        result,
        Err(MigrationError::BlobTransferFailed { .. })
    ));
}

// ── Task 3 tests: transfer_preferences ─────────────────────────────────

// Pure gate test: transfer_preferences before BlobsTransferred phase fails
#[test]
fn test_transfer_preferences_phase_too_low() {
    let state = Some(OutboundMigrationState {
        did: "did:plc:abc123".into(),
        source_pds_url: "https://source.pds".into(),
        dest_pds_url: "https://dest.pds".into(),
        dest_did: "did:web:dest".into(),
        handle: "alice.test".into(),
        source_client: None,
        dest_client: None,
        phase: MigrationPhase::RepoTransferred, // Too early for transfer_preferences!
        accepted_blob_loss: Vec::new(),
        recovery: false,
    });

    let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::BlobsTransferred);
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
}

// transfer_preferences fetches from source and posts to destination, advances phase.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_transfer_preferences_impl_success() {
    let source = MockServer::start();
    let get_prefs = source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/app.bsky.actor.getPreferences");
        then.status(200).json_body(serde_json::json!({
            "preferences": [
                { "name": "theme", "value": "dark" }
            ]
        }));
    });

    let dest = MockServer::start();
    let put_prefs = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/app.bsky.actor.putPreferences")
            .json_body(serde_json::json!({
                "preferences": [
                    { "name": "theme", "value": "dark" }
                ]
            }));
        then.status(200);
    });

    let source_client = bearer_client_at(source.base_url());
    let dest_client = bearer_client_at(dest.base_url());

    let result = transfer_preferences_impl(&source_client, &dest_client).await;

    assert!(result.is_ok());
    assert_eq!(get_prefs.calls(), 1);
    assert_eq!(put_prefs.calls(), 1);
}

// Failure case: source getPreferences 500 → PreferencesTransferFailed
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_transfer_preferences_impl_source_failure() {
    let source = MockServer::start();
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/app.bsky.actor.getPreferences");
        then.status(500).body("server error");
    });

    let dest = MockServer::start();

    let source_client = bearer_client_at(source.base_url());
    let dest_client = bearer_client_at(dest.base_url());

    let result = transfer_preferences_impl(&source_client, &dest_client).await;

    assert!(matches!(
        result,
        Err(MigrationError::PreferencesTransferFailed { .. })
    ));
}

// Failure case: dest putPreferences 500 → PreferencesTransferFailed
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_transfer_preferences_impl_dest_failure() {
    let source = MockServer::start();
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/app.bsky.actor.getPreferences");
        then.status(200).json_body(serde_json::json!({
            "preferences": []
        }));
    });

    let dest = MockServer::start();
    dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/app.bsky.actor.putPreferences");
        then.status(500).body("server error");
    });

    let source_client = bearer_client_at(source.base_url());
    let dest_client = bearer_client_at(dest.base_url());

    let result = transfer_preferences_impl(&source_client, &dest_client).await;

    assert!(matches!(
        result,
        Err(MigrationError::PreferencesTransferFailed { .. })
    ));
}

// ── Task 4 tests: verify_import ────────────────────────────────────────

// Pure: import_reconciles is true when imported_blobs == expected_blobs AND repo_commit exists
#[test]
fn test_import_reconciles_true_when_complete() {
    let status = crate::pds_client::AccountStatus {
        activated: false,
        valid_did: true,
        repo_commit: Some("baffy".to_string()),
        repo_rev: Some("rev".to_string()),
        stored_blocks: 10,
        indexed_records: 5,
        private_state_values: 0,
        expected_blobs: 10,
        imported_blobs: 10,
    };

    assert!(import_reconciles_with_loss(&status, 0));
}

// Pure: import_reconciles is true even when valid_did = false
#[test]
fn test_import_reconciles_ignores_valid_did() {
    let status = crate::pds_client::AccountStatus {
        activated: false,
        valid_did: false, // Still invalid DID, but import reconciles
        repo_commit: Some("baffy".to_string()),
        repo_rev: Some("rev".to_string()),
        stored_blocks: 10,
        indexed_records: 5,
        private_state_values: 0,
        expected_blobs: 10,
        imported_blobs: 10,
    };

    assert!(import_reconciles_with_loss(&status, 0));
}

// Pure: import_reconciles is false when imported_blobs < expected_blobs
#[test]
fn test_import_reconciles_false_when_blobs_incomplete() {
    let status = crate::pds_client::AccountStatus {
        activated: false,
        valid_did: true,
        repo_commit: Some("baffy".to_string()),
        repo_rev: Some("rev".to_string()),
        stored_blocks: 10,
        indexed_records: 5,
        private_state_values: 0,
        expected_blobs: 10,
        imported_blobs: 5, // Incomplete
    };

    assert!(!import_reconciles_with_loss(&status, 0));
}

// Pure: import_reconciles is false when repo_commit is None
#[test]
fn test_import_reconciles_false_when_repo_absent() {
    let status = crate::pds_client::AccountStatus {
        activated: false,
        valid_did: true,
        repo_commit: None, // No repo yet
        repo_rev: None,
        stored_blocks: 0,
        indexed_records: 0,
        private_state_values: 0,
        expected_blobs: 10,
        imported_blobs: 10,
    };

    assert!(!import_reconciles_with_loss(&status, 0));
}

// Pure: a degraded import reconciles when imported + accepted-loss == expected. The
// skipped blobs never arrive, so without the tolerance verify_import would reject forever.
#[test]
fn test_import_reconciles_with_loss_tolerates_accepted_skips() {
    let status = crate::pds_client::AccountStatus {
        activated: false,
        valid_did: true,
        repo_commit: Some("baffy".to_string()),
        repo_rev: Some("rev".to_string()),
        stored_blocks: 10,
        indexed_records: 5,
        private_state_values: 0,
        expected_blobs: 10,
        imported_blobs: 7, // 3 blobs permanently lost
    };

    // 3 accepted losses close the gap; 2 leaves it open; 0 (exact) fails.
    assert!(import_reconciles_with_loss(&status, 3));
    assert!(!import_reconciles_with_loss(&status, 2));
    assert!(!import_reconciles_with_loss(&status, 0));
}

// Pure: accepted loss never papers over a MISSING repo — a degraded blob set with no
// repo commit must still fail the gate.
#[test]
fn test_import_reconciles_with_loss_still_requires_repo() {
    let status = crate::pds_client::AccountStatus {
        activated: false,
        valid_did: true,
        repo_commit: None,
        repo_rev: None,
        stored_blocks: 0,
        indexed_records: 0,
        private_state_values: 0,
        expected_blobs: 10,
        imported_blobs: 7,
    };

    assert!(!import_reconciles_with_loss(&status, 3));
}

// Pure: the per-blob backoff is 250ms after the 1st failure, 500ms after the 2nd.
#[test]
fn test_blob_backoff_schedule() {
    assert_eq!(blob_backoff(1), std::time::Duration::from_millis(250));
    assert_eq!(blob_backoff(2), std::time::Duration::from_millis(500));
}

// A real checkAccountStatus payload with imported==expected and a repo commit passes the
// import_reconciles gate (the branch verify_import uses to decide whether to advance to Verified).
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_verify_import_gate_reconciles_on_complete_status() {
    let dest = MockServer::start();
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.server.checkAccountStatus");
        then.status(200).json_body(serde_json::json!({
            "activated": false,
            "validDid": true,
            "repoCommit": "baffy",
            "repoRev": "rev",
            "storedBlocks": 10,
            "indexedRecords": 5,
            "privateStateValues": 0,
            "expectedBlobs": 10,
            "importedBlobs": 10
        }));
    });

    let dest_client = bearer_client_at(dest.base_url());

    let status = crate::pds_client::check_account_status(&dest_client)
        .await
        .unwrap();

    assert!(import_reconciles_with_loss(&status, 0));
    assert_eq!(status.imported_blobs, 10);
    assert_eq!(status.expected_blobs, 10);
}

// A real checkAccountStatus payload with imported<expected fails the import_reconciles
// gate (the branch on which verify_import returns VerificationIncomplete with these counts).
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_verify_import_gate_rejects_incomplete_status() {
    let dest = MockServer::start();
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.server.checkAccountStatus");
        then.status(200).json_body(serde_json::json!({
            "activated": false,
            "validDid": false,
            "repoCommit": null,
            "repoRev": null,
            "storedBlocks": 0,
            "indexedRecords": 0,
            "privateStateValues": 0,
            "expectedBlobs": 10,
            "importedBlobs": 5
        }));
    });

    let dest_client = bearer_client_at(dest.base_url());

    let status = crate::pds_client::check_account_status(&dest_client)
        .await
        .unwrap();

    // Verify the pure gate catches the incompleteness
    assert!(!import_reconciles_with_loss(&status, 0));
    assert_eq!(status.imported_blobs, 5);
    assert_eq!(status.expected_blobs, 10);
}

// ── Task 1 tests: arm_identity_leg ─────────────────────────────────────

// Pure gate: arm_identity_leg before Verified phase returns MIGRATION_NOT_READY
#[test]
fn test_arm_identity_leg_phase_gate_too_low() {
    let state = Some(OutboundMigrationState {
        did: "did:plc:abc123".into(),
        source_pds_url: "https://source.pds".into(),
        dest_pds_url: "https://dest.pds".into(),
        dest_did: "did:web:dest".into(),
        handle: "alice.test".into(),
        source_client: None,
        dest_client: Some(Arc::new(bearer_client_at("https://dest.pds".into()))),
        phase: MigrationPhase::PreferencesTransferred, // Too early!
        accepted_blob_loss: Vec::new(),
        recovery: false,
    });

    let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::Verified);
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
}

// Build a Verified OutboundMigrationState with both clients populated.
fn verified_state(did: &str) -> OutboundMigrationState {
    OutboundMigrationState {
        did: did.into(),
        source_pds_url: "https://source.pds".into(),
        dest_pds_url: "https://dest.pds".into(),
        dest_did: "did:web:dest".into(),
        handle: "alice.test".into(),
        source_client: Some(Arc::new(bearer_client_at("https://source.pds".into()))),
        dest_client: Some(Arc::new(bearer_client_at("https://dest.pds".into()))),
        phase: MigrationPhase::Verified,
        accepted_blob_loss: Vec::new(),
        recovery: false,
    }
}

// Re-running an earlier step rewinds the phase, so a re-drained migration can't finalize
// without verifying again; and a swapped-in migration for another DID refuses the write.
#[tokio::test]
async fn migration_journal_rewinds_on_rerun_and_refuses_another_did() {
    let did = "did:plc:abc123";
    let orchestration = tokio::sync::Mutex::new(Some(verified_state(did)));
    let journal = MigrationJournal::new(&orchestration, did);

    journal
        .commit(MigrationPhase::BlobsTransferred, |mig| {
            mig.accepted_blob_loss = Vec::new()
        })
        .await
        .unwrap();
    assert_eq!(
        journal.load().await.unwrap(),
        Some(MigrationPhase::BlobsTransferred)
    );
    assert!(ensure_phase_did(
        &*orchestration.lock().await,
        did,
        MigrationPhase::IdentityArmed
    )
    .is_err());

    let other = MigrationJournal::new(&orchestration, "did:plc:other");
    assert_eq!(other.load().await.unwrap(), None);
    assert!(matches!(
        other.save(MigrationPhase::Finalized).await,
        Err(MigrationError::MigrationNotReady { .. })
    ));
    assert_eq!(
        journal.load().await.unwrap(),
        Some(MigrationPhase::BlobsTransferred)
    );
}

// The REAL arm_identity_leg_core parks a migrate::MigrationState AND advances the
// orchestration phase to IdentityArmed (drives production code, not a hand-rolled copy).
#[tokio::test]
async fn test_arm_identity_leg_core_populates_state_and_advances_phase() {
    let did = "did:plc:abc123";
    let orchestration = tokio::sync::Mutex::new(Some(verified_state(did)));
    let migration_state = tokio::sync::Mutex::new(None);

    arm_identity_leg_core(&orchestration, &migration_state, did)
        .await
        .expect("arm should succeed on a Verified state");

    // migrate::MigrationState parked with the right DID …
    let mig = migration_state.lock().await;
    assert_eq!(mig.as_ref().expect("migration_state parked").did, did);
    // … and the orchestration phase advanced to IdentityArmed.
    assert_eq!(
        orchestration.lock().await.as_ref().unwrap().phase,
        MigrationPhase::IdentityArmed
    );
}

// arm_identity_leg_core before Verified → MIGRATION_NOT_READY, and nothing is parked.
#[tokio::test]
async fn test_arm_identity_leg_core_gate_before_verified() {
    let did = "did:plc:abc123";
    let mut early = verified_state(did);
    early.phase = MigrationPhase::PreferencesTransferred; // one below Verified
    let orchestration = tokio::sync::Mutex::new(Some(early));
    let migration_state = tokio::sync::Mutex::new(None);

    let result = arm_identity_leg_core(&orchestration, &migration_state, did).await;
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
    assert!(
        migration_state.lock().await.is_none(),
        "must not park on a failed gate"
    );
}

// Missing dest_client (impossible past DestCreated, but defended) → AccountCreationFailed.
#[tokio::test]
async fn test_arm_identity_leg_core_missing_dest_client() {
    let did = "did:plc:abc123";
    let mut state = verified_state(did);
    state.dest_client = None;
    let orchestration = tokio::sync::Mutex::new(Some(state));
    let migration_state = tokio::sync::Mutex::new(None);

    let result = arm_identity_leg_core(&orchestration, &migration_state, did).await;
    assert!(matches!(
        result,
        Err(MigrationError::AccountCreationFailed { .. })
    ));
}

// ── Task 2 tests: finalize_migration ───────────────────────────────────

// Gate: finalize_migration before IdentityArmed returns MIGRATION_NOT_READY
#[test]
fn test_finalize_migration_phase_gate_too_low() {
    let state = Some(OutboundMigrationState {
        did: "did:plc:abc123".into(),
        source_pds_url: "https://source.pds".into(),
        dest_pds_url: "https://dest.pds".into(),
        dest_did: "did:web:dest".into(),
        handle: "alice.test".into(),
        source_client: None,
        dest_client: None,
        phase: MigrationPhase::Verified, // Too early for finalize!
        accepted_blob_loss: Vec::new(),
        recovery: false,
    });

    let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::IdentityArmed);
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
}

// Build an IdentityArmed state wired to two live mock servers for cutover tests.
fn armed_state_at(did: &str, dest_url: &str, source_url: &str) -> OutboundMigrationState {
    let mut s = armed_state(did);
    s.dest_client = Some(Arc::new(bearer_client_at(dest_url.to_string())));
    s.source_client = Some(Arc::new(bearer_client_at(source_url.to_string())));
    s
}

// The cutover runs in strict order: activate destination → sovereign session → deactivate
// source. Ordering is OBSERVED — the two account mocks and the injected session step each
// record their name into a shared vec, and we assert the recorded sequence.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_finalize_migration_core_orders_activate_session_deactivate() {
    use std::sync::Mutex as StdMutex;
    let did = "did:plc:abc123";
    let order: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));

    let dest = MockServer::start();
    let order_a = order.clone();
    let activate = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.activateAccount")
            .is_true(move |_req| {
                order_a.lock().unwrap().push("activate".to_string());
                true
            });
        then.status(200).body("{}");
    });

    let source = MockServer::start();
    let order_d = order.clone();
    let deactivate = source.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.deactivateAccount")
            .is_true(move |_req| {
                order_d.lock().unwrap().push("deactivate".to_string());
                true
            });
        then.status(200).body("{}");
    });

    let orchestration = tokio::sync::Mutex::new(Some(armed_state_at(
        did,
        &dest.base_url(),
        &source.base_url(),
    )));
    let migration_state = tokio::sync::Mutex::new(None);

    let order_s = order.clone();
    let result = finalize_migration_core(&orchestration, &migration_state, did, || async move {
        order_s.lock().unwrap().push("session".to_string());
        Ok::<(), MigrationError>(())
    })
    .await;

    assert!(result.is_ok());
    assert_eq!(activate.calls(), 1, "activate must be called once");
    assert_eq!(deactivate.calls(), 1, "deactivate must be called once");
    assert_eq!(
        *order.lock().unwrap(),
        vec![
            "activate".to_string(),
            "session".to_string(),
            "deactivate".to_string()
        ],
        "activate → persist sovereign session → deactivate"
    );
    assert_eq!(
        orchestration.lock().await.as_ref().unwrap().phase,
        MigrationPhase::Finalized
    );
}

// A sovereign-login failure (401/429/5xx/transport) after activation leaves the source
// account untouched (deactivate never called) and the phase un-advanced — retryable.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_finalize_migration_core_sovereign_failure_leaves_source_untouched() {
    let did = "did:plc:abc123";
    let dest = MockServer::start();
    let activate = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.activateAccount");
        then.status(200).body("{}");
    });
    let source = MockServer::start();
    let deactivate = source.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.deactivateAccount");
        then.status(200).body("{}");
    });

    let orchestration = tokio::sync::Mutex::new(Some(armed_state_at(
        did,
        &dest.base_url(),
        &source.base_url(),
    )));
    let migration_state = tokio::sync::Mutex::new(None);

    let result = finalize_migration_core(&orchestration, &migration_state, did, || async {
        Err::<(), MigrationError>(MigrationError::SovereignLoginFailed {
            message: "destination rejected the device-key proof".into(),
        })
    })
    .await;

    assert!(matches!(
        result,
        Err(MigrationError::SovereignLoginFailed { .. })
    ));
    assert_eq!(
        activate.calls(),
        1,
        "destination activated before the sovereign leg"
    );
    assert_eq!(
        deactivate.calls(),
        0,
        "source untouched — deactivate not called"
    );
    assert_eq!(
        orchestration.lock().await.as_ref().unwrap().phase,
        MigrationPhase::IdentityArmed,
        "phase not advanced — the cutover is retryable"
    );
}

// A Keychain write failure (session minted but not persisted) also leaves the source untouched
// and keeps the phase resumable, without corrupting an existing token record.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_finalize_migration_core_persist_failure_leaves_source_untouched() {
    let did = "did:plc:abc123";
    let dest = MockServer::start();
    let activate = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.activateAccount");
        then.status(200).body("{}");
    });
    let source = MockServer::start();
    let deactivate = source.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.deactivateAccount");
        then.status(200).body("{}");
    });

    let orchestration = tokio::sync::Mutex::new(Some(armed_state_at(
        did,
        &dest.base_url(),
        &source.base_url(),
    )));
    let migration_state = tokio::sync::Mutex::new(None);

    let result = finalize_migration_core(&orchestration, &migration_state, did, || async {
        Err::<(), MigrationError>(MigrationError::SessionPersistFailed {
            message: "keychain write denied".into(),
        })
    })
    .await;

    assert!(matches!(
        result,
        Err(MigrationError::SessionPersistFailed { .. })
    ));
    assert_eq!(
        deactivate.calls(),
        0,
        "source untouched — deactivate not called"
    );
    assert_eq!(activate.calls(), 1);
    assert_eq!(
        orchestration.lock().await.as_ref().unwrap().phase,
        MigrationPhase::IdentityArmed
    );
}

// Repeating finalize after a successful activation is safe: activate/deactivate are server
// idempotent and the account is never recreated or reactivated. (No reserveSigningKey /
// createAccount mock exists, so a re-finalize that tried to recreate would fail loudly.)
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_finalize_migration_core_repeat_is_safe() {
    let did = "did:plc:abc123";
    let dest = MockServer::start();
    let activate = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.activateAccount");
        then.status(200).body("{}");
    });
    let source = MockServer::start();
    let deactivate = source.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.deactivateAccount");
        then.status(200).body("{}");
    });

    let orchestration = tokio::sync::Mutex::new(Some(armed_state_at(
        did,
        &dest.base_url(),
        &source.base_url(),
    )));
    let migration_state = tokio::sync::Mutex::new(None);

    for _ in 0..2 {
        finalize_migration_core(&orchestration, &migration_state, did, || async {
            Ok::<(), MigrationError>(())
        })
        .await
        .expect("repeating finalize after activation is safe");
    }

    assert_eq!(
        activate.calls(),
        2,
        "activate is server-idempotent (no-op when active)"
    );
    assert_eq!(
        deactivate.calls(),
        2,
        "source deactivated, never reactivated"
    );
    assert_eq!(
        orchestration.lock().await.as_ref().unwrap().phase,
        MigrationPhase::Finalized
    );
}

// Idempotency of the sovereign leg itself: when a persisted record with an unexpired refresh
// token already exists, ensure_sovereign_session_persisted returns Ok WITHOUT minting (no
// device-key signature, no network). Proven by pointing the PdsClient at an unroutable address
// — a mint attempt would error, so Ok is only reachable via the skip.
#[tokio::test]
async fn test_ensure_sovereign_session_persisted_skips_when_valid_record_exists() {
    let did = "did:plc:idempotentskip";
    let core = &crate::test_support::core_at(1_000);
    let store = core.identities();
    store.add_identity(did).unwrap();
    store.get_or_create_device_key(did).unwrap();

    let now = 1_000i64;
    let record = crate::identity_store::SovereignTokenRecord {
        version: crate::identity_store::SovereignTokenRecord::VERSION,
        access_jwt: "access".into(),
        refresh_jwt: "refresh".into(),
        pds_url: "https://dest.example".into(),
        server_did: "did:web:dest.example".into(),
        access_expires_at: Some(9_999),
        refresh_expires_at: Some(9_999), // well beyond `now`
        stored_at: now as u64,
    };
    store.store_oauth_tokens(did, &record).unwrap();

    let pds_client = crate::pds_client::new_for_test("http://127.0.0.1:1/".into());
    let result =
        ensure_sovereign_session_persisted(&core.with_pds_client(pds_client.clone()), did).await;
    assert!(
        result.is_ok(),
        "valid persisted session → skip mint (no network, no signature)"
    );

    // The pre-existing record is untouched.
    let loaded = store.load_oauth_tokens(did).unwrap().unwrap();
    assert_eq!(loaded.refresh_jwt, "refresh");

    let _ = store.remove_identity(did);
}

/// A JWT carrying the full claim set `ensure_bearer_session_persisted` validates.
fn make_session_jwt(sub: &str, aud: &str, exp: u64) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#);
    let payload = URL_SAFE_NO_PAD.encode(format!(
        r#"{{"exp":{},"sub":"{}","aud":"{}"}}"#,
        exp, sub, aud
    ));
    format!("{}.{}.sig", header, payload)
}

// Happy path: the destination Bearer pair is validated (sub == did, aud == destination)
// and persisted with the claim-derived expiries. No network, no signature.
#[tokio::test]
async fn test_ensure_bearer_session_persisted_stores_bearer_pair() {
    let did = "did:web:rehearsal.example";
    let core = &crate::test_support::core_at(1_000);
    let store = core.identities();
    store.add_identity(did).unwrap();

    let access = make_session_jwt(did, "did:web:pds.example", 9_000);
    let refresh = make_session_jwt(did, "did:web:pds.example", 20_000);
    let client = OAuthClient::new_bearer(
        access.clone(),
        refresh.clone(),
        "https://pds.example".into(),
    )
    .unwrap();

    ensure_bearer_session_persisted(
        core,
        did,
        &client,
        "https://pds.example/",
        "did:web:pds.example",
    )
    .await
    .expect("valid pair persists");

    let record = store.load_oauth_tokens(did).unwrap().unwrap();
    assert_eq!(record.access_jwt, access);
    assert_eq!(record.refresh_jwt, refresh);
    assert_eq!(
        record.pds_url, "https://pds.example",
        "trailing slash trimmed"
    );
    assert_eq!(record.server_did, "did:web:pds.example");
    assert_eq!(record.access_expires_at, Some(9_000));
    assert_eq!(record.refresh_expires_at, Some(20_000));

    let _ = store.remove_identity(did);
}

fn capabilities(reached: bool, names: &[&str]) -> ServerCapabilities {
    ServerCapabilities {
        reached,
        version: None,
        capabilities: names.iter().map(|name| name.to_string()).collect(),
    }
}

// The credential decision, over every combination that reaches it. The did:plc rows are
// the point of this change: the same DID finalizes differently depending only on whether
// the destination advertises the route that would have to serve the mint.
#[test]
fn test_destination_credential_matrix() {
    let plc = "did:plc:subject";
    let web = "did:web:subject.example";

    // Custos destination: unchanged from before this branch existed.
    assert_eq!(
        destination_credential(
            plc,
            &capabilities(
                true,
                &[crate::pds_capabilities::capability::SOVEREIGN_SESSIONS]
            )
        ),
        DestinationCredential::Sovereign
    );
    // A reference PDS / bsky.social answers describeServer with no `custos` object.
    assert_eq!(
        destination_credential(plc, &capabilities(true, &[])),
        DestinationCredential::Bearer
    );
    // A Custos deployment running with sovereign sessions switched off is the same case.
    assert_eq!(
        destination_credential(
            plc,
            &capabilities(true, &[crate::pds_capabilities::capability::ESCROW])
        ),
        DestinationCredential::Bearer
    );
    // Never asked: keep today's behavior rather than infer an absence from silence.
    assert_eq!(
        destination_credential(plc, &ServerCapabilities::none()),
        DestinationCredential::Sovereign
    );

    // A did:web has no rotation keys to sign the proof with — host is irrelevant.
    for destination in [
        capabilities(
            true,
            &[crate::pds_capabilities::capability::SOVEREIGN_SESSIONS],
        ),
        capabilities(true, &[]),
        ServerCapabilities::none(),
    ] {
        assert_eq!(
            destination_credential(web, &destination),
            DestinationCredential::Bearer
        );
    }
}

// The Phase 3 case end to end at the persistence seam: a did:plc account migrating onto a
// non-Custos host stores the createAccount pair into the same `{did}:oauth-tokens` record
// `sovereign_login` writes, which is what lets `session_provider` restore and refresh it
// afterwards with no knowledge of which path minted it.
#[tokio::test]
async fn test_ensure_bearer_session_persisted_serves_a_did_plc_on_a_foreign_host() {
    let did = "did:plc:foreignhost";
    let core = &crate::test_support::core_at(1_000);
    let store = core.identities();
    store.add_identity(did).unwrap();

    let access = make_session_jwt(did, "did:web:reference.example", 9_000);
    let refresh = make_session_jwt(did, "did:web:reference.example", 20_000);
    let client = OAuthClient::new_bearer(
        access.clone(),
        refresh.clone(),
        "https://reference.example".into(),
    )
    .unwrap();

    ensure_bearer_session_persisted(
        core,
        did,
        &client,
        "https://reference.example",
        "did:web:reference.example",
    )
    .await
    .expect("a did:plc bearer pair persists exactly like a did:web one");

    let record = store.load_oauth_tokens(did).unwrap().unwrap();
    assert_eq!(record.access_jwt, access);
    assert_eq!(record.refresh_jwt, refresh);
    assert_eq!(record.pds_url, "https://reference.example");
    assert_eq!(record.refresh_expires_at, Some(20_000));

    let _ = store.remove_identity(did);
}

// Idempotency: an existing record with an unexpired refresh token short-circuits before any
// token validation — proven by handing a client whose tokens would FAIL validation (wrong sub)
// and still getting Ok with the original record intact.
#[tokio::test]
async fn test_ensure_bearer_session_persisted_skips_when_valid_record_exists() {
    let did = "did:web:rehearsal.example";
    let core = &crate::test_support::core_at(1_000);
    let store = core.identities();
    store.add_identity(did).unwrap();

    let now = 1_000i64;
    let record = crate::identity_store::SovereignTokenRecord {
        version: crate::identity_store::SovereignTokenRecord::VERSION,
        access_jwt: "access".into(),
        refresh_jwt: "refresh".into(),
        pds_url: "https://pds.example".into(),
        server_did: "did:web:pds.example".into(),
        access_expires_at: Some(9_999),
        refresh_expires_at: Some(9_999), // well beyond `now`
        stored_at: now as u64,
    };
    store.store_oauth_tokens(did, &record).unwrap();

    let wrong = make_session_jwt("did:web:someone.else", "did:web:pds.example", 9_000);
    let client =
        OAuthClient::new_bearer(wrong.clone(), wrong, "https://pds.example".into()).unwrap();

    ensure_bearer_session_persisted(
        core,
        did,
        &client,
        "https://pds.example",
        "did:web:pds.example",
    )
    .await
    .expect("valid persisted session → skip without validating the client pair");

    let loaded = store.load_oauth_tokens(did).unwrap().unwrap();
    assert_eq!(loaded.refresh_jwt, "refresh", "original record untouched");

    let _ = store.remove_identity(did);
}

// A session pair whose subject is not the migrated DID must never be persisted under it.
#[tokio::test]
async fn test_ensure_bearer_session_persisted_rejects_sub_mismatch() {
    let did = "did:web:rehearsal.example";
    let core = &crate::test_support::core_at(1_000);
    let store = core.identities();
    store.add_identity(did).unwrap();

    let wrong = make_session_jwt("did:web:someone.else", "did:web:pds.example", 9_000);
    let client =
        OAuthClient::new_bearer(wrong.clone(), wrong, "https://pds.example".into()).unwrap();

    let result = ensure_bearer_session_persisted(
        core,
        did,
        &client,
        "https://pds.example",
        "did:web:pds.example",
    )
    .await;
    assert!(matches!(
        result,
        Err(MigrationError::SessionPersistFailed { .. })
    ));
    assert!(store.load_oauth_tokens(did).unwrap().is_none());

    let _ = store.remove_identity(did);
}

// A session pair minted for a different server (audience mismatch on both the server DID and
// the PDS URL) is refused.
#[tokio::test]
async fn test_ensure_bearer_session_persisted_rejects_aud_mismatch() {
    let did = "did:web:rehearsal.example";
    let core = &crate::test_support::core_at(1_000);
    let store = core.identities();
    store.add_identity(did).unwrap();

    let foreign = make_session_jwt(did, "did:web:other-server.example", 9_000);
    let client =
        OAuthClient::new_bearer(foreign.clone(), foreign, "https://pds.example".into()).unwrap();

    let result = ensure_bearer_session_persisted(
        core,
        did,
        &client,
        "https://pds.example",
        "did:web:pds.example",
    )
    .await;
    assert!(matches!(
        result,
        Err(MigrationError::SessionPersistFailed { .. })
    ));
    assert!(store.load_oauth_tokens(did).unwrap().is_none());

    let _ = store.remove_identity(did);
}

// An IdentityArmed OutboundMigrationState with both clients populated.
fn armed_state(did: &str) -> OutboundMigrationState {
    let mut s = verified_state(did);
    s.phase = MigrationPhase::IdentityArmed;
    s
}

// The REAL finalize_migration_core refuses while migrate::migration_state is still Some
// (identity op not yet submitted). No network is reached, so this is a pure test.
#[tokio::test]
async fn test_finalize_migration_core_rejects_when_identity_op_not_submitted() {
    let did = "did:plc:abc123";
    let orchestration = tokio::sync::Mutex::new(Some(armed_state(did)));
    // migration_state still Some → the identity op has NOT been submitted.
    let migration_state = tokio::sync::Mutex::new(Some(crate::migrate::MigrationState {
        did: did.into(),
        dest_oauth_client: Arc::new(bearer_client_at("https://dest.pds".into())),
        signed_op: None,
        op_cid: None,
    }));

    let result = finalize_migration_core(&orchestration, &migration_state, did, || async {
        Ok::<(), MigrationError>(())
    })
    .await;
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
    // Phase must not advance on a failed gate.
    assert_eq!(
        orchestration.lock().await.as_ref().unwrap().phase,
        MigrationPhase::IdentityArmed
    );
}

// Phase gate: finalize_migration_core before IdentityArmed → MIGRATION_NOT_READY.
#[tokio::test]
async fn test_finalize_migration_core_gate_before_identity_armed() {
    let did = "did:plc:abc123";
    let orchestration = tokio::sync::Mutex::new(Some(verified_state(did))); // Verified, not armed
    let migration_state = tokio::sync::Mutex::new(None);

    let result = finalize_migration_core(&orchestration, &migration_state, did, || async {
        Ok::<(), MigrationError>(())
    })
    .await;
    assert!(matches!(
        result,
        Err(MigrationError::MigrationNotReady { .. })
    ));
}

// End-to-end via the core: armed + cleared migration_state + mock activate/deactivate
// → Ok AND the orchestration phase advances to Finalized.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_finalize_migration_core_advances_to_finalized() {
    let did = "did:plc:abc123";
    let dest = MockServer::start();
    dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.activateAccount");
        then.status(200).body("{}");
    });
    let source = MockServer::start();
    source.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.deactivateAccount");
        then.status(200).body("{}");
    });

    let mut state = armed_state(did);
    state.dest_client = Some(Arc::new(bearer_client_at(dest.base_url())));
    state.source_client = Some(Arc::new(bearer_client_at(source.base_url())));
    let orchestration = tokio::sync::Mutex::new(Some(state));
    let migration_state = tokio::sync::Mutex::new(None); // identity op already submitted

    finalize_migration_core(&orchestration, &migration_state, did, || async {
        Ok::<(), MigrationError>(())
    })
    .await
    .expect("finalize should succeed when armed + identity op submitted");

    assert_eq!(
        orchestration.lock().await.as_ref().unwrap().phase,
        MigrationPhase::Finalized
    );
}

// ── Task 3 tests: Full-pipeline integration test ────────────────────────

// Full migration pipeline with three mock servers
// (source/old-PDS, dest/new-PDS, plc.directory). Drives the sequence:
// 1. reserveSigningKey + getServiceAuth + createAccount → dest_client
// 2. getRepo + importRepo (assert importRepo before uploadBlob)
// 3. listMissingBlobs + getBlob + uploadBlob (loop until empty)
// 4. getPreferences + putPreferences
// 5. checkAccountStatus → import_reconciles
// 6. arm_identity_leg (populates migration_state)
// 7. getRecommendedDidCredentials + plc.directory POST (identity submit)
// 8. activateAccount (dest) BEFORE deactivateAccount (source) — last hit (ordering enforced)
// Asserts: full sequence completes, all three legs hit in order,
// plc.directory POST exactly once, resume with partial blobs,
// abort before identity leg leaves dest deactivated.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_full_migration_pipeline_happy_path() {
    let core = &crate::test_support::core();
    let did = "did:plc:fullpipe";

    // The identity leg (build_migration_op) self-signs with the per-DID device key, which must
    // be registered first (IdentityStore/Keychain) and must be rotationKeys[0] in the current
    // audit log for the guard to pass. Mirrors migrate.rs's build/submit test setup.
    let store = core.identities();
    let _ = store.remove_identity(did);
    store.add_identity(did).expect("add_identity");
    let device_key_id = store
        .get_or_create_device_key(did)
        .expect("device key generation")
        .key_id;

    // ─ Set up three MockServers (source, dest, plc.directory) ─
    let source = MockServer::start();
    let source_url = source.base_url();

    let dest = MockServer::start();
    let dest_url = dest.base_url();

    let plc = MockServer::start();
    let plc_url = plc.base_url();

    // ─ Mock dest.reserveSigningKey ─
    dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.reserveSigningKey");
        then.status(200)
            .json_body(serde_json::json!({ "signingKey": "did:key:zDEST" }));
    });

    // ─ Mock source.getServiceAuth ─
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.server.getServiceAuth");
        then.status(200)
            .json_body(serde_json::json!({ "token": make_bearer_jwt(9999999999) }));
    });

    // ─ Mock dest.createAccount ─
    dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.createAccount");
        then.status(200).json_body(serde_json::json!({
            "accessJwt": make_bearer_jwt(9999999999),
            "refreshJwt": "refresh",
            "handle": "alice.test",
            "did": did
        }));
    });

    // ─ Mock source.getRepo (CAR bytes) ─
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getRepo");
        then.status(200).body("CAR-DATA");
    });

    // ─ Mock dest.importRepo ─
    dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.repo.importRepo");
        then.status(200);
    });

    // ─ Mock dest.listMissingBlobs (empty on first call) ─
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs");
        then.status(200)
            .json_body(serde_json::json!({ "blobs": [], "cursor": null }));
    });

    // ─ Mock source.getPreferences ─
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/app.bsky.actor.getPreferences");
        then.status(200)
            .json_body(serde_json::json!({ "preferences": [] }));
    });

    // ─ Mock dest.putPreferences ─
    dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/app.bsky.actor.putPreferences");
        then.status(200);
    });

    // ─ Mock dest.checkAccountStatus ─
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.server.checkAccountStatus");
        then.status(200).json_body(serde_json::json!({
            "activated": false,
            "validDid": false,
            "repoCommit": "baffy",
            "repoRev": "rev",
            "storedBlocks": 1,
            "indexedRecords": 0,
            "privateStateValues": 0,
            "expectedBlobs": 0,
            "importedBlobs": 0
        }));
    });

    // ─ Mock dest.getRecommendedDidCredentials ─
    dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials");
            then.status(200).json_body(serde_json::json!({
                "rotationKeys": ["did:key:zDEST"],
                "alsoKnownAs": ["at://alice.test"],
                "verificationMethods": { "atproto": "did:key:zDEST" },
                "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": &dest_url } }
            }));
        });

    // ─ Mock plc.directory POST (identity submit) ─
    let plc_post = plc.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path(format!("/{}", did));
        then.status(200);
    });

    // ─ Mock plc.directory GET (audit log fetch for build_migration_op) ─
    let plc_get_audit = plc.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/{}/log/audit", did));
            then.status(200)
                .json_body(serde_json::json!([{
                    "did": did,
                    "cid": "bafy_current",
                    "createdAt": "2026-07-03T00:00:00Z",
                    "nullified": false,
                    "operation": {
                        "type": "plc_operation",
                        // rotationKeys[0] must be the real per-DID device key (guard: sovereignty +
                        // authorization — the wallet key must already be in the current rotation set).
                        "rotationKeys": [device_key_id.clone(), "did:key:zOLD"],
                        "verificationMethods": { "atproto": "did:key:zOLDSIGN" },
                        "alsoKnownAs": ["at://alice.test"],
                        "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": &source_url } },
                        "prev": "bafy_prev",
                        "sig": "placeholder"
                    }
                }]));
        });

    // ─ Mock plc.directory GET (DID doc refetch — the PLC *data* document,
    //   the cached shape with rotationKeys) ─
    plc.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/{}/data", did));
            then.status(200).json_body(serde_json::json!({
                "did": did,
                "alsoKnownAs": ["at://alice.test"],
                "rotationKeys": [device_key_id.clone(), "did:key:zNEWSIGN"],
                "verificationMethods": { "atproto": "did:key:zNEWSIGN" },
                "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": &dest_url } }
            }));
        });

    // ─ Mock dest.activateAccount ─
    let activate = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.activateAccount");
        then.status(200);
    });

    // ─ Mock source.deactivateAccount ─
    let deactivate = source.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.deactivateAccount");
        then.status(200);
    });

    // ─ Sovereign-session leg (cutover step 2) ─
    // discover_pds resolves the DID doc from plc.directory (now pointing at dest after the
    // identity op landed) and HEAD-probes the endpoint; describeServer yields the server DID;
    // then the device-key-signed proof is POSTed to /v1/sessions/sovereign.

    // plc.directory GET /{did} — the W3C DID document (dest is the current PDS).
    plc.mock(|when, then| {
        when.method(httpmock::Method::GET).path(format!("/{}", did));
        then.status(200).json_body(serde_json::json!({
            "id": did,
            "alsoKnownAs": ["at://alice.test"],
            "verificationMethod": [],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": &dest_url,
            }],
        }));
    });

    // dest HEAD / — discover_pds reachability probe.
    dest.mock(|when, then| {
        when.method(httpmock::Method::HEAD).path("/");
        then.status(200);
    });

    // dest describeServer — yields the destination server DID used as the proof audience.
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.server.describeServer");
        then.status(200).json_body(serde_json::json!({
            "did": "did:web:dest",
            "availableUserDomains": [".dest.example"],
        }));
    });

    // Sovereign-session response JWTs: sub == did, aud == dest PDS URL (so
    // audience_matches_server accepts them), exp far in the future.
    let sovereign_jwt = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "exp": 9_999_999_999u64,
                "sub": did,
                "aud": dest_url.as_str(),
            }))
            .unwrap(),
        );
        format!("e30.{payload}.sig")
    };

    // dest POST /v1/sessions/sovereign — mints the durable full-access session.
    let sovereign = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path(crypto::SOVEREIGN_SESSION_PATH);
        then.status(200).json_body(serde_json::json!({
            "accessJwt": &sovereign_jwt,
            "refreshJwt": &sovereign_jwt,
            "handle": "alice.test",
            "did": did,
        }));
    });

    // ─ Build clients and state ─
    let pds_client = crate::pds_client::new_for_test(plc_url.clone());
    let core = &core.with_pds_client(pds_client.clone());

    let source_client = Arc::new(bearer_client_at(source_url.clone()));

    // ─ Step 1: create_destination_account_impl (returns the real dest Bearer client) ─
    let dest_result = create_destination_account_impl(
        &pds_client,
        &source_client,
        &dest_url,
        "did:web:dest",
        did,
        "alice.test",
        "alice@example.com",
        None,
        None,
    )
    .await;
    assert!(
        dest_result.is_ok(),
        "create_destination_account_impl should succeed"
    );
    let dest_client = dest_result.unwrap();

    // ─ Step 2: transfer_repo_impl ─
    let repo_result = transfer_repo_impl(&pds_client, &dest_client, &source_url, did, None).await;
    assert!(repo_result.is_ok(), "transfer_repo_impl should succeed");

    // ─ Step 3: drain_missing_blobs ─
    let blobs_result =
        drain_missing_blobs(&pds_client, &dest_client, Some(&source_url), did, None).await;
    assert!(blobs_result.is_ok(), "drain_missing_blobs should succeed");

    // ─ Step 4: transfer_preferences_impl ─
    let prefs_result = transfer_preferences_impl(&source_client, &dest_client).await;
    assert!(
        prefs_result.is_ok(),
        "transfer_preferences_impl should succeed"
    );

    // ─ Step 5: check_account_status via import_reconciles ─
    let status = crate::pds_client::check_account_status(&dest_client)
        .await
        .expect("check_account_status should succeed");
    assert!(
        import_reconciles_with_loss(&status, 0),
        "import should reconcile"
    );

    // ─ Step 6/7: identity leg — build_migration_op (dest getRecommendedDidCredentials +
    //   plc.directory audit fetch). arm_identity_leg (parking migrate::MigrationState) is a
    //   thin State mutation covered by its own gate test; here we drive the pure core. ─
    let built_op = crate::migrate::build_migration_op(core, &dest_client, did)
        .await
        .expect("build_migration_op should succeed");
    plc_get_audit.assert();

    // ─ Step 8: submit_migration_op (plc.directory POST) ─
    crate::migrate::submit_migration_op(core, did, &built_op.signed_op)
        .await
        .expect("submit_migration_op should succeed");
    plc_post.assert(); // Verify plc.directory was hit exactly once

    // ─ Step 9: the safe cutover via the production seam — activate dest → mint + persist the
    //   sovereign session → deactivate source → Finalized. Driven through finalize_migration_core
    //   with the real ensure_sovereign_session_persisted closure so the new seam is covered
    //   end-to-end (not the pure activate/deactivate helper). ─
    let orchestration = tokio::sync::Mutex::new(Some(OutboundMigrationState {
        did: did.into(),
        source_pds_url: source_url.clone(),
        dest_pds_url: dest_url.clone(),
        dest_did: "did:web:dest".into(),
        handle: "alice.test".into(),
        source_client: Some(source_client.clone()),
        dest_client: Some(dest_client),
        phase: MigrationPhase::IdentityArmed,
        accepted_blob_loss: Vec::new(),
        recovery: false,
    }));
    let migration_state = tokio::sync::Mutex::new(None); // identity op already submitted

    finalize_migration_core(&orchestration, &migration_state, did, || async move {
        ensure_sovereign_session_persisted(core, did).await
    })
    .await
    .expect("safe cutover should succeed");

    // ─ Verify plc.directory POST was hit exactly once ─
    assert_eq!(
        plc_post.calls(),
        1,
        "plc.directory POST must be hit exactly once"
    );

    // ─ Verify the full cutover: activate, mint sovereign session, deactivate ─
    assert_eq!(activate.calls(), 1, "activate must be called");
    assert_eq!(
        sovereign.calls(),
        1,
        "sovereign session must be minted once"
    );
    assert_eq!(deactivate.calls(), 1, "deactivate must be called");
    assert_eq!(
        orchestration.lock().await.as_ref().unwrap().phase,
        MigrationPhase::Finalized
    );

    // ─ The destination credential is durable: after this cutover a fresh client can be
    //   reconstructed from the persisted record alone (no in-memory session truth). ─
    assert!(
        crate::sovereign_session::stored_bearer_client(core, did)
            .expect("stored session should load")
            .is_some(),
        "migrated DID must have a persisted destination session"
    );

    let _ = store.remove_identity(did);
}

// The Phase 3 promise, end to end through the production seam: a did:plc account whose
// destination is a spec-compliant non-Custos PDS finalizes without ever calling
// /v1/sessions/sovereign, and lands a durable credential all the same.
//
// The sibling of the happy-path test's step 9, but driven through `finalize_migration_impl`
// — the whole snapshot → capability probe → branch → cutover path, everything the Tauri
// command does bar unwrapping `State`. The destination's describeServer carries no `custos`
// object, which is what every reference PDS / bsky.social answers, so the branch is chosen
// from a real probe of a real response rather than from an injected verdict.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_finalize_migration_uses_bearer_on_a_non_custos_destination() {
    let core = &crate::test_support::core();
    let did = "did:plc:noncustosdest";

    let store = core.identities();
    let _ = store.remove_identity(did);
    store.add_identity(did).expect("add_identity");

    // httpmock reuses ports across tests, so a verdict another test recorded for this
    // address would otherwise be read here instead of the mock below being asked.
    crate::pds_capabilities::clear_for_test();

    let source = MockServer::start();
    let source_url = source.base_url();
    let dest = MockServer::start();
    let dest_url = dest.base_url();
    let plc = MockServer::start();

    // The pair `createAccount` issues — sub == did, aud == the destination, both readable
    // JWTs, since the Bearer branch validates that binding before persisting.
    let session_jwt = |exp: u64| {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "exp": exp,
                "sub": did,
                "aud": dest_url.as_str(),
            }))
            .unwrap(),
        );
        format!("e30.{payload}.sig")
    };
    let access_jwt = session_jwt(9_999_999_999);
    let refresh_jwt = session_jwt(9_999_999_998);

    dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.reserveSigningKey");
        then.status(200)
            .json_body(serde_json::json!({ "signingKey": "did:key:zDEST" }));
    });
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.server.getServiceAuth");
        then.status(200)
            .json_body(serde_json::json!({ "token": make_bearer_jwt(9999999999) }));
    });
    let create_account = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.createAccount");
        then.status(200).json_body(serde_json::json!({
            "accessJwt": &access_jwt,
            "refreshJwt": &refresh_jwt,
            "handle": "alice.test",
            "did": did,
        }));
    });

    // The whole point: a describeServer with NO `custos` object — a real answer meaning
    // "this host advertises nothing", which is what the reference PDS returns.
    let describe = dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.server.describeServer");
        then.status(200).json_body(serde_json::json!({
            "did": "did:web:reference",
            "availableUserDomains": [".reference.example"],
        }));
    });

    let activate = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.activateAccount");
        then.status(200);
    });
    let deactivate = source.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.deactivateAccount");
        then.status(200);
    });

    // Registered so a call can be counted, and deliberately never expected to be hit.
    // A non-Custos host would 404 this path; the assertion below is the PR's core claim.
    let sovereign = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path(crypto::SOVEREIGN_SESSION_PATH);
        then.status(404);
    });

    let pds_client = crate::pds_client::new_for_test(plc.base_url());
    let source_client = Arc::new(bearer_client_at(source_url.clone()));

    let dest_client = create_destination_account_impl(
        &pds_client,
        &source_client,
        &dest_url,
        "did:web:reference",
        did,
        "alice.test",
        "alice@example.com",
        None,
        None,
    )
    .await
    .expect("createAccount against the non-Custos destination should succeed");
    create_account.assert();

    let orchestration = tokio::sync::Mutex::new(Some(OutboundMigrationState {
        did: did.into(),
        source_pds_url: source_url.clone(),
        dest_pds_url: dest_url.clone(),
        dest_did: "did:web:reference".into(),
        handle: "alice.test".into(),
        source_client: Some(source_client.clone()),
        dest_client: Some(dest_client),
        phase: MigrationPhase::IdentityArmed,
        accepted_blob_loss: Vec::new(),
        recovery: false,
    }));
    let migration_state = tokio::sync::Mutex::new(None); // identity op already submitted

    let core = &core.with_pds_client(pds_client.clone());
    *core.orchestration_state.lock().await = orchestration.into_inner();
    *core.migration_state.lock().await = migration_state.into_inner();
    finalize_migration(core, did.to_string())
        .await
        .expect("the cutover must complete against a non-Custos destination");

    assert!(
        describe.calls() >= 1,
        "the destination must actually be asked what it supports"
    );
    assert_eq!(
        sovereign.calls(),
        0,
        "/v1/sessions/sovereign must never be called for a destination that does not serve it"
    );
    assert_eq!(activate.calls(), 1, "destination must be activated");
    assert_eq!(deactivate.calls(), 1, "source must be deactivated");
    assert_eq!(
        core.orchestration_state
            .lock()
            .await
            .as_ref()
            .unwrap()
            .phase,
        MigrationPhase::Finalized
    );

    // The credential is durable and is exactly the pair createAccount issued.
    let record = store
        .load_oauth_tokens(did)
        .expect("record loads")
        .expect("the cutover must leave a persisted destination session");
    assert_eq!(record.access_jwt, access_jwt);
    assert_eq!(record.refresh_jwt, refresh_jwt);
    assert_eq!(record.server_did, "did:web:reference");
    assert!(
        crate::sovereign_session::stored_bearer_client(core, did)
            .expect("stored session should load")
            .is_some(),
        "a client must be reconstructible from the persisted record alone"
    );

    crate::pds_capabilities::clear_for_test();
    let _ = store.remove_identity(did);
}

// Resume scenario — listMissingBlobs returns partial set on first call, then empty
// Verify only the still-missing blobs are uploaded (not the full set)
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_full_migration_resume_partial_blobs() {
    let source = MockServer::start();
    let dest = MockServer::start();

    // ─ First page (no cursor): the still-missing set left by a partial prior drain ─
    // Matched only on the no-cursor request (query_param_missing) so it can't also match the
    // cursor=c1 re-list below (overlapping mocks would be ambiguous and could loop forever).
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs")
            .query_param_missing("cursor");
        then.status(200).json_body(serde_json::json!({
            "blobs": [
                { "cid": "cid_a", "recordUri": "at://did/1" },
                { "cid": "cid_b", "recordUri": "at://did/2" }
            ],
            "cursor": "c1"
        }));
    });

    // ─ Second listMissingBlobs (cursor=c1): drained → empty, terminates the loop ─
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs")
            .query_param("cursor", "c1");
        then.status(200)
            .json_body(serde_json::json!({ "blobs": [], "cursor": null }));
    });

    // ─ Mock source.getBlob for each CID ─
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getBlob");
        then.status(200).body("blob-data");
    });

    // ─ Mock dest.uploadBlob ─
    let upload = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.repo.uploadBlob");
        then.status(200)
            .json_body(serde_json::json!({ "blob": { "$type": "blob" } }));
    });

    let pds_client = crate::pds_client::PdsClient::new();
    let dest_client = bearer_client_at(dest.base_url());

    let result = drain_missing_blobs(
        &pds_client,
        &dest_client,
        Some(&source.base_url()),
        "did:plc:test",
        None,
    )
    .await;

    assert!(result.is_ok(), "drain should complete successfully");
    // uploadBlob must be hit exactly twice (only the blobs on the first page)
    assert_eq!(
        upload.calls(),
        2,
        "uploadBlob hit count must match still-missing blobs (not full set)"
    );
}

// Abort before the identity leg — verify the dest stays deactivated (coherent state).
// Drives: create dest account → transfer repo → blobs → prefs → verify, then STOPS (no
// arm_identity_leg / finalize). Asserts activateAccount is never hit.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn test_full_migration_abort_before_identity_leg_leaves_dest_deactivated() {
    let source = MockServer::start();
    let dest = MockServer::start();
    let plc = MockServer::start();

    // ─ dest.reserveSigningKey ─
    dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.reserveSigningKey");
        then.status(200)
            .json_body(serde_json::json!({ "signingKey": "did:key:zDEST" }));
    });

    // ─ source.getServiceAuth ─
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.server.getServiceAuth");
        then.status(200)
            .json_body(serde_json::json!({ "token": make_bearer_jwt(9999999999) }));
    });

    // ─ dest.createAccount ─
    dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.createAccount");
        then.status(200).json_body(serde_json::json!({
            "accessJwt": make_bearer_jwt(9999999999),
            "refreshJwt": "refresh",
            "handle": "alice.test",
            "did": "did:plc:test"
        }));
    });

    // ─ source.getRepo ─
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.sync.getRepo");
        then.status(200).body("CAR");
    });

    // ─ dest.importRepo ─
    dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.repo.importRepo");
        then.status(200);
    });

    // ─ dest.listMissingBlobs (empty) ─
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs");
        then.status(200)
            .json_body(serde_json::json!({ "blobs": [], "cursor": null }));
    });

    // ─ source.getPreferences ─
    source.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/app.bsky.actor.getPreferences");
        then.status(200)
            .json_body(serde_json::json!({ "preferences": [] }));
    });

    // ─ dest.putPreferences ─
    dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/app.bsky.actor.putPreferences");
        then.status(200);
    });

    // ─ dest.checkAccountStatus ─
    dest.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/xrpc/com.atproto.server.checkAccountStatus");
        then.status(200).json_body(serde_json::json!({
            "activated": false,
            "validDid": false,
            "repoCommit": "baffy",
            "repoRev": "rev",
            "storedBlocks": 1,
            "indexedRecords": 0,
            "privateStateValues": 0,
            "expectedBlobs": 0,
            "importedBlobs": 0
        }));
    });

    // ─ Mock dest.activateAccount (MUST NEVER BE HIT) ─
    let activate = dest.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/xrpc/com.atproto.server.activateAccount");
        then.status(200);
    });

    let pds_client = crate::pds_client::new_for_test(plc.base_url());
    let source_client = Arc::new(bearer_client_at(source.base_url()));

    // ─ Run through steps 1–5 (up to verify_import, but NOT arm/finalize) ─
    let dest_client = create_destination_account_impl(
        &pds_client,
        &source_client,
        &dest.base_url(),
        "did:web:dest",
        "did:plc:test",
        "alice.test",
        "alice@example.com",
        None,
        None,
    )
    .await
    .expect("create dest");

    transfer_repo_impl(
        &pds_client,
        &dest_client,
        &source.base_url(),
        "did:plc:test",
        None,
    )
    .await
    .expect("transfer repo");

    drain_missing_blobs(
        &pds_client,
        &dest_client,
        Some(&source.base_url()),
        "did:plc:test",
        None,
    )
    .await
    .expect("drain blobs");

    transfer_preferences_impl(&source_client, &dest_client)
        .await
        .expect("transfer prefs");

    // Verify import is reconciled (now would come arm_identity_leg → identity op → finalize)
    // BUT: we stop here without calling finalize, simulating an abort.
    let status = crate::pds_client::check_account_status(&dest_client)
        .await
        .expect("check status");
    assert!(import_reconciles_with_loss(&status, 0));

    // ─ Verify dest was NEVER activated (coherent state on abort) ─
    assert_eq!(
        activate.calls(),
        0,
        "activateAccount must never be hit on abort before identity leg"
    );
}
