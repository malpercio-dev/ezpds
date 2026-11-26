//! The space transfer (`spaces.rs`) and the digest half of `verify_import`.

use super::tests::bearer_client_at;
use super::*;
use httpmock::{Method, MockServer};

const DID: &str = "did:plc:spacer";
/// A space this account is the authority of.
const AUTHORITY_SPACE: &str = "at://did:plc:spacer/space/app.example.group/alpha";
/// A space another account is the authority of; this account only writes there.
const WRITER_SPACE: &str = "at://did:plc:other/space/app.example.group/beta";

fn view(space: &str, data: Option<&str>) -> custos_client::spaces::SpaceView {
    serde_json::from_value(match data {
        Some(d) => serde_json::json!({ "space": space, "repoRev": "3l", "data": { "$bytes": d } }),
        None => serde_json::json!({ "space": space }),
    })
    .unwrap()
}

fn listing() -> serde_json::Value {
    serde_json::json!({ "spaces": [
        { "space": AUTHORITY_SPACE, "repoRev": "3la", "data": { "$bytes": "AAAA" }, "spaceRev": "3ls" },
        { "space": WRITER_SPACE, "repoRev": "3lb", "data": { "$bytes": "BBBB" } },
    ]})
}

fn status(imported: u64, expected: u64) -> serde_json::Value {
    serde_json::json!({
        "activated": false, "validDid": false, "repoCommit": "bafycommit", "repoRev": "rev",
        "storedBlocks": 1, "indexedRecords": 1, "privateStateValues": 0,
        "expectedBlobs": expected, "importedBlobs": imported
    })
}

fn state_at(
    phase: MigrationPhase,
    source: &MockServer,
    dest: &MockServer,
) -> tokio::sync::Mutex<Option<OutboundMigrationState>> {
    tokio::sync::Mutex::new(Some(OutboundMigrationState {
        did: DID.into(),
        source_pds_url: source.base_url(),
        dest_pds_url: dest.base_url(),
        dest_did: "did:web:dest".into(),
        handle: "spacer.test".into(),
        source_client: Some(Arc::new(bearer_client_at(source.base_url()))),
        dest_client: Some(Arc::new(bearer_client_at(dest.base_url()))),
        phase,
        accepted_blob_loss: Vec::new(),
        spaces: Default::default(),
        recovery: false,
    }))
}

async fn phase_of(state: &tokio::sync::Mutex<Option<OutboundMigrationState>>) -> MigrationPhase {
    state.lock().await.as_ref().unwrap().phase
}

/// The source side every transfer test shares: two spaces, one blob in the authority's.
fn mock_source(source: &MockServer, blob_status: u16) {
    source.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.space.listSpaces");
        then.status(200).json_body(listing());
    });
    for (space, body) in [(AUTHORITY_SPACE, "REPO-A"), (WRITER_SPACE, "REPO-B")] {
        source.mock(|when, then| {
            when.method(Method::GET)
                .path("/xrpc/com.atproto.space.getRepo")
                .query_param("space", space)
                .query_param("repo", DID);
            then.status(200).body(body);
        });
    }
    source.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.space.listBlobs")
            .query_param("space", AUTHORITY_SPACE);
        then.status(200)
            .json_body(serde_json::json!({ "cids": ["bafyalpha"] }));
    });
    source.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.space.listBlobs")
            .query_param("space", WRITER_SPACE);
        then.status(200)
            .json_body(serde_json::json!({ "cids": [] }));
    });
    source.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.space.getBlob")
            .query_param("space", AUTHORITY_SPACE)
            .query_param("cid", "bafyalpha");
        if blob_status == 200 {
            then.status(200).body("ALPHA-BYTES");
        } else {
            then.status(blob_status)
                .json_body(serde_json::json!({ "error": "InternalServerError" }));
        }
    });
}

// ── pure cores ─────────────────────────────────────────────────────

#[test]
fn authority_is_read_from_the_space_ref() {
    assert!(is_space_authority(AUTHORITY_SPACE, DID));
    assert!(!is_space_authority(WRITER_SPACE, DID));
    assert!(!is_space_authority("did:plc:spacer", DID));
    assert!(!is_space_authority("at://did:plc:spacerx/space/a.b/c", DID));
}

#[test]
fn digest_mismatches_names_missing_and_changed_spaces_but_not_accepted_ones() {
    let source = [
        view(AUTHORITY_SPACE, Some("AAAA")),
        view(WRITER_SPACE, Some("BBBB")),
        view("at://did:plc:x/space/a.b/gone", Some("CCCC")),
        view("at://did:plc:spacer/space/a.b/norepo", None),
    ];
    let dest = [
        view(AUTHORITY_SPACE, Some("AAAA")),
        view(WRITER_SPACE, Some("BBBC")),
        view("at://did:plc:spacer/space/a.b/norepo", None),
    ];
    assert_eq!(
        digest_mismatches(&source, &dest, &[]),
        vec![
            WRITER_SPACE.to_string(),
            "at://did:plc:x/space/a.b/gone".to_string()
        ]
    );
    assert_eq!(
        digest_mismatches(
            &source,
            &dest,
            &[
                WRITER_SPACE.to_string(),
                "at://did:plc:x/space/a.b/gone".to_string()
            ]
        ),
        Vec::<String>::new()
    );
}

#[test]
fn space_errors_and_space_blob_losses_serialize_for_the_wallet() {
    let json = serde_json::to_value(MigrationError::SpacesUnsupported {
        spaces: vec![AUTHORITY_SPACE.into()],
    })
    .unwrap();
    assert_eq!(json["code"], "SPACES_UNSUPPORTED");
    assert_eq!(json["spaces"][0], AUTHORITY_SPACE);
    let json = serde_json::to_value(MigrationError::SpaceVerificationFailed {
        spaces: vec![WRITER_SPACE.into()],
    })
    .unwrap();
    assert_eq!(json["code"], "SPACE_VERIFICATION_FAILED");
    assert_eq!(
        serde_json::to_value(MigrationError::SpaceTransferFailed {
            message: "x".into()
        })
        .unwrap()["code"],
        "SPACE_TRANSFER_FAILED"
    );

    let loss = |space: Option<&str>| BlobLoss {
        cid: "bafy".into(),
        record_uri: "at://x".into(),
        direction: BlobTransferDirection::Source,
        reason: "500".into(),
        space: space.map(str::to_string),
    };
    assert_eq!(
        serde_json::to_value(loss(Some(AUTHORITY_SPACE))).unwrap()["space"],
        AUTHORITY_SPACE
    );
    assert!(serde_json::to_value(loss(None))
        .unwrap()
        .get("space")
        .is_none());
}

// ── mock-server flows ──────────────────────────────────────────────

/// The destination's verify surface: its account status, the public blobs it still misses, and
/// which space blobs it stores (a `HEAD` on space `getBlob` answers 200 for those, 404 else).
fn mock_dest_verify<'a>(
    dest: &'a MockServer,
    imported: u64,
    expected: u64,
    missing: &[&str],
    stored: &[(&str, &str)],
) -> Vec<httpmock::Mock<'a>> {
    dest.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.server.checkAccountStatus");
        then.status(200).json_body(status(imported, expected));
    });
    let blobs: Vec<_> = missing
        .iter()
        .map(|cid| serde_json::json!({ "cid": cid, "recordUri": "at://did:plc:spacer/app.bsky.feed.post/1" }))
        .collect();
    dest.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.repo.listMissingBlobs");
        then.status(200)
            .json_body(serde_json::json!({ "blobs": blobs }));
    });
    let heads = stored
        .iter()
        .map(|(space, cid)| {
            dest.mock(|when, then| {
                when.method(Method::HEAD)
                    .path("/xrpc/com.atproto.space.getBlob")
                    .query_param("space", *space)
                    .query_param("repo", DID)
                    .query_param("cid", *cid);
                then.status(200);
            })
        })
        .collect();
    dest.mock(|when, then| {
        when.method(Method::HEAD)
            .path("/xrpc/com.atproto.space.getBlob");
        then.status(404);
    });
    heads
}

/// A destination that accepts every space import and blob upload and lists `listing()`.
fn mock_dest_imports(dest: &MockServer) {
    dest.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.space.listSpaces");
        then.status(200).json_body(listing());
    });
    for path in [
        "/xrpc/com.atproto.space.importSpaceMeta",
        "/xrpc/com.atproto.space.importRepo",
    ] {
        dest.mock(|when, then| {
            when.method(Method::POST).path(path);
            then.status(200).json_body(serde_json::json!({}));
        });
    }
    dest.mock(|when, then| {
        when.method(Method::POST)
            .path("/xrpc/com.atproto.repo.uploadBlob");
        then.status(200)
            .json_body(serde_json::json!({ "blob": {} }));
    });
}

fn mock_export(source: &MockServer) -> httpmock::Mock<'_> {
    source.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.space.exportSpaceMeta")
            .query_param("space", AUTHORITY_SPACE);
        then.status(200).body("META-A");
    })
}

async fn advance_to_preferences(state: &tokio::sync::Mutex<Option<OutboundMigrationState>>) {
    MigrationJournal::new(state, DID)
        .save(MigrationPhase::PreferencesTransferred)
        .await
        .unwrap();
}

// Two spaces, one this account is authority of and one it only writes in, reach Verified:
// digests match and the space blob is stored. Only the authority's space takes the meta pass;
// both take the repo pass. The destination's `importedBlobs` counting the space blob beside the
// public ones doesn't matter, because verify reads missing CIDs, not counts.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn two_spaces_transfer_and_verify_with_their_blobs() {
    let source = MockServer::start();
    let dest = MockServer::start();
    mock_source(&source, 200);
    let export = mock_export(&source);

    dest.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.space.listSpaces");
        then.status(200).json_body(listing());
    });
    let import_meta = dest.mock(|when, then| {
        when.method(Method::POST)
            .path("/xrpc/com.atproto.space.importSpaceMeta")
            .header("content-type", "application/vnd.dasl.star")
            .body("META-A");
        then.status(200).json_body(serde_json::json!({}));
    });
    let import_repos: Vec<_> = ["REPO-A", "REPO-B"]
        .into_iter()
        .map(|body| {
            dest.mock(|when, then| {
                when.method(Method::POST)
                    .path("/xrpc/com.atproto.space.importRepo")
                    .header("content-type", "application/vnd.dasl.star")
                    .body(body);
                then.status(200).json_body(serde_json::json!({}));
            })
        })
        .collect();
    let upload = dest.mock(|when, then| {
        when.method(Method::POST)
            .path("/xrpc/com.atproto.repo.uploadBlob")
            .body("ALPHA-BYTES");
        then.status(200)
            .json_body(serde_json::json!({ "blob": {} }));
    });
    let heads = mock_dest_verify(&dest, 5, 4, &[], &[(AUTHORITY_SPACE, "bafyalpha")]);

    let state = state_at(MigrationPhase::BlobsTransferred, &source, &dest);
    transfer_spaces_core(&state, DID, false).await.unwrap();
    assert_eq!(phase_of(&state).await, MigrationPhase::SpacesTransferred);
    assert_eq!(export.calls(), 1, "only the authority's space is exported");
    assert_eq!(import_meta.calls(), 1);
    for import in &import_repos {
        assert_eq!(import.calls(), 1);
    }
    assert_eq!(upload.calls(), 1);

    advance_to_preferences(&state).await;
    verify_import_core(&state, DID).await.unwrap();
    assert_eq!(phase_of(&state).await, MigrationPhase::Verified);
    assert_eq!(
        heads[0].calls(),
        1,
        "the space blob was checked on the destination"
    );
}

// A space blob the records reference but the destination doesn't store fails verify, naming its
// space, even though both hosts' digests match.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn verify_refuses_a_space_whose_blob_is_missing() {
    let source = MockServer::start();
    let dest = MockServer::start();
    mock_source(&source, 200);
    mock_dest_imports(&dest);
    mock_dest_verify(&dest, 4, 4, &[], &[]);

    let state = state_at(MigrationPhase::PreferencesTransferred, &source, &dest);
    match verify_import_core(&state, DID).await {
        Err(MigrationError::SpaceVerificationFailed { spaces }) => {
            assert_eq!(spaces, vec![AUTHORITY_SPACE])
        }
        other => panic!("expected SpaceVerificationFailed, got {other:?}"),
    }
    assert_eq!(
        phase_of(&state).await,
        MigrationPhase::PreferencesTransferred
    );
}

// The app is killed after a space transfer and the move starts over: a fresh migration state,
// against a destination already holding the space repos and blobs, transfers again (the imports
// replace) and verifies. Nothing verify reads came from the first session.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn a_rerun_from_a_fresh_state_against_a_partly_filled_destination_verifies() {
    let source = MockServer::start();
    let dest = MockServer::start();
    mock_source(&source, 200);
    mock_export(&source);
    mock_dest_imports(&dest);
    mock_dest_verify(&dest, 5, 4, &[], &[(AUTHORITY_SPACE, "bafyalpha")]);

    let first = state_at(MigrationPhase::BlobsTransferred, &source, &dest);
    transfer_spaces_core(&first, DID, false).await.unwrap();
    drop(first); // the killed session

    let fresh = state_at(MigrationPhase::BlobsTransferred, &source, &dest);
    transfer_spaces_core(&fresh, DID, false).await.unwrap();
    advance_to_preferences(&fresh).await;
    verify_import_core(&fresh, DID).await.unwrap();
    assert_eq!(phase_of(&fresh).await, MigrationPhase::Verified);
}

// With no spaces at all, verify is the public check alone: a still-missing public blob passes
// only once the user accepted it as lost from the drain.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn public_blob_accounting_without_spaces() {
    let source = MockServer::start();
    let dest = MockServer::start();
    source.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.space.listSpaces");
        then.status(501)
            .json_body(serde_json::json!({ "error": "MethodNotImplemented" }));
    });
    mock_dest_verify(&dest, 2, 3, &["bafypublic"], &[]);

    let state = state_at(MigrationPhase::PreferencesTransferred, &source, &dest);
    match verify_import_core(&state, DID).await {
        Err(MigrationError::VerificationIncomplete { imported, expected }) => {
            assert_eq!((imported, expected), (2, 3))
        }
        other => panic!("expected VerificationIncomplete, got {other:?}"),
    }

    state.lock().await.as_mut().unwrap().accepted_blob_loss = vec![BlobLoss {
        cid: "bafypublic".into(),
        record_uri: "at://did:plc:spacer/app.bsky.feed.post/1".into(),
        direction: BlobTransferDirection::Source,
        reason: "500".into(),
        space: None,
    }];
    verify_import_core(&state, DID).await.unwrap();
    assert_eq!(phase_of(&state).await, MigrationPhase::Verified);
}

// One blob referenced by a public record and a space record is stored once, so the destination's
// `importedBlobs` counts it once. Verify still passes: nothing subtracts space blobs from a count.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn a_blob_shared_by_a_public_and_a_space_record_verifies() {
    let source = MockServer::start();
    let dest = MockServer::start();
    source.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.space.listSpaces");
        then.status(200).json_body(serde_json::json!({ "spaces": [
            { "space": AUTHORITY_SPACE, "repoRev": "3la", "data": { "$bytes": "AAAA" }, "spaceRev": "3ls" },
        ]}));
    });
    source.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.space.listBlobs")
            .query_param("space", AUTHORITY_SPACE);
        then.status(200)
            .json_body(serde_json::json!({ "cids": ["bafyshared"] }));
    });
    dest.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.space.listSpaces");
        then.status(200).json_body(serde_json::json!({ "spaces": [
            { "space": AUTHORITY_SPACE, "repoRev": "3lz", "data": { "$bytes": "AAAA" }, "spaceRev": "3lt" },
        ]}));
    });
    // One public reference, one stored blob, nothing missing.
    mock_dest_verify(&dest, 1, 1, &[], &[(AUTHORITY_SPACE, "bafyshared")]);

    let state = state_at(MigrationPhase::PreferencesTransferred, &source, &dest);
    verify_import_core(&state, DID).await.unwrap();
    assert_eq!(phase_of(&state).await, MigrationPhase::Verified);
}

// A destination without spaces stops the step before anything is imported; accepting the loss
// advances it, and verify then leaves those spaces out.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn an_unsupported_destination_stops_before_importing_until_the_loss_is_accepted() {
    let source = MockServer::start();
    let dest = MockServer::start();
    mock_source(&source, 200);
    let export = mock_export(&source);
    dest.mock(|when, then| {
        when.path_prefix("/xrpc/com.atproto.space.");
        then.status(501)
            .json_body(serde_json::json!({ "error": "MethodNotImplemented" }));
    });
    mock_dest_verify(&dest, 0, 0, &[], &[]);

    let state = state_at(MigrationPhase::BlobsTransferred, &source, &dest);
    match transfer_spaces_core(&state, DID, false).await {
        Err(MigrationError::SpacesUnsupported { spaces }) => {
            assert_eq!(spaces, vec![AUTHORITY_SPACE, WRITER_SPACE])
        }
        other => panic!("expected SpacesUnsupported, got {other:?}"),
    }
    assert_eq!(phase_of(&state).await, MigrationPhase::BlobsTransferred);
    assert_eq!(
        export.calls(),
        0,
        "nothing is exported before the user decides"
    );

    transfer_spaces_core(&state, DID, true).await.unwrap();
    assert_eq!(phase_of(&state).await, MigrationPhase::SpacesTransferred);
    assert_eq!(export.calls(), 0);
    assert_eq!(
        state.lock().await.as_ref().unwrap().spaces.accepted_loss,
        vec![AUTHORITY_SPACE, WRITER_SPACE]
    );

    advance_to_preferences(&state).await;
    verify_import_core(&state, DID).await.unwrap();
}

// A space blob the source can't serve joins the loss manifest with its space-ref. Accepting it
// advances, and verify excuses that blob (and only the accepted public loss on the public side).
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn a_space_blob_loss_joins_the_manifest_and_is_accepted() {
    let source = MockServer::start();
    let dest = MockServer::start();
    mock_source(&source, 500);
    mock_export(&source);
    mock_dest_imports(&dest);
    mock_dest_verify(&dest, 4, 5, &["bafypublic"], &[]);

    let state = state_at(MigrationPhase::BlobsTransferred, &source, &dest);
    state.lock().await.as_mut().unwrap().accepted_blob_loss = vec![BlobLoss {
        cid: "bafypublic".into(),
        record_uri: "at://did:plc:spacer/app.bsky.feed.post/1".into(),
        direction: BlobTransferDirection::Source,
        reason: "500".into(),
        space: None,
    }];

    let losses = match transfer_spaces_core(&state, DID, false).await {
        Err(MigrationError::BlobDrainIncomplete { losses }) => losses,
        other => panic!("expected BlobDrainIncomplete, got {other:?}"),
    };
    assert_eq!(losses.len(), 1);
    assert_eq!(losses[0].cid, "bafyalpha");
    assert_eq!(losses[0].space.as_deref(), Some(AUTHORITY_SPACE));
    assert_eq!(losses[0].record_uri, AUTHORITY_SPACE);
    assert_eq!(phase_of(&state).await, MigrationPhase::BlobsTransferred);

    transfer_spaces_core(&state, DID, true).await.unwrap();
    let accepted = state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .accepted_blob_loss
        .clone();
    assert_eq!(
        accepted.len(),
        2,
        "the public loss is kept beside the space one"
    );

    advance_to_preferences(&state).await;
    verify_import_core(&state, DID).await.unwrap();
}

// A destination whose digest differs from the source's fails verify and names the space; the
// phase stays put.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn verify_refuses_a_space_whose_digest_differs() {
    let source = MockServer::start();
    let dest = MockServer::start();
    mock_source(&source, 200);
    dest.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.space.listSpaces");
        then.status(200).json_body(serde_json::json!({ "spaces": [
            { "space": AUTHORITY_SPACE, "repoRev": "3lz", "data": { "$bytes": "AAAA" } },
            { "space": WRITER_SPACE, "repoRev": "3lz", "data": { "$bytes": "BBBC" } },
        ]}));
    });
    mock_dest_verify(&dest, 0, 0, &[], &[(AUTHORITY_SPACE, "bafyalpha")]);

    let state = state_at(MigrationPhase::PreferencesTransferred, &source, &dest);
    match verify_import_core(&state, DID).await {
        Err(MigrationError::SpaceVerificationFailed { spaces }) => {
            assert_eq!(spaces, vec![WRITER_SPACE])
        }
        other => panic!("expected SpaceVerificationFailed, got {other:?}"),
    }
    assert_eq!(
        phase_of(&state).await,
        MigrationPhase::PreferencesTransferred
    );
}

// A source that doesn't implement spaces holds none: the step advances without asking the
// destination anything.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn a_source_without_spaces_counts_as_zero_spaces() {
    let source = MockServer::start();
    let dest = MockServer::start();
    source.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.space.listSpaces");
        then.status(501)
            .json_body(serde_json::json!({ "error": "MethodNotImplemented" }));
    });
    let probe = dest.mock(|when, then| {
        when.path_prefix("/xrpc/com.atproto.space.");
        then.status(200)
            .json_body(serde_json::json!({ "spaces": [] }));
    });

    let state = state_at(MigrationPhase::BlobsTransferred, &source, &dest);
    transfer_spaces_core(&state, DID, false).await.unwrap();
    assert_eq!(phase_of(&state).await, MigrationPhase::SpacesTransferred);
    assert_eq!(probe.calls(), 0);
}

// A source listing that fails for any other reason is not "no spaces": the step stops.
#[tokio::test]
#[ignore] // Requires socket binding; ignore in sandboxed environments
async fn a_failing_source_listing_is_not_zero_spaces() {
    let source = MockServer::start();
    let dest = MockServer::start();
    source.mock(|when, then| {
        when.method(Method::GET)
            .path("/xrpc/com.atproto.space.listSpaces");
        then.status(500)
            .json_body(serde_json::json!({ "error": "InternalServerError" }));
    });

    let state = state_at(MigrationPhase::BlobsTransferred, &source, &dest);
    assert!(matches!(
        transfer_spaces_core(&state, DID, false).await,
        Err(MigrationError::SpaceTransferFailed { .. })
    ));
    assert_eq!(phase_of(&state).await, MigrationPhase::BlobsTransferred);
}
