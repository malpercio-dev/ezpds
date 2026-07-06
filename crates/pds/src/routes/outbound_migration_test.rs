// MM-231 audit: composes the wallet-authorized outbound migration flow (ADR-0002) across two
// independently configured servers (their own DB pool, master key, and — critically — distinct
// `resolve_server_did()`), driving every step through the real HTTP handlers rather than calling
// internal functions directly. No test elsewhere exercises `getServiceAuth`'s output against a
// second server's `createAccount`, or the source-side data-transfer legs (`getRepo`/`listBlobs`/
// `getBlob`) feeding a real `importRepo`/`uploadBlob` on a destination.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

use crate::app::{app, AppState};
use crate::routes::test_utils::{access_jwt, body_json, seed_account_with_repo, seed_did_document};

const MIGRATING_DID: &str = "did:plc:outboundmigrant2222222";
const HANDLE: &str = "alice.migrated.example";
const SOURCE_URL: &str = "https://source.example.com";
const DEST_URL: &str = "https://dest.example.com";

/// `state_with_master_key()`-equivalent, but with `public_url` overridden so its
/// `resolve_server_did()` differs from a same-defaults sibling state — required to model two
/// independent PDS instances (source and destination) rather than one server talking to itself.
async fn state_with_master_key_and_url(public_url: &str) -> AppState {
    let base = crate::routes::test_utils::state_with_master_key().await;
    let mut config = (*base.config).clone();
    config.public_url = public_url.to_string();
    // Migration-mode createAccount has no invite code to present (matches every other
    // migration-mode test in create_account_xrpc.rs).
    config.invite_code_required = false;
    AppState {
        config: Arc::new(config),
        ..base
    }
}

fn bearer(method: &str, uri: String, token: Option<&str>, body: Body) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header("Authorization", format!("Bearer {t}"));
    }
    b.body(body).unwrap()
}

/// Like [`bearer`], but with a JSON `Content-Type` — required by handlers whose body is a
/// `Json<T>` extractor (axum rejects a JSON body with no/wrong content type as 415).
fn bearer_json(
    method: &str,
    uri: String,
    token: Option<&str>,
    body: serde_json::Value,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json");
    if let Some(t) = token {
        b = b.header("Authorization", format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

/// Seed the destination's `did_documents` cache with a document whose `#atproto` verification
/// method is the migrating account's *real* repo key (as minted by [`seed_account_with_repo`] on
/// the source) — mirroring `create_account_xrpc::seed_migration_did`. This lets
/// `create_account_migration`'s `resolve_did_document` short-circuit on its local cache instead of
/// requiring a live plc.directory to resolve a `did:plc`, exactly like every other migration-mode
/// test in this crate.
async fn seed_matching_did_document(db: &sqlx::SqlitePool, kp: &crypto::P256Keypair) {
    let multibase = kp
        .key_id
        .0
        .strip_prefix("did:key:")
        .expect("key_id is a did:key URI")
        .to_string();
    seed_did_document(
        db,
        MIGRATING_DID,
        serde_json::json!({
            "id": MIGRATING_DID,
            "alsoKnownAs": [format!("at://{HANDLE}")],
            "verificationMethod": [{
                "id": format!("{MIGRATING_DID}#atproto"),
                "type": "Multikey",
                "controller": MIGRATING_DID,
                "publicKeyMultibase": multibase,
            }],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": SOURCE_URL,
            }],
        }),
    )
    .await;
}

/// Drives the full source-side outbound migration sequence end to end, entirely through the real
/// XRPC handlers of two independently configured `AppState`s:
///
/// 1. `reserveSigningKey` (destination) reserves a repo key for the migrating DID.
/// 2. `getServiceAuth` (source) mints a service-auth JWT scoped to the destination's DID + the
///    `createAccount` method — the exact audience/lexicon pair a real migration tool would request.
/// 3. `createAccount` (destination, migration mode) verifies that token against the DID's
///    `#atproto` key and creates a deactivated, repo-less account.
/// 4. `getRepo` (source, full export) → `importRepo` (destination) transfers the repo.
/// 5. `listBlobs`/`getBlob` (source) → `uploadBlob` (destination) transfers every blob;
///    `listMissingBlobs` (destination) converges to empty.
/// 6. `checkAccountStatus` (destination) confirms the import is complete, then `activateAccount`
///    brings the migrated repo live — and the migrated record is servable.
/// 7. `deactivateAccount` (source) ends the migration, emitting an `#account` firehose event; the
///    source's read-only sync surface keeps serving the (now deactivated) repo, tolerating a
///    retried or delayed blob fetch mid-migration.
#[tokio::test]
async fn wallet_authorized_outbound_migration_transfers_repo_and_blobs_to_a_peer_pds() {
    let source_state = state_with_master_key_and_url(SOURCE_URL).await;
    let dest_state = state_with_master_key_and_url(DEST_URL).await;
    assert_ne!(
        source_state.config.resolve_server_did(),
        dest_state.config.resolve_server_did(),
        "the two states must model genuinely independent servers"
    );

    let kp = seed_account_with_repo(&source_state.db, MIGRATING_DID).await;
    let source_token = access_jwt(&source_state.jwt_secret, MIGRATING_DID);
    let source_app = app(source_state.clone());

    // A plain record and a blob-referencing record, so the transferred repo has content to check.
    let upload_resp = source_app
        .clone()
        .oneshot(bearer(
            "POST",
            "/xrpc/com.atproto.repo.uploadBlob".to_string(),
            Some(&source_token),
            Body::from(vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), // PNG magic bytes
        ))
        .await
        .unwrap();
    assert_eq!(upload_resp.status(), StatusCode::OK, "source uploadBlob");
    let blob_cid = body_json(upload_resp).await["blob"]["ref"]["$link"]
        .as_str()
        .unwrap()
        .to_string();

    let put_text = crate::routes::test_utils::put_record_request(
        MIGRATING_DID,
        "app.bsky.feed.post",
        "hello",
        serde_json::json!({ "record": { "text": "migrating out" } }),
        Some(&source_token),
    );
    assert_eq!(
        source_app.clone().oneshot(put_text).await.unwrap().status(),
        StatusCode::OK,
        "source putRecord (text)"
    );
    let put_image = crate::routes::test_utils::put_record_request(
        MIGRATING_DID,
        "app.bsky.feed.post",
        "withimage",
        serde_json::json!({
            "record": {
                "text": "with image",
                "embed": {
                    "images": [{
                        "image": {
                            "$type": "blob",
                            "ref": { "$link": blob_cid },
                            "mimeType": "image/png",
                            "size": 8
                        },
                        "alt": "test"
                    }]
                }
            }
        }),
        Some(&source_token),
    );
    assert_eq!(
        source_app
            .clone()
            .oneshot(put_image)
            .await
            .unwrap()
            .status(),
        StatusCode::OK,
        "source putRecord (blob-referencing)"
    );

    // The destination resolves the migrating DID from its local cache (same shape every other
    // migration-mode test in this crate uses), avoiding a dependency on a live plc.directory.
    seed_matching_did_document(&dest_state.db, &kp).await;
    let dest_app = app(dest_state.clone());

    // 1. Destination reserves a repo signing key for the migrating DID ahead of createAccount.
    let reserve_resp = dest_app
        .clone()
        .oneshot(bearer_json(
            "POST",
            "/xrpc/com.atproto.server.reserveSigningKey".to_string(),
            None,
            serde_json::json!({ "did": MIGRATING_DID }),
        ))
        .await
        .unwrap();
    assert_eq!(reserve_resp.status(), StatusCode::OK, "reserveSigningKey");

    // 2. Source mints a service-auth token scoped to the destination + createAccount — the exact
    //    audience/lexicon pair ADR-0002's outbound flow requests.
    let dest_did = dest_state.config.resolve_server_did();
    let service_auth_resp = source_app
        .clone()
        .oneshot(bearer(
            "GET",
            format!(
                "/xrpc/com.atproto.server.getServiceAuth?aud={dest_did}&lxm=com.atproto.server.createAccount"
            ),
            Some(&source_token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(service_auth_resp.status(), StatusCode::OK, "getServiceAuth");
    let migration_token = body_json(service_auth_resp).await["token"]
        .as_str()
        .unwrap()
        .to_string();

    // 3. Destination verifies that token against the DID's #atproto key and creates the account.
    let create_resp = dest_app
        .clone()
        .oneshot(bearer_json(
            "POST",
            "/xrpc/com.atproto.server.createAccount".to_string(),
            Some(&migration_token),
            serde_json::json!({
                "handle": HANDLE,
                "email": "migrant@example.com",
                "did": MIGRATING_DID,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(
        create_resp.status(),
        StatusCode::OK,
        "createAccount (migration mode) must accept a real getServiceAuth token from an \
         independently configured source server"
    );
    let create_json = body_json(create_resp).await;
    let dest_token = create_json["accessJwt"].as_str().unwrap().to_string();

    // 4. Full repo export from source, imported into the deactivated, repo-less destination account.
    let car_resp = source_app
        .clone()
        .oneshot(bearer(
            "GET",
            format!("/xrpc/com.atproto.sync.getRepo?did={MIGRATING_DID}"),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(car_resp.status(), StatusCode::OK, "source getRepo");
    let car_bytes = body_bytes(car_resp).await;

    let import_resp = dest_app
        .clone()
        .oneshot(bearer(
            "POST",
            "/xrpc/com.atproto.repo.importRepo".to_string(),
            Some(&dest_token),
            Body::from(car_bytes),
        ))
        .await
        .unwrap();
    assert_eq!(
        import_resp.status(),
        StatusCode::OK,
        "destination importRepo"
    );

    // 5. Every blob CID is listed and fetched from the source, then re-uploaded at the destination.
    let list_blobs_resp = source_app
        .clone()
        .oneshot(bearer(
            "GET",
            format!("/xrpc/com.atproto.sync.listBlobs?did={MIGRATING_DID}"),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(list_blobs_resp.status(), StatusCode::OK, "source listBlobs");
    let cids: Vec<String> = body_json(list_blobs_resp).await["cids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        cids,
        vec![blob_cid.clone()],
        "the uploaded blob must be listed"
    );

    for cid in &cids {
        let get_blob_resp = source_app
            .clone()
            .oneshot(bearer(
                "GET",
                format!("/xrpc/com.atproto.sync.getBlob?did={MIGRATING_DID}&cid={cid}"),
                None,
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            get_blob_resp.status(),
            StatusCode::OK,
            "source getBlob {cid}"
        );
        let blob_bytes = body_bytes(get_blob_resp).await;

        let upload_resp = dest_app
            .clone()
            .oneshot(bearer(
                "POST",
                "/xrpc/com.atproto.repo.uploadBlob".to_string(),
                Some(&dest_token),
                Body::from(blob_bytes),
            ))
            .await
            .unwrap();
        assert_eq!(
            upload_resp.status(),
            StatusCode::OK,
            "destination uploadBlob {cid}"
        );
        let reuploaded_cid = body_json(upload_resp).await["blob"]["ref"]["$link"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            &reuploaded_cid, cid,
            "content-addressing must round-trip the CID"
        );
    }

    let missing_resp = dest_app
        .clone()
        .oneshot(bearer(
            "GET",
            "/xrpc/com.atproto.repo.listMissingBlobs".to_string(),
            Some(&dest_token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        missing_resp.status(),
        StatusCode::OK,
        "destination listMissingBlobs"
    );
    assert_eq!(
        body_json(missing_resp).await["blobs"]
            .as_array()
            .unwrap()
            .len(),
        0,
        "every referenced blob must have been transferred"
    );

    // 6. checkAccountStatus confirms completeness, then activation brings the migrated repo live.
    let status_resp = dest_app
        .clone()
        .oneshot(bearer(
            "GET",
            "/xrpc/com.atproto.server.checkAccountStatus".to_string(),
            Some(&dest_token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        status_resp.status(),
        StatusCode::OK,
        "destination checkAccountStatus"
    );
    let status_json = body_json(status_resp).await;
    assert_eq!(status_json["activated"], false, "not yet activated");
    assert_eq!(status_json["indexedRecords"], 2);
    assert_eq!(status_json["expectedBlobs"], 1);
    assert_eq!(status_json["importedBlobs"], 1);

    let activate_resp = dest_app
        .clone()
        .oneshot(bearer(
            "POST",
            "/xrpc/com.atproto.server.activateAccount".to_string(),
            Some(&dest_token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        activate_resp.status(),
        StatusCode::OK,
        "destination activateAccount"
    );

    let get_record_resp = dest_app
        .clone()
        .oneshot(bearer(
            "GET",
            format!(
                "/xrpc/com.atproto.repo.getRecord?did={MIGRATING_DID}&collection=app.bsky.feed.post&rkey=hello"
            ),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        get_record_resp.status(),
        StatusCode::OK,
        "migrated record must be servable"
    );
    assert_eq!(
        body_json(get_record_resp).await["value"]["text"],
        "migrating out"
    );

    // 7. Source deactivates now the transfer is complete — the AC's "source account ends
    //    deactivated" — and the transition is announced on the firehose.
    let mut source_firehose = source_state.firehose.subscribe();
    let deactivate_resp = source_app
        .clone()
        .oneshot(bearer(
            "POST",
            "/xrpc/com.atproto.server.deactivateAccount".to_string(),
            Some(&source_token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        deactivate_resp.status(),
        StatusCode::OK,
        "source deactivateAccount"
    );
    let crate::firehose::FirehoseEvent::Account(event) = source_firehose.try_recv().unwrap() else {
        panic!("expected an #account firehose event announcing the source's deactivation");
    };
    assert_eq!(event.did, MIGRATING_DID);
    assert!(!event.active);
    assert_eq!(event.status.as_deref(), Some("deactivated"));

    // The source's read-only sync surface must keep serving the deactivated repo: a migration
    // tool that fetches blobs after (or retries across) the source's own deactivation must not be
    // cut off mid-transfer.
    let post_deactivation_repo = source_app
        .oneshot(bearer(
            "GET",
            format!("/xrpc/com.atproto.sync.getRepo?did={MIGRATING_DID}"),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        post_deactivation_repo.status(),
        StatusCode::OK,
        "getRepo must keep serving a deactivated account's repo"
    );
}
