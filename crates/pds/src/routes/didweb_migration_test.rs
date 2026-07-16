// pattern: Imperative Shell
//
// End-to-end migration choreography for a `did:web` identity (MM-278): moving the operator's
// primary account, `did:web:malpercio.dev`, onto Custos. The differentiator from the did:plc
// canonical test (`outbound_migration_test.rs`) is that Custos does NOT serve the DID document —
// the operator controls `malpercio.dev`'s web hosting independently, so `.well-known/did.json`
// stays on the operator's own host and is edited there. Custos only resolves it.
//
// This test proves the inbound migration is genuinely method-agnostic: `createAccount` (migration
// mode), `importRepo`, the blob drain, `getRecommendedDidCredentials`, `checkAccountStatus`, and
// `activateAccount` all work with a `did:web` DID exactly as with a `did:plc` one — because a DID
// is an opaque TEXT key everywhere and migration-in never inspects the method. It also confirms
// the handle `@malpercio.dev` binds even though this PDS serves neither that DID document nor that
// handle domain.
//
// COVERAGE BOUNDARY — read before trusting this test. The externally-hosted `did.json` is modeled
// by the destination's `did_documents` cache — the same technique every migration-mode test uses
// (`create_account_xrpc::seed_migration_did`, `outbound_migration_test::seed_matching_did_document`).
// A `did:web` document is served over HTTPS from a real domain, which is not hermetically mockable
// in-process (unlike `did:plc`, whose directory URL is configurable). So:
//   * What this test genuinely proves: migration-mode `createAccount` / `importRepo` / blob drain /
//     `getRecommendedDidCredentials` / `checkAccountStatus` / `activateAccount` accept a `did:web`
//     DID and bind its foreign `@malpercio.dev` handle on a PDS that serves neither.
//   * What it does NOT exercise: the live `did:web` HTTPS resolution path
//     (`resolve_web_did_document`) — cache-seeding short-circuits it (as in production only on a
//     cold cache) — nor the force-refresh cache rewrite for a `did:web`. Step 7 below MODELS the
//     operator's edit by writing the post-edit document straight into the cache, so its `resolveDid`
//     assertion documents the end state rather than driving the refresh network leg.
//   * What is covered elsewhere: only the `#identity`-emission *decision* is method-agnostic (it
//     branches on `account_exists`, not the DID method) and is unit-tested in `resolve_identity.rs`
//     against `did:plc`. The `did:web` force-refresh network fetch + rewrite remains production-only.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

use crate::app::{app, AppState};
use crate::routes::test_utils::{access_jwt, body_json, seed_account_with_repo, seed_did_document};

const MIGRATING_DID: &str = "did:web:malpercio.dev";
const HANDLE: &str = "malpercio.dev";
const OLD_PDS_URL: &str = "https://old.example.com";
const CUSTOS_URL: &str = "https://custos.example.com";

/// `state_with_master_key()` with `public_url` overridden so its `resolve_server_did()` differs
/// from a same-defaults sibling — modeling two independent PDS instances (the operator's old PDS
/// and Custos) rather than one server talking to itself. Invite codes off (every migration-mode
/// test does the same).
async fn state_with_master_key_and_url(public_url: &str) -> AppState {
    let base = crate::routes::test_utils::state_with_master_key().await;
    let mut config = (*base.config).clone();
    config.public_url = public_url.to_string();
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

/// The `did:web` document `malpercio.dev` hosts, as Custos caches it. `#atproto` is `kp` (the
/// migrating account's real repo key on the old PDS, so the old PDS's service-auth token verifies),
/// `alsoKnownAs` keeps `@malpercio.dev`, and the PDS service endpoint is `endpoint`.
fn didweb_document(kp: &crypto::P256Keypair, endpoint: &str) -> serde_json::Value {
    let multibase = kp
        .key_id
        .0
        .strip_prefix("did:key:")
        .expect("key_id is a did:key URI")
        .to_string();
    serde_json::json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
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
            "serviceEndpoint": endpoint,
        }],
    })
}

/// The full inbound migration of `did:web:malpercio.dev` onto Custos, driven entirely through the
/// real XRPC handlers of two independently configured `AppState`s (old PDS + Custos):
///
/// 1. `reserveSigningKey` (Custos) reserves a repo key for the migrating DID.
/// 2. `getServiceAuth` (old PDS) mints a token scoped to Custos + `createAccount`.
/// 3. `createAccount` (Custos, migration mode) resolves the externally-hosted `did:web` document
///    (from cache — Custos does not serve it), verifies the token against its `#atproto` key, and
///    creates a deactivated, repo-less account. The handle `@malpercio.dev` binds even though
///    Custos serves neither the DID document nor the `malpercio.dev` handle domain.
/// 4. `getRepo` (old PDS) → `importRepo` (Custos) transfers the repo.
/// 5. `listBlobs`/`getBlob` (old PDS) → `uploadBlob` (Custos); `listMissingBlobs` converges empty.
/// 6. `getRecommendedDidCredentials` (Custos) returns the fields the operator hand-edits into the
///    externally-hosted `did.json`: the reserved `#atproto` key and the Custos PDS endpoint.
/// 7. The operator edits `https://malpercio.dev/.well-known/did.json` (modeled by rewriting Custos's
///    cache to the post-edit document) → `resolveDid` (cache-first) now serves the Custos endpoint.
/// 8. `checkAccountStatus` (Custos) confirms completeness, `activateAccount` brings the repo live,
///    and the migrated record is servable.
/// 9. `deactivateAccount` (old PDS) ends the migration.
#[tokio::test]
async fn didweb_account_migrates_onto_custos_without_custos_serving_did_json() {
    let old_state = state_with_master_key_and_url(OLD_PDS_URL).await;
    let custos_state = state_with_master_key_and_url(CUSTOS_URL).await;
    assert_ne!(
        old_state.config.resolve_server_did(),
        custos_state.config.resolve_server_did(),
        "the two states must model genuinely independent servers"
    );

    let kp = seed_account_with_repo(&old_state.db, MIGRATING_DID).await;
    let old_token = access_jwt(&old_state.jwt_secret, MIGRATING_DID);
    let old_app = app(old_state.clone());

    // A plain record and a blob-referencing record, so the transferred repo has content to check.
    let upload_resp = old_app
        .clone()
        .oneshot(bearer(
            "POST",
            "/xrpc/com.atproto.repo.uploadBlob".to_string(),
            Some(&old_token),
            Body::from(vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), // PNG magic bytes
        ))
        .await
        .unwrap();
    assert_eq!(upload_resp.status(), StatusCode::OK, "old-PDS uploadBlob");
    let blob_cid = body_json(upload_resp).await["blob"]["ref"]["$link"]
        .as_str()
        .unwrap()
        .to_string();

    let put_text = crate::routes::test_utils::put_record_request(
        MIGRATING_DID,
        "app.bsky.feed.post",
        "hello",
        serde_json::json!({ "record": { "text": "the operator's post" } }),
        Some(&old_token),
    );
    assert_eq!(
        old_app.clone().oneshot(put_text).await.unwrap().status(),
        StatusCode::OK,
        "old-PDS putRecord (text)"
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
        Some(&old_token),
    );
    assert_eq!(
        old_app.clone().oneshot(put_image).await.unwrap().status(),
        StatusCode::OK,
        "old-PDS putRecord (blob-referencing)"
    );

    // Custos resolves the externally-hosted did:web document from its local cache (it does not serve
    // it). Pre-edit, that document points `#atproto_pds` at the old PDS.
    seed_did_document(
        &custos_state.db,
        MIGRATING_DID,
        didweb_document(&kp, OLD_PDS_URL),
    )
    .await;
    let custos_app = app(custos_state.clone());

    // 1. Custos reserves a repo signing key for the migrating DID ahead of createAccount.
    let reserve_resp = custos_app
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

    // 2. Old PDS mints a service-auth token scoped to Custos + createAccount.
    let custos_did = custos_state.config.resolve_server_did();
    let service_auth_resp = old_app
        .clone()
        .oneshot(bearer(
            "GET",
            format!(
                "/xrpc/com.atproto.server.getServiceAuth?aud={custos_did}&lxm=com.atproto.server.createAccount"
            ),
            Some(&old_token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(service_auth_resp.status(), StatusCode::OK, "getServiceAuth");
    let migration_token = body_json(service_auth_resp).await["token"]
        .as_str()
        .unwrap()
        .to_string();

    // 3. Custos verifies the token against the did:web document's #atproto key and creates the
    //    deactivated account — keeping the foreign `@malpercio.dev` handle.
    let create_resp = custos_app
        .clone()
        .oneshot(bearer_json(
            "POST",
            "/xrpc/com.atproto.server.createAccount".to_string(),
            Some(&migration_token),
            serde_json::json!({
                "handle": HANDLE,
                "email": "operator@malpercio.dev",
                "did": MIGRATING_DID,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(
        create_resp.status(),
        StatusCode::OK,
        "createAccount (migration mode) must accept a did:web DID"
    );
    let create_json = body_json(create_resp).await;
    assert_eq!(create_json["did"], MIGRATING_DID);
    assert_eq!(create_json["handle"], HANDLE);
    let custos_token = create_json["accessJwt"].as_str().unwrap().to_string();

    // The handle bound locally even though Custos serves neither this DID document nor the
    // `malpercio.dev` domain (its served domains are `example.com`). Handle verification stays on
    // the operator's own domain — zero PDS work.
    let handle_did: Option<String> = sqlx::query_scalar("SELECT did FROM handles WHERE handle = ?")
        .bind(HANDLE)
        .fetch_optional(&custos_state.db)
        .await
        .unwrap();
    assert_eq!(
        handle_did.as_deref(),
        Some(MIGRATING_DID),
        "the @malpercio.dev handle must bind to the did:web DID on a PDS that does not serve that domain"
    );

    // 4. Full repo export from the old PDS, imported into the deactivated Custos account.
    let car_resp = old_app
        .clone()
        .oneshot(bearer(
            "GET",
            format!("/xrpc/com.atproto.sync.getRepo?did={MIGRATING_DID}"),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(car_resp.status(), StatusCode::OK, "old-PDS getRepo");
    let car_bytes = body_bytes(car_resp).await;

    let import_resp = custos_app
        .clone()
        .oneshot(bearer(
            "POST",
            "/xrpc/com.atproto.repo.importRepo".to_string(),
            Some(&custos_token),
            Body::from(car_bytes),
        ))
        .await
        .unwrap();
    assert_eq!(import_resp.status(), StatusCode::OK, "Custos importRepo");

    // 5. Blob drain: list + fetch from the old PDS, re-upload at Custos, converge to empty.
    let list_blobs_resp = old_app
        .clone()
        .oneshot(bearer(
            "GET",
            format!("/xrpc/com.atproto.sync.listBlobs?did={MIGRATING_DID}"),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        list_blobs_resp.status(),
        StatusCode::OK,
        "old-PDS listBlobs"
    );
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
        let get_blob_resp = old_app
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
            "old-PDS getBlob {cid}"
        );
        let blob_bytes = body_bytes(get_blob_resp).await;

        let reupload_resp = custos_app
            .clone()
            .oneshot(bearer(
                "POST",
                "/xrpc/com.atproto.repo.uploadBlob".to_string(),
                Some(&custos_token),
                Body::from(blob_bytes),
            ))
            .await
            .unwrap();
        assert_eq!(
            reupload_resp.status(),
            StatusCode::OK,
            "Custos uploadBlob {cid}"
        );
        assert_eq!(
            body_json(reupload_resp).await["blob"]["ref"]["$link"].as_str(),
            Some(cid.as_str()),
            "content-addressing must round-trip the CID"
        );
    }

    let missing_resp = custos_app
        .clone()
        .oneshot(bearer(
            "GET",
            "/xrpc/com.atproto.repo.listMissingBlobs".to_string(),
            Some(&custos_token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        missing_resp.status(),
        StatusCode::OK,
        "Custos listMissingBlobs"
    );
    assert_eq!(
        body_json(missing_resp).await["blobs"]
            .as_array()
            .unwrap()
            .len(),
        0,
        "every referenced blob must have been transferred"
    );

    // 6. getRecommendedDidCredentials tells the operator exactly what to put in their did.json:
    //    the Custos-reserved #atproto key and the Custos PDS endpoint. The operator edits the
    //    externally-hosted did.json by hand — there is no PLC operation for a did:web identity.
    let creds_resp = custos_app
        .clone()
        .oneshot(bearer(
            "GET",
            "/xrpc/com.atproto.identity.getRecommendedDidCredentials".to_string(),
            Some(&custos_token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        creds_resp.status(),
        StatusCode::OK,
        "getRecommendedDidCredentials must work for a did:web account"
    );
    let creds = body_json(creds_resp).await;
    let recommended_key = creds["verificationMethods"]["atproto"]
        .as_str()
        .expect("recommended #atproto key")
        .to_string();
    assert_eq!(
        creds["alsoKnownAs"][0],
        format!("at://{HANDLE}"),
        "recommended alsoKnownAs must keep @malpercio.dev"
    );
    assert_eq!(
        creds["services"]["atproto_pds"]["endpoint"], CUSTOS_URL,
        "recommended PDS endpoint must be Custos"
    );
    // The recommended key is a `did:key:` — what the operator writes as the did.json #atproto VM.
    let recommended_multibase = recommended_key
        .strip_prefix("did:key:")
        .expect("recommended key is a did:key URI")
        .to_string();

    // 7. The operator edits https://malpercio.dev/.well-known/did.json: #atproto → the Custos key,
    //    #atproto_pds → Custos. In production `refreshIdentity` force-refreshes this over HTTPS,
    //    rewrites the cache row, and (on a real change) emits an `#identity` frame. That network leg
    //    is not mockable here (see the COVERAGE BOUNDARY at the top), so this step MODELS its cache
    //    effect directly. The `resolveDid` assertion below therefore documents the intended end
    //    state — resolveDid is cache-first, so it necessarily returns what we just wrote — rather
    //    than driving the refresh; treat it as end-state documentation, not as coverage of the leg.
    let post_edit_doc = serde_json::json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": MIGRATING_DID,
        "alsoKnownAs": [format!("at://{HANDLE}")],
        "verificationMethod": [{
            "id": format!("{MIGRATING_DID}#atproto"),
            "type": "Multikey",
            "controller": MIGRATING_DID,
            "publicKeyMultibase": recommended_multibase,
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": CUSTOS_URL,
        }]
    });
    // UPDATE-only rewrite of the existing cache row — exactly what the force-refresh path
    // (`resolve_did_document_force_refresh` → `rewrite_did_document`) does after re-resolving the
    // edited external did.json.
    let rewrote =
        crate::db::dids::rewrite_did_document(&custos_state.db, MIGRATING_DID, &post_edit_doc)
            .await
            .unwrap();
    assert!(
        rewrote,
        "the cached did:web document row must be rewritten in place"
    );

    let resolve_resp = custos_app
        .clone()
        .oneshot(bearer(
            "GET",
            format!("/xrpc/com.atproto.identity.resolveDid?did={MIGRATING_DID}"),
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resolve_resp.status(), StatusCode::OK, "Custos resolveDid");
    assert_eq!(
        body_json(resolve_resp).await["didDoc"]["service"][0]["serviceEndpoint"],
        CUSTOS_URL,
        "after the operator's edit propagates, the DID document points at Custos"
    );

    // 8. checkAccountStatus confirms completeness, activation brings the migrated repo live.
    let status_resp = custos_app
        .clone()
        .oneshot(bearer(
            "GET",
            "/xrpc/com.atproto.server.checkAccountStatus".to_string(),
            Some(&custos_token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        status_resp.status(),
        StatusCode::OK,
        "Custos checkAccountStatus"
    );
    let status_json = body_json(status_resp).await;
    assert_eq!(status_json["activated"], false, "not yet activated");
    assert_eq!(status_json["indexedRecords"], 2);
    assert_eq!(status_json["expectedBlobs"], 1);
    assert_eq!(status_json["importedBlobs"], 1);

    let activate_resp = custos_app
        .clone()
        .oneshot(bearer(
            "POST",
            "/xrpc/com.atproto.server.activateAccount".to_string(),
            Some(&custos_token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(
        activate_resp.status(),
        StatusCode::OK,
        "Custos activateAccount"
    );

    let get_record_resp = custos_app
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
        "migrated record must be servable from Custos"
    );
    assert_eq!(
        body_json(get_record_resp).await["value"]["text"],
        "the operator's post"
    );

    // 9. The old PDS deactivates now the transfer is complete. The body is the wallet's real
    //    `{}` — the lexicon layer, like the reference PDS, requires a body on a procedure that
    //    declares an input.
    let deactivate_resp = old_app
        .oneshot(bearer_json(
            "POST",
            "/xrpc/com.atproto.server.deactivateAccount".to_string(),
            Some(&old_token),
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(
        deactivate_resp.status(),
        StatusCode::OK,
        "old-PDS deactivateAccount"
    );
}
