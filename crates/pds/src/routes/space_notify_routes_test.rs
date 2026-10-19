// pattern: Imperative Shell
//
// End-to-end coverage of the space-host notification surface (listRepos, registerNotify,
// unregisterNotify, notifyWrite) plus the two effects that hang off the write path: the writer
// set a local commit records, and the authority auto-registration a write into a *foreign*
// authority's space creates. Driven through the real router, so the lexicon layer, the space
// auth seam and the store are all in the path — cross-route journeys live here because routes
// may not import one another (the `space_routes_test.rs` convention).
//
// Delivery itself is never exercised, and cannot be by accident: `seed_undeliverable` seeds a
// DID document with no service endpoint at all, and the one seed that does carry an endpoint
// points it at a `.invalid` host (RFC 2606 — guaranteed never to resolve). A test that starts
// writing while a subscriber is registered therefore still leaves no packet, rather than
// depending on a convention someone has to remember.

use axum::body::Body;
use axum::http::{self, Request, StatusCode};

use crate::app::AppState;
use crate::auth::space::{mint_space_credential, unix_now};
use crate::db::dids::seed_did_document;
use crate::routes::space_test_support::{send, xrpc_get as get, xrpc_post as post};
use crate::routes::test_utils::{
    access_jwt, seed_account_with_repo, state_with_master_key, DpopProofKey,
};
use crate::space_record_write::{
    apply_space_writes, SpaceWriteAction, SpaceWriteAdmission, SpaceWriteOp,
};
use crate::space_uri::parse_space_ref;

const ALICE: &str = "did:plc:alicenotifyaaaaaaaaaaaa";
const BOB: &str = "did:plc:bobnotifyaaaaaaaaaaaaaa";
const FOREIGN: &str = "did:plc:foreignauthorityaaaaaaa";
const SYNCER: &str = "did:web:syncer.example.com";
const TYPE: &str = "org.example.bucket";
const COLLECTION: &str = "org.example.note";
const SPACE: &str = "at://did:plc:alicenotifyaaaaaaaaaaaa/space/org.example.bucket/main";
const FOREIGN_SPACE: &str = "at://did:plc:foreignauthorityaaaaaaa/space/org.example.bucket/main";

/// Alice hosts an account and a simplespace of her own; Bob is a second local account.
async fn setup() -> AppState {
    let state = state_with_master_key().await;
    seed_account_with_repo(&state.db, ALICE).await;
    seed_account_with_repo(&state.db, BOB).await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    let (status, body) = send(
        &state,
        post(
            "com.atproto.simplespace.createSpace",
            &alice,
            serde_json::json!({
                "type": TYPE,
                "skey": "main",
                "policy": { "$type": "com.atproto.simplespace.defs#publicPolicy" },
                "appAccess": { "$type": "com.atproto.simplespace.defs#open" },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    state
}

/// A DID document with a verification method but **no** service entry: enough for service-auth
/// verification, never enough to deliver to.
async fn seed_undeliverable(state: &AppState, did: &str, kp: &crypto::P256Keypair) {
    let multibase = kp.key_id.0.strip_prefix("did:key:").unwrap().to_string();
    seed_did_document(
        &state.db,
        did,
        serde_json::json!({
            "id": did,
            "verificationMethod": [
                { "id": format!("{did}#atproto"), "type": "Multikey", "controller": did, "publicKeyMultibase": multibase },
            ],
        }),
    )
    .await;
}

/// One committed write into `space` by `did`, awaiting the notification task it spawns so the
/// test observes its effects rather than racing them.
async fn write_one(state: &AppState, space_uri: &str, did: &str, rkey: &str) -> String {
    let space = parse_space_ref(space_uri).unwrap();
    let outcome = apply_space_writes(
        state,
        &space,
        did,
        &[SpaceWriteOp {
            action: SpaceWriteAction::Put,
            collection: COLLECTION.to_string(),
            rkey: rkey.to_string(),
            value: Some(serde_json::json!({ "text": rkey })),
        }],
        SpaceWriteAdmission::Active,
    )
    .await
    .unwrap();
    crate::space_notify::fan_out_write(state, &space, did, &outcome.rev, &outcome.hash)
        .await
        .unwrap();
    outcome.rev
}

fn registrations(body: &serde_json::Value) -> Vec<String> {
    body["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["did"].as_str().unwrap().to_string())
        .collect()
}

// ── listRepos ───────────────────────────────────────────────────────────────

/// A local write into a space this host is the authority for lands in the writer set, and
/// `listRepos` reports it with the commit's rev and hash.
#[tokio::test]
async fn list_repos_reports_the_writers_of_a_locally_hosted_space() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);

    // Nobody has written yet.
    let (status, body) = send(&state, get(&list_repos_query(SPACE), &alice)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(registrations(&body).is_empty(), "{body}");

    let rev = write_one(&state, SPACE, ALICE, "one").await;
    write_one(&state, SPACE, BOB, "two").await;

    let (status, body) = send(&state, get(&list_repos_query(SPACE), &alice)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(registrations(&body), vec![ALICE, BOB], "{body}");
    let alice_row = &body["repos"][0];
    assert_eq!(alice_row["rev"], rev);
    assert!(
        alice_row["hash"]["$bytes"].is_string(),
        "hash is lex-JSON bytes: {body}"
    );

    // A second write advances the same row rather than adding one — the set is per repo.
    let rev2 = write_one(&state, SPACE, ALICE, "three").await;
    let (_, body) = send(&state, get(&list_repos_query(SPACE), &alice)).await;
    assert_eq!(registrations(&body), vec![ALICE, BOB], "{body}");
    assert_eq!(body["repos"][0]["rev"], rev2, "{body}");
}

/// A full page carries a cursor; the page it opens is the rest.
#[tokio::test]
async fn list_repos_pages_on_the_repo_did() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    write_one(&state, SPACE, ALICE, "one").await;
    write_one(&state, SPACE, BOB, "two").await;

    let (_, body) = send(
        &state,
        get(&format!("{}&limit=1", list_repos_query(SPACE)), &alice),
    )
    .await;
    assert_eq!(registrations(&body), vec![ALICE], "{body}");
    let cursor = body["cursor"].as_str().expect("full page carries a cursor");

    let (_, body) = send(
        &state,
        get(
            &format!("{}&limit=1&cursor={cursor}", list_repos_query(SPACE)),
            &alice,
        ),
    )
    .await;
    assert_eq!(registrations(&body), vec![BOB], "{body}");
}

fn list_repos_query(space: &str) -> String {
    format!("com.atproto.space.listRepos?space={space}")
}

// ── registerNotify / unregisterNotify ───────────────────────────────────────

/// A syncer subscribes, gets an expiry, is fanned out to on the next write, and can withdraw.
#[tokio::test]
async fn register_and_unregister_notify_round_trip() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    let kp = crypto::generate_p256_keypair().unwrap();
    seed_syncer_document(&state, &kp).await;
    let service = format!("{SYNCER}#atproto_space_syncer");

    let (status, body) = send(
        &state,
        post(
            "com.atproto.space.registerNotify",
            &alice,
            serde_json::json!({ "space": SPACE, "service": service }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let expires_at = body["expiresAt"].as_str().expect("expiresAt");
    assert!(
        expires_at.ends_with('Z') && expires_at.contains('T'),
        "{body}"
    );

    let subscribers = crate::db::space_notify::subscribers_for_write(&state.db, SPACE, ALICE, 10)
        .await
        .unwrap();
    assert_eq!(subscribers, vec![service.clone()]);

    // Withdrawal, and its idempotent repeat.
    for _ in 0..2 {
        let (status, body) = send(
            &state,
            post(
                "com.atproto.space.unregisterNotify",
                &alice,
                serde_json::json!({ "space": SPACE, "service": service }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let subscribers = crate::db::space_notify::subscribers_for_write(&state.db, SPACE, ALICE, 10)
        .await
        .unwrap();
    assert!(subscribers.is_empty());
}

/// A service identifier that resolves to no delivery endpoint is refused at registration, rather
/// than becoming a subscription that silently never delivers.
#[tokio::test]
async fn register_notify_refuses_an_unresolvable_service() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    let kp = crypto::generate_p256_keypair().unwrap();
    seed_undeliverable(&state, SYNCER, &kp).await;

    let (status, body) = send(
        &state,
        post(
            "com.atproto.space.registerNotify",
            &alice,
            serde_json::json!({ "space": SPACE, "service": SYNCER }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "ServiceNotResolvable");
    assert!(
        crate::db::space_notify::subscribers_for_write(&state.db, SPACE, ALICE, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Every space-host method is answerable only by the space's authority. A holder of a perfectly
/// valid credential for a *foreign* authority's space — the one caller the auth seam does admit,
/// since a credential says nothing about who hosts the repos — gets `SpaceNotFound`: the same
/// reply an unknown space gets, so this surface never discloses that some other authority's
/// space happens to have a repo here.
///
/// (An OAuth caller never reaches this check: `authenticate_space_access` already refuses a
/// non-authority with `NotSpaceOwner`.)
#[tokio::test]
async fn space_host_methods_refuse_a_foreign_authoritys_space() {
    let state = setup().await;
    let foreign_kp = crypto::generate_p256_keypair().unwrap();
    seed_undeliverable(&state, FOREIGN, &foreign_kp).await;
    // Alice's write records the foreign `spaces` row locally, so the space is genuinely known
    // here — only its authority is elsewhere.
    write_one(&state, FOREIGN_SPACE, ALICE, "one").await;

    let signer = repo_engine::CommitSigner::from_bytes(&foreign_kp.private_key_bytes).unwrap();
    let key = DpopProofKey::generate();
    let credential = mint_space_credential(
        |b| signer.sign(b),
        FOREIGN,
        &parse_space_ref(FOREIGN_SPACE).unwrap(),
        &key.thumbprint(),
        unix_now().unwrap(),
    );

    for (method, request) in [
        (
            "com.atproto.space.listRepos",
            dpop_get(&list_repos_query(FOREIGN_SPACE), &credential, &key),
        ),
        (
            "com.atproto.space.registerNotify",
            dpop_post(
                "com.atproto.space.registerNotify",
                &credential,
                &key,
                serde_json::json!({ "space": FOREIGN_SPACE, "service": SYNCER }),
            ),
        ),
        (
            "com.atproto.space.unregisterNotify",
            dpop_post(
                "com.atproto.space.unregisterNotify",
                &credential,
                &key,
                serde_json::json!({ "space": FOREIGN_SPACE, "service": SYNCER }),
            ),
        ),
    ] {
        let (status, body) = send(&state, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method}: {body}");
        assert_eq!(body["error"], "SpaceNotFound", "{method}");
    }
}

/// A credential-authed GET. The proof's `htu` is the URL without its query (RFC 9449 §4.2).
fn dpop_get(method_and_query: &str, credential: &str, key: &DpopProofKey) -> Request<Body> {
    let path = format!("/xrpc/{}", method_and_query.split('?').next().unwrap());
    Request::builder()
        .method(http::Method::GET)
        .uri(format!("/xrpc/{method_and_query}"))
        .header("Authorization", format!("DPoP {credential}"))
        .header(
            "DPoP",
            key.proof(
                "GET",
                &format!("https://test.example.com{path}"),
                credential,
            ),
        )
        .body(Body::empty())
        .unwrap()
}

/// A credential-authed POST.
fn dpop_post(
    method: &str,
    credential: &str,
    key: &DpopProofKey,
    body: serde_json::Value,
) -> Request<Body> {
    let path = format!("/xrpc/{method}");
    Request::builder()
        .method(http::Method::POST)
        .uri(&path)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("DPoP {credential}"))
        .header(
            "DPoP",
            key.proof(
                "POST",
                &format!("https://test.example.com{path}"),
                credential,
            ),
        )
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// A syncer DID document that *does* carry a service endpoint, so `registerNotify`'s
/// resolvability check passes — pointed at an RFC 2606 `.invalid` host, which by definition has
/// no DNS answer, so a fan-out that reached delivery would still never leave the machine.
async fn seed_syncer_document(state: &AppState, kp: &crypto::P256Keypair) {
    let multibase = kp.key_id.0.strip_prefix("did:key:").unwrap().to_string();
    seed_did_document(
        &state.db,
        SYNCER,
        serde_json::json!({
            "id": SYNCER,
            "verificationMethod": [
                { "id": format!("{SYNCER}#atproto"), "type": "Multikey", "controller": SYNCER, "publicKeyMultibase": multibase },
            ],
            "service": [
                { "id": format!("{SYNCER}#atproto_space_syncer"), "type": "AtprotoSpaceService", "serviceEndpoint": "https://syncer.invalid" },
            ],
        }),
    )
    .await;
}

// ── auto-registration ───────────────────────────────────────────────────────

/// The spec's auto-registration: a write into a space whose authority lives elsewhere subscribes
/// that authority's `#atproto_space_host` to this repo, so the very first write reaches it. A
/// write into a space *this* host is the authority for registers nothing — there is no one to
/// tell but ourselves.
#[tokio::test]
async fn a_write_into_a_foreign_space_auto_registers_the_authority() {
    let state = setup().await;
    let kp = crypto::generate_p256_keypair().unwrap();
    seed_undeliverable(&state, FOREIGN, &kp).await;

    write_one(&state, FOREIGN_SPACE, ALICE, "one").await;
    let subscribers =
        crate::db::space_notify::subscribers_for_write(&state.db, FOREIGN_SPACE, ALICE, 10)
            .await
            .unwrap();
    assert_eq!(subscribers, vec![format!("{FOREIGN}#atproto_space_host")]);
    // ...and the foreign space's writer set stays empty: this host does not answer `listRepos`
    // for it, so it keeps no claim about it.
    assert!(
        crate::db::space_notify::list_writers(&state.db, FOREIGN_SPACE, None, 10)
            .await
            .unwrap()
            .is_empty()
    );

    write_one(&state, SPACE, ALICE, "one").await;
    assert!(
        crate::db::space_notify::subscribers_for_write(&state.db, SPACE, ALICE, 10)
            .await
            .unwrap()
            .is_empty(),
        "a write into our own space registers nobody"
    );
}

// ── notifyWrite ─────────────────────────────────────────────────────────────

/// A repo host reports its user's write; the authority records it in the writer set, so a repo
/// that lives nowhere near this host still shows up in `listRepos`.
#[tokio::test]
async fn notify_write_records_a_foreign_repo_in_the_writer_set() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    let (carol, token) = foreign_repo_token(&state, "com.atproto.space.notifyWrite").await;

    let (status, body) = send(
        &state,
        post(
            "com.atproto.space.notifyWrite",
            &token,
            notify_body(SPACE, &carol, "3kabcdefghij2"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, body) = send(&state, get(&list_repos_query(SPACE), &alice)).await;
    assert_eq!(registrations(&body), vec![carol.clone()], "{body}");
    assert_eq!(body["repos"][0]["rev"], "3kabcdefghij2");
}

/// The token must be issued by one of the two parties entitled to speak about the write: the
/// repo whose head moved, or the space's authority forwarding it. A third party is refused even
/// with a perfectly valid service-auth token.
#[tokio::test]
async fn notify_write_refuses_an_unrelated_issuer() {
    let state = setup().await;
    let (carol, _) = foreign_repo_token(&state, "com.atproto.space.notifyWrite").await;
    // Bob's token is valid, but the write it reports is Carol's.
    let bob = service_auth_for(&state, BOB, "com.atproto.space.notifyWrite").await;

    let (status, body) = send(
        &state,
        post(
            "com.atproto.space.notifyWrite",
            &bob,
            notify_body(SPACE, &carol, "3kabcdefghij2"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(
        crate::db::space_notify::list_writers(&state.db, SPACE, None, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

fn notify_body(space: &str, repo: &str, rev: &str) -> serde_json::Value {
    use base64::Engine as _;
    serde_json::json!({
        "space": space,
        "repo": repo,
        "rev": rev,
        "hash": { "$bytes": base64::engine::general_purpose::STANDARD.encode([7u8; 32]) },
    })
}

/// A foreign account (DID document seeded, no local account row) plus a service-auth token it
/// signed for `lxm`, addressed to this server.
async fn foreign_repo_token(state: &AppState, lxm: &str) -> (String, String) {
    const CAROL: &str = "did:plc:carolnotifyaaaaaaaaaaaa";
    let kp = crypto::generate_p256_keypair().unwrap();
    seed_undeliverable(state, CAROL, &kp).await;
    let signer = repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap();
    let now = crate::auth::space::unix_now().unwrap();
    let token = crate::auth::jwt::mint_service_auth_jwt(
        |b| signer.sign(b),
        CAROL,
        &state.config.resolve_server_did(),
        Some(lxm),
        now,
        now + 60,
    );
    (CAROL.to_string(), token)
}

/// A service-auth token signed by a *local* account's repo key.
async fn service_auth_for(state: &AppState, did: &str, lxm: &str) -> String {
    let kp = crypto::generate_p256_keypair().unwrap();
    seed_undeliverable(state, did, &kp).await;
    let signer = repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap();
    let now = crate::auth::space::unix_now().unwrap();
    crate::auth::jwt::mint_service_auth_jwt(
        |b| signer.sign(b),
        did,
        &state.config.resolve_server_did(),
        Some(lxm),
        now,
        now + 60,
    )
}

// ── deletion ────────────────────────────────────────────────────────────────

/// Deleting a space drops its writer set with everything else, so `listRepos` stops answering
/// for it entirely (via the tombstone) rather than reporting a stale set.
#[tokio::test]
async fn deleting_a_space_drops_its_writer_set() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    write_one(&state, SPACE, ALICE, "one").await;
    assert_eq!(
        crate::db::space_notify::list_writers(&state.db, SPACE, None, 10)
            .await
            .unwrap()
            .len(),
        1
    );

    let (status, body) = send(
        &state,
        post(
            "com.atproto.simplespace.deleteSpace",
            &alice,
            serde_json::json!({ "space": SPACE }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        crate::db::space_notify::list_writers(&state.db, SPACE, None, 10)
            .await
            .unwrap()
            .is_empty()
    );

    let (status, body) = send(&state, get(&list_repos_query(SPACE), &alice)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "SpaceNotFound");
}
