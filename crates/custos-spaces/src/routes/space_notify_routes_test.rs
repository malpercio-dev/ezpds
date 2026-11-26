// pattern: Imperative Shell
//
// End-to-end coverage of the space-host notification surface (listWriters, notifyRepoUpdate,
// notifyCredentialsRevoked) plus the two effects that hang off the write path: the writer set a
// local commit records, and the *absence* of any registration when a write lands in a foreign
// authority's space (the repo host reports it directly; see `space_notify`'s tests). Driven
// through the real router, so the lexicon layer, the space auth seam and the store are all in
// the path — cross-route journeys live here because routes may not import one another (the
// `space_routes_test.rs` convention). Registration through `authorizeSpaceSync` is tested with
// that route.
//
// Delivery itself is never exercised, and cannot be by accident: `seed_undeliverable` seeds a
// DID document with no service endpoint at all, and no test here registers a syncer.

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use custos_core::CoreState;

use crate::auth::space::{mint_space_credential, unix_now};
use crate::space_record_write::{apply_space_writes, SpaceWriteAction, SpaceWriteOp};
use crate::test_support::{access_jwt, seed_account_with_repo, state_with_master_key, SpaceSigKey};
use crate::test_support::{send, xrpc_get as get, xrpc_post as post};
use custos_core::space_uri::parse_space_ref;
use custos_db::dids::seed_did_document;

const ALICE: &str = "did:plc:alicenotifyaaaaaaaaaaaa";
const BOB: &str = "did:plc:bobnotifyaaaaaaaaaaaaaa";
const FOREIGN: &str = "did:plc:foreignauthorityaaaaaaa";
const SYNCER: &str = "did:web:syncer.example.com";
const TYPE: &str = "org.example.bucket";
const COLLECTION: &str = "org.example.note";
const SPACE: &str = "at://did:plc:alicenotifyaaaaaaaaaaaa/space/org.example.bucket/main";
const FOREIGN_SPACE: &str = "at://did:plc:foreignauthorityaaaaaaa/space/org.example.bucket/main";

/// Alice hosts an account and a public memberspace of her own; Bob is a second local account.
async fn setup() -> CoreState {
    let state = state_with_master_key().await;
    seed_account_with_repo(&state.db, ALICE).await;
    seed_account_with_repo(&state.db, BOB).await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    let (status, body) = send(
        &state,
        post(
            "com.atproto.space.createSpace",
            &alice,
            serde_json::json!({
                "spaceType": TYPE,
                "skey": "main",
                "policy": {
                    "$type": "com.atproto.memberspace.policy",
                    "publicRead": true,
                    "publicWrite": true,
                },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    state
}

/// A DID document with a verification method but **no** service entry: enough for service-auth
/// verification, never enough to deliver to.
async fn seed_undeliverable(state: &CoreState, did: &str, kp: &crypto::P256Keypair) {
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

/// One committed write into `space` by `did`. The notification it spawns has no local effect
/// to wait for: delivery is covered by `space_notify`'s tests.
async fn write_one(state: &CoreState, space_uri: &str, did: &str, rkey: &str) -> String {
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
    )
    .await
    .unwrap();
    outcome.rev
}

fn registrations(body: &serde_json::Value) -> Vec<String> {
    body["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["repo"].as_str().unwrap().to_string())
        .collect()
}

// ── listWriters ───────────────────────────────────────────────────────────────

/// A local write into a space this host is the authority for lands in the writer set, and
/// `listWriters` reports it with the commit's rev and hash.
#[tokio::test]
async fn list_writers_reports_the_writers_of_a_locally_hosted_space() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);

    // Nobody has written yet.
    let (status, body) = send(&state, get(&list_writers_query(SPACE), &alice)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(registrations(&body).is_empty(), "{body}");

    let rev = write_one(&state, SPACE, ALICE, "one").await;
    write_one(&state, SPACE, BOB, "two").await;

    let (status, body) = send(&state, get(&list_writers_query(SPACE), &alice)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(registrations(&body), vec![ALICE, BOB], "{body}");
    let alice_row = &body["repos"][0];
    assert_eq!(alice_row["$type"], "com.atproto.space.defs#repoWrite");
    assert_eq!(alice_row["repoRev"], rev);
    assert!(alice_row.get("prevSpaceRev").is_none(), "{body}");
    assert!(
        alice_row["data"]["$bytes"].is_string(),
        "data is lex-JSON bytes: {body}"
    );

    // A second write advances the same row rather than adding one — the set is per repo.
    let rev2 = write_one(&state, SPACE, ALICE, "three").await;
    let (_, body) = send(&state, get(&list_writers_query(SPACE), &alice)).await;
    assert_eq!(
        registrations(&body),
        vec![BOB, ALICE],
        "ordered by spaceRev, so the repo that just moved comes last: {body}"
    );
    assert_eq!(body["repos"][1]["repoRev"], rev2, "{body}");
    assert!(
        body["repos"][0]["spaceRev"].as_str() < body["repos"][1]["spaceRev"].as_str(),
        "{body}"
    );
}

/// The cursor is a `spaceRev`: a page opens strictly after it, and a short page still carries
/// one so a syncer can resume later and see only what changed.
#[tokio::test]
async fn list_writers_pages_on_the_space_rev() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    write_one(&state, SPACE, ALICE, "one").await;
    write_one(&state, SPACE, BOB, "two").await;

    let (_, body) = send(
        &state,
        get(&format!("{}&limit=1", list_writers_query(SPACE)), &alice),
    )
    .await;
    assert_eq!(registrations(&body), vec![ALICE], "{body}");
    let cursor = body["cursor"].as_str().expect("full page carries a cursor");

    let (_, body) = send(
        &state,
        get(
            &format!("{}&limit=1&cursor={cursor}", list_writers_query(SPACE)),
            &alice,
        ),
    )
    .await;
    assert_eq!(registrations(&body), vec![BOB], "{body}");
    let cursor = body["cursor"]
        .as_str()
        .expect("a short page still carries a cursor");
    assert_eq!(cursor, body["repos"][0]["spaceRev"].as_str().unwrap());

    let (_, body) = send(
        &state,
        get(
            &format!("{}&cursor={cursor}", list_writers_query(SPACE)),
            &alice,
        ),
    )
    .await;
    assert!(registrations(&body).is_empty(), "{body}");
    assert!(body.get("cursor").is_none(), "{body}");
}

fn list_writers_query(space: &str) -> String {
    format!("com.atproto.space.listWriters?space={space}")
}

/// A syncer pages the writer set with the `spaceRev` cursor and later resumes from the last one
/// it saw, getting only what changed since.
#[tokio::test]
async fn list_writers_resumes_from_a_space_rev_cursor() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    write_one(&state, SPACE, ALICE, "one").await;
    write_one(&state, SPACE, BOB, "two").await;

    let page = |cursor: Option<String>| {
        let mut query = format!("{}&limit=1", list_writers_query(SPACE));
        if let Some(cursor) = cursor {
            query.push_str(&format!("&cursor={cursor}"));
        }
        get(&query, &alice)
    };
    let (_, first) = send(&state, page(None)).await;
    assert_eq!(registrations(&first), vec![ALICE.to_string()], "{first}");
    let (_, second) = send(&state, page(first["cursor"].as_str().map(str::to_string))).await;
    assert_eq!(registrations(&second), vec![BOB.to_string()], "{second}");
    let caught_up = second["cursor"].as_str().map(str::to_string);
    let (_, empty) = send(&state, page(caught_up.clone())).await;
    assert!(registrations(&empty).is_empty(), "{empty}");

    // Alice writes again; resuming from where the syncer stopped yields her alone.
    write_one(&state, SPACE, ALICE, "three").await;
    let (_, resumed) = send(&state, page(caught_up)).await;
    assert_eq!(
        registrations(&resumed),
        vec![ALICE.to_string()],
        "{resumed}"
    );
}

/// The writer-set entry for `did`, as `listWriters` reports it.
async fn writer_entry(state: &CoreState, did: &str) -> serde_json::Value {
    let alice = access_jwt(&state.jwt_secret, ALICE);
    let (status, body) = send(state, get(&list_writers_query(SPACE), &alice)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["repos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["repo"] == did)
        .cloned()
        .unwrap_or_else(|| panic!("{did} missing from {body}"))
}

fn remove_writer(token: &str, repo: &str) -> Request<Body> {
    post(
        "com.atproto.space.removeWriter",
        token,
        serde_json::json!({ "space": SPACE, "repo": repo }),
    )
}

/// `removeWriter` turns the entry into a `repoRemoved` at a new `spaceRev`, does nothing the
/// second time, and the writer's next write (admitted here by `publicWrite`) brings it back.
#[tokio::test]
async fn a_removed_writer_is_listed_as_removed_until_it_writes_again() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    write_one(&state, SPACE, ALICE, "one").await;
    write_one(&state, SPACE, BOB, "two").await;
    let before = writer_entry(&state, BOB).await;

    let (status, body) = send(&state, remove_writer(&alice, BOB)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let removed = writer_entry(&state, BOB).await;
    assert_eq!(
        removed,
        serde_json::json!({
            "$type": "com.atproto.space.defs#repoRemoved",
            "repo": BOB,
            "spaceRev": removed["spaceRev"],
        }),
        "a removal carries no repoRev, data or prevSpaceRev"
    );
    assert!(removed["spaceRev"].as_str() > before["spaceRev"].as_str());
    assert_eq!(
        writer_entry(&state, ALICE).await["$type"],
        "com.atproto.space.defs#repoWrite"
    );

    // Already removed, and never a writer: both do nothing.
    for repo in [BOB, "did:plc:neverwroteaaaaaaaaaaaaa"] {
        let (status, body) = send(&state, remove_writer(&alice, repo)).await;
        assert_eq!(status, StatusCode::OK, "{repo}: {body}");
    }
    assert_eq!(writer_entry(&state, BOB).await, removed);

    let rev = write_one(&state, SPACE, BOB, "three").await;
    let rejoined = writer_entry(&state, BOB).await;
    assert_eq!(rejoined["$type"], "com.atproto.space.defs#repoWrite");
    assert_eq!(rejoined["repoRev"], rev);
    assert!(rejoined["spaceRev"].as_str() > removed["spaceRev"].as_str());
}

/// Only the authority removes writers.
#[tokio::test]
async fn remove_writer_is_the_authoritys_alone() {
    let state = setup().await;
    write_one(&state, SPACE, ALICE, "one").await;
    let bob = access_jwt(&state.jwt_secret, BOB);
    let (status, body) = send(&state, remove_writer(&bob, ALICE)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "NotAuthorized");
    assert_eq!(
        writer_entry(&state, ALICE).await["$type"],
        "com.atproto.space.defs#repoWrite"
    );
}

/// `putMembers` with `write: false` and `removeMembers` each take the member out of the writer
/// set; changing the policy's `$type` doesn't.
#[tokio::test]
async fn member_changes_remove_writers_but_a_type_change_does_not() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    let put_bob = |write: bool| {
        post(
            "com.atproto.memberspace.putMembers",
            &alice,
            serde_json::json!({
                "space": SPACE,
                "members": [{ "did": BOB, "read": true, "write": write }],
            }),
        )
    };
    let kind = |entry: serde_json::Value| entry["$type"].as_str().unwrap().to_string();
    const WRITE: &str = "com.atproto.space.defs#repoWrite";
    const REMOVED: &str = "com.atproto.space.defs#repoRemoved";

    let (status, body) = send(&state, put_bob(true)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    write_one(&state, SPACE, BOB, "one").await;
    assert_eq!(kind(writer_entry(&state, BOB).await), WRITE);

    let (status, body) = send(&state, put_bob(false)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(kind(writer_entry(&state, BOB).await), REMOVED);

    let (status, body) = send(&state, put_bob(true)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    write_one(&state, SPACE, BOB, "two").await;
    assert_eq!(kind(writer_entry(&state, BOB).await), WRITE);
    let (status, body) = send(
        &state,
        post(
            "com.atproto.memberspace.removeMembers",
            &alice,
            serde_json::json!({ "space": SPACE, "dids": [BOB] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(kind(writer_entry(&state, BOB).await), REMOVED);

    write_one(&state, SPACE, BOB, "three").await;
    let (status, body) = send(
        &state,
        post(
            "com.atproto.space.updateSpace",
            &alice,
            serde_json::json!({
                "space": SPACE,
                "policy": { "$type": "com.atproto.personalspace.policy" },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(kind(writer_entry(&state, BOB).await), WRITE);
}

/// Alice's space reconfigured to `policy` (lexicon JSON).
async fn set_policy(state: &CoreState, policy: serde_json::Value) {
    let alice = access_jwt(&state.jwt_secret, ALICE);
    let (status, body) = send(
        state,
        post(
            "com.atproto.space.updateSpace",
            &alice,
            serde_json::json!({ "space": SPACE, "policy": policy }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

async fn put_member(state: &CoreState, did: &str, write: bool) {
    let alice = access_jwt(&state.jwt_secret, ALICE);
    let (status, body) = send(
        state,
        post(
            "com.atproto.memberspace.putMembers",
            &alice,
            serde_json::json!({
                "space": SPACE,
                "members": [{ "did": did, "read": true, "write": write }],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// `did`'s writer-set row, if it has one: `(rev, removed)`.
async fn writer_row(state: &CoreState, did: &str) -> Option<(String, bool)> {
    crate::db::space_notify::list_writers(&state.db, SPACE, None, 100)
        .await
        .unwrap()
        .into_iter()
        .find(|w| w.repo_did == did)
        .map(|w| (w.rev, w.removed))
}

/// A local write the space's write policy refuses still commits to the writer's own repo, but
/// joins nothing; a removed member's write doesn't rejoin; an authorized write joins and rejoins.
#[tokio::test]
async fn the_write_policy_gates_joining_the_writer_set_not_the_write() {
    let state = setup().await;
    set_policy(
        &state,
        serde_json::json!({ "$type": "com.atproto.memberspace.policy", "publicRead": true }),
    )
    .await;

    // A member without `write`: the record lands, the writer set doesn't move.
    put_member(&state, BOB, false).await;
    let rev = write_one(&state, SPACE, BOB, "one").await;
    let repo = crate::db::space_repos::get_repo(&state.db, SPACE, BOB)
        .await
        .unwrap()
        .expect("the write committed");
    assert_eq!(repo.rev, rev);
    assert_eq!(writer_row(&state, BOB).await, None);

    // Granted `write`, the next write joins.
    put_member(&state, BOB, true).await;
    let rev = write_one(&state, SPACE, BOB, "two").await;
    assert_eq!(writer_row(&state, BOB).await, Some((rev.clone(), false)));

    // Removed from the members, Bob leaves the set, and his next write doesn't rejoin it.
    let alice = access_jwt(&state.jwt_secret, ALICE);
    let (status, body) = send(
        &state,
        post(
            "com.atproto.memberspace.removeMembers",
            &alice,
            serde_json::json!({ "space": SPACE, "dids": [BOB] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    write_one(&state, SPACE, BOB, "three").await;
    assert_eq!(writer_row(&state, BOB).await, Some((rev, true)));

    // Admitted again, his next write rejoins.
    put_member(&state, BOB, true).await;
    let rev = write_one(&state, SPACE, BOB, "four").await;
    assert_eq!(writer_row(&state, BOB).await, Some((rev, false)));
}

/// Under a managedspace the managing app's `checkAccess` decides the join, and no answer means
/// no join.
#[tokio::test]
async fn a_managing_app_decides_the_join_and_fails_closed() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let state = setup().await;
    const APP: &str = "did:web:managing.example";
    let server = MockServer::start().await;
    let answer = |write: bool| {
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.managedspace.checkAccess"))
            .and(query_param("repo", BOB))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "read": true, "write": write })),
            )
    };
    seed_did_document(
        &state.db,
        APP,
        serde_json::json!({
            "id": APP,
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": server.uri(),
            }],
        }),
    )
    .await;
    set_policy(
        &state,
        serde_json::json!({
            "$type": "com.atproto.managedspace.policy",
            "managingApp": format!("{APP}#atproto_pds"),
        }),
    )
    .await;

    answer(true).mount(&server).await;
    let rev = write_one(&state, SPACE, BOB, "one").await;
    assert_eq!(writer_row(&state, BOB).await, Some((rev.clone(), false)));

    // The app refuses: the write commits, the entry stays where it was.
    server.reset().await;
    answer(false).mount(&server).await;
    write_one(&state, SPACE, BOB, "two").await;
    assert_eq!(writer_row(&state, BOB).await, Some((rev.clone(), false)));

    // The app answers nothing usable: denied, as no answer always is.
    server.reset().await;
    write_one(&state, SPACE, BOB, "three").await;
    assert_eq!(writer_row(&state, BOB).await, Some((rev, false)));
}

/// Every space-host method is answerable only by the space's authority. A holder of a perfectly
/// valid credential for a *foreign* authority's space — the one caller the auth seam does admit,
/// since a credential says nothing about who hosts the repos — gets `SpaceNotFound`: the same
/// reply an unknown space gets, so this surface never discloses that some other authority's
/// space happens to have a repo here.
///
/// (An OAuth caller never reaches this check: `authenticate_space_access` already refuses a
/// non-authority with `NotAuthorized`.)
#[tokio::test]
async fn space_host_methods_refuse_a_foreign_authoritys_space() {
    let state = setup().await;
    let foreign_kp = crypto::generate_p256_keypair().unwrap();
    seed_undeliverable(&state, FOREIGN, &foreign_kp).await;
    // Alice's write records the foreign `spaces` row locally, so the space is genuinely known
    // here — only its authority is elsewhere.
    write_one(&state, FOREIGN_SPACE, ALICE, "one").await;

    let signer = repo_engine::CommitSigner::from_bytes(&foreign_kp.private_key_bytes).unwrap();
    let key = SpaceSigKey::generate();
    let credential = mint_space_credential(
        |b| signer.sign(b),
        FOREIGN,
        &parse_space_ref(FOREIGN_SPACE).unwrap(),
        key.key_id(),
        unix_now().unwrap(),
    );

    let (status, body) = send(
        &state,
        signed_get(&list_writers_query(FOREIGN_SPACE), &credential, &key),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "SpaceNotFound");
}

/// A credential-authed GET, addressed to the space's authority as every space-host method is.
fn signed_get(method_and_query: &str, credential: &str, key: &SpaceSigKey) -> Request<Body> {
    let mut b = Request::builder()
        .method(http::Method::GET)
        .uri(format!("/xrpc/{method_and_query}"));
    b.headers_mut()
        .unwrap()
        .extend(key.credential_headers(credential, FOREIGN));
    b.body(Body::empty()).unwrap()
}

// ── repo-host reporting ─────────────────────────────────────────────────────

/// A write into a space whose authority lives elsewhere leaves no registration row and no
/// writer-set claim here: the repo host reports straight to the authority, and this host does not
/// answer `listWriters` for a space it is not the authority of.
#[tokio::test]
async fn a_write_into_a_foreign_space_registers_nothing() {
    let state = setup().await;
    let kp = crypto::generate_p256_keypair().unwrap();
    seed_undeliverable(&state, FOREIGN, &kp).await;

    write_one(&state, FOREIGN_SPACE, ALICE, "one").await;
    write_one(&state, SPACE, ALICE, "one").await;
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM space_notify_registrations")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    assert!(
        crate::db::space_notify::list_writers(&state.db, FOREIGN_SPACE, None, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

// ── notifyRepoUpdate ─────────────────────────────────────────────────────────────

/// A repo host reports its user's write; the authority records it in the writer set, so a repo
/// that lives nowhere near this host still shows up in `listWriters`.
#[tokio::test]
async fn notify_repo_update_records_a_foreign_repo_in_the_writer_set() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    let (carol, token) = foreign_repo_token(&state, "com.atproto.space.notifyRepoUpdate").await;

    let (status, body) = send(
        &state,
        post(
            "com.atproto.space.notifyRepoUpdate",
            &token,
            notify_body(SPACE, &carol, "3kabcdefghij2"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, body) = send(&state, get(&list_writers_query(SPACE), &alice)).await;
    assert_eq!(registrations(&body), vec![carol.clone()], "{body}");
    assert_eq!(body["repos"][0]["repoRev"], "3kabcdefghij2");
}

/// Without `publicWrite`, a non-member's report is acknowledged but never tracked; granting the
/// member's `write` bit is what admits it.
#[tokio::test]
async fn notify_repo_update_from_a_non_member_is_ignored_without_public_write() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    let (status, body) = send(
        &state,
        post(
            "com.atproto.space.updateSpace",
            &alice,
            serde_json::json!({
                "space": SPACE,
                "policy": { "$type": "com.atproto.memberspace.policy", "publicRead": true },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (carol, token) = foreign_repo_token(&state, "com.atproto.space.notifyRepoUpdate").await;
    let notify = || {
        post(
            "com.atproto.space.notifyRepoUpdate",
            &token,
            notify_body(SPACE, &carol, "3kabcdefghij2"),
        )
    };

    let (status, body) = send(&state, notify()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = send(&state, get(&list_writers_query(SPACE), &alice)).await;
    assert!(registrations(&body).is_empty(), "{body}");

    let (status, body) = send(
        &state,
        post(
            "com.atproto.memberspace.putMembers",
            &alice,
            serde_json::json!({
                "space": SPACE,
                "members": [{ "did": carol, "read": false, "write": true }],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = send(&state, notify()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = send(&state, get(&list_writers_query(SPACE), &alice)).await;
    assert_eq!(registrations(&body), vec![carol], "{body}");
}

/// A report that does not advance the repo's stored `repoRev` is acknowledged and ignored: the
/// writer row keeps the newer rev and the space revision does not move.
#[tokio::test]
async fn notify_repo_update_ignores_a_non_increasing_rev() {
    let state = setup().await;
    let (carol, token) = foreign_repo_token(&state, "com.atproto.space.notifyRepoUpdate").await;
    let report = |rev: &'static str| {
        post(
            "com.atproto.space.notifyRepoUpdate",
            &token,
            notify_body(SPACE, &carol, rev),
        )
    };
    let writer = || async {
        let mut rows = crate::db::space_notify::list_writers(&state.db, SPACE, None, 10)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        rows.remove(0)
    };

    let (status, body) = send(&state, report("3kabcdefghij3")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let accepted = writer().await;

    // An older rev, then a replay of the current one.
    for rev in ["3kabcdefghij2", "3kabcdefghij3"] {
        let (status, body) = send(&state, report(rev)).await;
        assert_eq!(status, StatusCode::OK, "{rev}: {body}");
    }
    let after = writer().await;
    assert_eq!(after.rev, "3kabcdefghij3");
    assert_eq!(
        after.space_rev, accepted.space_rev,
        "an ignored report assigns no space revision"
    );
}

/// A taken-down space stops acting as space host: a report about it is acknowledged and not
/// recorded.
#[tokio::test]
async fn notify_repo_update_records_nothing_for_a_taken_down_space() {
    let state = setup().await;
    let (carol, token) = foreign_repo_token(&state, "com.atproto.space.notifyRepoUpdate").await;
    crate::db::spaces::set_space_takedown(&state.db, SPACE, true)
        .await
        .unwrap();

    let (status, body) = send(
        &state,
        post(
            "com.atproto.space.notifyRepoUpdate",
            &token,
            notify_body(SPACE, &carol, "3kabcdefghij2"),
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
}

/// A `repoRev` ahead of the permitted clock skew is refused rather than pinned into the writer
/// set, where it would sort ahead of every honest update.
#[tokio::test]
async fn notify_repo_update_refuses_a_future_rev() {
    let state = setup().await;
    let (carol, token) = foreign_repo_token(&state, "com.atproto.space.notifyRepoUpdate").await;
    let future = "j222222222222".to_string();

    let (status, body) = send(
        &state,
        post(
            "com.atproto.space.notifyRepoUpdate",
            &token,
            notify_body(SPACE, &carol, &future),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "FutureRev");
}

/// The token must be issued by the repo whose head moved. Anyone else is refused even with a
/// perfectly valid service-auth token, the space's own authority included: syncers hear from it
/// through `notifySpaceUpdate`, never through this method.
#[tokio::test]
async fn notify_repo_update_refuses_an_issuer_other_than_the_repo() {
    let state = setup().await;
    let (carol, _) = foreign_repo_token(&state, "com.atproto.space.notifyRepoUpdate").await;

    // Each token is valid, but the write it reports is Carol's.
    for issuer in [BOB, ALICE] {
        let token = service_auth_for(&state, issuer, "com.atproto.space.notifyRepoUpdate").await;
        let (status, body) = send(
            &state,
            post(
                "com.atproto.space.notifyRepoUpdate",
                &token,
                notify_body(SPACE, &carol, "3kabcdefghij2"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{issuer}: {body}");
    }
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
        "repoRev": rev,
        "data": { "$bytes": base64::engine::general_purpose::STANDARD.encode([7u8; 32]) },
    })
}

/// A foreign account (DID document seeded, no local account row) plus a service-auth token it
/// signed for `lxm`, addressed to this server.
async fn foreign_repo_token(state: &CoreState, lxm: &str) -> (String, String) {
    foreign_repo_token_to(state, lxm, &state.config.resolve_server_did()).await
}

/// [`foreign_repo_token`] addressed to `aud`.
async fn foreign_repo_token_to(state: &CoreState, lxm: &str, aud: &str) -> (String, String) {
    const CAROL: &str = "did:plc:carolnotifyaaaaaaaaaaaa";
    let kp = crypto::generate_p256_keypair().unwrap();
    seed_undeliverable(state, CAROL, &kp).await;
    let signer = repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap();
    let now = crate::auth::space::unix_now().unwrap();
    let token = custos_core::auth::jwt::mint_service_auth_jwt(
        |b| signer.sign(b),
        CAROL,
        aud,
        Some(lxm),
        now,
        now + 60,
    );
    (CAROL.to_string(), token)
}

/// The reference's repo host addresses the authority's `#atproto_pds` service, not the host
/// serving it, and writes `$bytes` unpadded. Both must be accepted; another DID must not.
#[tokio::test]
async fn notify_repo_update_accepts_the_reference_shaped_notification() {
    use base64::Engine as _;
    let state = setup().await;
    let lxm = "com.atproto.space.notifyRepoUpdate";
    let mut body = notify_body(SPACE, "unused", "3kabcdefghij2");
    body["data"]["$bytes"] = base64::engine::general_purpose::STANDARD_NO_PAD
        .encode([7u8; 32])
        .into();

    let (_, wrong) = foreign_repo_token_to(&state, lxm, &format!("{BOB}#atproto_pds")).await;
    let (carol, token) = foreign_repo_token_to(&state, lxm, &format!("{ALICE}#atproto_pds")).await;
    body["repo"] = carol.clone().into();
    let (status, out) = send(&state, post(lxm, &wrong, body.clone())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{out}");
    let (status, out) = send(&state, post(lxm, &token, body)).await;
    assert_eq!(status, StatusCode::OK, "{out}");

    let writers = crate::db::space_notify::list_writers(&state.db, SPACE, None, 10)
        .await
        .unwrap();
    assert_eq!(writers.len(), 1);
}

/// A service-auth token signed by a *local* account's repo key.
async fn service_auth_for(state: &CoreState, did: &str, lxm: &str) -> String {
    let kp = crypto::generate_p256_keypair().unwrap();
    seed_undeliverable(state, did, &kp).await;
    let signer = repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap();
    let now = crate::auth::space::unix_now().unwrap();
    custos_core::auth::jwt::mint_service_auth_jwt(
        |b| signer.sign(b),
        did,
        &state.config.resolve_server_did(),
        Some(lxm),
        now,
        now + 60,
    )
}

// ── deletion ────────────────────────────────────────────────────────────────

/// Deleting a space drops its writer set with everything else, so `listWriters` stops answering
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
            "com.atproto.space.deleteSpace",
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

    let (status, body) = send(&state, get(&list_writers_query(SPACE), &alice)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "SpaceNotFound");
}

// ── notifyCredentialsRevoked ─────────────────────────────────────────────────

/// A foreign authority with a resolvable key, a space of its own Alice has written into (so the
/// space is known here), and a credential it issued for that space.
async fn foreign_space_credential(
    state: &CoreState,
) -> (repo_engine::CommitSigner, SpaceSigKey, String) {
    let foreign_kp = crypto::generate_p256_keypair().unwrap();
    seed_undeliverable(state, FOREIGN, &foreign_kp).await;
    write_one(state, FOREIGN_SPACE, ALICE, "one").await;
    let signer = repo_engine::CommitSigner::from_bytes(&foreign_kp.private_key_bytes).unwrap();
    let key = SpaceSigKey::generate();
    let credential = mint_space_credential(
        |b| signer.sign(b),
        FOREIGN,
        &parse_space_ref(FOREIGN_SPACE).unwrap(),
        key.key_id(),
        unix_now().unwrap(),
    );
    (signer, key, credential)
}

fn credential_jti(credential: &str) -> String {
    use base64::Engine as _;
    let payload = credential.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    claims["jti"].as_str().unwrap().to_string()
}

fn revoke_token(signer: &repo_engine::CommitSigner, iss: &str, aud: &str) -> String {
    let now = unix_now().unwrap();
    custos_core::auth::jwt::mint_service_auth_jwt(
        |b| signer.sign(b),
        iss,
        aud,
        Some("com.atproto.space.notifyCredentialsRevoked"),
        now,
        now + 60,
    )
}

fn read_alice(credential: &str, key: &SpaceSigKey) -> Request<Body> {
    let mut b = Request::builder().method(http::Method::GET).uri(format!(
        "/xrpc/com.atproto.space.listRecords?space={FOREIGN_SPACE}&repo={ALICE}&collection={COLLECTION}"
    ));
    b.headers_mut()
        .unwrap()
        .extend(key.credential_headers(credential, ALICE));
    b.body(Body::empty()).unwrap()
}

/// The authority revokes a credential that was reading fine; the same credential is refused from
/// then on, and the revocation is kept past the credential's own life. Repeating it is a no-op.
#[tokio::test]
async fn a_revoked_credential_is_refused_on_read() {
    let state = setup().await;
    let (signer, key, credential) = foreign_space_credential(&state).await;
    let (status, body) = send(&state, read_alice(&credential, &key)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Addressed to the repo DID, as the lexicon describes.
    let token = revoke_token(&signer, FOREIGN, ALICE);
    let body =
        serde_json::json!({ "space": FOREIGN_SPACE, "credentials": [credential_jti(&credential)] });
    for _ in 0..2 {
        let (status, resp) = send(
            &state,
            post(
                "com.atproto.space.notifyCredentialsRevoked",
                &token,
                body.clone(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
    }

    let (status, body) = send(&state, read_alice(&credential, &key)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let outlives: bool = sqlx::query_scalar(
        "SELECT expires_at >= datetime('now', '+3600 seconds') FROM space_revoked_credentials",
    )
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert!(
        outlives,
        "the revocation must outlive the longest-lived credential"
    );
}

/// Only the space's authority may revoke its credentials.
#[tokio::test]
async fn notify_credentials_revoked_refuses_a_non_authority_issuer() {
    let state = setup().await;
    let (_, key, credential) = foreign_space_credential(&state).await;
    let bob_kp = crypto::generate_p256_keypair().unwrap();
    seed_undeliverable(&state, BOB, &bob_kp).await;
    let bob = repo_engine::CommitSigner::from_bytes(&bob_kp.private_key_bytes).unwrap();

    let (status, body) = send(
        &state,
        post(
            "com.atproto.space.notifyCredentialsRevoked",
            &revoke_token(&bob, BOB, ALICE),
            serde_json::json!({ "space": FOREIGN_SPACE, "credentials": [credential_jti(&credential)] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let (status, body) = send(&state, read_alice(&credential, &key)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The audience must be this server or an account it hosts; a token addressed elsewhere is
/// refused before any key is resolved.
#[tokio::test]
async fn notify_credentials_revoked_refuses_a_foreign_audience() {
    let state = setup().await;
    let (signer, _, credential) = foreign_space_credential(&state).await;
    let (status, body) = send(
        &state,
        post(
            "com.atproto.space.notifyCredentialsRevoked",
            &revoke_token(&signer, FOREIGN, SYNCER),
            serde_json::json!({ "space": FOREIGN_SPACE, "credentials": [credential_jti(&credential)] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

/// A revocation for a space this host holds nothing of is acknowledged and stores nothing.
#[tokio::test]
async fn notify_credentials_revoked_for_an_unknown_space_stores_nothing() {
    let state = setup().await;
    let foreign_kp = crypto::generate_p256_keypair().unwrap();
    seed_undeliverable(&state, FOREIGN, &foreign_kp).await;
    let signer = repo_engine::CommitSigner::from_bytes(&foreign_kp.private_key_bytes).unwrap();

    let (status, body) = send(
        &state,
        post(
            "com.atproto.space.notifyCredentialsRevoked",
            &revoke_token(&signer, FOREIGN, &state.config.resolve_server_did()),
            serde_json::json!({ "space": FOREIGN_SPACE, "credentials": ["anything"] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM space_revoked_credentials")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}
