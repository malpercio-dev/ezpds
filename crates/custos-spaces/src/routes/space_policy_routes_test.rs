// pattern: Imperative Shell
//
// End-to-end coverage of space management — `com.atproto.space.{createSpace,updateSpace,
// deleteSpace,getSpace}` and the memberspace member list — driven through the real router so the
// lexicon layer (incl. the open-union `$type` handling), the authority seam and the store are all
// in the path. Cross-route journeys — create here, see it there, delete, then create again — live
// in this one test-only module, as `space_routes_test.rs` does for the record surface; each route
// keeps only what is genuinely local to it.

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use custos_core::CoreState;
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::auth::space::authorize_credential_request;
use crate::policy::{
    MANAGEDSPACE, MEMBERSPACE, MEMBER_COLLECTION, PERSONALSPACE, POLICY_COLLECTION,
};
use crate::test_support::test_app as app;
use crate::test_support::{
    access_jwt, scoped_access_jwt, seed_account_with_repo, state_with_master_key,
};
use crate::test_support::{send, xrpc_get, xrpc_post};

const ALICE: &str = "did:plc:alicespacepolicyaaaaaaaa";
const BOB: &str = "did:plc:bobspacepolicyaaaaaaaaaa";
const TYPE: &str = "org.example.bucket";
const SPACE: &str = "at://did:plc:alicespacepolicyaaaaaaaa/space/org.example.bucket/main";

async fn setup() -> CoreState {
    let state = state_with_master_key().await;
    seed_account_with_repo(&state.db, ALICE).await;
    seed_account_with_repo(&state.db, BOB).await;
    state
}

fn post(method: &str, token: &str, body: Value) -> Request<Body> {
    xrpc_post(&format!("com.atproto.{method}"), token, body)
}

fn get(method_and_query: &str, token: &str) -> Request<Body> {
    xrpc_get(&format!("com.atproto.{method_and_query}"), token)
}

fn memberspace(public_read: bool) -> Value {
    json!({ "$type": MEMBERSPACE, "publicRead": public_read })
}

fn create_body(policy: Value) -> Value {
    json!({ "spaceType": TYPE, "skey": "main", "policy": policy })
}

fn put_members(members: Value) -> Value {
    json!({ "space": SPACE, "members": members })
}

async fn ok(state: &CoreState, request: Request<Body>) -> Value {
    let (status, body) = send(state, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn error(state: &CoreState, request: Request<Body>) -> String {
    let (status, body) = send(state, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    body["error"].as_str().unwrap_or_default().to_string()
}

/// The stored policy and its parsed form, for the issuance checks.
async fn stored(state: &CoreState) -> (crate::db::spaces::SpaceRow, crate::policy::SpacePolicy) {
    let row = crate::db::spaces::get_space(&state.db, SPACE)
        .await
        .unwrap()
        .unwrap();
    let policy = row.space_policy().unwrap().unwrap();
    (row, policy)
}

async fn may_read(state: &CoreState, did: &str) -> bool {
    let (row, policy) = stored(state).await;
    authorize_credential_request(state, &row, &policy, did, None)
        .await
        .is_ok()
}

/// The decoded record at `collection/rkey` in Alice's repo in the space, if any.
async fn published(state: &CoreState, collection: &str, rkey: &str) -> Option<Value> {
    crate::db::space_repos::get_record(&state.db, SPACE, ALICE, collection, rkey)
        .await
        .unwrap()
        .map(|row| crate::views::decode_value(&row.value).unwrap())
}

/// The journey a client takes: create, describe, manage members (and see the member list feed
/// credential issuance), reconfigure, delete, then create the same URI again.
#[tokio::test]
async fn create_get_members_update_delete_round_trip() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);

    let body = ok(
        &state,
        post("space.createSpace", &alice, create_body(memberspace(false))),
    )
    .await;
    assert_eq!(body, json!({ "space": SPACE }));
    assert_eq!(
        error(
            &state,
            post("space.createSpace", &alice, create_body(memberspace(false)))
        )
        .await,
        "SpaceAlreadyExists"
    );

    // Without a skey, one is generated (a TID) and the space is distinct.
    let body = ok(
        &state,
        post(
            "space.createSpace",
            &alice,
            json!({ "spaceType": TYPE, "policy": { "$type": PERSONALSPACE } }),
        ),
    )
    .await;
    let generated = body["space"].as_str().unwrap();
    assert_ne!(generated, SPACE);
    assert!(generated.starts_with(&format!("at://{ALICE}/space/{TYPE}/")));

    // getSpace serves the normalized policy: defaults filled in.
    let body = ok(
        &state,
        get(&format!("space.getSpace?space={SPACE}"), &alice),
    )
    .await;
    assert_eq!(
        body,
        json!({
            "space": SPACE,
            "policy": {
                "$type": MEMBERSPACE,
                "publicRead": false,
                "publicWrite": false,
                "publishPolicy": false,
                "publishMembers": false,
            },
        })
    );

    // Members: added in a batch (a DID listed twice takes its last entry), listed, and
    // consulted by the credential issuance policy.
    ok(
        &state,
        post(
            "memberspace.putMembers",
            &alice,
            put_members(json!([
                { "did": BOB, "read": false, "write": false },
                { "did": BOB, "read": true, "write": true },
            ])),
        ),
    )
    .await;
    let body = ok(
        &state,
        get(&format!("memberspace.listMembers?space={SPACE}"), &alice),
    )
    .await;
    assert_eq!(
        body["members"],
        json!([{ "did": BOB, "read": true, "write": true }])
    );
    assert!(
        body.get("cursor").is_none(),
        "a short page carries no cursor"
    );
    assert!(may_read(&state, BOB).await);

    // putMembers is an upsert, and the two bits round-trip independently.
    ok(
        &state,
        post(
            "memberspace.putMembers",
            &alice,
            put_members(json!([{ "did": BOB, "read": false, "write": true }])),
        ),
    )
    .await;
    let body = ok(
        &state,
        get(&format!("memberspace.listMembers?space={SPACE}"), &alice),
    )
    .await;
    assert_eq!(
        body["members"],
        json!([{ "did": BOB, "read": false, "write": true }])
    );
    assert!(!may_read(&state, BOB).await);

    // removeMembers ignores a DID that is not a member.
    ok(
        &state,
        post(
            "memberspace.removeMembers",
            &alice,
            json!({ "space": SPACE, "dids": [BOB, "did:plc:nobody"] }),
        ),
    )
    .await;
    assert!(!may_read(&state, BOB).await);

    // updateSpace replaces the policy wholesale.
    ok(
        &state,
        post(
            "space.updateSpace",
            &alice,
            json!({ "space": SPACE, "policy": memberspace(true) }),
        ),
    )
    .await;
    assert!(may_read(&state, "did:plc:stranger").await);

    // The authority writes into its own space; deletion takes that repo with it.
    let (status, body) = send(
        &state,
        xrpc_post(
            "com.atproto.space.createRecord",
            &alice,
            json!({
                "space": SPACE, "repo": ALICE, "collection": "org.example.note",
                "rkey": "aaa", "record": { "text": "hi" },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    ok(
        &state,
        post("space.deleteSpace", &alice, json!({ "space": SPACE })),
    )
    .await;
    assert!(crate::db::space_repos::get_repo(&state.db, SPACE, ALICE)
        .await
        .unwrap()
        .is_none());
    let row = crate::db::spaces::get_space(&state.db, SPACE)
        .await
        .unwrap()
        .unwrap();
    assert!(row.deleted_at.is_some(), "the tombstone survives");
    assert!(row.policy.is_none(), "with its policy cleared");

    // Deleted: reads and management answer SpaceNotFound; delete is idempotent.
    for request in [
        get(&format!("space.getSpace?space={SPACE}"), &alice),
        get(&format!("memberspace.listMembers?space={SPACE}"), &alice),
        post(
            "space.updateSpace",
            &alice,
            json!({ "space": SPACE, "policy": memberspace(true) }),
        ),
        post(
            "memberspace.putMembers",
            &alice,
            put_members(json!([{ "did": BOB, "read": true, "write": true }])),
        ),
    ] {
        assert_eq!(error(&state, request).await, "SpaceNotFound");
    }
    ok(
        &state,
        post("space.deleteSpace", &alice, json!({ "space": SPACE })),
    )
    .await;

    // A deleted space may be created again, fresh.
    ok(
        &state,
        post("space.createSpace", &alice, create_body(memberspace(true))),
    )
    .await;
    let body = ok(
        &state,
        get(&format!("memberspace.listMembers?space={SPACE}"), &alice),
    )
    .await;
    assert_eq!(body["members"], json!([]));
    assert!(may_read(&state, BOB).await);
}

/// `policy` is an open union: a `$type` this host does not implement is refused at create and
/// update time and nothing is stored, as is a managing app no resolution could address.
#[tokio::test]
async fn unsupported_policies_are_refused_and_never_stored() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);

    let unsupported = json!({ "$type": "com.example.futurePolicy" });
    assert_eq!(
        error(
            &state,
            post(
                "space.createSpace",
                &alice,
                create_body(unsupported.clone())
            )
        )
        .await,
        "UnsupportedPolicy"
    );
    for app in [
        "https://forum.example",
        "did:web:forum.example",
        "did:web:forum.example#",
    ] {
        let policy = json!({ "$type": MANAGEDSPACE, "managingApp": app });
        assert_eq!(
            error(
                &state,
                post("space.createSpace", &alice, create_body(policy))
            )
            .await,
            "InvalidRequest",
            "{app}"
        );
    }
    assert!(crate::db::spaces::get_space(&state.db, SPACE)
        .await
        .unwrap()
        .is_none());

    // The same on update: the stored policy is untouched.
    ok(
        &state,
        post("space.createSpace", &alice, create_body(memberspace(false))),
    )
    .await;
    assert_eq!(
        error(
            &state,
            post(
                "space.updateSpace",
                &alice,
                json!({ "space": SPACE, "policy": unsupported })
            )
        )
        .await,
        "UnsupportedPolicy"
    );
    let body = ok(
        &state,
        get(&format!("space.getSpace?space={SPACE}"), &alice),
    )
    .await;
    assert_eq!(body["policy"]["$type"], MEMBERSPACE);

    // A missing required union is the lexicon layer's refusal, before any handler runs.
    assert_eq!(
        error(
            &state,
            post(
                "space.createSpace",
                &alice,
                json!({ "spaceType": TYPE, "skey": "other" })
            ),
        )
        .await,
        "InvalidRequest"
    );
}

/// The three baseline policies through the routes: personalspace admits only the authority,
/// managedspace round-trips its managing app, and the member methods belong to memberspace.
#[tokio::test]
async fn the_three_baseline_policies_work_through_the_routes() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);

    ok(
        &state,
        post(
            "space.createSpace",
            &alice,
            create_body(json!({ "$type": PERSONALSPACE })),
        ),
    )
    .await;
    let body = ok(
        &state,
        get(&format!("space.getSpace?space={SPACE}"), &alice),
    )
    .await;
    assert_eq!(body["policy"], json!({ "$type": PERSONALSPACE }));
    assert!(may_read(&state, ALICE).await);
    assert!(!may_read(&state, BOB).await);
    for request in [
        get(&format!("memberspace.listMembers?space={SPACE}"), &alice),
        post(
            "memberspace.putMembers",
            &alice,
            put_members(json!([{ "did": BOB, "read": true, "write": true }])),
        ),
        post(
            "memberspace.removeMembers",
            &alice,
            json!({ "space": SPACE, "dids": [BOB] }),
        ),
    ] {
        assert_eq!(error(&state, request).await, "PolicyMismatch");
    }

    const APP: &str = "did:web:forum.example#forum";
    let managed = json!({ "$type": MANAGEDSPACE, "managingApp": APP, "publishPolicy": true });
    ok(
        &state,
        post(
            "space.updateSpace",
            &alice,
            json!({ "space": SPACE, "policy": managed.clone() }),
        ),
    )
    .await;
    let body = ok(
        &state,
        get(&format!("space.getSpace?space={SPACE}"), &alice),
    )
    .await;
    assert_eq!(body["policy"], managed);
    assert_eq!(
        error(
            &state,
            get(&format!("memberspace.listMembers?space={SPACE}"), &alice)
        )
        .await,
        "PolicyMismatch"
    );

    ok(
        &state,
        post(
            "space.updateSpace",
            &alice,
            json!({ "space": SPACE, "policy": memberspace(false) }),
        ),
    )
    .await;
    ok(
        &state,
        post(
            "memberspace.putMembers",
            &alice,
            put_members(json!([{ "did": BOB, "read": true, "write": false }])),
        ),
    )
    .await;
    assert!(may_read(&state, BOB).await);
}

/// A `$type` change discards the previous policy's member list (switching back does not restore
/// it) but leaves the writer set alone; a same-type update keeps the members.
#[tokio::test]
async fn a_type_change_clears_members_but_not_writers() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    ok(
        &state,
        post("space.createSpace", &alice, create_body(memberspace(false))),
    )
    .await;
    ok(
        &state,
        post(
            "memberspace.putMembers",
            &alice,
            put_members(json!([{ "did": BOB, "read": true, "write": true }])),
        ),
    )
    .await;
    ok(
        &state,
        xrpc_post(
            "com.atproto.space.createRecord",
            &alice,
            json!({
                "space": SPACE, "repo": ALICE, "collection": "org.example.note",
                "rkey": "aaa", "record": { "text": "hi" },
            }),
        ),
    )
    .await;
    let writers = || async {
        crate::db::space_notify::list_writers(&state.db, SPACE, None, 10)
            .await
            .unwrap()
            .len()
    };
    assert_eq!(writers().await, 1);

    ok(
        &state,
        post(
            "space.updateSpace",
            &alice,
            json!({ "space": SPACE, "policy": memberspace(true) }),
        ),
    )
    .await;
    let body = ok(
        &state,
        get(&format!("memberspace.listMembers?space={SPACE}"), &alice),
    )
    .await;
    assert_eq!(
        body["members"].as_array().unwrap().len(),
        1,
        "same type keeps members"
    );

    for policy in [json!({ "$type": PERSONALSPACE }), memberspace(false)] {
        ok(
            &state,
            post(
                "space.updateSpace",
                &alice,
                json!({ "space": SPACE, "policy": policy }),
            ),
        )
        .await;
    }
    let body = ok(
        &state,
        get(&format!("memberspace.listMembers?space={SPACE}"), &alice),
    )
    .await;
    assert_eq!(
        body["members"],
        json!([]),
        "switching back does not restore them"
    );
    assert_eq!(writers().await, 1, "the writer set is left alone");
}

/// `publishPolicy`/`publishMembers` mirror the policy and member list into the authority's repo
/// in the same commit as the change, and withdraw them when turned off. Nobody writes those
/// collections directly.
#[tokio::test]
async fn published_policy_and_members_follow_the_configuration() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    let publishing = json!({ "$type": MEMBERSPACE, "publishPolicy": true, "publishMembers": true });

    ok(
        &state,
        post("space.createSpace", &alice, create_body(publishing.clone())),
    )
    .await;
    let record = published(&state, POLICY_COLLECTION, "self").await.unwrap();
    assert_eq!(record["$type"], POLICY_COLLECTION);
    assert_eq!(record["policy"]["publishMembers"], true);

    ok(
        &state,
        post(
            "memberspace.putMembers",
            &alice,
            put_members(json!([
                { "did": BOB, "read": true, "write": false },
                { "did": "did:web:localhost%3A2583", "read": true, "write": true },
            ])),
        ),
    )
    .await;
    assert_eq!(
        published(&state, MEMBER_COLLECTION, BOB).await.unwrap(),
        json!({ "$type": MEMBER_COLLECTION, "read": true, "write": false })
    );
    assert!(
        published(&state, MEMBER_COLLECTION, "did:web:localhost:2583")
            .await
            .is_some()
    );

    ok(
        &state,
        post(
            "memberspace.removeMembers",
            &alice,
            json!({ "space": SPACE, "dids": [BOB] }),
        ),
    )
    .await;
    assert!(published(&state, MEMBER_COLLECTION, BOB).await.is_none());

    // Turning both off withdraws the policy record and the whole published member list.
    ok(
        &state,
        post(
            "space.updateSpace",
            &alice,
            json!({ "space": SPACE, "policy": memberspace(false) }),
        ),
    )
    .await;
    assert!(published(&state, POLICY_COLLECTION, "self").await.is_none());
    assert!(
        published(&state, MEMBER_COLLECTION, "did:web:localhost:2583")
            .await
            .is_none()
    );
    // ...and turning members back on republishes the list that is still there.
    ok(
        &state,
        post(
            "space.updateSpace",
            &alice,
            json!({ "space": SPACE, "policy": publishing }),
        ),
    )
    .await;
    assert!(
        published(&state, MEMBER_COLLECTION, "did:web:localhost:2583")
            .await
            .is_some()
    );

    // A direct write to either collection is refused, in any repo.
    for collection in [POLICY_COLLECTION, MEMBER_COLLECTION] {
        let (status, body) = send(
            &state,
            xrpc_post(
                "com.atproto.space.putRecord",
                &alice,
                json!({
                    "space": SPACE, "repo": ALICE, "collection": collection,
                    "rkey": "self", "record": { "read": true, "write": true },
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "InvalidRequest");
    }
}

/// Management needs the matching `manage=` verb on a granular grant, and the caller must be the
/// space's authority; `getSpace`/`listMembers` take `read_self` but are authority-only too.
#[tokio::test]
async fn management_is_gated_by_manage_grants_and_authority() {
    let state = setup().await;

    let create_only = scoped_access_jwt(
        &state.jwt_secret,
        ALICE,
        &format!("atproto space:{TYPE}?skey=main&manage=create"),
    );
    ok(
        &state,
        post(
            "space.createSpace",
            &create_only,
            create_body(memberspace(false)),
        ),
    )
    .await;
    for request in [
        post(
            "space.updateSpace",
            &create_only,
            json!({ "space": SPACE, "policy": memberspace(true) }),
        ),
        post(
            "memberspace.putMembers",
            &create_only,
            put_members(json!([{ "did": BOB, "read": true, "write": true }])),
        ),
        post(
            "memberspace.removeMembers",
            &create_only,
            json!({ "space": SPACE, "dids": [BOB] }),
        ),
        post("space.deleteSpace", &create_only, json!({ "space": SPACE })),
    ] {
        let (status, body) = send(&state, request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "InsufficientScope");
    }
    ok(
        &state,
        get(
            &format!("memberspace.listMembers?space={SPACE}"),
            &create_only,
        ),
    )
    .await;

    // A grant on a different skey does not create this one.
    let other_skey = scoped_access_jwt(
        &state.jwt_secret,
        ALICE,
        &format!("atproto space:{TYPE}?skey=other&manage=create"),
    );
    let (status, body) = send(
        &state,
        post(
            "space.createSpace",
            &other_skey,
            create_body(memberspace(false)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Bob (full session, so no grant to evaluate) is not the authority of Alice's space.
    let bob = access_jwt(&state.jwt_secret, BOB);
    for request in [
        post(
            "space.updateSpace",
            &bob,
            json!({ "space": SPACE, "policy": memberspace(true) }),
        ),
        post(
            "memberspace.putMembers",
            &bob,
            put_members(json!([{ "did": BOB, "read": true, "write": true }])),
        ),
        post("space.deleteSpace", &bob, json!({ "space": SPACE })),
        get(&format!("space.getSpace?space={SPACE}"), &bob),
        get(&format!("memberspace.listMembers?space={SPACE}"), &bob),
    ] {
        assert_eq!(error(&state, request).await, "NotAuthorized");
    }

    // No credential at all.
    let response = app(state.clone())
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri(format!("/xrpc/com.atproto.space.getSpace?space={SPACE}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_members_pages_by_did_and_batches_are_bounded() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    ok(
        &state,
        post("space.createSpace", &alice, create_body(memberspace(false))),
    )
    .await;
    let member = |did: &str| json!({ "did": did, "read": true, "write": true });
    ok(
        &state,
        post(
            "memberspace.putMembers",
            &alice,
            put_members(json!([
                member("did:plc:m1"),
                member("did:plc:m2"),
                member("did:plc:m3")
            ])),
        ),
    )
    .await;

    let page1 = ok(
        &state,
        get(
            &format!("memberspace.listMembers?space={SPACE}&limit=2"),
            &alice,
        ),
    )
    .await;
    assert_eq!(
        page1["members"],
        json!([member("did:plc:m1"), member("did:plc:m2")])
    );
    assert_eq!(page1["cursor"], "did:plc:m2");
    let page2 = ok(
        &state,
        get(
            &format!("memberspace.listMembers?space={SPACE}&limit=2&cursor=did:plc:m2"),
            &alice,
        ),
    )
    .await;
    assert_eq!(page2["members"], json!([member("did:plc:m3")]));
    assert!(page2.get("cursor").is_none());

    // The lexicon bounds `limit` and the batch sizes.
    let (status, _) = send(
        &state,
        get(
            &format!("memberspace.listMembers?space={SPACE}&limit=1001"),
            &alice,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let too_many: Vec<Value> = (0..101)
        .map(|i| member(&format!("did:plc:m{i:03}")))
        .collect();
    assert_eq!(
        error(
            &state,
            post(
                "memberspace.putMembers",
                &alice,
                put_members(json!(too_many))
            )
        )
        .await,
        "InvalidRequest"
    );
    let too_many: Vec<String> = (0..101).map(|i| format!("did:plc:m{i:03}")).collect();
    assert_eq!(
        error(
            &state,
            post(
                "memberspace.removeMembers",
                &alice,
                json!({ "space": SPACE, "dids": too_many })
            )
        )
        .await,
        "InvalidRequest"
    );
}

/// `listSpaces` includes a space the caller is the authority of before it has written there,
/// with `spaceRev` only for the authority and the repo head only once a repo exists.
#[tokio::test]
async fn list_spaces_includes_spaces_the_caller_is_authority_of() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    ok(
        &state,
        post("space.createSpace", &alice, create_body(memberspace(true))),
    )
    .await;

    let body = ok(&state, xrpc_get("com.atproto.space.listSpaces", &alice)).await;
    assert_eq!(body["spaces"], json!([{ "space": SPACE }]));

    ok(
        &state,
        xrpc_post(
            "com.atproto.space.createRecord",
            &alice,
            json!({
                "space": SPACE, "repo": ALICE, "collection": "org.example.note",
                "rkey": "aaa", "record": { "text": "hi" },
            }),
        ),
    )
    .await;
    let body = ok(
        &state,
        xrpc_get(
            &format!("com.atproto.space.listSpaces?spaceDid={ALICE}"),
            &alice,
        ),
    )
    .await;
    let view = &body["spaces"][0];
    assert_eq!(view["space"], SPACE);
    assert!(
        view["repoRev"].is_string() && view["data"]["$bytes"].is_string(),
        "{view}"
    );
    assert!(
        view["spaceRev"].is_string(),
        "the authority sees the space revision: {view}"
    );

    // Bob holds nothing there and is not its authority.
    let bob = access_jwt(&state.jwt_secret, BOB);
    let body = ok(&state, xrpc_get("com.atproto.space.listSpaces", &bob)).await;
    assert_eq!(body["spaces"], json!([]));
}

/// Publishing writes records into the authority's repo, so it waits for the authority's KEM key
/// like any other space write; a space with nothing to publish is created regardless.
#[tokio::test]
async fn publishing_waits_for_a_published_kem_key() {
    let state = state_with_master_key().await;
    // No KEM key published (the core fixture, not this crate's publishing one).
    custos_core::test_support::seed_account_with_repo(&state.db, ALICE).await;
    let alice = access_jwt(&state.jwt_secret, ALICE);

    let publishing = json!({ "$type": MEMBERSPACE, "publishPolicy": true });
    assert_eq!(
        error(
            &state,
            post("space.createSpace", &alice, create_body(publishing))
        )
        .await,
        "KemKeyNotPublished"
    );
    ok(
        &state,
        post("space.createSpace", &alice, create_body(memberspace(false))),
    )
    .await;
}
