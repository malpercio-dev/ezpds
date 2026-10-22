// pattern: Imperative Shell
//
// End-to-end coverage of the `com.atproto.simplespace.*` management surface, driven through the
// real router so the lexicon layer (incl. the open-union `$type` handling), the owner seam and
// the store are all in the path. Cross-route journeys — create here, see it there, delete, then
// create again — live in this one test-only module, as `space_routes_test.rs` does for the
// record surface; each route keeps only what is genuinely local to it.

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use tower::ServiceExt;

use crate::auth::space::{authorize_credential_request, mint_space_credential, unix_now};
use crate::db::dids::seed_did_document;
use crate::space_uri::parse_space_ref;
use crate::test_support::test_app as app;
use crate::test_support::{
    access_jwt, scoped_access_jwt, seed_account_with_repo, state_with_master_key, SpaceSigKey,
};
use crate::test_support::{send, xrpc_get, xrpc_post};
use crate::SpacesState;

const ALICE: &str = "did:plc:alicesimplespaceaaaaaaaa";
const BOB: &str = "did:plc:bobsimplespaceaaaaaaaaaa";
const CAROL: &str = "did:plc:carolsimplespaceaaaaaaaa";
const TYPE: &str = "org.example.bucket";
const SPACE: &str = "at://did:plc:alicesimplespaceaaaaaaaa/space/org.example.bucket/main";

const PUBLIC: &str = "com.atproto.simplespace.defs#publicPolicy";
const MEMBER_LIST: &str = "com.atproto.simplespace.defs#memberListPolicy";
const MANAGING_APP: &str = "com.atproto.simplespace.defs#managingAppPolicy";
const OPEN: &str = "com.atproto.simplespace.defs#open";
const ALLOW_LIST: &str = "com.atproto.simplespace.defs#allowList";

async fn setup() -> SpacesState {
    let state = state_with_master_key().await;
    seed_account_with_repo(&state.db, ALICE).await;
    seed_account_with_repo(&state.db, BOB).await;
    state
}

fn post(method: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    xrpc_post(&format!("com.atproto.simplespace.{method}"), token, body)
}

fn get(method_and_query: &str, token: &str) -> Request<Body> {
    xrpc_get(
        &format!("com.atproto.simplespace.{method_and_query}"),
        token,
    )
}

fn create_body(policy: &str, app_access: &str) -> serde_json::Value {
    serde_json::json!({
        "spaceType": TYPE,
        "skey": "main",
        "readPolicy": { "$type": policy },
        "writePolicy": { "$type": policy },
        "appAccess": { "$type": app_access },
    })
}

/// The journey a client takes: create, describe, reconfigure, manage members (and see the
/// member list feed credential issuance), delete, then create the same URI again.
#[tokio::test]
async fn create_get_update_members_delete_round_trip() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);

    let (status, body) = send(
        &state,
        post("createSpace", &alice, create_body(MEMBER_LIST, OPEN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["uri"], SPACE);

    let (status, body) = send(
        &state,
        post("createSpace", &alice, create_body(MEMBER_LIST, OPEN)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "SpaceAlreadyExists");

    // Without a skey, one is generated (a TID) and the space is distinct.
    let (status, body) = send(
        &state,
        post(
            "createSpace",
            &alice,
            serde_json::json!({
                "spaceType": TYPE,
                "readPolicy": { "$type": PUBLIC },
                "writePolicy": { "$type": PUBLIC },
                "appAccess": { "$type": OPEN },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let generated = body["uri"].as_str().unwrap();
    assert_ne!(generated, SPACE);
    assert!(generated.starts_with(&format!("at://{ALICE}/space/{TYPE}/")));

    let (status, body) = send(&state, get(&format!("getSpace?space={SPACE}"), &alice)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["uri"], SPACE);
    assert_eq!(body["readPolicy"]["$type"], MEMBER_LIST);
    assert_eq!(body["appAccess"]["$type"], OPEN);

    // Members: added, listed, and consulted by the credential issuance policy.
    let (status, _) = send(
        &state,
        post(
            "putMember",
            &alice,
            serde_json::json!({ "space": SPACE, "did": BOB, "read": true, "write": true }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(&state, get(&format!("listMembers?space={SPACE}"), &alice)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["members"],
        serde_json::json!([{ "did": BOB, "read": true, "write": true }])
    );
    assert!(
        body.get("cursor").is_none(),
        "a short page carries no cursor"
    );

    let space = parse_space_ref(SPACE).unwrap();
    let row = crate::db::spaces::get_space(&state.db, SPACE)
        .await
        .unwrap()
        .unwrap();
    assert!(authorize_credential_request(&state, &row, BOB, None)
        .await
        .is_ok());

    // putMember is an upsert, and the two bits round-trip independently.
    let (status, _) = send(
        &state,
        post(
            "putMember",
            &alice,
            serde_json::json!({ "space": SPACE, "did": BOB, "read": false, "write": true }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = send(&state, get(&format!("listMembers?space={SPACE}"), &alice)).await;
    assert_eq!(
        body["members"],
        serde_json::json!([{ "did": BOB, "read": false, "write": true }])
    );
    assert!(authorize_credential_request(&state, &row, BOB, None)
        .await
        .is_err());

    let (status, _) = send(
        &state,
        post(
            "removeMember",
            &alice,
            serde_json::json!({ "space": SPACE, "did": BOB }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        *authorize_credential_request(&state, &row, BOB, None)
            .await
            .unwrap_err()
            .code(),
        common::ErrorCode::UserNotAuthorized
    );

    // updateSpace replaces only the axis supplied.
    let (status, _) = send(
        &state,
        post(
            "updateSpace",
            &alice,
            serde_json::json!({ "space": SPACE, "readPolicy": { "$type": PUBLIC } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &state,
        post(
            "updateSpace",
            &alice,
            serde_json::json!({ "space": SPACE, "appAccess": { "$type": OPEN } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = send(&state, get(&format!("getSpace?space={SPACE}"), &alice)).await;
    assert_eq!(body["readPolicy"]["$type"], PUBLIC);
    assert_eq!(body["appAccess"]["$type"], OPEN);

    // The authority writes into its own space; deletion takes that repo with it.
    let (status, body) = send(
        &state,
        Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.space.createRecord")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {alice}"))
            .body(Body::from(
                serde_json::json!({
                    "space": SPACE, "repo": ALICE, "collection": "org.example.note",
                    "rkey": "aaa", "record": {"text": "hi"},
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(crate::db::space_repos::get_repo(&state.db, SPACE, ALICE)
        .await
        .unwrap()
        .is_some());

    let (status, _) = send(
        &state,
        post("deleteSpace", &alice, serde_json::json!({ "space": SPACE })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(crate::db::space_repos::get_repo(&state.db, SPACE, ALICE)
        .await
        .unwrap()
        .is_none());
    let row = crate::db::spaces::get_space(&state.db, SPACE)
        .await
        .unwrap()
        .unwrap();
    assert!(row.deleted_at.is_some(), "the tombstone survives");
    assert!(row.policy.is_none(), "with its config cleared");

    // Deleted: reads and management answer SpaceNotFound; delete is idempotent.
    for request in [
        get(&format!("getSpace?space={SPACE}"), &alice),
        get(&format!("listMembers?space={SPACE}"), &alice),
        post(
            "updateSpace",
            &alice,
            serde_json::json!({ "space": SPACE, "readPolicy": { "$type": PUBLIC } }),
        ),
        post(
            "putMember",
            &alice,
            serde_json::json!({ "space": SPACE, "did": BOB, "read": true, "write": true }),
        ),
    ] {
        let (status, body) = send(&state, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "SpaceNotFound");
    }
    let (status, _) = send(
        &state,
        post("deleteSpace", &alice, serde_json::json!({ "space": SPACE })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "idempotent");

    // A deleted space may be created again, fresh — and getSpaceCredential's issuance policy
    // sees the revived row, not the tombstone.
    let (status, body) = send(
        &state,
        post("createSpace", &alice, create_body(PUBLIC, OPEN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = send(&state, get(&format!("listMembers?space={SPACE}"), &alice)).await;
    assert_eq!(body["members"], serde_json::json!([]));
    let row = crate::db::spaces::get_space(&state.db, SPACE)
        .await
        .unwrap()
        .unwrap();
    assert!(row.deleted_at.is_none());
    assert!(authorize_credential_request(&state, &row, BOB, None)
        .await
        .is_ok());
    let _ = space;
}

/// `policy` and `appAccess` are open unions: a member this host does not implement is refused
/// at create and update time, and nothing is stored.
#[tokio::test]
async fn unimplemented_open_union_members_are_refused_and_never_stored() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);

    for (body, error) in [
        (
            serde_json::json!({
                "spaceType": TYPE, "skey": "main",
                "readPolicy": { "$type": "com.example.futurePolicy" },
                "writePolicy": { "$type": "com.example.futurePolicy" },
                "appAccess": { "$type": OPEN },
            }),
            "UnsupportedPolicy",
        ),
        // `managingApp` is a service identifier — a DID with an optional service fragment.
        // A space whose decider cannot be addressed is a space that could never mint, so every
        // shape that can never resolve is refused rather than stored: not a DID at all, a bare
        // prefix, a DID with no method-specific id, and an empty fragment.
        (
            serde_json::json!({
                "spaceType": TYPE, "skey": "main",
                "readPolicy": { "$type": MANAGING_APP, "managingApp": "https://forum.example" },
                "writePolicy": { "$type": MANAGING_APP, "managingApp": "https://forum.example" },
                "appAccess": { "$type": OPEN },
            }),
            "UnsupportedPolicy",
        ),
        (
            serde_json::json!({
                "spaceType": TYPE, "skey": "main",
                "readPolicy": { "$type": MANAGING_APP, "managingApp": "did:" },
                "writePolicy": { "$type": MANAGING_APP, "managingApp": "did:" },
                "appAccess": { "$type": OPEN },
            }),
            "UnsupportedPolicy",
        ),
        (
            serde_json::json!({
                "spaceType": TYPE, "skey": "main",
                "readPolicy": { "$type": MANAGING_APP, "managingApp": "did:web:" },
                "writePolicy": { "$type": MANAGING_APP, "managingApp": "did:web:" },
                "appAccess": { "$type": OPEN },
            }),
            "UnsupportedPolicy",
        ),
        (
            serde_json::json!({
                "spaceType": TYPE, "skey": "main",
                "readPolicy": { "$type": MANAGING_APP, "managingApp": "did:web:forum.example#" },
                "writePolicy": { "$type": MANAGING_APP, "managingApp": "did:web:forum.example#" },
                "appAccess": { "$type": OPEN },
            }),
            "UnsupportedPolicy",
        ),
        (
            serde_json::json!({
                "spaceType": TYPE, "skey": "main",
                "readPolicy": { "$type": PUBLIC },
                "writePolicy": { "$type": PUBLIC },
                "appAccess": { "$type": "com.example.futureAccess" },
            }),
            "UnsupportedAppAccess",
        ),
    ] {
        let (status, response) = send(&state, post("createSpace", &alice, body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(response["error"], error);
    }
    assert!(crate::db::spaces::get_space(&state.db, SPACE)
        .await
        .unwrap()
        .is_none());

    // The same on update: the stored config is untouched.
    let (status, _) = send(
        &state,
        post("createSpace", &alice, create_body(MEMBER_LIST, OPEN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for (patch, error) in [
        (
            serde_json::json!({ "readPolicy": { "$type": "com.example.futurePolicy" } }),
            "UnsupportedPolicy",
        ),
        (
            serde_json::json!({ "appAccess": { "$type": "com.example.futureAccess" } }),
            "UnsupportedAppAccess",
        ),
    ] {
        let mut body = serde_json::json!({ "space": SPACE });
        body.as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        let (status, response) = send(&state, post("updateSpace", &alice, body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(response["error"], error);
    }
    let (_, body) = send(&state, get(&format!("getSpace?space={SPACE}"), &alice)).await;
    assert_eq!(body["readPolicy"]["$type"], MEMBER_LIST);
    assert_eq!(body["appAccess"]["$type"], OPEN);

    // A missing required union is the lexicon layer's refusal, before any handler runs.
    let (status, body) = send(
        &state,
        post(
            "createSpace",
            &alice,
            serde_json::json!({ "spaceType": TYPE, "skey": "other", "readPolicy": { "$type": PUBLIC }, "writePolicy": { "$type": PUBLIC } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest", "{body}");
}

/// The two config members that need app identity — `managing-app` policy and `allowList` app
/// access — round-trip through create, update, and `getSpace` with their payloads intact.
///
/// The allow list is the payload worth pinning: it is the only part of the config that is a
/// list rather than a tag, so it is the part that can silently come back empty — and an empty
/// allow list admits no app at all.
#[tokio::test]
async fn managing_app_and_allow_list_config_round_trips() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    const APP: &str = "did:web:forum.example#forum";
    const CLIENT: &str = "https://app.example.com/client-metadata.json";

    let (status, body) = send(
        &state,
        post(
            "createSpace",
            &alice,
            serde_json::json!({
                "spaceType": TYPE, "skey": "main",
                "readPolicy": { "$type": MANAGING_APP, "managingApp": APP },
                "writePolicy": { "$type": MANAGING_APP, "managingApp": APP },
                "appAccess": { "$type": ALLOW_LIST, "allowed": [CLIENT] },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = send(&state, get(&format!("getSpace?space={SPACE}"), &alice)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["readPolicy"]["$type"], MANAGING_APP);
    assert_eq!(body["readPolicy"]["managingApp"], APP);
    assert_eq!(body["appAccess"]["$type"], ALLOW_LIST);
    assert_eq!(body["appAccess"]["allowed"], serde_json::json!([CLIENT]));

    // Replacing the `appAccess` axis replaces its list with it, and leaving the axis alone
    // leaves the list alone.
    let (status, _) = send(
        &state,
        post(
            "updateSpace",
            &alice,
            serde_json::json!({
                "space": SPACE,
                "appAccess": { "$type": ALLOW_LIST, "allowed": [CLIENT, "https://b.example/c"] },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &state,
        post(
            "updateSpace",
            &alice,
            serde_json::json!({ "space": SPACE, "readPolicy": { "$type": PUBLIC } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = send(&state, get(&format!("getSpace?space={SPACE}"), &alice)).await;
    assert_eq!(body["readPolicy"]["$type"], PUBLIC);
    assert_eq!(
        body["appAccess"]["allowed"],
        serde_json::json!([CLIENT, "https://b.example/c"]),
        "a policy-only update must not disturb the allow list",
    );

    // Switching back to `open` drops the list; switching to `allowList` again starts fresh.
    let (status, _) = send(
        &state,
        post(
            "updateSpace",
            &alice,
            serde_json::json!({ "space": SPACE, "appAccess": { "$type": OPEN } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = send(&state, get(&format!("getSpace?space={SPACE}"), &alice)).await;
    assert_eq!(body["appAccess"], serde_json::json!({ "$type": OPEN }));
}

/// Management needs the matching `manage=` verb on a granular grant, and the caller must be
/// the space's authority; `getSpace`/`listMembers` take `read_self` but are owner-only too.
#[tokio::test]
async fn management_is_gated_by_manage_grants_and_ownership() {
    let state = setup().await;

    // manage=create only: may create, may not reconfigure or delete; the default `action`
    // set carries `read`, which covers the owner-only reads.
    let create_only = scoped_access_jwt(
        &state.jwt_secret,
        ALICE,
        &format!("atproto space:{TYPE}?skey=main&manage=create"),
    );
    let (status, body) = send(
        &state,
        post("createSpace", &create_only, create_body(MEMBER_LIST, OPEN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for request in [
        post(
            "updateSpace",
            &create_only,
            serde_json::json!({ "space": SPACE, "readPolicy": { "$type": PUBLIC } }),
        ),
        post(
            "putMember",
            &create_only,
            serde_json::json!({ "space": SPACE, "did": BOB, "read": true, "write": true }),
        ),
        post(
            "removeMember",
            &create_only,
            serde_json::json!({ "space": SPACE, "did": BOB }),
        ),
        post(
            "deleteSpace",
            &create_only,
            serde_json::json!({ "space": SPACE }),
        ),
    ] {
        let (status, body) = send(&state, request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "InsufficientScope");
    }
    let (status, body) = send(
        &state,
        get(&format!("listMembers?space={SPACE}"), &create_only),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A grant on a different skey does not create this one.
    let other_skey = scoped_access_jwt(
        &state.jwt_secret,
        ALICE,
        &format!("atproto space:{TYPE}?skey=other&manage=create"),
    );
    let (status, body) = send(
        &state,
        post("createSpace", &other_skey, create_body(MEMBER_LIST, OPEN)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Bob (full session, so no grant to evaluate) is not the owner of Alice's space.
    let bob = access_jwt(&state.jwt_secret, BOB);
    for request in [
        post(
            "updateSpace",
            &bob,
            serde_json::json!({ "space": SPACE, "readPolicy": { "$type": PUBLIC } }),
        ),
        post(
            "putMember",
            &bob,
            serde_json::json!({ "space": SPACE, "did": BOB, "read": true, "write": true }),
        ),
        post("deleteSpace", &bob, serde_json::json!({ "space": SPACE })),
        get(&format!("getSpace?space={SPACE}"), &bob),
        get(&format!("listMembers?space={SPACE}"), &bob),
    ] {
        let (status, body) = send(&state, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "NotSpaceOwner");
    }

    // No credential at all.
    let response = app(state.clone())
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri(format!(
                    "/xrpc/com.atproto.simplespace.getSpace?space={SPACE}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// `getSpace` is the one simplespace method a space credential reaches: a member hosted
/// anywhere presents the credential the authority issued, signed by its bound key.
#[tokio::test]
async fn get_space_accepts_a_signed_space_credential() {
    let state = setup().await;
    let kp = seed_account_with_repo(&state.db, CAROL).await;
    let multibase = kp.key_id.0.strip_prefix("did:key:").unwrap().to_string();
    seed_did_document(
        &state.db,
        CAROL,
        serde_json::json!({
            "id": CAROL,
            "verificationMethod": [
                { "id": format!("{CAROL}#atproto"), "type": "Multikey", "controller": CAROL, "publicKeyMultibase": multibase },
                { "id": format!("{CAROL}#atproto_space"), "type": "Multikey", "controller": CAROL, "publicKeyMultibase": multibase },
            ],
        }),
    )
    .await;
    let signer = repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap();
    let carol_space = format!("at://{CAROL}/space/{TYPE}/main");
    let carol = access_jwt(&state.jwt_secret, CAROL);
    let (status, body) = send(
        &state,
        post("createSpace", &carol, create_body(MEMBER_LIST, OPEN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let key = SpaceSigKey::generate();
    let space = parse_space_ref(&carol_space).unwrap();
    let credential = mint_space_credential(
        |b| signer.sign(b),
        CAROL,
        &space,
        key.key_id(),
        unix_now().unwrap(),
    );
    // A space-level read is addressed to the space's authority.
    let signed_get = |uri: String, credential: &str, audience: &str| {
        let mut b = Request::builder().method(http::Method::GET).uri(uri);
        b.headers_mut()
            .unwrap()
            .extend(key.credential_headers(credential, audience));
        b.body(Body::empty()).unwrap()
    };
    let query = format!("/xrpc/com.atproto.simplespace.getSpace?space={carol_space}");
    let (status, body) = send(&state, signed_get(query.clone(), &credential, CAROL)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["uri"], carol_space);
    assert_eq!(body["readPolicy"]["$type"], MEMBER_LIST);

    // Addressed to anyone but the authority, it is refused.
    let (status, _) = send(&state, signed_get(query.clone(), &credential, ALICE)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A credential for some other space is refused, and one presented as Bearer is too.
    let other = mint_space_credential(
        |b| signer.sign(b),
        CAROL,
        &parse_space_ref(&format!("at://{CAROL}/space/{TYPE}/other")).unwrap(),
        key.key_id(),
        unix_now().unwrap(),
    );
    let (status, _) = send(&state, signed_get(query.clone(), &other, CAROL)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(
        &state,
        Request::builder()
            .method(http::Method::GET)
            .uri(&query)
            .header("Authorization", format!("Bearer {credential}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // listMembers is OAuth-only: the credential does not reach the authority's member list.
    let (status, _) = send(
        &state,
        signed_get(
            format!("/xrpc/com.atproto.simplespace.listMembers?space={carol_space}"),
            &credential,
            CAROL,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_members_pages_by_did() {
    let state = setup().await;
    let alice = access_jwt(&state.jwt_secret, ALICE);
    send(
        &state,
        post("createSpace", &alice, create_body(MEMBER_LIST, OPEN)),
    )
    .await;
    for did in ["did:plc:m1", "did:plc:m2", "did:plc:m3"] {
        let (status, _) = send(
            &state,
            post(
                "putMember",
                &alice,
                serde_json::json!({ "space": SPACE, "did": did, "read": true, "write": true }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    // Adding twice is idempotent.
    let (status, _) = send(
        &state,
        post(
            "putMember",
            &alice,
            serde_json::json!({ "space": SPACE, "did": "did:plc:m1", "read": true, "write": true }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, page1) = send(
        &state,
        get(&format!("listMembers?space={SPACE}&limit=2"), &alice),
    )
    .await;
    assert_eq!(
        page1["members"],
        serde_json::json!([
            { "did": "did:plc:m1", "read": true, "write": true },
            { "did": "did:plc:m2", "read": true, "write": true }
        ])
    );
    assert_eq!(page1["cursor"], "did:plc:m2");
    let (_, page2) = send(
        &state,
        get(
            &format!("listMembers?space={SPACE}&limit=2&cursor=did:plc:m2"),
            &alice,
        ),
    )
    .await;
    assert_eq!(
        page2["members"],
        serde_json::json!([{ "did": "did:plc:m3", "read": true, "write": true }])
    );
    assert!(page2.get("cursor").is_none());

    // The lexicon bounds `limit`.
    let (status, _) = send(
        &state,
        get(&format!("listMembers?space={SPACE}&limit=1001"), &alice),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
