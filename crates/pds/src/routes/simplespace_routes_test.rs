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

use crate::app::{app, AppState};
use crate::auth::space::{authorize_credential_request, mint_space_credential, unix_now};
use crate::db::dids::seed_did_document;
use crate::routes::test_utils::{
    access_jwt, body_json, scoped_access_jwt, seed_account_with_repo, state_with_master_key,
    DpopProofKey,
};
use crate::space_uri::parse_space_ref;

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

async fn setup() -> AppState {
    let state = state_with_master_key().await;
    seed_account_with_repo(&state.db, ALICE).await;
    seed_account_with_repo(&state.db, BOB).await;
    state
}

fn post(method: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(http::Method::POST)
        .uri(format!("/xrpc/com.atproto.simplespace.{method}"))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get(method_and_query: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(http::Method::GET)
        .uri(format!("/xrpc/com.atproto.simplespace.{method_and_query}"))
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn create_body(policy: &str, app_access: &str) -> serde_json::Value {
    serde_json::json!({
        "type": TYPE,
        "skey": "main",
        "policy": { "$type": policy },
        "appAccess": { "$type": app_access },
    })
}

async fn send(state: &AppState, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    (status, body_json(response).await)
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
                "type": TYPE,
                "policy": { "$type": PUBLIC },
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
    assert_eq!(body["policy"]["$type"], MEMBER_LIST);
    assert_eq!(body["appAccess"]["$type"], OPEN);

    // Members: added, listed, and consulted by the credential issuance policy.
    let (status, _) = send(
        &state,
        post(
            "addMember",
            &alice,
            serde_json::json!({ "space": SPACE, "did": BOB }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(&state, get(&format!("listMembers?space={SPACE}"), &alice)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["members"], serde_json::json!([{ "did": BOB }]));
    assert!(
        body.get("cursor").is_none(),
        "a short page carries no cursor"
    );

    let space = parse_space_ref(SPACE).unwrap();
    let row = crate::db::spaces::get_space(&state.db, SPACE)
        .await
        .unwrap()
        .unwrap();
    assert!(authorize_credential_request(&state.db, &row, BOB)
        .await
        .is_ok());
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
        *authorize_credential_request(&state.db, &row, BOB)
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
            serde_json::json!({ "space": SPACE, "policy": { "$type": PUBLIC } }),
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
    assert_eq!(body["policy"]["$type"], PUBLIC);
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
            serde_json::json!({ "space": SPACE, "policy": { "$type": PUBLIC } }),
        ),
        post(
            "addMember",
            &alice,
            serde_json::json!({ "space": SPACE, "did": BOB }),
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
    assert!(authorize_credential_request(&state.db, &row, BOB)
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
                "type": TYPE, "skey": "main",
                "policy": { "$type": MANAGING_APP, "managingApp": "did:web:forum.example#forum" },
                "appAccess": { "$type": OPEN },
            }),
            "UnsupportedPolicy",
        ),
        (
            serde_json::json!({
                "type": TYPE, "skey": "main",
                "policy": { "$type": "com.example.futurePolicy" },
                "appAccess": { "$type": OPEN },
            }),
            "UnsupportedPolicy",
        ),
        (
            serde_json::json!({
                "type": TYPE, "skey": "main",
                "policy": { "$type": PUBLIC },
                "appAccess": { "$type": ALLOW_LIST, "allowed": ["https://app.example/client"] },
            }),
            "UnsupportedAppAccess",
        ),
        (
            serde_json::json!({
                "type": TYPE, "skey": "main",
                "policy": { "$type": PUBLIC },
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
            serde_json::json!({ "policy": { "$type": MANAGING_APP, "managingApp": "did:web:x" } }),
            "UnsupportedPolicy",
        ),
        (
            serde_json::json!({ "appAccess": { "$type": ALLOW_LIST, "allowed": [] } }),
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
    assert_eq!(body["policy"]["$type"], MEMBER_LIST);
    assert_eq!(body["appAccess"]["$type"], OPEN);

    // A missing required union is the lexicon layer's refusal, before any handler runs.
    let (status, body) = send(
        &state,
        post(
            "createSpace",
            &alice,
            serde_json::json!({ "type": TYPE, "skey": "other", "policy": { "$type": PUBLIC } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest", "{body}");
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
            serde_json::json!({ "space": SPACE, "policy": { "$type": PUBLIC } }),
        ),
        post(
            "addMember",
            &create_only,
            serde_json::json!({ "space": SPACE, "did": BOB }),
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
            serde_json::json!({ "space": SPACE, "policy": { "$type": PUBLIC } }),
        ),
        post(
            "addMember",
            &bob,
            serde_json::json!({ "space": SPACE, "did": BOB }),
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
/// anywhere presents the DPoP-bound credential the authority issued, with a per-request proof.
#[tokio::test]
async fn get_space_accepts_a_dpop_bound_space_credential() {
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

    let key = DpopProofKey::generate();
    let space = parse_space_ref(&carol_space).unwrap();
    let credential = mint_space_credential(
        |b| signer.sign(b),
        CAROL,
        &space,
        &key.thumbprint(),
        unix_now().unwrap(),
    );
    // The proof's `htu` is the request URL without its query (RFC 9449 §4.2).
    let path = "/xrpc/com.atproto.simplespace.getSpace";
    let query = format!("{path}?space={carol_space}");
    let request = |credential: &str| {
        Request::builder()
            .method(http::Method::GET)
            .uri(&query)
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
    };
    let (status, body) = send(&state, request(&credential)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["uri"], carol_space);
    assert_eq!(body["policy"]["$type"], MEMBER_LIST);

    // A credential for some other space is refused, and one presented as Bearer is too.
    let other = mint_space_credential(
        |b| signer.sign(b),
        CAROL,
        &parse_space_ref(&format!("at://{CAROL}/space/{TYPE}/other")).unwrap(),
        &key.thumbprint(),
        unix_now().unwrap(),
    );
    let (status, _) = send(&state, request(&other)).await;
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
    let list_path = "/xrpc/com.atproto.simplespace.listMembers";
    let (status, _) = send(
        &state,
        Request::builder()
            .method(http::Method::GET)
            .uri(format!("{list_path}?space={carol_space}"))
            .header("Authorization", format!("DPoP {credential}"))
            .header(
                "DPoP",
                key.proof(
                    "GET",
                    &format!("https://test.example.com{list_path}"),
                    &credential,
                ),
            )
            .body(Body::empty())
            .unwrap(),
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
                "addMember",
                &alice,
                serde_json::json!({ "space": SPACE, "did": did }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    // Adding twice is idempotent.
    let (status, _) = send(
        &state,
        post(
            "addMember",
            &alice,
            serde_json::json!({ "space": SPACE, "did": "did:plc:m1" }),
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
        serde_json::json!([{ "did": "did:plc:m1" }, { "did": "did:plc:m2" }])
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
        serde_json::json!([{ "did": "did:plc:m3" }])
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
