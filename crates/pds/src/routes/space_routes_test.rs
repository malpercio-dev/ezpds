// pattern: Imperative Shell
//
// End-to-end coverage of the `com.atproto.space.*` record surface, driven through the real
// router so the lexicon layer, the auth seam and the write choke point are all in the path.
//
// Routes may not import one another, so the cross-route journeys — write here, read it back
// there — live in this one test-only module rather than being split across eight files. Each
// route keeps only what is genuinely local to it.
//
// COVERAGE BOUNDARY. The `space:` grants exercised here all name their own `collection`, so the
// scope matcher decides them without resolving anything. The *other* branch — a bare grant
// falling back to the space type declaration's `collections` — is a live DNS-and-HTTP lookup and
// is covered where that resolver already is, in `auth/space_consent.rs`'s tests; what is proved
// here is that the routes reach the gate at all, and fail closed when it says no.

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use tower::ServiceExt;

use crate::app::AppState;
use crate::routes::test_utils::{
    access_jwt, app_pass_jwt, body_json, scoped_access_jwt, seed_account_with_repo,
    state_with_master_key,
};

const DID: &str = "did:plc:spaceroutesaaaaaaaaaaaaa";
const SPACE: &str = "at://did:plc:authorityaaaaaaaaaaaaaaa/space/org.example.bucket/main";
const COLLECTION: &str = "org.example.note";

/// A grant covering exactly this space and collection, for every record verb plus `read_self`.
/// Carries the mandatory `atproto` base token, as every real OAuth scope string does.
const GRANT: &str =
    "atproto space:org.example.bucket?authority=did:plc:authorityaaaaaaaaaaaaaaa&skey=main\
&collection=org.example.note&action=create&action=update&action=delete&action=read_self";

async fn setup() -> AppState {
    let state = state_with_master_key().await;
    seed_account_with_repo(&state.db, DID).await;
    state
}

fn post(uri: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(http::Method::POST)
        .uri(format!("/xrpc/{uri}"))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(http::Method::GET)
        .uri(format!("/xrpc/{uri}"))
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn create_body(rkey: &str, text: &str) -> serde_json::Value {
    serde_json::json!({
        "space": SPACE,
        "repo": DID,
        "collection": COLLECTION,
        "rkey": rkey,
        "record": {"text": text},
    })
}

/// The journey a client actually takes: create a record, read it back, see it in the listing,
/// and see the space itself appear in `listSpaces` — which reports spaces *written to*, so it is
/// the write that puts it there.
#[tokio::test]
async fn create_read_and_list_round_trip() {
    let state = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    let response = crate::app::app(state.clone())
        .oneshot(post(
            "com.atproto.space.createRecord",
            &token,
            create_body("aaa", "hello"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let created = body_json(response).await;
    assert_eq!(
        created["uri"],
        format!("{SPACE}/{DID}/{COLLECTION}/aaa"),
        "a space record's uri is the space ref, then author, collection and rkey"
    );
    let cid = created["cid"].as_str().unwrap().to_string();

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!(
                "com.atproto.space.getRecord?space={SPACE}&repo={DID}&collection={COLLECTION}&rkey=aaa"
            ),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let fetched = body_json(response).await;
    assert_eq!(fetched["cid"], cid);
    assert_eq!(fetched["value"]["text"], "hello");

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.listRecords?space={SPACE}&repo={DID}"),
            &token,
        ))
        .await
        .unwrap();
    let listed = body_json(response).await;
    assert_eq!(listed["records"].as_array().unwrap().len(), 1);
    assert_eq!(listed["records"][0]["rkey"], "aaa");
    assert_eq!(
        listed["records"][0]["value"]["text"], "hello",
        "values are inlined unless excludeValues asks otherwise"
    );

    let response = crate::app::app(state)
        .oneshot(get("com.atproto.space.listSpaces", &token))
        .await
        .unwrap();
    let spaces = body_json(response).await;
    assert_eq!(spaces["spaces"][0]["uri"], SPACE);
}

/// `excludeValues` drops the record bodies but keeps the metadata a healing syncer diffs on, and
/// paging walks `(collection, rkey)` order with a cursor that survives the round trip.
#[tokio::test]
async fn list_records_pages_and_can_omit_values() {
    let state = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);
    for rkey in ["aaa", "bbb", "ccc"] {
        let response = crate::app::app(state.clone())
            .oneshot(post(
                "com.atproto.space.createRecord",
                &token,
                create_body(rkey, rkey),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let page = body_json(
        crate::app::app(state.clone())
            .oneshot(get(
                &format!(
                    "com.atproto.space.listRecords?space={SPACE}&repo={DID}&limit=2&excludeValues=true"
                ),
                &token,
            ))
            .await
            .unwrap(),
    )
    .await;
    // Default order is descending by rkey, so the newest key leads.
    assert_eq!(page["records"][0]["rkey"], "ccc");
    assert_eq!(page["records"][1]["rkey"], "bbb");
    assert!(
        page["records"][0].get("value").is_none(),
        "excludeValues must omit the body, not send a null one"
    );
    assert!(page["records"][0]["cid"].is_string());

    let cursor = page["cursor"]
        .as_str()
        .expect("a full page carries a cursor");
    let rest = body_json(
        crate::app::app(state)
            .oneshot(get(
                &format!(
                    "com.atproto.space.listRecords?space={SPACE}&repo={DID}&limit=2&cursor={cursor}"
                ),
                &token,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(rest["records"].as_array().unwrap().len(), 1);
    assert_eq!(rest["records"][0]["rkey"], "aaa");
    assert!(
        rest.get("cursor").is_none(),
        "a short page is the last one and ends the walk"
    );
}

/// `getLatestCommit` mints a commit rather than serving a stored one: two calls over an
/// unchanged repo return different `ikm`/`sig`/`mac` and the same `hash`, and each one verifies
/// against the account's published signing key.
#[tokio::test]
async fn get_latest_commit_mints_a_fresh_deniable_commit_each_time() {
    let state = state_with_master_key().await;
    let keypair = seed_account_with_repo(&state.db, DID).await;
    let token = access_jwt(&state.jwt_secret, DID);

    crate::app::app(state.clone())
        .oneshot(post(
            "com.atproto.space.createRecord",
            &token,
            create_body("aaa", "hello"),
        ))
        .await
        .unwrap();

    let fetch = || {
        let state = state.clone();
        let token = token.clone();
        async move {
            let response = crate::app::app(state)
                .oneshot(get(
                    &format!("com.atproto.space.getLatestCommit?space={SPACE}&repo={DID}"),
                    &token,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            body_json(response).await["commit"].clone()
        }
    };
    let first = fetch().await;
    let second = fetch().await;

    assert_eq!(first["ver"], 1);
    assert_eq!(first["rev"], second["rev"], "the repo did not move");
    assert_eq!(first["hash"], second["hash"], "nor did its contents");
    assert_ne!(
        first["ikm"], second["ikm"],
        "a fresh ikm per serving is what makes the commit deniable"
    );
    assert_ne!(first["sig"], second["sig"]);
    assert_ne!(first["mac"], second["mac"]);

    // Each minted commit must actually verify — signature over the ctx, MAC over the hash.
    let commit = crypto::SignedSpaceCommit {
        ver: first["ver"].as_u64().unwrap() as u8,
        hash: lex_bytes(&first["hash"]),
        ikm: lex_bytes(&first["ikm"]),
        sig: lex_bytes64(&first["sig"]),
        mac: lex_bytes(&first["mac"]),
        rev: first["rev"].as_str().unwrap().to_string(),
    };
    crypto::verify_space_commit(
        &commit,
        &crypto::SpaceCommitCtx {
            space: SPACE,
            author: DID,
            rev: first["rev"].as_str().unwrap(),
        },
        &keypair.key_id,
    )
    .expect("a served commit must verify against the account's signing key");
}

fn decode_lex_bytes(value: &serde_json::Value) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value["$bytes"].as_str().expect("lex-JSON byte string"))
        .expect("valid base64")
}

fn lex_bytes(value: &serde_json::Value) -> [u8; 32] {
    decode_lex_bytes(value).try_into().expect("32 bytes")
}

fn lex_bytes64(value: &serde_json::Value) -> [u8; 64] {
    decode_lex_bytes(value).try_into().expect("64 bytes")
}

/// A batch commits or it does not: an `#update` naming a record that does not exist fails the
/// whole request with `RecordNotFound`, and the sibling create in the same batch does not land.
#[tokio::test]
async fn apply_writes_is_atomic_and_enforces_per_op_preconditions() {
    let state = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);

    let response = crate::app::app(state.clone())
        .oneshot(post(
            "com.atproto.space.applyWrites",
            &token,
            serde_json::json!({
                "space": SPACE,
                "repo": DID,
                "writes": [
                    {"$type": "com.atproto.space.applyWrites#create",
                     "collection": COLLECTION, "rkey": "landed", "value": {"text": "one"}},
                    {"$type": "com.atproto.space.applyWrites#update",
                     "collection": COLLECTION, "rkey": "missing", "value": {"text": "two"}},
                ],
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "RecordNotFound");

    let listed = body_json(
        crate::app::app(state.clone())
            .oneshot(get(
                &format!("com.atproto.space.listRecords?space={SPACE}&repo={DID}"),
                &token,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        listed["error"], "RepoNotFound",
        "the failed batch created no repo at all"
    );

    // The same batch without the impossible op lands whole, reporting one result per write in
    // request order and labelling each by the verb that was asked for.
    let response = crate::app::app(state.clone())
        .oneshot(post(
            "com.atproto.space.applyWrites",
            &token,
            serde_json::json!({
                "space": SPACE,
                "repo": DID,
                "writes": [
                    {"$type": "com.atproto.space.applyWrites#create",
                     "collection": COLLECTION, "rkey": "landed", "value": {"text": "one"}},
                    {"$type": "com.atproto.space.applyWrites#create",
                     "collection": COLLECTION, "rkey": "gone", "value": {"text": "two"}},
                ],
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let results = body_json(response).await;
    assert_eq!(
        results["results"][0]["$type"],
        "com.atproto.space.applyWrites#createResult"
    );
    assert_eq!(
        results["results"][0]["uri"],
        format!("{SPACE}/{DID}/{COLLECTION}/landed")
    );

    let response = crate::app::app(state.clone())
        .oneshot(post(
            "com.atproto.space.applyWrites",
            &token,
            serde_json::json!({
                "space": SPACE,
                "repo": DID,
                "writes": [
                    {"$type": "com.atproto.space.applyWrites#update",
                     "collection": COLLECTION, "rkey": "landed", "value": {"text": "revised"}},
                    {"$type": "com.atproto.space.applyWrites#delete",
                     "collection": COLLECTION, "rkey": "gone"},
                ],
            }),
        ))
        .await
        .unwrap();
    let results = body_json(response).await;
    assert_eq!(
        results["results"][0]["$type"],
        "com.atproto.space.applyWrites#updateResult"
    );
    assert_eq!(
        results["results"][1]["$type"],
        "com.atproto.space.applyWrites#deleteResult"
    );
}

/// `deleteRecord` succeeds whether or not the record was there, as its lexicon promises — and
/// the absent case burns no revision, because nothing is committed for a write that changed
/// nothing.
#[tokio::test]
async fn delete_record_is_idempotent_without_burning_a_revision() {
    let state = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);
    crate::app::app(state.clone())
        .oneshot(post(
            "com.atproto.space.createRecord",
            &token,
            create_body("aaa", "hello"),
        ))
        .await
        .unwrap();
    let rev_before = crate::db::space_repos::get_repo(&state.db, SPACE, DID)
        .await
        .unwrap()
        .unwrap()
        .rev;

    let delete = || {
        post(
            "com.atproto.space.deleteRecord",
            &token,
            serde_json::json!({
                "space": SPACE, "repo": DID, "collection": COLLECTION, "rkey": "aaa",
            }),
        )
    };
    assert_eq!(
        crate::app::app(state.clone())
            .oneshot(delete())
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let rev_after_delete = crate::db::space_repos::get_repo(&state.db, SPACE, DID)
        .await
        .unwrap()
        .unwrap()
        .rev;
    assert!(rev_after_delete > rev_before, "the real delete committed");

    assert_eq!(
        crate::app::app(state.clone())
            .oneshot(delete())
            .await
            .unwrap()
            .status(),
        StatusCode::OK,
        "deleting an absent record still succeeds"
    );
    assert_eq!(
        crate::db::space_repos::get_repo(&state.db, SPACE, DID)
            .await
            .unwrap()
            .unwrap()
            .rev,
        rev_after_delete,
        "but commits nothing"
    );
}

/// Every space route refuses an unauthenticated caller.
#[tokio::test]
async fn unauthenticated_callers_are_refused_everywhere() {
    let state = setup().await;
    for request in [
        Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.space.createRecord")
            .header("Content-Type", "application/json")
            .body(Body::from(create_body("aaa", "x").to_string()))
            .unwrap(),
        Request::builder()
            .method(http::Method::GET)
            .uri(format!(
                "/xrpc/com.atproto.space.getRecord?space={SPACE}&repo={DID}&collection={COLLECTION}&rkey=aaa"
            ))
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method(http::Method::GET)
            .uri("/xrpc/com.atproto.space.listSpaces")
            .body(Body::empty())
            .unwrap(),
    ] {
        let response = crate::app::app(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

/// A caller naming someone else's repo is told the same thing an absent repo says. Writes, which
/// disclose nothing by refusing, say so plainly instead.
#[tokio::test]
async fn another_accounts_repo_is_not_found_on_reads_and_forbidden_on_writes() {
    let state = setup().await;
    let other = "did:plc:someoneelseaaaaaaaaaaaaa";
    seed_account_with_repo(&state.db, other).await;
    let token = access_jwt(&state.jwt_secret, other);

    let response = crate::app::app(state.clone())
        .oneshot(get(
            &format!("com.atproto.space.getLatestCommit?space={SPACE}&repo={DID}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(response).await["error"],
        "RepoNotFound",
        "whether another account holds a repo here is not the caller's to learn"
    );

    let response = crate::app::app(state)
        .oneshot(post(
            "com.atproto.space.createRecord",
            &token,
            create_body("aaa", "x"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// The `space:` scope gate: a granular OAuth grant covering this space passes, one covering a
/// different collection does not, and no space grant at all does not.
#[tokio::test]
async fn granular_oauth_grants_are_matched_against_the_operation() {
    let state = setup().await;

    let granted = scoped_access_jwt(&state.jwt_secret, DID, GRANT);
    assert_eq!(
        crate::app::app(state.clone())
            .oneshot(post(
                "com.atproto.space.createRecord",
                &granted,
                create_body("aaa", "x")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        crate::app::app(state.clone())
            .oneshot(get(
                &format!("com.atproto.space.listRecords?space={SPACE}&repo={DID}"),
                &granted
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK,
        "the same grant's read_self action covers reading the holder's own repo"
    );

    for scope in [
        // Right space, wrong collection.
        "atproto space:org.example.bucket?authority=did:plc:authorityaaaaaaaaaaaaaaa&skey=main&collection=org.example.other&action=create",
        // A repo grant is not a space grant.
        "atproto repo:org.example.note",
        // `transition:generic` is app-password-equivalent and predates spaces entirely.
        "atproto transition:generic",
    ] {
        let token = scoped_access_jwt(&state.jwt_secret, DID, scope);
        let response = crate::app::app(state.clone())
            .oneshot(post(
                "com.atproto.space.createRecord",
                &token,
                create_body("bbb", "x"),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "scope must not admit this write: {scope}"
        );
        assert_eq!(body_json(response).await["error"], "InsufficientScope");
    }
}

/// An app-password session carries no space grants to evaluate, so it is bounded by the repo
/// ownership check alone — the same latitude the reference gives legacy credentials, and the
/// same one this PDS already gives them on public repo writes.
#[tokio::test]
async fn app_password_sessions_are_bounded_by_repo_ownership() {
    let state = setup().await;
    let token = app_pass_jwt(&state.jwt_secret, DID, false);
    assert_eq!(
        crate::app::app(state.clone())
            .oneshot(post(
                "com.atproto.space.createRecord",
                &token,
                create_body("aaa", "x")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

/// A space record may reference another space record. The write-time record-format gate asserts
/// every `at://` string in a record parses, and a space AT-URI is not the public form — so
/// without both families admitted, the two protocols could not refer to each other at all.
#[tokio::test]
async fn a_record_may_reference_another_space_record() {
    let state = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);
    let mut body = create_body("aaa", "x");
    body["record"] = serde_json::json!({
        "text": "see also",
        "subject": format!("{SPACE}/{DID}/{COLLECTION}/other"),
        "space": SPACE,
    });
    let response = crate::app::app(state)
        .oneshot(post("com.atproto.space.createRecord", &token, body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// A malformed `space` never reaches a handler: the lexicon's `space-ref` format rejects it, so
/// no store row can be keyed on a URI that was never checked.
#[tokio::test]
async fn a_malformed_space_ref_is_rejected_by_the_lexicon_layer() {
    let state = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);
    for space in [
        // A record within a space, not the space itself.
        "at://did:plc:authorityaaaaaaaaaaaaaaa/space/org.example.bucket/main/did:plc:memberaaaaaaaaaaaaaaaaaa/org.example.note/a",
        // A public repo URI.
        "at://did:plc:authorityaaaaaaaaaaaaaaa/org.example.note/aaa",
        // Authority must be a DID.
        "at://authority.example.com/space/org.example.bucket/main",
    ] {
        let mut body = create_body("aaa", "x");
        body["space"] = serde_json::Value::String(space.to_string());
        let response = crate::app::app(state.clone())
            .oneshot(post("com.atproto.space.createRecord", &token, body))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "should reject space: {space}"
        );
    }
}
