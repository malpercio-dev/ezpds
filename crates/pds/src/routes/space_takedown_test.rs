// pattern: Imperative Shell
//
// End-to-end coverage of the per-space operator takedown (V070), driven through the real router
// so the admin surface (`/v1/admin/spaces*`), the space auth seam, the write choke point and the
// member-facing listing are all in one path. Cross-route by nature — an operator action here is
// only meaningful by what a *member's* call answers afterwards — so it lives in this one
// test-only module rather than being split across the routes it spans.
//
// The fixture is deliberately a space whose authority is NOT a local account: that is the case
// account takedown cannot reach and `deleteSpace` is not this host's to call, and it is the
// reason the surface exists.

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use tower::ServiceExt;

use crate::app::{app, AppState};
use crate::routes::test_utils::{
    access_jwt, body_json, scoped_access_jwt, seed_account_with_repo, state_with_master_key,
};

const ADMIN: &str = "test-admin-token";
const DID: &str = "did:plc:spacetakedownaaaaaaaaaaa";
/// A space governed elsewhere: this host only stores `DID`'s repo in it.
const SPACE: &str = "at://did:plc:foreignauthorityaaaaaaaa/space/org.example.bucket/main";
const COLLECTION: &str = "org.example.note";

const GRANT: &str = "atproto space:org.example.bucket?authority=did:plc:foreignauthorityaaaaaaaa\
&skey=main&collection=org.example.note&action=create&action=update&action=delete\
&action=read_self";

/// A state with both the signing-key master key (space commits are signed) and an admin token.
async fn setup() -> AppState {
    let base = state_with_master_key().await;
    let mut config = (*base.config).clone();
    config.admin_token = Some(common::Sensitive(ADMIN.to_string()));
    let state = AppState {
        config: std::sync::Arc::new(config),
        ..base
    };
    seed_account_with_repo(&state.db, DID).await;
    state
}

fn post(path: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(http::Method::POST)
        .uri(path)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(http::Method::GET)
        .uri(path)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn send(state: &AppState, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = app(state.clone()).oneshot(request).await.unwrap();
    (response.status(), body_json(response).await)
}

fn create_record(token: &str, rkey: &str) -> Request<Body> {
    post(
        "/xrpc/com.atproto.space.createRecord",
        token,
        serde_json::json!({
            "space": SPACE, "repo": DID, "collection": COLLECTION,
            "rkey": rkey, "record": {"text": "x"},
        }),
    )
}

/// Apply or clear the takedown through the real admin route, as an operator would.
async fn takedown(state: &AppState, uri: &str, applied: bool) -> (StatusCode, serde_json::Value) {
    send(
        state,
        post(
            "/v1/admin/spaces/takedown",
            ADMIN,
            serde_json::json!({ "uri": uri, "applied": applied }),
        ),
    )
    .await
}

/// The core promise: while taken down, every seam that serves the space refuses — and clearing
/// it puts the space back exactly as it was, records included. A record write, a repo read, and
/// the member's own `listSpaces` stand for the rest: each enters through a different gate (the
/// write choke point's in-transaction read, the read seam, and the listing query), and there is
/// no fourth kind.
#[tokio::test]
async fn takedown_closes_the_space_and_restore_reopens_it() {
    let state = setup().await;
    let token = scoped_access_jwt(&state.jwt_secret, DID, GRANT);

    // Baseline: the write records the foreign-authority space on first use, which is the only
    // way this host ever learns of it.
    let (status, body) = send(&state, create_record(&token, "a")).await;
    assert_eq!(status, StatusCode::OK, "precondition: {body}");

    let (status, body) = takedown(&state, SPACE, true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["applied"], true);
    assert!(body["takendownAt"].is_string(), "{body}");

    let (status, body) = send(&state, create_record(&token, "b")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "write must be refused");
    assert_eq!(body["error"], "SpaceNotFound", "{body}");

    let (status, body) = send(
        &state,
        get(
            &format!(
                "/xrpc/com.atproto.space.listRecords?space={SPACE}&repo={DID}\
                 &collection={COLLECTION}"
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "read must be refused");
    // `SpaceNotFound`, never `SpaceDeleted`: the latter is the spec's durable "drop your copy"
    // signal to syncers, and a takedown is reversible.
    assert_eq!(body["error"], "SpaceNotFound", "{body}");

    // A legacy full session: an OAuth grant narrow enough to name one space cannot satisfy an
    // unfiltered `listSpaces` anyway, and that is a scope question with its own coverage.
    let session = access_jwt(&state.jwt_secret, DID);
    let (_, body) = send(&state, get("/xrpc/com.atproto.space.listSpaces", &session)).await;
    assert_eq!(
        body["spaces"].as_array().map(Vec::len),
        Some(0),
        "a taken-down space must not be listed as one the member can open: {body}"
    );

    // Nothing was destroyed while it was down — the restore is what proves it.
    let (status, _) = takedown(&state, SPACE, false).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(
        &state,
        get(
            &format!(
                "/xrpc/com.atproto.space.listRecords?space={SPACE}&repo={DID}\
                 &collection={COLLECTION}"
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["records"].as_array().map(Vec::len),
        Some(1),
        "the record written before the takedown must still be served: {body}"
    );
    let (status, _) = send(&state, create_record(&token, "c")).await;
    assert_eq!(status, StatusCode::OK, "writes must resume");
}

/// A takedown is a refusal to serve, not a deletion: the stored rows stay put while it is
/// applied. Asserted against the store rather than the wire, because the wire is refusing.
#[tokio::test]
async fn takedown_destroys_nothing() {
    let state = setup().await;
    let token = scoped_access_jwt(&state.jwt_secret, DID, GRANT);
    let (status, _) = send(&state, create_record(&token, "a")).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = takedown(&state, SPACE, true).await;
    assert_eq!(status, StatusCode::OK);

    let records: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM space_records WHERE space_uri = ?")
        .bind(SPACE)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(records, 1, "records must survive a takedown");
    assert!(
        crate::db::space_repos::get_repo(&state.db, SPACE, DID)
            .await
            .unwrap()
            .is_some(),
        "the repo head must survive a takedown"
    );
    let row = crate::db::spaces::get_space(&state.db, SPACE)
        .await
        .unwrap()
        .unwrap();
    assert!(
        row.deleted_at.is_none(),
        "the operator's refusal must not be written as the owner's tombstone"
    );
}

/// The listing is the operator's inventory of what is actually stored, and it has to name the
/// foreign-authority spaces — the ones with no owner-side lever — as such.
#[tokio::test]
async fn listing_reports_stored_spaces_and_filters_to_the_taken_down() {
    let state = setup().await;
    let token = scoped_access_jwt(&state.jwt_secret, DID, GRANT);
    let (status, _) = send(&state, create_record(&token, "a")).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send(&state, get("/v1/admin/spaces", ADMIN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let spaces = body["spaces"].as_array().unwrap();
    assert_eq!(spaces.len(), 1, "{body}");
    assert_eq!(spaces[0]["uri"], SPACE);
    assert_eq!(
        spaces[0]["localAuthority"], false,
        "a space recorded by a member's write is governed elsewhere: {body}"
    );
    assert_eq!(spaces[0]["repoCount"], 1);
    assert_eq!(spaces[0]["recordCount"], 1);
    assert!(spaces[0].get("takendownAt").is_none(), "{body}");

    // The refusal list is empty until there is a refusal.
    let (_, body) = send(&state, get("/v1/admin/spaces?status=takendown", ADMIN)).await;
    assert_eq!(body["spaces"].as_array().map(Vec::len), Some(0), "{body}");

    takedown(&state, SPACE, true).await;
    let (_, body) = send(&state, get("/v1/admin/spaces?status=takendown", ADMIN)).await;
    let spaces = body["spaces"].as_array().unwrap();
    assert_eq!(spaces.len(), 1, "{body}");
    assert!(spaces[0]["takendownAt"].is_string(), "{body}");

    // An unknown filter is a 400, not a silently empty page.
    let (status, _) = send(&state, get("/v1/admin/spaces?status=nonsense", ADMIN)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Idempotent in both directions, and the original timestamp survives a re-apply so the audit
/// log and the listing agree on when the refusal began.
#[tokio::test]
async fn takedown_is_idempotent_and_keeps_its_original_timestamp() {
    let state = setup().await;
    let token = scoped_access_jwt(&state.jwt_secret, DID, GRANT);
    send(&state, create_record(&token, "a")).await;

    let (_, first) = takedown(&state, SPACE, true).await;
    let (status, second) = takedown(&state, SPACE, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["takendownAt"], first["takendownAt"]);

    let (status, cleared) = takedown(&state, SPACE, false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cleared["applied"], false);
    assert!(cleared.get("takendownAt").is_none(), "{cleared}");
    let (status, again) = takedown(&state, SPACE, false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["applied"], false);
}

/// Every operator action lands in the append-only audit log, attributed and subject-keyed to the
/// space URI, so `GET /v1/admin/audit?subject=<uri>` reads back one space's moderation history.
#[tokio::test]
async fn each_action_is_audited_against_the_space_uri() {
    let state = setup().await;
    let token = scoped_access_jwt(&state.jwt_secret, DID, GRANT);
    send(&state, create_record(&token, "a")).await;

    takedown(&state, SPACE, true).await;
    takedown(&state, SPACE, false).await;

    let (status, body) = send(
        &state,
        get(&format!("/v1/admin/audit?subject={SPACE}"), ADMIN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let events = body["events"].as_array().unwrap();
    let actions: Vec<&str> = events
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    // Newest first.
    assert_eq!(actions, ["space_restore", "space_takedown"], "{body}");
}

/// A host cannot refuse to serve a space it stores nothing for — and existence is checked after
/// auth, so an unauthenticated caller cannot use the route as a space-presence oracle.
#[tokio::test]
async fn unknown_space_is_404_and_unauthenticated_is_401() {
    let state = setup().await;

    let (status, _) = takedown(&state, SPACE, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let response = app(state.clone())
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/v1/admin/spaces/takedown")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "uri": SPACE, "applied": true }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // A URI that is not a space ref at all is a 400, not a 404.
    let (status, _) = takedown(&state, "at://did:plc:x/app.bsky.feed.post/3k", true).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The owner must not be able to undo a takedown by deleting and re-creating the same URI, so
/// `createSpace` refuses to claim a taken-down row.
#[tokio::test]
async fn a_taken_down_uri_cannot_be_re_created() {
    let state = setup().await;
    let local_space = format!("at://{DID}/space/org.example.bucket/own");
    let grant = format!(
        "atproto space:org.example.bucket?authority={DID}&skey=own\
         &manage=create&manage=delete&action=read_self"
    );
    let token = scoped_access_jwt(&state.jwt_secret, DID, &grant);
    let create = || {
        post(
            "/xrpc/com.atproto.simplespace.createSpace",
            &token,
            serde_json::json!({
                "type": "org.example.bucket",
                "skey": "own",
                "policy": { "$type": "com.atproto.simplespace.defs#publicPolicy" },
                "appAccess": { "$type": "com.atproto.simplespace.defs#open" },
            }),
        )
    };

    let (status, body) = send(&state, create()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = takedown(&state, &local_space, true).await;
    assert_eq!(status, StatusCode::OK);

    // Deleting is refused too — the space is not being served at all while it is down.
    let (status, body) = send(
        &state,
        post(
            "/xrpc/com.atproto.simplespace.deleteSpace",
            &token,
            serde_json::json!({ "space": local_space }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "SpaceNotFound", "{body}");

    // And the URI cannot be re-claimed around the refusal.
    let (status, body) = send(&state, create()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "SpaceAlreadyExists", "{body}");
}
