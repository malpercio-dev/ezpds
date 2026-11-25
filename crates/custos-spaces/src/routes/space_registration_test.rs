// pattern: Imperative Shell
//
// Notification registration through `authorizeSpaceSync`, end to end: the syncer's endpoint is
// a wiremock (on `localhost`, since a registration refuses IP-literal hosts), and the write that
// reaches it goes through the real commit path. Driven through the real router, so the lexicon
// layer validates the `notify` input.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use custos_core::CoreState;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::auth::space::unix_now;
use crate::db::space_notify::{
    put_registration, registrations_for_space, PutRegistration, Registration,
};
use crate::space_notify::MAX_REGISTRATIONS;
use crate::space_record_write::{apply_space_writes, SpaceWriteAction, SpaceWriteOp};
use crate::test_support::{
    memberspace_policy, seed_account_with_repo, seed_authority_space, send, state_with_master_key,
};
use custos_core::space_uri::parse_space_ref;

const AUTHORITY: &str = "did:plc:authorityregistrationaaa";
const SPACE: &str = "at://did:plc:authorityregistrationaaa/space/org.example.bucket/main";
const CONFIRM: &str = "/xrpc/com.atproto.space.confirmRegistration";
const UPDATE: &str = "/xrpc/com.atproto.space.notifySpaceUpdate";

/// An authority with a space of its own; `public` opens it to anyone, so no delegation token is
/// needed to authorize.
async fn setup(public: bool) -> CoreState {
    let state = state_with_master_key().await;
    seed_account_with_repo(&state.db, AUTHORITY).await;
    seed_authority_space(&state.db, SPACE, &memberspace_policy(public)).await;
    state
}

/// A syncer that confirms every registration and accepts every notice.
async fn syncer() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(CONFIRM))
        .respond_with(|request: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "challenge": body["challenge"] }))
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(UPDATE))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;
    server
}

/// The server's base URL on a domain host, as a registration requires.
fn endpoint(server: &MockServer) -> String {
    server.uri().replace("127.0.0.1", "localhost")
}

fn authorize(endpoint: &str, token: &str) -> Request<Body> {
    let key = crypto::generate_p256_keypair().unwrap().key_id.0;
    let body = serde_json::json!({
        "space": SPACE,
        "credentialKey": key,
        "notify": { "endpoint": endpoint, "token": token },
    });
    Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.space.authorizeSpaceSync")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn calls(server: &MockServer, to: &str) -> Vec<wiremock::Request> {
    let requests = server.received_requests().await.unwrap_or_default();
    requests
        .into_iter()
        .filter(|r| r.url.path() == to)
        .collect()
}

async fn rows(state: &CoreState) -> Vec<Registration> {
    registrations_for_space(&state.db, SPACE, false, 1000)
        .await
        .unwrap()
}

fn credential_exp(credential: &str) -> i64 {
    let payload = credential.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    claims["exp"].as_i64().unwrap()
}

async fn write(state: &CoreState, rkey: &str) {
    apply_space_writes(
        state,
        &parse_space_ref(SPACE).unwrap(),
        AUTHORITY,
        &[SpaceWriteOp {
            action: SpaceWriteAction::Put,
            collection: "org.example.note".to_string(),
            rkey: rkey.to_string(),
            value: Some(serde_json::json!({ "text": rkey })),
        }],
    )
    .await
    .unwrap();
}

/// The whole journey. A syncer registers and is confirmed once; renewing doesn't confirm again.
/// The registration expires exactly at the credential's `exp`. A write then reaches the syncer
/// as a `repoWrite`, authenticated by the token in the body alone.
#[tokio::test]
async fn a_syncer_registers_confirms_and_hears_a_write() {
    let state = setup(true).await;
    let server = syncer().await;
    let endpoint = endpoint(&server);

    let (status, body) = send(&state, authorize(&endpoint, "sync-token")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(calls(&server, CONFIRM).await.len(), 1);
    let confirm: serde_json::Value =
        serde_json::from_slice(&calls(&server, CONFIRM).await[0].body).unwrap();
    assert_eq!(confirm["space"], SPACE);
    assert_eq!(confirm["token"], "sync-token");

    let exp = credential_exp(body["credential"].as_str().unwrap());
    let at_exp: bool = sqlx::query_scalar(
        "SELECT expires_at = datetime(?, 'unixepoch') FROM space_notify_registrations",
    )
    .bind(exp)
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert!(at_exp, "the registration lapses with the credential");

    let (status, body) = send(&state, authorize(&endpoint, "sync-token")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        calls(&server, CONFIRM).await.len(),
        1,
        "a renewal is not confirmed again"
    );
    assert_eq!(rows(&state).await.len(), 1);

    write(&state, "one").await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let notice = loop {
        if let Some(notice) = calls(&server, UPDATE).await.pop() {
            break notice;
        }
        assert!(tokio::time::Instant::now() < deadline, "no notice arrived");
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let body: serde_json::Value = serde_json::from_slice(&notice.body).unwrap();
    assert_eq!(body["space"], SPACE);
    assert_eq!(body["token"], "sync-token");
    assert_eq!(body["update"]["$type"], "com.atproto.space.defs#repoWrite");
    assert_eq!(body["update"]["repo"], AUTHORITY);
    assert!(notice.headers.get("authorization").is_none());

    // Once the credential's `exp` passes, the registration is no longer active.
    sqlx::query("UPDATE space_notify_registrations SET expires_at = datetime(?, 'unixepoch')")
        .bind(unix_now().unwrap() as i64 - 1)
        .execute(&state.db)
        .await
        .unwrap();
    assert!(registrations_for_space(&state.db, SPACE, true, 10)
        .await
        .unwrap()
        .is_empty());
}

/// The endpoint is checked before anything is sent to it: an IP-literal host is refused even
/// when it is the live syncer, and nothing is registered.
#[tokio::test]
async fn an_ip_literal_endpoint_is_refused_before_any_request() {
    let state = setup(true).await;
    let server = syncer().await;

    for bad in [server.uri(), "ftp://localhost".to_string()] {
        let (status, body) = send(&state, authorize(&bad, "t")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
        assert_eq!(body["error"], "InvalidRequest", "{bad}");
    }
    assert!(server
        .received_requests()
        .await
        .unwrap_or_default()
        .is_empty());
    assert!(rows(&state).await.is_empty());
}

/// An endpoint that doesn't echo the challenge is `RegistrationNotConfirmed`, and no credential
/// or registration comes of it.
#[tokio::test]
async fn an_unconfirmed_registration_is_refused() {
    let state = setup(true).await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "challenge": "nope" })),
        )
        .mount(&server)
        .await;

    let (status, body) = send(&state, authorize(&endpoint(&server), "t")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "RegistrationNotConfirmed");
    assert!(rows(&state).await.is_empty());
}

/// A space holds at most 100 active registrations. A new one past that is refused before the
/// endpoint is called; one already held still renews.
#[tokio::test]
async fn the_cap_refuses_a_new_registration_but_not_a_renewal() {
    let state = setup(true).await;
    let server = syncer().await;
    let endpoint = endpoint(&server);
    let exp = unix_now().unwrap() + 600;
    for i in 0..MAX_REGISTRATIONS {
        hold(&state, &endpoint, &format!("held-{i}"), exp).await;
    }

    let (status, body) = send(&state, authorize(&endpoint, "new")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "TooManyRegistrations");
    assert!(calls(&server, CONFIRM).await.is_empty());

    let (status, body) = send(&state, authorize(&endpoint, "held-0")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The cap holds under concurrency. At one below it, several new registrations all pass the
/// pre-check while their confirmations are in flight, and exactly one is written.
#[tokio::test]
async fn concurrent_registrations_at_the_last_slot_admit_exactly_one() {
    let state = setup(true).await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(CONFIRM))
        .respond_with(|request: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "challenge": body["challenge"] }))
                .set_delay(Duration::from_millis(200))
        })
        .mount(&server)
        .await;
    let endpoint = endpoint(&server);
    let exp = unix_now().unwrap() + 600;
    for i in 0..MAX_REGISTRATIONS - 1 {
        hold(&state, &endpoint, &format!("held-{i}"), exp).await;
    }

    let attempts = (0..8).map(|i| send(&state, authorize(&endpoint, &format!("racer-{i}"))));
    let outcomes = futures_util::future::join_all(attempts).await;

    assert!(
        calls(&server, CONFIRM).await.len() > 1,
        "the race was run: more than one request reached the confirmation"
    );
    let admitted = outcomes
        .iter()
        .filter(|(status, _)| *status == StatusCode::OK)
        .count();
    assert_eq!(admitted, 1, "{outcomes:?}");
    for (status, body) in outcomes.iter().filter(|(s, _)| *s != StatusCode::OK) {
        assert_eq!(*status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "TooManyRegistrations", "{body}");
    }
    let active = crate::db::space_notify::count_active_registrations(&state.db, SPACE)
        .await
        .unwrap();
    assert_eq!(active, MAX_REGISTRATIONS);
}

/// Lapsed rows don't pile up. A new registration first prunes those that lapsed more than 72 h
/// ago without their expiry notice being claimed. A more recent lapse is still owed that notice,
/// and a claimed one is removed with its notice, so both stay.
#[tokio::test]
async fn a_registration_prunes_long_lapsed_rows() {
    let state = setup(true).await;
    let server = syncer().await;
    let endpoint = endpoint(&server);
    let now = unix_now().unwrap();
    let long_ago = now - 73 * 60 * 60;
    hold(&state, &endpoint, "stale", long_ago).await;
    hold(&state, &endpoint, "stale-claimed", long_ago).await;
    hold(&state, &endpoint, "recent", now - 60 * 60).await;
    sqlx::query("UPDATE space_notify_registrations SET expiry_notified = 1 WHERE token = ?")
        .bind("stale-claimed")
        .execute(&state.db)
        .await
        .unwrap();

    let (status, body) = send(&state, authorize(&endpoint, "new")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let mut tokens: Vec<String> = rows(&state).await.into_iter().map(|r| r.token).collect();
    tokens.sort();
    assert_eq!(tokens, ["new", "recent", "stale-claimed"]);
}

/// Hold `(endpoint, token)` until `exp`, as a past authorization would have.
async fn hold(state: &CoreState, endpoint: &str, token: &str, exp: u64) {
    let registration = Registration {
        endpoint: endpoint.to_string(),
        token: token.to_string(),
    };
    let written = put_registration(&state.db, SPACE, &registration, exp, MAX_REGISTRATIONS)
        .await
        .unwrap();
    assert_eq!(written, PutRegistration::Written);
}

/// A refused authorization withdraws the registration it carries, so a syncer that has lost
/// access stops being notified.
#[tokio::test]
async fn a_refusal_withdraws_the_registration() {
    let state = setup(false).await;
    let server = syncer().await;
    let endpoint = endpoint(&server);
    hold(&state, &endpoint, "t", unix_now().unwrap() + 600).await;

    // No delegation token, and the space isn't public.
    let (status, body) = send(&state, authorize(&endpoint, "t")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "AccountNotAuthorized");
    assert!(rows(&state).await.is_empty());
}

/// Waits for the `n`th `notifySpaceUpdate` to reach the syncer and returns its body.
async fn nth_update(server: &MockServer, n: usize) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(notice) = calls(server, UPDATE).await.get(n - 1) {
            return serde_json::from_slice(&notice.body).unwrap();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no notice {n} arrived"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A write the space's write policy refuses commits to the writer's own repo, but is neither
/// recorded in the writer set nor sent to the syncer.
#[tokio::test]
async fn a_refused_write_is_not_fanned_out() {
    const OUTSIDER: &str = "did:plc:outsiderregistrationaaa";
    let state = state_with_master_key().await;
    seed_account_with_repo(&state.db, AUTHORITY).await;
    seed_account_with_repo(&state.db, OUTSIDER).await;
    let read_only = serde_json::json!({
        "$type": crate::policy::MEMBERSPACE,
        "publicRead": true,
        "publicWrite": false,
        "publishPolicy": false,
        "publishMembers": false,
    });
    seed_authority_space(&state.db, SPACE, &read_only.to_string()).await;
    let server = syncer().await;
    let (status, body) = send(&state, authorize(&endpoint(&server), "sync-token")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    apply_space_writes(
        &state,
        &parse_space_ref(SPACE).unwrap(),
        OUTSIDER,
        &[SpaceWriteOp {
            action: SpaceWriteAction::Put,
            collection: "org.example.note".to_string(),
            rkey: "mine".to_string(),
            value: Some(serde_json::json!({ "text": "mine" })),
        }],
    )
    .await
    .expect("the write itself commits");
    write(&state, "one").await;

    let first = nth_update(&server, 1).await;
    assert_eq!(first["update"]["repo"], AUTHORITY);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        calls(&server, UPDATE).await.len(),
        1,
        "the refused write was sent"
    );
    let writers = crate::db::space_notify::list_writers(&state.db, SPACE, None, 10)
        .await
        .unwrap();
    assert_eq!(
        writers
            .iter()
            .map(|w| w.repo_did.as_str())
            .collect::<Vec<_>>(),
        vec![AUTHORITY]
    );
}

/// A writer's removal reaches the syncer as a `repoRemoved`, sequenced after the write before it,
/// on the same one-attempt fan-out a write takes.
#[tokio::test]
async fn a_removal_reaches_the_syncer_as_repo_removed() {
    let state = setup(true).await;
    let server = syncer().await;
    let (status, body) = send(&state, authorize(&endpoint(&server), "sync-token")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    write(&state, "one").await;
    let wrote = nth_update(&server, 1).await;
    assert_eq!(wrote["update"]["$type"], "com.atproto.space.defs#repoWrite");

    let token = crate::test_support::access_jwt(&state.jwt_secret, AUTHORITY);
    let (status, body) = send(
        &state,
        crate::test_support::xrpc_post(
            "com.atproto.space.removeWriter",
            &token,
            serde_json::json!({ "space": SPACE, "repo": AUTHORITY }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let removed = nth_update(&server, 2).await;
    assert_eq!(removed["token"], "sync-token");
    assert_eq!(
        removed["update"],
        serde_json::json!({
            "$type": "com.atproto.space.defs#repoRemoved",
            "repo": AUTHORITY,
            "spaceRev": removed["update"]["spaceRev"],
            "prevSpaceRev": wrote["update"]["spaceRev"],
        })
    );
    assert!(removed["update"]["spaceRev"].as_str() > wrote["update"]["spaceRev"].as_str());
}
