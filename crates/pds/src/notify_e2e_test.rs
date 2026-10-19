// pattern: Imperative Shell
//
// The loopback end-to-end test for the whole notification path:
//
//     pds route → send worker → iroh → notify-relay → APNs (wiremock) → fixture "device"
//
// Every layer here is the real one. The relay is the actual `notify-relay` crate running its
// real accept loop, store, and APNs client in-process; the transport is real QUIC over
// loopback; the seal is real HPKE. Only Apple is a stand-in, because Apple is the one party
// we cannot run.
//
// This is what the per-layer tests cannot cover: each side's unit tests prove it is
// self-consistent, and this proves the two sides agree — the envelope Custos builds is the
// envelope the relay serializes, the padding budget Custos computed is the length Apple
// actually sees, and the payload a device receives opens under the key the instance
// published. A wire drift between the crates fails here and nowhere else.

#![cfg(test)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr};
use notify_relay::protocol::ALPN;
use serde_json::json;
use tower::ServiceExt;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::app::AppState;
use crate::db::notifications as store;
use crate::routes::test_utils::insert_account_with_email;

const ACCOUNT_DID: &str = "did:plc:notifye2e";
/// A second identity on the *same* device, for the multi-identity case.
const SECOND_DID: &str = "did:plc:notifye2e2";
const DEVICE_UUID: &str = "device-e2e-1";
/// One physical device means one APNs token, whatever the identity count: the wallet
/// registers this same value for every identity it holds.
const APNS_TOKEN: &str = "deadbeef0123456789";
const MASTER_KEY: [u8; 32] = [0x5au8; 32];

/// An offline endpoint on loopback (`Minimal` preset: rustls only — no relay, no discovery),
/// so the whole test runs with no network.
async fn loopback_endpoint(accepts: bool) -> Endpoint {
    let mut builder = Endpoint::builder(presets::Minimal)
        .bind_addr("127.0.0.1:0")
        .expect("valid bind addr");
    if accepts {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    builder.bind().await.expect("bind loopback endpoint")
}

/// A real `notify-relay` wired to a stand-in Apple, with open enrollment.
async fn start_relay(
    apple_uri: &str,
) -> (
    Endpoint,
    Arc<notify_relay::service::RelayService>,
    tempfile::TempDir,
) {
    use notify_relay::config::load_from_env_only;

    // The relay needs a real PKCS#8 P-256 key on disk to mint its APNs provider JWT. Generate
    // one rather than vendoring a fixture: the JWT is signed and sent, and wiremock accepts
    // any bearer, so the only requirement is that it is a genuine key.
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("apns.p8");
    let signing_key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
    let pem = p256::pkcs8::EncodePrivateKey::to_pkcs8_pem(
        &p256::SecretKey::from(&signing_key),
        p256::pkcs8::LineEnding::LF,
    )
    .expect("encode PKCS#8");
    std::fs::write(&key_path, pem.as_bytes()).expect("write APNs key");

    let env = std::collections::HashMap::from([
        ("EZPDS_NOTIFY_OPEN_ENROLLMENT".to_owned(), "true".to_owned()),
        (
            "EZPDS_NOTIFY_APNS_KEY_PATH".to_owned(),
            key_path.display().to_string(),
        ),
        (
            "EZPDS_NOTIFY_APNS_KEY_ID".to_owned(),
            "KEYID12345".to_owned(),
        ),
        (
            "EZPDS_NOTIFY_APNS_TEAM_ID".to_owned(),
            "TEAM123456".to_owned(),
        ),
        ("EZPDS_NOTIFY_APNS_URL".to_owned(), apple_uri.to_owned()),
    ]);
    let config = Arc::new(load_from_env_only(&env).expect("relay config"));

    let pool = notify_relay::db::open_pool("sqlite::memory:")
        .await
        .expect("relay pool");
    notify_relay::db::run_migrations(&pool)
        .await
        .expect("relay migrations");

    let apns = notify_relay::apns::ApnsClient::new(&config.apns).expect("APNs client");
    assert!(apns.is_some(), "the test relay must have APNs credentials");

    let service = Arc::new(notify_relay::service::RelayService::new(pool, config).with_apns(apns));
    let endpoint = loopback_endpoint(true).await;
    notify_relay::transport::spawn_accept_loop(endpoint.clone(), Arc::clone(&service));
    (endpoint, service, dir)
}

/// A pds wired to dial the relay at `relay_addr`, with notifications configured.
async fn start_pds(relay_addr: EndpointAddr) -> (AppState, Endpoint) {
    let mut state = crate::state::test_state().await;

    let mut config = (*state.config).clone();
    // A node id is required for the feature to be considered configured; the client dials
    // `relay_addr` directly, since loopback has no discovery to resolve this against.
    config.notifications.relay = Some(relay_addr.id.to_string());
    config.iroh.enabled = true;
    config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(MASTER_KEY)));
    state.config = Arc::new(config);

    let dialer = loopback_endpoint(false).await;
    let client =
        crate::notify_relay_client::NotifyRelayClient::with_addr(dialer.clone(), relay_addr, None);
    let (sender, _worker) = crate::notify_relay_client::spawn_worker(
        Arc::new(client),
        state.db.clone(),
        state.metrics.clone(),
    );
    state.notify_sender = Some(sender);

    seed_account(&state, ACCOUNT_DID).await;

    (state, dialer)
}

async fn seed_account(state: &AppState, did: &str) {
    insert_account_with_email(&state.db, did, &format!("{did}@example.com")).await;
}

fn access_token(state: &AppState, did: &str) -> String {
    #[derive(serde::Serialize)]
    struct Claims {
        sub: String,
        aud: String,
        exp: u64,
        scope: String,
    }
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &Claims {
            sub: did.to_string(),
            aud: "did:plc:test".to_string(),
            exp: (chrono::Utc::now().timestamp() + 3600) as u64,
            scope: "com.atproto.access".to_string(),
        },
        &jsonwebtoken::EncodingKey::from_secret(&state.jwt_secret),
    )
    .expect("token")
}

/// Register `device_public_key` through the real HTTP route, then wait for the background
/// worker to complete the relay round trip.
async fn register_device(state: &AppState, device_public_key: &str) {
    register_identity(state, ACCOUNT_DID, device_public_key, false).await;
}

/// The same, for a named identity. Every identity registers one `DEVICE_UUID` and one
/// `APNS_TOKEN` because they are all on one physical device — the composition that makes the
/// relay's per-token handle shared between them.
async fn register_identity(state: &AppState, did: &str, device_public_key: &str, ping: bool) {
    let response = crate::app::app(state.clone())
        .oneshot(
            Request::post("/v1/notifications/register")
                .header(
                    "authorization",
                    format!("Bearer {}", access_token(state, did)),
                )
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "deviceUuid": DEVICE_UUID,
                        "notificationPublicKey": device_public_key,
                        "apnsToken": APNS_TOKEN,
                        "apnsTopic": "org.obsign.identitywallet",
                        "ping": ping,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("register response");
    assert_eq!(response.status(), StatusCode::OK);

    // The route returns before the relay knows anything — that is the deliberate design.
    // Wait for the handle rather than sleeping a fixed amount, so the test is not timing-luck.
    let handle = await_condition("a relay push handle", || async {
        registration_handle(state, did).await
    })
    .await;
    assert!(!handle.is_empty());
}

/// This identity's stored relay handle, if its round trip has landed.
async fn registration_handle(state: &AppState, did: &str) -> Option<String> {
    store::list_registrations(&state.db, did)
        .await
        .ok()
        .and_then(|rows| rows.into_iter().next())
        .and_then(|row| row.push_handle)
}

/// Poll `probe` until it yields a value, or fail the test. Condition-based rather than a
/// fixed sleep: the worker is asynchronous, and a sleep would either be flaky or slow.
async fn await_condition<T, F, Fut>(what: &str, mut probe: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(value) = probe().await {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The instance's published sender key, as a device would fetch and pin it.
async fn published_sender_key(state: &AppState) -> (i64, Vec<u8>) {
    let keys = crate::notifications::published_sender_keys(state)
        .await
        .expect("published keys");
    let (kid, did_key) = keys.into_iter().next().expect("at least one sender key");
    (
        kid,
        crypto::p256_public_key_from_did_key(&did_key).expect("a decodable did:key"),
    )
}

/// The full happy path: register, seal, push — and the device opens it.
#[tokio::test]
async fn a_notification_travels_from_custos_through_the_relay_to_a_device_that_opens_it() {
    let apple = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&apple)
        .await;

    let (relay_endpoint, _relay, _keydir) = start_relay(&apple.uri()).await;
    let relay_addr =
        EndpointAddr::new(relay_endpoint.id()).with_ip_addr(relay_endpoint.bound_sockets()[0]);
    let (state, dialer) = start_pds(relay_addr).await;

    // The "device": a keypair the app would generate and register.
    let device = crypto::generate_p256_keypair().expect("device keypair");
    register_device(&state, &device.key_id.0).await;

    let (kid, sender_public_key) = published_sender_key(&state).await;

    crate::notifications::notify_device(
        &state,
        ACCOUNT_DID,
        crate::notifications::NotificationPayload::new(
            "agent_claim_pending",
            "Confirm agent access",
            "An agent is waiting for you to approve it.",
        )
        .with_data(json!({ "claimAttemptId": "clm_e2e" })),
    )
    .await;

    // Apple's first request is the registration-time nothing; the push is the one with a body
    // carrying our envelope. Wait for it rather than assuming ordering.
    // Keep the raw byte length alongside the parsed value: the padding assertion below has to
    // measure what actually crossed the wire, since parse-and-reserialize could normalize away
    // the very size drift it is there to catch.
    let (serialized_len, body) = await_condition("the pushed APNs body", || async {
        apple
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find_map(|req| {
                serde_json::from_slice::<serde_json::Value>(&req.body)
                    .ok()
                    .map(|parsed| (req.body.len(), parsed))
            })
    })
    .await;

    // What Apple (and the relay) can see: a fixed, content-free placeholder. The actual
    // notification is opaque to both.
    assert_eq!(body["aps"]["alert"]["title"], "Custos");
    assert_eq!(body["aps"]["alert"]["body"], "Encrypted notification");
    assert_eq!(body["aps"]["mutable-content"], 1);
    assert_eq!(body["ezpds"]["v"], 1);
    assert_eq!(
        body["ezpds"]["kid"], kid,
        "the envelope must name the key the instance published"
    );

    // The body Apple received must sit on a padding bucket — the assertion that catches the two
    // crates disagreeing about the envelope's shape, since Custos computed the pad against its
    // own model of these very bytes. The one-byte tolerance is not slack: base64's four-chars-
    // per-three-bytes step makes some bucket targets unreachable, so `plaintext_pad_len`
    // documents (and its own tests pin) landing on the bucket or one byte under it.
    assert!(
        crypto::PADDING_BUCKETS.contains(&serialized_len)
            || crypto::PADDING_BUCKETS.contains(&(serialized_len + 1)),
        "body was {serialized_len} bytes, not on a padding bucket {:?}",
        crypto::PADDING_BUCKETS
    );

    // Now the device's half: open the payload, which also *verifies the sender*. HPKE
    // mode_auth means a successful open is proof the instance's sender key sealed it — the
    // relay could not have authored this.
    let decode = |field: &str| {
        data_encoding::BASE64URL_NOPAD
            .decode(body["ezpds"][field].as_str().expect("string").as_bytes())
            .expect("base64url")
    };
    let plaintext = crypto::open_notification(
        &device.private_key_bytes,
        &sender_public_key,
        &decode("enc"),
        &decode("ct"),
    )
    .expect("the device must be able to open a payload sealed to it");

    let opened: serde_json::Value = serde_json::from_slice(&plaintext).expect("payload JSON");
    assert_eq!(opened["type"], "agent_claim_pending");
    assert_eq!(opened["title"], "Confirm agent access");
    assert_eq!(opened["data"]["claimAttemptId"], "clm_e2e");

    // An impostor holding the same ciphertext cannot make it verify as ours.
    let impostor = crypto::generate_p256_keypair().expect("impostor keypair");
    let impostor_public = crypto::public_key_for_secret(&impostor.private_key_bytes).unwrap();
    assert!(
        crypto::open_notification(
            &device.private_key_bytes,
            &impostor_public,
            &decode("enc"),
            &decode("ct"),
        )
        .is_err(),
        "mode_auth must refuse a payload attributed to the wrong sender"
    );

    dialer.close().await;
    relay_endpoint.close().await;
}

/// Ping mode, end to end: a registration that opted in receives a content-free
/// `content-available` background push — the body Apple (and the relay) sees carries no
/// `ezpds` key, no alert, and nothing derived from the notification at all.
#[tokio::test]
async fn a_ping_registration_receives_no_ciphertext_at_the_relay() {
    let apple = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&apple)
        .await;

    let (relay_endpoint, _relay, _keydir) = start_relay(&apple.uri()).await;
    let relay_addr =
        EndpointAddr::new(relay_endpoint.id()).with_ip_addr(relay_endpoint.bound_sockets()[0]);
    let (state, dialer) = start_pds(relay_addr).await;

    let device = crypto::generate_p256_keypair().expect("device keypair");
    register_identity(&state, ACCOUNT_DID, &device.key_id.0, true).await;

    let enqueued = crate::notifications::notify_device(
        &state,
        ACCOUNT_DID,
        crate::notifications::NotificationPayload::new(
            "agent_claim_pending",
            "Confirm agent access",
            "SECRET-BODY-THAT-MUST-NOT-LEAVE",
        ),
    )
    .await;
    assert_eq!(enqueued, 1);

    let request = await_condition("the pushed APNs request", || async {
        apple
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|req| !req.body.is_empty())
    })
    .await;

    assert_eq!(
        request.headers["apns-push-type"].to_str().expect("ascii"),
        "background"
    );
    assert_eq!(
        request.headers["apns-priority"].to_str().expect("ascii"),
        "5",
        "Apple requires priority 5 for a background push"
    );

    let body: serde_json::Value = serde_json::from_slice(&request.body).expect("JSON body");
    assert!(
        body.get("ezpds").is_none(),
        "a ping push must carry no ciphertext at the relay: {body}"
    );
    assert_eq!(
        body,
        json!({ "aps": { "content-available": 1 } }),
        "the whole body is the wake bit — nothing derived from the notification"
    );

    // A pure-ping fan-out seals nothing, so it must not have minted the instance's first
    // sender key just to throw it away.
    let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_sender_keys")
        .fetch_one(&state.db)
        .await
        .expect("count");
    assert_eq!(keys, 0, "a ping-only fan-out must not mint key material");

    dialer.close().await;
    relay_endpoint.close().await;
}

/// Phase C of wallet-confirmed OAuth consent, end to end on the server side: a login started
/// on another surface (`GET /oauth/authorize` with a `login_hint` naming a hosted account)
/// produces a sealed `login-approval` push through the real relay; the device opens it and
/// finds the routing data; the login page displays the mandatory match number; and the relay
/// and Apple see only the fixed placeholder — they never learn a login is happening.
#[tokio::test]
async fn a_hinted_login_pushes_a_sealed_login_approval_to_the_wallet() {
    let apple = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&apple)
        .await;

    let (relay_endpoint, _relay, _keydir) = start_relay(&apple.uri()).await;
    let relay_addr =
        EndpointAddr::new(relay_endpoint.id()).with_ip_addr(relay_endpoint.bound_sockets()[0]);
    let (state, dialer) = start_pds(relay_addr).await;

    // A hosted, handle-bearing account with a registered wallet device.
    sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
        .bind("notifye2e.example.com")
        .bind(ACCOUNT_DID)
        .execute(&state.db)
        .await
        .expect("seed handle");
    let device = crypto::generate_p256_keypair().expect("device keypair");
    register_device(&state, &device.key_id.0).await;
    let (_kid, sender_public_key) = published_sender_key(&state).await;

    // A registered OAuth client, and the login another device starts against it.
    crate::db::oauth::register_oauth_client(
        &state.db,
        "https://app.example.com/client-metadata.json",
        r#"{"redirect_uris":["https://app.example.com/callback"],"client_name":"Test App"}"#,
    )
    .await
    .expect("register client");

    // The authorize endpoint is PAR-only, so the login's parameters are pushed first
    // and the GET carries only the issued reference.
    let request_uri = "urn:ietf:params:oauth:request_uri:notify-e2e-hinted-login";
    crate::db::oauth::store_par_request(
        &state.db,
        request_uri,
        "https://app.example.com/client-metadata.json",
        r#"{"redirect_uri":"https://app.example.com/callback","code_challenge":"e3b0c44298fc1c149afb","code_challenge_method":"S256","state":"teststate","response_type":"code","scope":"atproto","login_hint":"notifye2e.example.com"}"#,
    )
    .await
    .expect("store PAR request");

    let response = crate::app::app(state.clone())
        .oneshot(
            Request::get(format!(
                "/oauth/authorize\
                 ?client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
                 &request_uri={request_uri}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .expect("consent page");
    assert_eq!(response.status(), StatusCode::OK);
    let html_bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("page body");
    let html = std::str::from_utf8(&html_bytes).expect("utf8 page");

    // The pending row latched the match code, and the page displays that exact number.
    let (request_id, match_code): (String, String) = sqlx::query_as(
        "SELECT request_id, match_code FROM pending_oauth_authorizations WHERE match_code IS NOT NULL",
    )
    .fetch_one(&state.db)
    .await
    .expect("a push-dispatched pending row");
    assert!(
        html.contains(&format!(
            "<div class=\"match-code mono\" id=\"match-code\">{match_code}</div>"
        )),
        "the login surface must display the match number"
    );

    // The push that crossed the wire: placeholder alert outside, `login-approval` inside.
    let body = await_condition("the pushed APNs body", || async {
        apple
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find_map(|req| serde_json::from_slice::<serde_json::Value>(&req.body).ok())
    })
    .await;
    assert_eq!(body["aps"]["alert"]["title"], "Custos");
    assert_eq!(body["aps"]["alert"]["body"], "Encrypted notification");

    let decode = |field: &str| {
        data_encoding::BASE64URL_NOPAD
            .decode(body["ezpds"][field].as_str().expect("string").as_bytes())
            .expect("base64url")
    };
    let plaintext = crypto::open_notification(
        &device.private_key_bytes,
        &sender_public_key,
        &decode("enc"),
        &decode("ct"),
    )
    .expect("the device must open the login-approval payload");
    let opened: serde_json::Value = serde_json::from_slice(&plaintext).expect("payload JSON");
    assert_eq!(opened["type"], "login-approval");
    assert_eq!(opened["data"]["requestId"], request_id.as_str());
    assert_eq!(opened["data"]["did"], ACCOUNT_DID);
    assert_eq!(opened["data"]["clientName"], "Test App");
    // The match number must never ride in the push — it is the proof the approver can see the
    // login surface, so handing it to the wallet would defeat the channel binding. (Asserted on
    // the parsed fields, not a substring: a two-digit string can appear by chance inside the
    // random request_id.)
    assert!(
        opened.get("code").is_none() && opened["data"].get("code").is_none(),
        "no code field may ride in the push payload"
    );

    dialer.close().await;
    relay_endpoint.close().await;
}

/// Two identities on one device, both hosted here.
///
/// One device means one APNs token, and the relay keeps exactly one live handle per token — so
/// the second identity's registration rotates the first identity's handle away. Both must keep
/// receiving anyway. Writing the mint back only to the identity that asked for it left the
/// first naming a handle the relay no longer knew, and its pushes came back `unknownHandle`,
/// which is correctly not a prune signal: the row survived to fail again on every app open,
/// with nothing user-visible to explain the silence.
#[tokio::test]
async fn two_identities_on_one_device_both_keep_receiving() {
    let apple = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&apple)
        .await;

    let (relay_endpoint, _relay, _keydir) = start_relay(&apple.uri()).await;
    let relay_addr =
        EndpointAddr::new(relay_endpoint.id()).with_ip_addr(relay_endpoint.bound_sockets()[0]);
    let (state, dialer) = start_pds(relay_addr).await;
    seed_account(&state, SECOND_DID).await;

    // Each identity carries its own notification keypair: a payload is sealed to the identity
    // it is for, not to the hardware it lands on.
    let first = crypto::generate_p256_keypair().expect("device keypair");
    let second = crypto::generate_p256_keypair().expect("device keypair");
    register_identity(&state, ACCOUNT_DID, &first.key_id.0, false).await;
    register_identity(&state, SECOND_DID, &second.key_id.0, false).await;

    // Both rows must name the one handle the relay still resolves — the second registration's.
    let first_handle = registration_handle(&state, ACCOUNT_DID)
        .await
        .expect("the first identity keeps a handle");
    let second_handle = registration_handle(&state, SECOND_DID)
        .await
        .expect("the second identity has a handle");
    assert_eq!(
        first_handle, second_handle,
        "one device token has one live handle; both identities must resolve through it"
    );

    let (_kid, sender_public_key) = published_sender_key(&state).await;
    for did in [ACCOUNT_DID, SECOND_DID] {
        crate::notifications::notify_device(
            &state,
            did,
            crate::notifications::NotificationPayload::new(
                "agent_claim_pending",
                "Confirm agent access",
                "An agent is waiting for you to approve it.",
            ),
        )
        .await;
    }

    // The relay refuses a push on a rotated-away handle before ever calling Apple, so "two
    // bodies reached Apple" is the delivery assertion: with a per-identity write-back only one
    // ever arrives and this times out.
    let bodies = await_condition("both identities' pushed APNs bodies", || async {
        let parsed: Vec<serde_json::Value> = apple
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(|req| serde_json::from_slice(&req.body).ok())
            .collect();
        (parsed.len() >= 2).then_some(parsed)
    })
    .await;
    assert_eq!(bodies.len(), 2, "one push per identity, no more");

    // Delivered *and* addressed correctly: each identity's key opens exactly one of the two.
    // A shared transport handle must not become a shared payload.
    let opened_by = |device: &crypto::P256Keypair| {
        bodies
            .iter()
            .filter(|body| {
                let decode = |field: &str| {
                    data_encoding::BASE64URL_NOPAD
                        .decode(body["ezpds"][field].as_str().expect("string").as_bytes())
                        .expect("base64url")
                };
                crypto::open_notification(
                    &device.private_key_bytes,
                    &sender_public_key,
                    &decode("enc"),
                    &decode("ct"),
                )
                .is_ok()
            })
            .count()
    };
    assert_eq!(opened_by(&first), 1, "the first identity's own payload");
    assert_eq!(opened_by(&second), 1, "the second identity's own payload");

    dialer.close().await;
    relay_endpoint.close().await;
}

/// The pruning back-channel: Apple reports the device token dead, the relay relays that as
/// `unregistered`, and Custos deletes the registration at the moment of proof.
#[tokio::test]
async fn a_dead_device_token_prunes_its_registration() {
    let apple = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(410))
        .mount(&apple)
        .await;

    let (relay_endpoint, _relay, _keydir) = start_relay(&apple.uri()).await;
    let relay_addr =
        EndpointAddr::new(relay_endpoint.id()).with_ip_addr(relay_endpoint.bound_sockets()[0]);
    let (state, dialer) = start_pds(relay_addr).await;

    let device = crypto::generate_p256_keypair().expect("device keypair");
    register_device(&state, &device.key_id.0).await;

    crate::notifications::notify_device(
        &state,
        ACCOUNT_DID,
        crate::notifications::NotificationPayload::new("agent_claim_pending", "t", "b"),
    )
    .await;

    await_condition("the registration to be pruned", || async {
        let rows = store::list_registrations(&state.db, ACCOUNT_DID)
            .await
            .unwrap_or_default();
        rows.is_empty().then_some(())
    })
    .await;

    dialer.close().await;
    relay_endpoint.close().await;
}
