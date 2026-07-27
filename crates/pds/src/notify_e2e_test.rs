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

const ACCOUNT_DID: &str = "did:plc:notifye2e";
const DEVICE_UUID: &str = "device-e2e-1";
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

    sqlx::query(
        "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
         VALUES (?, 'e2e@example.com', 'hash', datetime('now'), datetime('now'))",
    )
    .bind(ACCOUNT_DID)
    .execute(&state.db)
    .await
    .expect("seed account");

    (state, dialer)
}

fn access_token(state: &AppState) -> String {
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
            sub: ACCOUNT_DID.to_string(),
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
    let response = crate::app::app(state.clone())
        .oneshot(
            Request::post("/v1/notifications/register")
                .header("authorization", format!("Bearer {}", access_token(state)))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "deviceUuid": DEVICE_UUID,
                        "notificationPublicKey": device_public_key,
                        "apnsToken": "deadbeef0123456789",
                        "apnsTopic": "org.obsign.identitywallet",
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
        store::list_registrations(&state.db, ACCOUNT_DID)
            .await
            .ok()
            .and_then(|rows| rows.into_iter().next())
            .and_then(|row| row.push_handle)
    })
    .await;
    assert!(!handle.is_empty());
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
