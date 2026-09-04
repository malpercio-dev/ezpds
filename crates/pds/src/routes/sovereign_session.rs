// pattern: Imperative Shell

//! `POST /v1/sessions/sovereign` — passwordless full-access session issuance from a signed proof.
//!
//! Exchanges a fresh timestamped proof, signed by a key in the hosted DID's authoritative
//! current signing authority (`identity::authority` — a did:plc account's current PLC
//! `rotationKeys`, a self-hosted did:web's published `#device` key), for the standard full-access
//! legacy session response.
//!
//! The canonical envelope binds the protocol domain and version, the destination server DID, the
//! method/path, the account DID, the signing-key DID, the timestamp, and a 32-byte random nonce.
//! P-256 and secp256k1 signatures are accepted only in canonical low-S form. The account's local
//! lifecycle is checked before *and inside* the transaction that consumes the nonce and issues
//! the session. plc.directory failures fail closed, and the cached W3C DID document is never a
//! rotation-key source — only the live authoritative state authorizes a session.
//!
//! Any current rotation key qualifies, including a Custos-held one: it operates under the same
//! PLC semantics as any other rotation key, granting Custos no power beyond what hosting the
//! account already gives it.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::StatusCode, response::Json};
use common::{ApiError, ApiResultExt, ErrorCode, SOVEREIGN_TIMESTAMP_WINDOW_SECS};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::signed_proof::{decode_canonical_base64url, NONCE_BYTES, SIGNATURE_BYTES};
use crate::db::accounts::active_local_account_exists;
use crate::db::sovereign_session_nonces::insert_nonce_if_absent;
use crate::identity::authority::{authorized_signing_keys, AuthorityError};
use crate::session_issuer::{issue_session_in_transaction, SessionKind};

const REJECTION_MESSAGE: &str = "sovereign session proof rejected";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SovereignSessionRequest {
    did: String,
    signing_key: String,
    timestamp: i64,
    nonce: String,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SovereignSessionResponse {
    access_jwt: String,
    refresh_jwt: String,
    handle: String,
    did: String,
    email: Option<String>,
}

fn rejected(reason: &'static str, did: &str, signing_key: &str) -> ApiError {
    tracing::warn!(
        reason,
        account_did = %did,
        signing_key_did = %signing_key,
        "sovereign session proof rejected"
    );
    ApiError::new(ErrorCode::AuthenticationRequired, REJECTION_MESSAGE)
}

fn unix_timestamp() -> Result<i64, ApiError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .or_internal_as(
            "system clock is before Unix epoch",
            "failed to verify request timestamp",
        )?
        .as_secs();
    i64::try_from(seconds).map_err(|_| {
        ApiError::new(
            ErrorCode::InternalError,
            "system timestamp exceeds supported range",
        )
    })
}

/// Exchange proof from a key in a hosted DID's authoritative current signing authority for a
/// standard full-access Custos session.
///
/// Method-agnostic: a `did:plc` account's authority is its current PLC rotation set (a Custos-held
/// rotation key qualifies under exactly the same PLC semantics as any other, granting Custos no
/// additional power over an account it already hosts), and a self-hosted `did:web` account's is its
/// published `#device` key. See [`crate::identity::authority`] for the policy and its rationale.
pub async fn create_sovereign_session(
    State(state): State<AppState>,
    Json(request): Json<SovereignSessionRequest>,
) -> Result<(StatusCode, Json<SovereignSessionResponse>), ApiError> {
    let signature = decode_canonical_base64url(&request.signature, SIGNATURE_BYTES)
        .and_then(|bytes| <[u8; SIGNATURE_BYTES]>::try_from(bytes).ok())
        .ok_or_else(|| {
            rejected(
                "invalid_signature_encoding",
                &request.did,
                &request.signing_key,
            )
        })?;
    if decode_canonical_base64url(&request.nonce, NONCE_BYTES).is_none() {
        return Err(rejected(
            "invalid_nonce_encoding",
            &request.did,
            &request.signing_key,
        ));
    }
    let now = unix_timestamp()?;
    if now.abs_diff(request.timestamp) > SOVEREIGN_TIMESTAMP_WINDOW_SECS as u64 {
        return Err(rejected(
            "timestamp_outside_window",
            &request.did,
            &request.signing_key,
        ));
    }

    // This cheap local gate precedes signature verification and the outbound PLC lookup. Missing
    // and every inactive lifecycle state intentionally share one response.
    if !active_local_account_exists(&state.db, &request.did).await? {
        return Err(rejected(
            "account_not_active_local",
            &request.did,
            &request.signing_key,
        ));
    }

    let server_did = state.config.resolve_server_did();
    let envelope = crypto::encode_sovereign_session_envelope(
        &server_did,
        &request.did,
        &request.signing_key,
        request.timestamp,
        &request.nonce,
    );
    let signing_key = crypto::DidKeyUri(request.signing_key.clone());
    crypto::verify_did_key_signature(&signing_key, &envelope, &signature).map_err(|_| {
        rejected(
            "signature_verification_failed",
            &request.did,
            &request.signing_key,
        )
    })?;

    // The account's signing authority, read live from its DID method's authoritative source — the
    // latest non-nullified PLC audit-log operation, or the published did:web document. The locally
    // cached W3C DID document is deliberately never consulted for either method.
    let authority = authorized_signing_keys(&state, &request.did)
        .await
        .map_err(|error| match error {
            AuthorityError::Unauthorized(reason) => {
                rejected(reason, &request.did, &request.signing_key)
            }
            AuthorityError::Lookup(err) => err,
        })?;
    if !authority.authorizes(&request.signing_key) {
        return Err(rejected(
            "signing_key_not_authorized",
            &request.did,
            &request.signing_key,
        ));
    }

    // The lifecycle recheck, one-time nonce insertion, and both session rows share one SQLite
    // transaction. A replay or a concurrent deactivation therefore cannot mint a partial session.
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, account_did = %request.did, "failed to begin sovereign session transaction");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;
    if !active_local_account_exists(&mut *tx, &request.did).await? {
        return Err(rejected(
            "account_became_inactive",
            &request.did,
            &request.signing_key,
        ));
    }
    if !insert_nonce_if_absent(&mut *tx, &request.did, &request.nonce)
        .await
        .map_err(|e| {
            {
                tracing::error!(error = %e, account_did = %request.did, "failed to consume sovereign nonce");
                ApiError::new(ErrorCode::InternalError, "failed to create session")
            }
        })?
    {
        return Err(rejected("nonce_replay", &request.did, &request.signing_key));
    }
    let issued =
        issue_session_in_transaction(&mut tx, &state, &request.did, &SessionKind::FullAccess)
            .await?;
    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, account_did = %request.did, "failed to commit sovereign session transaction");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;

    tracing::info!(
        account_did = %request.did,
        signing_key_did = %request.signing_key,
        authority = %authority.source,
        "sovereign full-access session issued"
    );
    Ok((
        StatusCode::OK,
        Json(SovereignSessionResponse {
            access_jwt: issued.access_jwt,
            refresh_jwt: issued.refresh_jwt,
            handle: issued.handle,
            did: issued.did,
            email: issued.email,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{body::Body, http::Request};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use k256::ecdsa::{signature::Signer as _, Signature as K256Signature};
    use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
    use rand_core::OsRng;
    use serde_json::{json, Value};
    use tower::ServiceExt;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[test]
    fn server_uses_the_shared_canonical_envelope_vector() {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Vector {
            server_did: String,
            account_did: String,
            signing_key_did: String,
            timestamp: i64,
            nonce: String,
            envelope: String,
        }
        let vector: Vector = serde_json::from_str(include_str!(
            "../../../../test-vectors/sovereign-session-envelope-v1.json"
        ))
        .unwrap();
        let actual = crypto::encode_sovereign_session_envelope(
            &vector.server_did,
            &vector.account_did,
            &vector.signing_key_did,
            vector.timestamp,
            &vector.nonce,
        );
        assert_eq!(String::from_utf8(actual).unwrap(), vector.envelope);
    }

    use super::*;
    use crate::app::{app, test_state_with_plc_url, AppState};
    use crate::auth::jwt::{parse_scope, verify_hs256_access_token, AuthScope};
    use crate::routes::test_utils::body_json;

    type SignFn = Box<dyn Fn(&[u8]) -> String + Send + Sync>;

    struct TestKey {
        did: String,
        sign: SignFn,
    }

    fn p256_key() -> TestKey {
        let generated = crypto::generate_p256_keypair().unwrap();
        let signing_key = P256SigningKey::from_bytes(generated.private_key_bytes.as_slice().into())
            .expect("valid P-256 scalar");
        TestKey {
            did: generated.key_id.0,
            sign: Box::new(move |message| {
                let sig: P256Signature = signing_key.sign(message);
                URL_SAFE_NO_PAD.encode(sig.normalize_s().unwrap_or(sig).to_bytes())
            }),
        }
    }

    fn secp256k1_key() -> TestKey {
        let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
        let mut multikey = vec![0xe7, 0x01];
        multikey.extend_from_slice(
            signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        );
        let did = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, multikey)
        );
        TestKey {
            did,
            sign: Box::new(move |message| {
                let sig: K256Signature = signing_key.sign(message);
                URL_SAFE_NO_PAD.encode(sig.normalize_s().unwrap_or(sig).to_bytes())
            }),
        }
    }

    async fn state_with_plc(server: &MockServer) -> AppState {
        test_state_with_plc_url(server.uri()).await
    }

    async fn seed_account(state: &AppState, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'owner@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO handles (handle, did, created_at) VALUES ('owner.example.com', ?, datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
    }

    async fn mount_audit_log(server: &MockServer, did: &str, rotation_keys: &[&str]) {
        let log = json!([{
            "did": did,
            "cid": "bafy-current-head",
            "createdAt": "2026-07-13T00:00:00Z",
            "nullified": false,
            "operation": {
                "type": "plc_operation",
                "prev": null,
                "rotationKeys": rotation_keys,
                "verificationMethods": {},
                "alsoKnownAs": ["at://owner.example.com"],
                "services": {}
            }
        }]);
        Mock::given(method("GET"))
            .and(path(format!("/{did}/log/audit")))
            .respond_with(ResponseTemplate::new(200).set_body_json(log))
            .mount(server)
            .await;
    }

    fn now() -> i64 {
        unix_timestamp().unwrap()
    }

    fn proof_body(state: &AppState, key: &TestKey, did: &str, timestamp: i64, fill: u8) -> Value {
        let nonce = URL_SAFE_NO_PAD.encode([fill; NONCE_BYTES]);
        let envelope = crypto::encode_sovereign_session_envelope(
            &state.config.resolve_server_did(),
            did,
            &key.did,
            timestamp,
            &nonce,
        );
        json!({
            "did": did,
            "signingKey": key.did,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": (key.sign)(&envelope)
        })
    }

    fn post(body: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(crypto::SOVEREIGN_SESSION_PATH)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    async fn assert_success_for_key(key: TestKey) {
        let plc = MockServer::start().await;
        let state = state_with_plc(&plc).await;
        let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
        seed_account(&state, did).await;
        mount_audit_log(&plc, did, &[&key.did]).await;

        let response = app(state.clone())
            .oneshot(post(proof_body(&state, &key, did, now(), 1)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["did"], did);
        assert_eq!(body["handle"], "owner.example.com");
        assert_eq!(body["email"], "owner@example.com");
        assert!(body["refreshJwt"].is_string());
        let claims =
            verify_hs256_access_token(body["accessJwt"].as_str().unwrap(), &state).unwrap();
        assert_eq!(parse_scope(&claims.scope).unwrap(), AuthScope::Access);
    }

    #[tokio::test]
    async fn current_p256_rotation_key_mints_full_access_session() {
        assert_success_for_key(p256_key()).await;
    }

    #[tokio::test]
    async fn current_secp256k1_rotation_key_mints_full_access_session() {
        assert_success_for_key(secp256k1_key()).await;
    }

    #[tokio::test]
    async fn fossil_and_current_atproto_non_rotation_keys_are_rejected() {
        for fill in [2, 3] {
            let plc = MockServer::start().await;
            let state = state_with_plc(&plc).await;
            let did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
            let claimed = p256_key();
            let current = p256_key();
            seed_account(&state, did).await;
            // This represents either a former rotation key after the PLC head moved, or the
            // current #atproto key: both verify cryptographically but are absent from rotationKeys.
            mount_audit_log(&plc, did, &[&current.did]).await;
            let response = app(state.clone())
                .oneshot(post(proof_body(&state, &claimed, did, now(), fill)))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn every_envelope_binding_is_signature_protected() {
        let plc = MockServer::start().await;
        let state = state_with_plc(&plc).await;
        let did = "did:plc:cccccccccccccccccccccccc";
        let key = p256_key();
        seed_account(&state, did).await;
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:dddddddddddddddddddddddd', 'other@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let timestamp = now();
        let base = proof_body(&state, &key, did, timestamp, 4);
        let other_key = p256_key();
        let mutations = [
            ("did", json!("did:plc:dddddddddddddddddddddddd")),
            ("signingKey", json!(other_key.did)),
            ("timestamp", json!(timestamp - 1)),
            ("nonce", json!(URL_SAFE_NO_PAD.encode([5u8; NONCE_BYTES]))),
        ];
        for (field, value) in mutations {
            let mut changed = base.clone();
            changed[field] = value;
            let response = app(state.clone()).oneshot(post(changed)).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "field {field}");
        }

        for wrong_envelope in [
            crypto::encode_sovereign_session_envelope(
                "did:web:other.example.com",
                did,
                &key.did,
                timestamp,
                base["nonce"].as_str().unwrap(),
            ),
            String::from_utf8(crypto::encode_sovereign_session_envelope(
                &state.config.resolve_server_did(),
                did,
                &key.did,
                timestamp,
                base["nonce"].as_str().unwrap(),
            ))
            .unwrap()
            .replace("method:4:POST", "method:3:GET")
            .into_bytes(),
            String::from_utf8(crypto::encode_sovereign_session_envelope(
                &state.config.resolve_server_did(),
                did,
                &key.did,
                timestamp,
                base["nonce"].as_str().unwrap(),
            ))
            .unwrap()
            .replace(
                "path:22:/v1/sessions/sovereign",
                "path:21:/v1/session/sovereign",
            )
            .into_bytes(),
        ] {
            let mut changed = base.clone();
            changed["signature"] = json!((key.sign)(&wrong_envelope));
            let response = app(state.clone()).oneshot(post(changed)).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    /// A timestamp outside the acceptance window is refused before the outbound authority lookup.
    ///
    /// "Before the lookup" is asserted against the mock server's **request log**, not against
    /// `verify()`: `verify()` only checks mounted mock expectations, and this server mounts none,
    /// so it would pass however many requests arrived. The recorded request set is the only thing
    /// that actually witnesses the absence of an outbound call.
    #[tokio::test]
    async fn stale_and_future_timestamps_are_rejected_before_plc_lookup() {
        for (timestamp, fill) in [
            (now() - SOVEREIGN_TIMESTAMP_WINDOW_SECS - 10, 6),
            (now() + SOVEREIGN_TIMESTAMP_WINDOW_SECS + 10, 7),
        ] {
            let plc = MockServer::start().await;
            let state = state_with_plc(&plc).await;
            let did = "did:plc:eeeeeeeeeeeeeeeeeeeeeeee";
            let key = p256_key();
            seed_account(&state, did).await;
            let response = app(state.clone())
                .oneshot(post(proof_body(&state, &key, did, timestamp, fill)))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                plc.received_requests()
                    .await
                    .expect("request recording is on by default")
                    .len(),
                0,
                "a timestamp outside the window must not reach plc.directory"
            );
        }
    }

    #[tokio::test]
    async fn exact_and_concurrent_replay_mint_only_one_session() {
        for concurrent in [false, true] {
            let plc = MockServer::start().await;
            let state = state_with_plc(&plc).await;
            let did = "did:plc:ffffffffffffffffffffffff";
            let key = p256_key();
            seed_account(&state, did).await;
            mount_audit_log(&plc, did, &[&key.did]).await;
            let body = proof_body(&state, &key, did, now(), if concurrent { 9 } else { 8 });

            let (first, second) = if concurrent {
                tokio::join!(
                    app(state.clone()).oneshot(post(body.clone())),
                    app(state.clone()).oneshot(post(body))
                )
            } else {
                let first = app(state.clone()).oneshot(post(body.clone())).await;
                let second = app(state.clone()).oneshot(post(body)).await;
                (first, second)
            };
            let statuses = [first.unwrap().status(), second.unwrap().status()];
            assert!(statuses.contains(&StatusCode::OK));
            assert!(statuses.contains(&StatusCode::UNAUTHORIZED));
            let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE did = ?")
                .bind(did)
                .fetch_one(&state.db)
                .await
                .unwrap();
            assert_eq!(sessions, 1);
        }
    }

    #[tokio::test]
    async fn missing_and_every_inactive_local_account_state_share_one_failure() {
        for (column, fill) in [
            (None, 10),
            (Some("deactivated_at"), 11),
            (Some("suspended_at"), 12),
            (Some("taken_down_at"), 13),
        ] {
            let plc = MockServer::start().await;
            let state = state_with_plc(&plc).await;
            let did = "did:plc:gggggggggggggggggggggggg";
            let key = p256_key();
            if let Some(column) = column {
                seed_account(&state, did).await;
                sqlx::query(&format!(
                    "UPDATE accounts SET {column} = datetime('now') WHERE did = ?"
                ))
                .bind(did)
                .execute(&state.db)
                .await
                .unwrap();
            }
            let response = app(state.clone())
                .oneshot(post(proof_body(&state, &key, did, now(), fill)))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let body = body_json(response).await;
            assert_eq!(body["error"]["message"], REJECTION_MESSAGE);
        }
    }

    /// A Custos-hosted did:web is refused before any outbound resolution, and no nonce is spent.
    ///
    /// `POST /v1/did-web/document` lets an account rewrite its served document under session auth,
    /// so admitting a hosted did:web would let a stolen session install an attacker `#device` key
    /// and bootstrap sovereign sessions — escalation with no key compromise. The mock PLC server's
    /// recorded request set proves nothing outbound was attempted (`verify()` would not: it only
    /// checks mounted mock expectations, and this server mounts none).
    #[tokio::test]
    async fn a_custos_hosted_did_web_account_cannot_open_a_sovereign_session() {
        let plc = MockServer::start().await;
        let state = state_with_plc(&plc).await;
        let did = "did:web:example.com";
        let key = p256_key();
        seed_account(&state, did).await;
        sqlx::query(
            "UPDATE accounts SET did_web_hosting_enabled_at = datetime('now') WHERE did = ?",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        let response = app(state.clone())
            .oneshot(post(proof_body(&state, &key, did, now(), 15)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await["error"]["message"],
            REJECTION_MESSAGE
        );
        assert_eq!(
            plc.received_requests()
                .await
                .expect("request recording is on by default")
                .len(),
            0,
            "a Custos-hosted did:web must not reach plc.directory"
        );
        let nonces: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sovereign_session_nonces WHERE did = ?")
                .bind(did)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(nonces, 0);
    }

    /// A DID method with no authority source Custos can consult shares the same opaque rejection.
    #[tokio::test]
    async fn an_unsupported_did_method_is_rejected() {
        let plc = MockServer::start().await;
        let state = state_with_plc(&plc).await;
        let did = "did:example:not-a-supported-method";
        let key = p256_key();
        seed_account(&state, did).await;

        let response = app(state.clone())
            .oneshot(post(proof_body(&state, &key, did, now(), 16)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            plc.received_requests()
                .await
                .expect("request recording is on by default")
                .len(),
            0,
            "an unsupported DID method must not reach plc.directory"
        );
    }

    #[tokio::test]
    async fn plc_failure_fails_closed_without_consuming_nonce_or_minting_session() {
        let plc = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&plc)
            .await;
        let state = state_with_plc(&plc).await;
        let did = "did:plc:hhhhhhhhhhhhhhhhhhhhhhhh";
        let key = p256_key();
        seed_account(&state, did).await;

        let response = app(state.clone())
            .oneshot(post(proof_body(&state, &key, did, now(), 14)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM sessions WHERE did = ?), \
                    (SELECT COUNT(*) FROM sovereign_session_nonces WHERE did = ?)",
        )
        .bind(did)
        .bind(did)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(counts, (0, 0));
    }

    #[tokio::test]
    async fn sovereign_endpoint_has_a_per_ip_session_creation_limit() {
        let plc = MockServer::start().await;
        let mut state = state_with_plc(&plc).await;
        state.rate_limiter = Arc::new(crate::rate_limit::RateLimiterState::new(
            &common::RateLimitConfig {
                enabled: true,
                global_ip_per_5min: 100,
                create_session_per_5min: 2,
                ..common::RateLimitConfig::default()
            },
        ));
        for expected in [
            StatusCode::UNPROCESSABLE_ENTITY,
            StatusCode::UNPROCESSABLE_ENTITY,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            let response = app(state.clone()).oneshot(post(json!({}))).await.unwrap();
            assert_eq!(response.status(), expected);
        }
    }
}
