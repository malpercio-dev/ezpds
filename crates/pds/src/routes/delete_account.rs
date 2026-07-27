// pattern: Imperative Shell
//
// Gathers: DB pool + firehose via AppState, JSON body { did, password, token, custos? }
// Processes: validate body → verify the credential factor (account password, or a device-key-signed
//            deletion proof) → consume the single-use email token → permanently delete the account
//            (all local data) and emit an `#account` (deleted) frame
// Returns: 200 OK (empty) on success; ApiError on failure
//
// Implements: POST /xrpc/com.atproto.server.deleteAccount
//
// Unlike deactivate/activate, this endpoint is **not** session-authenticated: the credentials are
// in the body (a user must be able to delete an account they can no longer log a session into).
// The email `token` (minted by `requestAccountDelete`) is always one of the two factors. The other
// is whichever the *request* presents:
//
//   * the account `password` — the standard lexicon field, unchanged; or
//   * a **deletion proof** — a fresh timestamped envelope (`crypto::encode_account_delete_envelope`)
//     signed by a key in the account's authoritative current signing authority
//     (`identity::authority`: a did:plc rotation set, or a self-hosted did:web's `#device` key),
//     carried in the off-lexicon `custos` extension object.
//
// The proof exists because an account created with no password (the `optionalPassword` capability)
// could otherwise never be deleted at all: every credential path folded into the same 401 and the
// holder had no way forward. It is accepted for a passworded account too — selecting the factor by
// what the request presents rather than by what the account has. A current rotation key is already
// the highest authority over the identity (it can migrate or tombstone the DID outright), so
// refusing it to an account that also happens to have a password would deny the stronger credential
// while honouring the weaker one, and would make the endpoint answer differently depending on
// whether a password exists — the oracle this route exists to avoid.
//
// The heavy lifting — the multi-table atomic delete, the firehose frame, and on-disk blob
// reclamation — lives in `account_delete::purge_account`, shared with the scheduled-deletion reaper.

use axum::{extract::State, http::StatusCode};
use serde::Deserialize;

use common::{ApiError, ErrorCode, SOVEREIGN_TIMESTAMP_WINDOW_SECS};

use crate::account_delete::purge_account;
use crate::app::AppState;
use crate::auth::password::{verify_password, VerifyResult};
use crate::auth::signed_proof::{decode_canonical_base64url, NONCE_BYTES, SIGNATURE_BYTES};
use crate::auth::token::hash_bearer_token;
use crate::db::account_deletion_tokens::consume_account_deletion_token;
use crate::db::accounts::account_password_hash;
use crate::db::sovereign_session_nonces::insert_nonce_if_absent;
use crate::identity::authority::{authorized_signing_keys, AuthorityError};
use crate::lexicon::LexiconInput;

#[derive(Deserialize)]
pub struct DeleteAccountRequest {
    did: String,
    /// The standard lexicon field. Empty when the caller presents a `custos.proof` instead: the
    /// vendored `com.atproto.server.deleteAccount` document marks `password` required, so it stays
    /// on the wire (as `""`) even for an account that has none.
    password: String,
    token: String,
    /// The off-lexicon Custos extension, following the `describeServer` `custos` convention — one
    /// distinctively-named key a future lexicon authority is unlikely to claim. Lexicon objects are
    /// open, so this is purely additive: a client that never sends it behaves exactly as before,
    /// and a reference PDS handed it ignores it.
    custos: Option<CustosDeleteExtension>,
}

#[derive(Deserialize)]
struct CustosDeleteExtension {
    proof: Option<DeleteProof>,
}

/// A device-key-signed authorization to delete this account, in the `sovereign_session` /
/// `oauth_consent` mold. The signed bytes bind the protocol domain (which *is* the deletion
/// intent), this server's DID, the account DID, the signing-key DID, the timestamp, and the nonce.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteProof {
    signing_key: String,
    timestamp: i64,
    nonce: String,
    signature: String,
}

/// The uniform error for any credential failure — unknown DID, no password on file, wrong password,
/// malformed proof, stale proof, bad signature, unauthorized signing key, or a replayed nonce.
/// Kept deliberately generic so the endpoint is not an account-existence, credential-shape, or
/// password oracle — the email token is bound to the DID, so a legitimate deleter always holds both
/// factors anyway.
fn invalid_credentials() -> ApiError {
    ApiError::new(ErrorCode::Unauthorized, "invalid credentials")
}

/// Verify a deletion proof: syntax, freshness, signature, then — and only then — the authoritative
/// signing-authority lookup, so an invalid signature never triggers an outbound plc.directory call.
///
/// Every rejection collapses into [`invalid_credentials`]; only a failure to *consult* the
/// authoritative source (a plc.directory outage) propagates as itself, so an upstream problem
/// fails closed with its own status rather than masquerading as a bad credential.
async fn verify_delete_proof(
    state: &AppState,
    did: &str,
    proof: &DeleteProof,
) -> Result<(), ApiError> {
    let signature = decode_canonical_base64url(&proof.signature, SIGNATURE_BYTES)
        .and_then(|bytes| <[u8; SIGNATURE_BYTES]>::try_from(bytes).ok())
        .ok_or_else(invalid_credentials)?;
    if decode_canonical_base64url(&proof.nonce, NONCE_BYTES).is_none() {
        return Err(invalid_credentials());
    }
    let now = crate::time::unix_now_secs();
    if now.abs_diff(proof.timestamp) > SOVEREIGN_TIMESTAMP_WINDOW_SECS as u64 {
        return Err(invalid_credentials());
    }

    let envelope = crypto::encode_account_delete_envelope(
        &state.config.resolve_server_did(),
        did,
        &proof.signing_key,
        proof.timestamp,
        &proof.nonce,
    );
    let signing_key = crypto::DidKeyUri(proof.signing_key.clone());
    crypto::verify_did_key_signature(&signing_key, &envelope, &signature)
        .map_err(|_| invalid_credentials())?;

    // Read live from the DID method's authoritative source — the latest non-nullified PLC
    // audit-log operation, or the published did:web document. The locally cached W3C DID
    // document is deliberately never consulted: it can be stale, and for a Custos-hosted
    // did:web it is writable under mere session auth.
    let authority = authorized_signing_keys(state, did)
        .await
        .map_err(|error| match error {
            AuthorityError::Unauthorized(reason) => {
                tracing::warn!(reason, account_did = %did, "account deletion proof rejected");
                invalid_credentials()
            }
            AuthorityError::Lookup(err) => err,
        })?;
    if !authority.authorizes(&proof.signing_key) {
        tracing::warn!(
            reason = "signing_key_not_authorized",
            account_did = %did,
            signing_key_did = %proof.signing_key,
            "account deletion proof rejected"
        );
        return Err(invalid_credentials());
    }
    Ok(())
}

/// POST /xrpc/com.atproto.server.deleteAccount
///
/// Permanently deletes the account named by `did` after verifying its credential factor — the
/// account `password`, or a device-key-signed `custos.proof` — and a single-use email `token`
/// (from `requestAccountDelete`). On success every local trace of the account is removed — repo
/// blocks/blobs (including on-disk blob files), sessions, tokens, handles, DID-doc cache,
/// preferences, app passwords, and the account row — and an `#account` frame (`active=false`,
/// `status="deleted"`) is broadcast so relays drop the repo. The did:plc identity itself is
/// untouched (the wallet owns the rotation key), matching ezpds's wallet-native model.
///
/// Credential failures return a uniform 401; a malformed body is 400. The 200 no-op applies only
/// in the narrow window where the account passed both checks but was purged (by the reaper or a
/// racing duplicate request) before this handler's own delete ran — an account that is already
/// fully gone before the credential check instead returns 401, since there is nothing to
/// authenticate against.
pub async fn delete_account_handler(
    State(state): State<AppState>,
    LexiconInput(payload): LexiconInput<DeleteAccountRequest>,
) -> Result<StatusCode, ApiError> {
    let proof = payload
        .custos
        .as_ref()
        .and_then(|extension| extension.proof.as_ref());
    if payload.did.trim().is_empty()
        || payload.token.trim().is_empty()
        || (payload.password.is_empty() && proof.is_none())
    {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "did, token, and either password or a Custos deletion proof are required",
        ));
    }

    // The existence gate, shared by both branches so an unknown DID fails identically on each —
    // and, on the proof branch, before any outbound plc.directory work is done on its behalf. The
    // lookup is deliberately lifecycle-unfiltered: a deactivated account must still be deletable.
    let Some(stored_hash) = account_password_hash(&state.db, &payload.did).await? else {
        return Err(invalid_credentials());
    };

    // Verify the credential factor first, so a bad one never burns the single-use email token.
    match proof {
        Some(proof) => verify_delete_proof(&state, &payload.did, proof).await?,
        // No proof presented: the password is the factor, and an account with none has nothing to
        // verify against — the case the proof branch exists to answer.
        None => match stored_hash {
            None => return Err(invalid_credentials()),
            Some(hash) => match verify_password(&hash, &payload.password) {
                VerifyResult::Ok => {}
                VerifyResult::WrongPassword => return Err(invalid_credentials()),
                VerifyResult::CorruptHash => {
                    tracing::error!(
                        did = %payload.did,
                        "stored password_hash is not a valid PHC string; possible DB corruption"
                    );
                    return Err(ApiError::new(ErrorCode::InternalError, "internal error"));
                }
            },
        },
    }

    // Spend the proof's nonce *before* the email token, and durably — not rolled back with a failed
    // token. That ordering is what makes a proof genuinely single-use rather than single-use-if-the
    // -other-factor-happened-to-hold: a captured envelope replayed later against a token the
    // attacker has since obtained lands on a nonce already seen. The cost is nil, since a client
    // retrying after a mistyped code signs a fresh envelope anyway.
    //
    // The nonce store is shared with sovereign sessions: both are DID-scoped single-use nonces for
    // wallet-signed proofs, the domain-versioned envelopes make them non-interchangeable across
    // surfaces, and reusing the table means the account-purge path already reclaims these rows
    // rather than gaining one more table to remember.
    if let Some(proof) = proof {
        if !insert_nonce_if_absent(&state.db, &payload.did, &proof.nonce)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %payload.did, "failed to consume account deletion nonce");
                ApiError::new(ErrorCode::InternalError, "failed to delete account")
            })?
        {
            tracing::warn!(
                reason = "nonce_replay",
                account_did = %payload.did,
                "account deletion proof rejected"
            );
            return Err(invalid_credentials());
        }
    }

    // Redeem the email token (atomic single-use, bound to the DID). The credential factor is
    // already verified, so consuming here neither leaks account existence nor burns a token on a
    // wrong password or a bad proof.
    let token_hash = hash_bearer_token(&payload.token)?;
    if !consume_account_deletion_token(&state.db, &payload.did, &token_hash).await? {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "invalid or expired account deletion token",
        ));
    }

    // Both factors check out — permanently delete. A `NotFound` here means the account was deleted
    // out from under us between the credential check and now (a race with the reaper or a duplicate
    // request); treat it as an idempotent success.
    purge_account(&state, &payload.did).await?;

    Ok(StatusCode::OK)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state, AppState};
    use crate::auth::token::generate_token;
    use crate::db::account_deletion_tokens::insert_account_deletion_token;
    use crate::firehose::FirehoseEvent;
    use crate::routes::test_utils::{body_json, insert_account_with_password};

    fn post_req(json: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.deleteAccount")
            .header("Content-Type", "application/json")
            .body(Body::from(json.to_string()))
            .unwrap()
    }

    /// Seed a deletion token for `did`, returning its plaintext (as a client would receive it).
    async fn seed_token(db: &sqlx::SqlitePool, did: &str) -> String {
        let token = generate_token();
        insert_account_deletion_token(db, did, &token.hash)
            .await
            .unwrap();
        token.plaintext
    }

    async fn account_exists(db: &sqlx::SqlitePool, did: &str) -> bool {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(db)
            .await
            .unwrap();
        count > 0
    }

    #[tokio::test]
    async fn valid_password_and_token_deletes_and_emits_frame() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:del1";
        insert_account_with_password(&db, did, "del1.example.com", "del1@example.com", "hunter2")
            .await;
        let token = seed_token(&db, did).await;
        let mut rx = state.firehose.subscribe();

        let response = app(state)
            .oneshot(post_req(serde_json::json!({
                "did": did, "password": "hunter2", "token": token,
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!account_exists(&db, did).await, "account must be gone");

        let FirehoseEvent::Account(event) = rx.try_recv().unwrap() else {
            panic!("expected an #account firehose event");
        };
        assert_eq!(event.did, did);
        assert!(!event.active);
        assert_eq!(event.status.as_deref(), Some("deleted"));
    }

    #[tokio::test]
    async fn wrong_password_returns_401_and_preserves_account_and_token() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:del2";
        insert_account_with_password(&db, did, "del2.example.com", "del2@example.com", "hunter2")
            .await;
        let token = seed_token(&db, did).await;

        let response = app(state)
            .oneshot(post_req(serde_json::json!({
                "did": did, "password": "wrong", "token": token,
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(account_exists(&db, did).await, "account must survive");

        // The token must not have been consumed by a failed password attempt.
        let used_at: Option<String> =
            sqlx::query_scalar("SELECT used_at FROM account_deletion_tokens WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(used_at, None, "a wrong password must not burn the token");
    }

    #[tokio::test]
    async fn invalid_token_returns_401_and_preserves_account() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:del3";
        insert_account_with_password(&db, did, "del3.example.com", "del3@example.com", "hunter2")
            .await;
        // A syntactically valid but never-issued token (base64url of 32 bytes hashes cleanly).
        let bogus = crate::auth::token::generate_token().plaintext;

        let response = app(state)
            .oneshot(post_req(serde_json::json!({
                "did": did, "password": "hunter2", "token": bogus,
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
        assert!(account_exists(&db, did).await, "account must survive");
    }

    #[tokio::test]
    async fn unknown_account_returns_401() {
        let state = test_state().await;
        let response = app(state)
            .oneshot(post_req(serde_json::json!({
                "did": "did:plc:ghostdelete", "password": "x", "token": "y",
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A password-only request against a passwordless account still fails — there is nothing to
    /// verify against. The way out is a deletion proof, covered below.
    #[tokio::test]
    async fn a_passwordless_account_refuses_a_password_only_request() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = "did:plc:delmobile";
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'm@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&db)
        .await
        .unwrap();
        let token = seed_token(&db, did).await;

        let response = app(state)
            .oneshot(post_req(serde_json::json!({
                "did": did, "password": "anything", "token": token,
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(account_exists(&db, did).await, "account must survive");
    }

    #[tokio::test]
    async fn missing_fields_returns_400() {
        let state: AppState = test_state().await;
        let response = app(state)
            .oneshot(post_req(
                serde_json::json!({ "did": "", "password": "", "token": "" }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ── Deletion proof (the passwordless credential factor) ──────────────────

    mod proof {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use p256::ecdsa::{signature::Signer as _, Signature as P256Signature, SigningKey};
        use serde_json::{json, Value};
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };

        use super::super::NONCE_BYTES;
        use super::*;
        use crate::app::test_state_with_plc_url;

        /// A DID whose rotation set the mock plc.directory answers for.
        const DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
        const OTHER_DID: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";

        struct TestKey {
            did: String,
            signing_key: SigningKey,
        }

        impl TestKey {
            fn generate() -> Self {
                let generated = crypto::generate_p256_keypair().unwrap();
                Self {
                    did: generated.key_id.0,
                    signing_key: SigningKey::from_bytes(
                        generated.private_key_bytes.as_slice().into(),
                    )
                    .expect("valid P-256 scalar"),
                }
            }

            fn sign(&self, message: &[u8]) -> String {
                let signature: P256Signature = self.signing_key.sign(message);
                URL_SAFE_NO_PAD.encode(signature.normalize_s().unwrap_or(signature).to_bytes())
            }
        }

        async fn seed_passwordless_account(db: &sqlx::SqlitePool, did: &str) {
            sqlx::query(
                "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
                 VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
            )
            .bind(did)
            .bind(format!("{did}@example.com"))
            .execute(db)
            .await
            .unwrap();
        }

        async fn mount_audit_log(server: &MockServer, did: &str, rotation_keys: &[&str]) {
            let log = json!([{
                "did": did,
                "cid": "bafy-current-head",
                "createdAt": "2026-07-27T00:00:00Z",
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

        /// Build a request body carrying a deletion proof. `envelope_did` is the DID the signed
        /// bytes name, which the binding tests set differently from the body's `did`.
        fn proof_body(
            state: &AppState,
            key: &TestKey,
            body_did: &str,
            envelope_did: &str,
            token: &str,
            nonce_fill: u8,
        ) -> Value {
            let nonce = URL_SAFE_NO_PAD.encode([nonce_fill; NONCE_BYTES]);
            let timestamp = crate::time::unix_now_secs();
            let envelope = crypto::encode_account_delete_envelope(
                &state.config.resolve_server_did(),
                envelope_did,
                &key.did,
                timestamp,
                &nonce,
            );
            json!({
                "did": body_did,
                "password": "",
                "token": token,
                "custos": { "proof": {
                    "signingKey": key.did,
                    "timestamp": timestamp,
                    "nonce": nonce,
                    "signature": key.sign(&envelope),
                }},
            })
        }

        async fn token_used(db: &sqlx::SqlitePool, did: &str) -> bool {
            let used_at: Option<String> =
                sqlx::query_scalar("SELECT used_at FROM account_deletion_tokens WHERE did = ?")
                    .bind(did)
                    .fetch_one(db)
                    .await
                    .unwrap();
            used_at.is_some()
        }

        /// The headline acceptance criterion: an account with no password at all is fully
        /// deletable, tombstone frame and all.
        #[tokio::test]
        async fn a_passwordless_account_is_deleted_by_a_current_rotation_key_proof() {
            let plc = MockServer::start().await;
            let state = test_state_with_plc_url(plc.uri()).await;
            let db = state.db.clone();
            let key = TestKey::generate();
            seed_passwordless_account(&db, DID).await;
            mount_audit_log(&plc, DID, &[&key.did]).await;
            let token = seed_token(&db, DID).await;
            let mut rx = state.firehose.subscribe();

            let body = proof_body(&state, &key, DID, DID, &token, 1);
            let response = app(state).oneshot(post_req(body)).await.unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            assert!(!account_exists(&db, DID).await, "account must be gone");
            let FirehoseEvent::Account(event) = rx.try_recv().unwrap() else {
                panic!("expected an #account firehose event");
            };
            assert_eq!(event.did, DID);
            assert!(!event.active);
            assert_eq!(event.status.as_deref(), Some("deleted"));
        }

        /// A proof is single-use in its own right, not merely because the token beside it was.
        /// The first attempt fails on a bad token — spending the nonce but leaving the real token
        /// intact — and the replay with the *good* token is then refused.
        #[tokio::test]
        async fn a_replayed_proof_is_refused_even_with_a_valid_token() {
            let plc = MockServer::start().await;
            let state = test_state_with_plc_url(plc.uri()).await;
            let db = state.db.clone();
            let key = TestKey::generate();
            seed_passwordless_account(&db, DID).await;
            mount_audit_log(&plc, DID, &[&key.did]).await;
            let token = seed_token(&db, DID).await;
            let bogus = crate::auth::token::generate_token().plaintext;

            let mut body = proof_body(&state, &key, DID, DID, &bogus, 2);
            let first = app(state.clone())
                .oneshot(post_req(body.clone()))
                .await
                .unwrap();
            assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
            assert!(
                !token_used(&db, DID).await,
                "a bad token must not consume the real one"
            );

            // Same envelope, now paired with the genuine token.
            body["token"] = json!(token);
            let replay = app(state).oneshot(post_req(body)).await.unwrap();

            assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(body_json(replay).await["error"]["code"], "UNAUTHORIZED");
            assert!(account_exists(&db, DID).await, "account must survive");
            assert!(
                !token_used(&db, DID).await,
                "a replayed proof must not burn the token"
            );
        }

        /// The envelope names the account it authorizes, so a proof minted for DID A cannot be
        /// re-aimed at DID B by rewriting the body — the server reconstructs the bytes from the
        /// body's DID and the signature no longer matches.
        #[tokio::test]
        async fn a_proof_bound_to_another_did_cannot_delete_this_account() {
            let plc = MockServer::start().await;
            let state = test_state_with_plc_url(plc.uri()).await;
            let db = state.db.clone();
            let key = TestKey::generate();
            seed_passwordless_account(&db, DID).await;
            seed_passwordless_account(&db, OTHER_DID).await;
            // The attacker's key really is a rotation key of the *victim* account, so only the
            // envelope's DID binding stands between the two.
            mount_audit_log(&plc, OTHER_DID, &[&key.did]).await;
            let token = seed_token(&db, OTHER_DID).await;

            let body = proof_body(&state, &key, OTHER_DID, DID, &token, 3);
            let response = app(state).oneshot(post_req(body)).await.unwrap();

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(account_exists(&db, OTHER_DID).await, "account must survive");
            assert!(!token_used(&db, OTHER_DID).await, "token must not be spent");
        }

        /// The oracle discipline: an unknown DID, a wrong password, and a key absent from the
        /// account's authoritative rotation set are one indistinguishable response.
        #[tokio::test]
        async fn unknown_did_wrong_password_and_bad_proof_are_indistinguishable() {
            let plc = MockServer::start().await;
            let state = test_state_with_plc_url(plc.uri()).await;
            let db = state.db.clone();
            let current = TestKey::generate();
            let stranger = TestKey::generate();
            insert_account_with_password(
                &db,
                DID,
                "oracle.example.com",
                "oracle@example.com",
                "hunter2",
            )
            .await;
            mount_audit_log(&plc, DID, &[&current.did]).await;
            let token = seed_token(&db, DID).await;

            let mut bodies = vec![
                serde_json::json!({ "did": "did:plc:cccccccccccccccccccccccc", "password": "x", "token": token }),
                serde_json::json!({ "did": DID, "password": "wrong", "token": token }),
            ];
            bodies.push(proof_body(&state, &stranger, DID, DID, &token, 4));

            let mut seen: Vec<(StatusCode, Value)> = Vec::new();
            for body in bodies {
                let response = app(state.clone()).oneshot(post_req(body)).await.unwrap();
                let status = response.status();
                seen.push((status, body_json(response).await));
            }
            let first = seen[0].clone();
            for (status, json) in &seen {
                assert_eq!(*status, StatusCode::UNAUTHORIZED);
                assert_eq!(
                    (status, json),
                    (&first.0, &first.1),
                    "credential failures must be byte-identical"
                );
            }
            assert!(account_exists(&db, DID).await, "account must survive");
            assert!(!token_used(&db, DID).await, "token must not be spent");
        }

        /// The credential factor is chosen by what the request presents, not by what the account
        /// has: a rotation key is already the highest authority over the identity, so a passworded
        /// account accepts a proof too.
        #[tokio::test]
        async fn a_passworded_account_also_accepts_a_rotation_key_proof() {
            let plc = MockServer::start().await;
            let state = test_state_with_plc_url(plc.uri()).await;
            let db = state.db.clone();
            let key = TestKey::generate();
            insert_account_with_password(
                &db,
                DID,
                "both.example.com",
                "both@example.com",
                "hunter2",
            )
            .await;
            mount_audit_log(&plc, DID, &[&key.did]).await;
            let token = seed_token(&db, DID).await;

            let body = proof_body(&state, &key, DID, DID, &token, 5);
            let response = app(state).oneshot(post_req(body)).await.unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            assert!(!account_exists(&db, DID).await, "account must be gone");
        }

        /// A stale envelope is refused before the outbound authority lookup, so a captured proof
        /// stops being useful once its window closes.
        ///
        /// "Before the lookup" is asserted against the mock server's **request log**, not against
        /// `verify()`: `verify()` only checks mounted mock expectations, and this server mounts
        /// none, so it would pass however many requests arrived. The recorded request set is the
        /// only thing that actually witnesses the absence of an outbound call.
        #[tokio::test]
        async fn a_stale_proof_is_refused_before_any_plc_lookup() {
            let plc = MockServer::start().await;
            let state = test_state_with_plc_url(plc.uri()).await;
            let db = state.db.clone();
            let key = TestKey::generate();
            seed_passwordless_account(&db, DID).await;
            let token = seed_token(&db, DID).await;

            let mut body = proof_body(&state, &key, DID, DID, &token, 6);
            let stale = crate::time::unix_now_secs() - common::SOVEREIGN_TIMESTAMP_WINDOW_SECS - 10;
            let nonce = body["custos"]["proof"]["nonce"]
                .as_str()
                .unwrap()
                .to_string();
            let envelope = crypto::encode_account_delete_envelope(
                &state.config.resolve_server_did(),
                DID,
                &key.did,
                stale,
                &nonce,
            );
            body["custos"]["proof"]["timestamp"] = json!(stale);
            body["custos"]["proof"]["signature"] = json!(key.sign(&envelope));

            let response = app(state).oneshot(post_req(body)).await.unwrap();

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                plc.received_requests()
                    .await
                    .expect("request recording is on by default")
                    .len(),
                0,
                "a stale proof must not reach plc.directory"
            );
            assert!(account_exists(&db, DID).await, "account must survive");
            assert!(!token_used(&db, DID).await, "token must not be spent");
        }
    }
}
