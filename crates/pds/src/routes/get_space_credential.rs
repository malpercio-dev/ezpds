// pattern: Imperative Shell
//
// Gathers: headers (delegation token in Authorization, DPoP proof), JSON body (space,
//          clientAttestation), DB pool + master key
// Processes: space-ref parse → space row (local authority, not deleted) → mint-time DPoP proof
//            → delegation token verify + jti spend → client attestation verify + jti spend
//            → issuance policy (app perimeter, then user) → load the authority's signer
//            → mint the DPoP-bound credential
// Returns: JSON { credential } on success; ApiError on failure
//
// Implements: POST /xrpc/com.atproto.space.getSpaceCredential

use axum::{extract::State, http::HeaderMap, response::Json};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::client_attestation::verify_client_attestation;
use crate::auth::extract_bearer_token;
use crate::auth::space::{
    authorize_credential_request, mint_space_credential, mint_time_dpop_thumbprint, space_host_aud,
    unix_now, verify_delegation_token,
};
use crate::lexicon::LexiconInput;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSpaceCredentialInput {
    /// The space to read (`space-ref`).
    space: String,
    /// Client attestation JWT, required only when the space gates on app identity. Verified
    /// whenever present — an app that names itself is held to that name even where the space
    /// would have admitted it anonymously.
    client_attestation: Option<String>,
}

#[derive(Serialize)]
pub struct GetSpaceCredentialResponse {
    credential: String,
}

/// POST /xrpc/com.atproto.space.getSpaceCredential
///
/// Exchange a delegation token (the request's `Authorization` token) plus a DPoP proof for a
/// space credential bound to the proof's key — the space-authority side of the Atproto Spaces
/// credential flow. This server answers only for spaces anchored on an account it hosts.
pub async fn get_space_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<GetSpaceCredentialInput>,
) -> Result<Json<GetSpaceCredentialResponse>, ApiError> {
    let space = super::space_views::parse_space(&input.space)?;

    let row = crate::db::spaces::get_space(&state.db, &space.uri)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, "failed to load space");
            ApiError::new(ErrorCode::InternalError, "internal server error")
        })?
        .ok_or_else(|| ApiError::new(ErrorCode::SpaceNotFound, "space not found"))?;
    if row.deleted_at.is_some() {
        return Err(ApiError::new(
            ErrorCode::SpaceDeleted,
            "this space has been deleted",
        ));
    }
    // Ordered after the tombstone check for the same reason `require_serviceable_authority` is:
    // `SpaceDeleted` is the one durable renewal signal, and a takedown is reversible, so it must
    // not overwrite it. Refusing here stops a syncer renewing its way past a takedown — the read
    // seam would refuse it anyway, but a 2 h credential should not outlive the operator's action.
    crate::auth::space::require_space_servable(&state, &space).await?;
    // A row with no simplespace config is a space this PDS only hosts repos for; its authority
    // lives elsewhere and is the one to ask.
    if row.policy.is_none() {
        return Err(ApiError::new(
            ErrorCode::SpaceNotFound,
            "this server is not the authority for this space",
        ));
    }
    // Ordered after the tombstone check on purpose: `SpaceDeleted` is the spec's one durable
    // renewal signal, so a deleted space must keep reporting it even once its authority stops
    // being an active account.
    crate::auth::space::require_serviceable_authority(&state, &space).await?;

    // Stateless checks first, so a malformed proof doesn't burn the single-use delegation token.
    let jkt = mint_time_dpop_thumbprint(&headers, &state)?;
    let now = unix_now()?;
    // The delegation token rides the Authorization header as a Bearer token (it is the grant
    // being exchanged, not the DPoP-bound credential being minted).
    let delegation_token = extract_bearer_token(&headers)?;
    let delegation = verify_delegation_token(&state, delegation_token, &space, now).await?;

    // After the delegation token, deliberately: verifying an attestation resolves a
    // caller-named client_id over the network, and gating that behind a valid single-use grant
    // keeps an unauthenticated caller from driving outbound fetches.
    let client_id = match &input.client_attestation {
        Some(attestation) => Some(
            verify_client_attestation(&state, attestation, &space_host_aud(&space), now).await?,
        ),
        None => None,
    };

    authorize_credential_request(&state, &row, &delegation.user_did, client_id.as_deref()).await?;

    // Signed with the authority account's repo key — the key this server publishes as the
    // authority's `#atproto_space` (and `#atproto`).
    let master_key: &[u8; 32] = state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|s| &*s.0)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::ServiceUnavailable,
                "signing key master key not configured",
            )
        })?;
    let signer =
        crate::auth::signing_key::load_repo_signer(&state.db, &row.authority_did, master_key)
            .await?;
    let credential = mint_space_credential(
        |bytes| signer.sign(bytes),
        &row.authority_did,
        &space,
        &jkt,
        now,
    );

    Ok(Json(GetSpaceCredentialResponse { credential }))
}

#[cfg(test)]
mod tests {
    use crate::app::{app, AppState};
    use crate::auth::space::{
        authenticate_space_read, mint_delegation_token, unix_now, SpaceReader, SPACE_CREDENTIAL_TYP,
    };
    use crate::db::dids::seed_did_document;
    use crate::db::spaces::{insert_space, NewSpace};
    use crate::routes::test_utils::{
        body_json, seed_account_with_repo, state_with_master_key, DpopProofKey,
    };
    use crate::space_uri::parse_space_ref;
    use axum::{
        body::Body,
        http::{header::AUTHORIZATION, HeaderMap, HeaderValue, Method, Request, StatusCode},
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use tower::ServiceExt;

    const AUTHORITY: &str = "did:plc:abc234567abc234567abc234";
    const ALICE: &str = "did:plc:alice";
    const BOB: &str = "did:plc:bob";
    const SPACE: &str = "at://did:plc:abc234567abc234567abc234/space/org.example.bucket/self";
    const PATH: &str = "/xrpc/com.atproto.space.getSpaceCredential";
    const HTU: &str = "https://test.example.com/xrpc/com.atproto.space.getSpaceCredential";

    fn did_doc(did: &str, kp: &crypto::P256Keypair) -> serde_json::Value {
        let multibase = kp.key_id.0.strip_prefix("did:key:").unwrap().to_string();
        serde_json::json!({
            "id": did,
            "verificationMethod": [
                { "id": format!("{did}#atproto"), "type": "Multikey", "controller": did, "publicKeyMultibase": multibase },
                { "id": format!("{did}#atproto_space"), "type": "Multikey", "controller": did, "publicKeyMultibase": multibase },
            ],
        })
    }

    /// Seed a local account + cached DID document; return its repo signer.
    async fn seed_identity(state: &AppState, did: &str) -> repo_engine::CommitSigner {
        let kp = seed_account_with_repo(&state.db, did).await;
        seed_did_document(&state.db, did, did_doc(did, &kp)).await;
        repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap()
    }

    async fn seed_space(state: &AppState, policy: &str) {
        seed_configured_space(state, policy, None, "open", None).await;
    }

    async fn seed_configured_space(
        state: &AppState,
        policy: &str,
        managing_app: Option<&str>,
        app_access: &str,
        app_allowed: Option<&str>,
    ) {
        insert_space(
            &state.db,
            &NewSpace {
                uri: SPACE,
                authority_did: AUTHORITY,
                space_type: "org.example.bucket",
                skey: "self",
                policy: Some(policy),
                app_access: Some(app_access),
                app_allowed,
                managing_app,
            },
        )
        .await
        .unwrap();
    }

    async fn add_member(state: &AppState, did: &str) {
        sqlx::query(
            "INSERT INTO space_members (space_uri, member_did, added_at) VALUES (?, ?, 'now')",
        )
        .bind(SPACE)
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
    }

    fn request(delegation: &str, dpop: Option<&str>, space: &str) -> Request<Body> {
        attested_request(delegation, dpop, space, None)
    }

    fn attested_request(
        delegation: &str,
        dpop: Option<&str>,
        space: &str,
        attestation: Option<&str>,
    ) -> Request<Body> {
        let mut b = Request::builder()
            .method("POST")
            .uri(PATH)
            .header(AUTHORIZATION, format!("Bearer {delegation}"))
            .header("content-type", "application/json");
        if let Some(p) = dpop {
            b = b.header("DPoP", p);
        }
        let mut body = serde_json::json!({ "space": space });
        if let Some(attestation) = attestation {
            body["clientAttestation"] = serde_json::Value::String(attestation.to_string());
        }
        b.body(Body::from(body.to_string())).unwrap()
    }

    fn segment(token: &str, i: usize) -> serde_json::Value {
        let b64 = token.split('.').nth(i).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(b64).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn exchanges_a_delegation_token_and_proof_for_a_dpop_bound_credential() {
        let state = state_with_master_key().await;
        seed_identity(&state, AUTHORITY).await;
        let alice = seed_identity(&state, ALICE).await;
        seed_space(&state, "member-list").await;
        add_member(&state, ALICE).await;
        let space = parse_space_ref(SPACE).unwrap();
        let key = DpopProofKey::generate();
        let now = unix_now().unwrap();

        let delegation = mint_delegation_token(|b| alice.sign(b), ALICE, &space, now);
        let proof = key.proof_no_ath("POST", HTU);
        let response = app(state.clone())
            .oneshot(request(&delegation, Some(&proof), SPACE))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let credential = body_json(response).await["credential"]
            .as_str()
            .unwrap()
            .to_string();

        let header = segment(&credential, 0);
        assert_eq!(header["typ"], SPACE_CREDENTIAL_TYP);
        assert_eq!(header["kid"], "#atproto_space");
        let claims = segment(&credential, 1);
        assert_eq!(claims["iss"], AUTHORITY);
        assert_eq!(claims["sub"], SPACE);
        assert_eq!(claims["cnf"]["jkt"], key.thumbprint());
        assert!(claims.get("aud").is_none());
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            7200
        );

        // The minted credential is accepted by the repo-host seam under DPoP with a proof from
        // the bound key — the full round trip.
        let read_path = "/xrpc/com.atproto.space.getRecord";
        let read_proof = key.proof(
            "GET",
            &format!("https://test.example.com{read_path}"),
            &credential,
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {credential}")).unwrap(),
        );
        headers.insert("DPoP", HeaderValue::from_str(&read_proof).unwrap());
        let reader = authenticate_space_read(
            &state,
            &headers,
            &Method::GET,
            &read_path.parse().unwrap(),
            &space,
            ALICE,
        )
        .await
        .unwrap();
        assert!(matches!(reader, SpaceReader::Credential(c) if c.jkt == key.thumbprint()));

        // The delegation token was single-use: replaying the exchange fails.
        let proof = key.proof_no_ath("POST", HTU);
        let response = app(state)
            .oneshot(request(&delegation, Some(&proof), SPACE))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(response).await["error"], "InvalidDelegationToken");
    }

    #[tokio::test]
    async fn refuses_without_proof_non_members_unknown_and_deleted_spaces() {
        let state = state_with_master_key().await;
        seed_identity(&state, AUTHORITY).await;
        let alice = seed_identity(&state, ALICE).await;
        seed_space(&state, "member-list").await;
        let space = parse_space_ref(SPACE).unwrap();
        let key = DpopProofKey::generate();
        let now = unix_now().unwrap();

        // No DPoP proof: refused before the delegation token is spent...
        let delegation = mint_delegation_token(|b| alice.sign(b), ALICE, &space, now);
        let response = app(state.clone())
            .oneshot(request(&delegation, None, SPACE))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // ...so the same token still exchanges once a proof is attached — but alice is not a
        // member, so the policy refuses her.
        let proof = key.proof_no_ath("POST", HTU);
        let response = app(state.clone())
            .oneshot(request(&delegation, Some(&proof), SPACE))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_json(response).await["error"], "UserNotAuthorized");

        // A proof bound to the wrong URL is refused.
        let delegation = mint_delegation_token(|b| alice.sign(b), ALICE, &space, now);
        let wrong = key.proof_no_ath(
            "POST",
            "https://elsewhere.example.com/xrpc/com.atproto.space.getSpaceCredential",
        );
        let response = app(state.clone())
            .oneshot(request(&delegation, Some(&wrong), SPACE))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Unknown space.
        let other = "at://did:plc:abc234567abc234567abc234/space/org.example.bucket/nosuch";
        let delegation = mint_delegation_token(
            |b| alice.sign(b),
            ALICE,
            &parse_space_ref(other).unwrap(),
            now,
        );
        let proof = key.proof_no_ath("POST", HTU);
        let response = app(state.clone())
            .oneshot(request(&delegation, Some(&proof), other))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(response).await["error"], "SpaceNotFound");

        // Deleted space.
        sqlx::query("UPDATE spaces SET deleted_at = 'now' WHERE uri = ?")
            .bind(SPACE)
            .execute(&state.db)
            .await
            .unwrap();
        let delegation = mint_delegation_token(|b| alice.sign(b), ALICE, &space, now);
        let proof = key.proof_no_ath("POST", HTU);
        let response = app(state)
            .oneshot(request(&delegation, Some(&proof), SPACE))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(response).await["error"], "SpaceDeleted");
    }

    // ── Client attestation + the app perimeter ───────────────────────────────

    /// A P-256 client authentication key, its published JWK, and the attestations it signs.
    struct ClientKey(p256::ecdsa::SigningKey);

    impl ClientKey {
        fn generate() -> Self {
            Self(p256::ecdsa::SigningKey::random(&mut rand_core::OsRng))
        }

        fn jwk(&self, kid: &str) -> serde_json::Value {
            let point = self.0.verifying_key().to_encoded_point(false);
            serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
                "kid": kid,
            })
        }

        /// A client attestation as the reference mints one: `typ
        /// atproto-client-attestation+jwt`, `iss` = `sub` = client_id, `aud` = the space host.
        fn attest(&self, client_id: &str, aud: &str, jti: &str, now: u64) -> String {
            self.attest_for(client_id, aud, jti, now, 60)
        }

        /// The same, with an explicit lifetime — for the over-long attestation the mint bound
        /// has to refuse.
        fn attest_for(&self, client_id: &str, aud: &str, jti: &str, now: u64, ttl: u64) -> String {
            use p256::ecdsa::{signature::Signer, Signature};
            let header = serde_json::json!({
                "typ": "atproto-client-attestation+jwt",
                "alg": "ES256",
                "kid": "k1",
            });
            let payload = serde_json::json!({
                "iss": client_id,
                "sub": client_id,
                "aud": aud,
                "iat": now,
                "exp": now + ttl,
                "jti": jti,
            });
            let hdr = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
            let pay = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
            let input = format!("{hdr}.{pay}");
            let sig: Signature = self.0.sign(input.as_bytes());
            format!(
                "{input}.{}",
                URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref() as &[u8])
            )
        }
    }

    /// Serve a client-metadata document publishing `key` inline, and return its client_id.
    ///
    /// Plain http on the loopback is the spec's local-development exception, and the metadata
    /// fetch goes through the SSRF-hardened client — which production builds with loopback
    /// refused, so this branch is only reachable from a test's loopback-permitting client.
    async fn serve_client_metadata(server: &wiremock::MockServer, key: &ClientKey) -> String {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        // Unique per call: the client-resolution negative cache is process-global and keyed by
        // client_id, so a reused loopback port must not alias another test's failed resolution.
        let doc_path = format!("/client-metadata-{}.json", uuid::Uuid::new_v4());
        let client_id = format!("{}{doc_path}", server.uri());
        Mock::given(method("GET"))
            .and(path(doc_path.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "client_id": client_id,
                "redirect_uris": ["https://app.example.com/callback"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": { "keys": [key.jwk("k1")] },
            })))
            .mount(server)
            .await;
        client_id
    }

    /// The `allowList` app-access perimeter, end to end: without a verified client attestation
    /// the space's client_id list is an unenforceable claim, so this is the test that says the
    /// perimeter is real.
    #[tokio::test]
    async fn an_allow_listed_space_mints_only_for_the_attested_client() {
        let state = state_with_master_key().await;
        seed_identity(&state, AUTHORITY).await;
        let alice = seed_identity(&state, ALICE).await;

        let key = ClientKey::generate();
        let server = wiremock::MockServer::start().await;
        let client_id = serve_client_metadata(&server, &key).await;
        seed_configured_space(
            &state,
            "public",
            None,
            "allowList",
            Some(&serde_json::json!([client_id]).to_string()),
        )
        .await;

        let space = parse_space_ref(SPACE).unwrap();
        let proof_key = DpopProofKey::generate();
        let now = unix_now().unwrap();
        let aud = format!("{AUTHORITY}#atproto_space_host");
        let mint = |attestation: Option<String>| {
            let state = state.clone();
            let delegation = mint_delegation_token(|b| alice.sign(b), ALICE, &space, now);
            let proof = proof_key.proof_no_ath("POST", HTU);
            async move {
                app(state)
                    .oneshot(attested_request(
                        &delegation,
                        Some(&proof),
                        SPACE,
                        attestation.as_deref(),
                    ))
                    .await
                    .unwrap()
            }
        };

        // No attestation: the space cannot tell which app is asking, so it refuses on the app.
        let response = mint(None).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_json(response).await["error"], "AppNotAuthorized");

        // An attestation the allow-listed client actually signed mints the credential.
        let response = mint(Some(key.attest(&client_id, &aud, "att-1", now))).await;
        assert_eq!(response.status(), StatusCode::OK);

        // Attestations are single-use: the same `jti` again is refused (with a fresh delegation
        // token, so this is the attestation's replay check and not the token's).
        let response = mint(Some(key.attest(&client_id, &aud, "att-1", now))).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await["error"],
            "InvalidClientAttestation"
        );

        // One minted for another authority's space host cannot be replayed here.
        let elsewhere = key.attest(
            &client_id,
            "did:plc:elsewhere#atproto_space_host",
            "att-2",
            now,
        );
        let response = mint(Some(elsewhere)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await["error"],
            "InvalidClientAttestation"
        );

        // A JWT the client's published key did not sign is not that client, whatever it claims.
        let imposter = ClientKey::generate();
        let response = mint(Some(imposter.attest(&client_id, &aud, "att-3", now))).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await["error"],
            "InvalidClientAttestation"
        );

        // An attestation whose lifetime outruns the replay row's retention horizon is refused
        // outright. Retaining the `jti` for less than the token's own validity would make
        // "single-use" expire with the row: once swept, the very same attestation replays for
        // the rest of its life. The bound therefore falls on what is admitted, not on how long
        // the row is kept.
        let long_lived = key.attest_for(&client_id, &aud, "att-4", now, 60 * 60);
        let response = mint(Some(long_lived)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await["error"],
            "InvalidClientAttestation"
        );
    }

    /// The `managing-app` policy hands the per-user decision to the app the config names, and
    /// denies whenever it cannot get an answer — the one policy that defers its decision must
    /// never become the one that skips it.
    #[tokio::test]
    async fn managing_app_policy_defers_to_the_app_and_fails_closed() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let state = state_with_master_key().await;
        seed_identity(&state, AUTHORITY).await;
        let alice = seed_identity(&state, ALICE).await;
        let bob = seed_identity(&state, BOB).await;

        const APP: &str = "did:web:managing.example";
        let server = MockServer::start().await;
        let check = "/xrpc/com.atproto.simplespace.checkUserAccess";
        // Service auth is what tells the app who is asking; a check reached without it would
        // authorize anyone who found the URL.
        Mock::given(method("GET"))
            .and(path(check))
            .and(query_param("space", SPACE))
            .and(query_param("user", ALICE))
            .and(wiremock::matchers::header_regex(
                "authorization",
                "^Bearer ",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "authorized": true })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(check))
            .and(query_param("user", BOB))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "authorized": false })),
            )
            .mount(&server)
            .await;
        seed_did_document(
            &state.db,
            APP,
            serde_json::json!({
                "id": APP,
                "service": [{
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": server.uri(),
                }],
            }),
        )
        .await;
        seed_configured_space(&state, "managing-app", Some(APP), "open", None).await;

        let space = parse_space_ref(SPACE).unwrap();
        let proof_key = DpopProofKey::generate();
        let now = unix_now().unwrap();
        let mint = |did: &'static str, signer: &repo_engine::CommitSigner| {
            let state = state.clone();
            let delegation = mint_delegation_token(|b| signer.sign(b), did, &space, now);
            let proof = proof_key.proof_no_ath("POST", HTU);
            async move {
                app(state)
                    .oneshot(request(&delegation, Some(&proof), SPACE))
                    .await
                    .unwrap()
            }
        };

        let response = mint(ALICE, &alice).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the app authorized alice"
        );

        let response = mint(BOB, &bob).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_json(response).await["error"], "UserNotAuthorized");

        // A managing app that publishes no endpoint for the named service cannot be asked, and
        // an unaskable app denies rather than being skipped.
        sqlx::query("UPDATE spaces SET managing_app = ? WHERE uri = ?")
            .bind("did:web:managing.example#nosuch")
            .bind(SPACE)
            .execute(&state.db)
            .await
            .unwrap();
        let response = mint(ALICE, &alice).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_json(response).await["error"], "UserNotAuthorized");
    }

    #[tokio::test]
    async fn public_policy_admits_anyone_and_the_authority_always_may() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY).await;
        let alice = seed_identity(&state, ALICE).await;
        seed_space(&state, "public").await;
        let space = parse_space_ref(SPACE).unwrap();
        let key = DpopProofKey::generate();
        let now = unix_now().unwrap();

        for (did, signer) in [(ALICE, &alice), (AUTHORITY, &authority)] {
            let delegation = mint_delegation_token(|b| signer.sign(b), did, &space, now);
            let proof = key.proof_no_ath("POST", HTU);
            let response = app(state.clone())
                .oneshot(request(&delegation, Some(&proof), SPACE))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{did}");
        }
    }
}
