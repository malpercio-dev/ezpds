// pattern: Imperative Shell
//
// Gathers: JSON body (space, credentialKey, delegationToken?, clientAttestation?, notify?), DB
//          pool + master key
// Processes: space-ref parse → credentialKey is a P-256 did:key → notify endpoint shape →
//            authority is an active local account → space row (not deleted, not taken down,
//            ours) → delegation token verify + jti spend (when present) → client attestation
//            verify + jti spend (when present) → issuance policy (app perimeter, then account;
//            a refusal withdraws the registration) → a new registration: the per-space cap, then
//            confirmRegistration → load the authority's signer → mint the credential bound to
//            credentialKey → register until the credential's exp → read spaceRev
// Returns: JSON { credential, spaceRev? } on success; ApiError on failure
//
// Implements: POST /xrpc/com.atproto.space.authorizeSpaceSync

use axum::{extract::State, response::Json};
use custos_core::CoreState;
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::auth::client_attestation::verify_client_attestation;
use crate::auth::space::{
    authorize_credential_request, mint_space_credential, require_active_space_host,
    require_space_servable, space_host_aud, unix_now, verify_delegation_token,
    SPACE_CREDENTIAL_TTL_SECS,
};
use crate::db::space_notify::Registration;
use crate::policy::SpacePolicy;
use custos_core::lexicon::LexiconInput;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeSpaceSyncInput {
    /// The space to sync (`space-ref`).
    space: String,
    /// The P-256 `did:key` the credential is bound to (`cnf.kid`). Possession is proven on each
    /// use of the credential, not here.
    credential_key: String,
    /// From the account's `getDelegationToken`, required unless the policy admits a request
    /// that names no account.
    delegation_token: Option<String>,
    /// Client attestation JWT, required only when the space gates on app identity. Verified
    /// whenever present — an app that names itself is held to that name even where the space
    /// would have admitted it anonymously.
    client_attestation: Option<String>,
    /// Register `endpoint` for `notifySpaceUpdate` until the minted credential expires.
    notify: Option<NotifyInput>,
}

#[derive(Deserialize)]
pub struct NotifyInput {
    endpoint: String,
    token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeSpaceSyncResponse {
    credential: String,
    /// Omitted before the space's first update.
    #[serde(skip_serializing_if = "Option::is_none")]
    space_rev: Option<String>,
}

/// POST /xrpc/com.atproto.space.authorizeSpaceSync
///
/// Mint a space credential bound to `credentialKey` — the space-authority side of the Atproto
/// Spaces credential flow — and report the space's current revision. Takes no request
/// authorization: the delegation token and client attestation ride the body. This server
/// answers only for spaces anchored on an account it hosts.
///
/// With `notify`, the call also registers the syncer's endpoint for `notifySpaceUpdate` until the
/// credential expires. The endpoint must be an https URL on a domain host, checked before
/// anything is sent to it. A new `(endpoint, token)` is confirmed first, outside any database
/// transaction, and refused past [`MAX_REGISTRATIONS`](crate::space_notify::MAX_REGISTRATIONS)
/// active ones per space (`TooManyRegistrations`, Custos's own bound).
pub async fn authorize_space_sync(
    State(state): State<CoreState>,
    LexiconInput(input): LexiconInput<AuthorizeSpaceSyncInput>,
) -> Result<Json<AuthorizeSpaceSyncResponse>, ApiError> {
    let space = crate::views::parse_space(&input.space)?;

    if !matches!(
        crypto::did_key_curve(&crypto::DidKeyUri(input.credential_key.clone())),
        Ok(crypto::DidKeyCurve::P256)
    ) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "credentialKey must be a P-256 did:key",
        ));
    }
    let registration = input.notify.map(|notify| Registration {
        endpoint: notify.endpoint,
        token: notify.token,
    });
    if let Some(registration) = &registration {
        custos_core::identity::proxy::validate_notify_endpoint(
            &registration.endpoint,
            state.allow_loopback_proxy_targets,
        )?;
    }

    // The authority's status comes first, as the reference orders it: a suspended or
    // deactivated authority answers with its status even for a space it has deleted.
    require_active_space_host(&state, &space).await?;

    let row = crate::db::spaces::get_space(&state.db, &space.uri)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, "failed to load space");
            ApiError::new(ErrorCode::InternalError, "internal server error")
        })?
        .ok_or_else(|| ApiError::new(ErrorCode::SpaceNotFound, "space not found"))?;
    // `SpaceDeleted` is answered whatever the request carries: it is how a syncer that missed
    // the deletion notice finds out, and a public space's syncer may hold no delegation token.
    if row.deleted_at.is_some() {
        return Err(ApiError::new(
            ErrorCode::SpaceDeleted,
            "this space has been deleted",
        ));
    }
    // After the tombstone check: `SpaceDeleted` is the one durable renewal signal, and a takedown
    // is reversible, so it must not overwrite it. Refusing here stops a syncer renewing its way
    // past a takedown — the read seam would refuse it anyway, but a credential should not outlive
    // the operator's action.
    require_space_servable(&state, &space).await?;
    // A row with no policy is a space this PDS only hosts repos for; its authority lives
    // elsewhere and is the one to ask.
    let Some(policy) = row.space_policy()? else {
        return Err(ApiError::new(
            ErrorCode::SpaceNotFound,
            "this server is not the authority for this space",
        ));
    };

    let now = unix_now()?;
    let account = match &input.delegation_token {
        Some(token) => Some(
            verify_delegation_token(&state, token, &space, now)
                .await?
                .user_did,
        ),
        None => None,
    };

    // After the delegation token when there is one, so a request carrying a bad grant cannot
    // drive the attestation's outbound client_id resolution. A request with no grant can — a
    // `publicRead` space's `allowedApps` needs the attestation — which is the exposure PAR's
    // client-metadata fetch already has, through the same SSRF-hardened client.
    let client_id = match &input.client_attestation {
        Some(attestation) => Some(
            verify_client_attestation(&state, attestation, &space_host_aud(&space), now).await?,
        ),
        None => None,
    };

    let internal = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space.uri, "failed to update notify registration");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    };

    if let Err(refusal) = authorize_credential_request(
        &state,
        &row,
        &policy,
        account.as_ref().map(common::Did::as_str),
        client_id.as_deref(),
    )
    .await
    {
        // A refusal withdraws the registration it carries, so a syncer that has lost access stops
        // being notified. A failure to decide leaves it in place. Custos answers an unreachable
        // managing app with the same `AccountNotAuthorized` as a refusing one, so under a
        // managedspace only the app perimeter is a definite refusal.
        let definite = match refusal.code() {
            ErrorCode::AppNotAuthorized => true,
            ErrorCode::AccountNotAuthorized => !matches!(policy, SpacePolicy::Managed(_)),
            _ => false,
        };
        if let (true, Some(registration)) = (definite, &registration) {
            crate::db::space_notify::remove_registration(&state.db, &space.uri, registration)
                .await
                .map_err(internal)?;
        }
        return Err(refusal);
    }

    // Only a new registration is confirmed, and only one that fits under the cap. A known one,
    // lapsed or not, is renewed as it stands. The count here only spares a full space the
    // outbound call; the cap itself is enforced atomically by `put_registration`.
    let too_many = || {
        ApiError::new(
            ErrorCode::TooManyRegistrations,
            "this space holds its maximum of notification registrations",
        )
    };
    if let Some(registration) = &registration {
        crate::db::space_notify::prune_lapsed_registrations(&state.db, &space.uri)
            .await
            .map_err(internal)?;
        let known =
            crate::db::space_notify::registration_exists(&state.db, &space.uri, registration)
                .await
                .map_err(internal)?;
        if !known {
            let active = crate::db::space_notify::count_active_registrations(&state.db, &space.uri)
                .await
                .map_err(internal)?;
            if active >= crate::space_notify::MAX_REGISTRATIONS {
                return Err(too_many());
            }
            crate::space_notify::confirm_registration(&state, &space, registration).await?;
        }
    }

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
        custos_core::auth::signing_key::load_repo_signer(&state.db, &row.authority_did, master_key)
            .await?;
    let credential = mint_space_credential(
        |bytes| signer.sign(bytes),
        &row.authority_did,
        &space,
        &input.credential_key,
        now,
    );

    let mut space_rev = row.last_space_rev;
    if let Some(registration) = &registration {
        // Renewed by each authorization, and lapsing with this credential, no grace period.
        use crate::db::space_notify::PutRegistration;
        match crate::db::space_notify::put_registration(
            &state.db,
            &space.uri,
            registration,
            now + SPACE_CREDENTIAL_TTL_SECS,
            crate::space_notify::MAX_REGISTRATIONS,
        )
        .await
        .map_err(internal)?
        {
            PutRegistration::Written => {}
            PutRegistration::Full => return Err(too_many()),
            PutRegistration::SpaceGone => {
                return Err(ApiError::new(
                    ErrorCode::SpaceDeleted,
                    "this space has been deleted",
                ))
            }
        }
        // Read after registering, so any update past this revision is notified.
        space_rev = crate::db::spaces::get_space(&state.db, &space.uri)
            .await
            .map_err(internal)?
            .and_then(|row| row.last_space_rev);
    }

    Ok(Json(AuthorizeSpaceSyncResponse {
        credential,
        space_rev,
    }))
}

#[cfg(test)]
mod tests {
    use crate::auth::space::{
        authenticate_space_read, mint_delegation_token, unix_now, SpaceReader, SPACE_CREDENTIAL_TYP,
    };
    use crate::test_support::test_app as app;
    use crate::test_support::{
        body_json, seed_account_with_repo, seed_authority_space, state_with_master_key, SpaceSigKey,
    };
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use custos_core::space_uri::parse_space_ref;
    use custos_core::CoreState;
    use custos_db::dids::seed_did_document;
    use p256::elliptic_curve::Generate as _;
    use tower::ServiceExt;

    const AUTHORITY: &str = "did:plc:abc234567abc234567abc234";
    const ALICE: &str = "did:plc:alice";
    const BOB: &str = "did:plc:bob";
    const SPACE: &str = "at:space/did:plc:abc234567abc234567abc234/org.example.bucket/self";
    const PATH: &str = "/xrpc/com.atproto.space.authorizeSpaceSync";

    fn did_doc(did: &str, kp: &crypto::P256Keypair) -> serde_json::Value {
        let multibase = kp.key_id.0.strip_prefix("did:key:").unwrap().to_string();
        serde_json::json!({
            "id": did,
            "verificationMethod": [
                { "id": format!("{did}#atproto"), "type": "Multikey", "controller": did, "publicKeyMultibase": multibase },
            ],
        })
    }

    /// Seed a local account + cached DID document; return its repo signer.
    async fn seed_identity(state: &CoreState, did: &str) -> repo_engine::CommitSigner {
        let kp = seed_account_with_repo(&state.db, did).await;
        seed_did_document(&state.db, did, did_doc(did, &kp)).await;
        repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap()
    }

    /// Seed the space under `policy` (lexicon JSON, normalized as `createSpace` would).
    async fn seed_space(state: &CoreState, policy: serde_json::Value) {
        let policy = crate::policy::SpacePolicy::from_lex(&policy).unwrap();
        seed_authority_space(&state.db, SPACE, &policy.to_json().to_string()).await;
    }

    fn memberspace(public_read: bool) -> serde_json::Value {
        serde_json::json!({ "$type": crate::policy::MEMBERSPACE, "publicRead": public_read })
    }

    async fn add_member(state: &CoreState, did: &str) {
        sqlx::query(
            "INSERT INTO space_members (space_uri, member_did, added_at) VALUES (?, ?, 'now')",
        )
        .bind(SPACE)
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
    }

    /// The request body: `key`'s did:key as `credentialKey`, plus whichever tokens are given.
    fn request(
        space: &str,
        key: &SpaceSigKey,
        delegation: Option<&str>,
        attestation: Option<&str>,
    ) -> Request<Body> {
        let mut body = serde_json::json!({ "space": space, "credentialKey": key.key_id() });
        if let Some(delegation) = delegation {
            body["delegationToken"] = delegation.into();
        }
        if let Some(attestation) = attestation {
            body["clientAttestation"] = attestation.into();
        }
        Request::builder()
            .method("POST")
            .uri(PATH)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn error(response: axum::response::Response) -> (StatusCode, String) {
        let status = response.status();
        let body = body_json(response).await;
        (
            status,
            body["error"].as_str().unwrap_or_default().to_string(),
        )
    }

    fn segment(token: &str, i: usize) -> serde_json::Value {
        let b64 = token.split('.').nth(i).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(b64).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn exchanges_a_delegation_token_for_a_credential_bound_to_the_named_key() {
        let state = state_with_master_key().await;
        seed_identity(&state, AUTHORITY).await;
        let alice = seed_identity(&state, ALICE).await;
        seed_space(&state, memberspace(false)).await;
        add_member(&state, ALICE).await;
        let space = parse_space_ref(SPACE).unwrap();
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();

        let delegation = mint_delegation_token(|b| alice.sign(b), ALICE, &space, now);
        let response = app(state.clone())
            .oneshot(request(SPACE, &key, Some(&delegation), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert!(
            json.get("spaceRev").is_none(),
            "omitted before the space's first update"
        );
        let credential = json["credential"].as_str().unwrap().to_string();

        let header = segment(&credential, 0);
        assert_eq!(header["typ"], SPACE_CREDENTIAL_TYP);
        assert_eq!(header["kid"], "#atproto");
        let claims = segment(&credential, 1);
        assert_eq!(claims["iss"], AUTHORITY);
        assert_eq!(claims["sub"], SPACE);
        assert_eq!(claims["cnf"], serde_json::json!({ "kid": key.key_id() }));
        assert!(claims.get("aud").is_none());
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            600
        );

        // The minted credential is accepted by the repo-host seam when signed by the bound key
        // — the full round trip.
        let reader = authenticate_space_read(
            &state,
            &key.credential_headers(&credential, ALICE),
            &Method::GET,
            &"/xrpc/com.atproto.space.getRecord".parse().unwrap(),
            &space,
            ALICE,
        )
        .await
        .unwrap();
        assert!(matches!(reader, SpaceReader::Credential(c) if c.kid == key.key_id()));

        // The delegation token was single-use: replaying the exchange fails.
        let response = app(state.clone())
            .oneshot(request(SPACE, &key, Some(&delegation), None))
            .await
            .unwrap();
        assert_eq!(
            error(response).await,
            (StatusCode::BAD_REQUEST, "InvalidDelegationToken".into())
        );

        // The space's current revision rides the answer once there is one.
        sqlx::query("UPDATE spaces SET last_space_rev = '3kabc2zv3ok2a' WHERE uri = ?")
            .bind(SPACE)
            .execute(&state.db)
            .await
            .unwrap();
        let delegation = mint_delegation_token(|b| alice.sign(b), ALICE, &space, now);
        let response = app(state)
            .oneshot(request(SPACE, &key, Some(&delegation), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["spaceRev"], "3kabc2zv3ok2a");
    }

    #[tokio::test]
    async fn refuses_bad_keys_non_members_unknown_and_deleted_spaces() {
        let state = state_with_master_key().await;
        seed_identity(&state, AUTHORITY).await;
        let alice = seed_identity(&state, ALICE).await;
        seed_space(&state, memberspace(false)).await;
        let space = parse_space_ref(SPACE).unwrap();
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let send = |req: Request<Body>| {
            let state = state.clone();
            async move { error(app(state).oneshot(req).await.unwrap()).await }
        };

        // A credentialKey that is not a P-256 did:key is refused before the token is spent...
        let delegation = mint_delegation_token(|b| alice.sign(b), ALICE, &space, now);
        for bad in [
            "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
            "not-a-key",
        ] {
            let body = serde_json::json!({
                "space": SPACE, "credentialKey": bad, "delegationToken": delegation,
            });
            let req = Request::builder()
                .method("POST")
                .uri(PATH)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            assert_eq!(send(req).await.0, StatusCode::BAD_REQUEST, "{bad}");
        }
        // ...so the same token still exchanges — but alice is not a member, so the policy refuses
        // her, as it refuses a request naming no account at all.
        assert_eq!(
            send(request(SPACE, &key, Some(&delegation), None)).await,
            (StatusCode::BAD_REQUEST, "AccountNotAuthorized".into())
        );
        assert_eq!(
            send(request(SPACE, &key, None, None)).await,
            (StatusCode::BAD_REQUEST, "AccountNotAuthorized".into())
        );

        // Unknown space.
        let other = "at:space/did:plc:abc234567abc234567abc234/org.example.bucket/nosuch";
        let delegation = mint_delegation_token(
            |b| alice.sign(b),
            ALICE,
            &parse_space_ref(other).unwrap(),
            now,
        );
        assert_eq!(
            send(request(other, &key, Some(&delegation), None)).await,
            (StatusCode::BAD_REQUEST, "SpaceNotFound".into())
        );

        // Deleted space, answered whether or not the request carries a delegation token.
        sqlx::query("UPDATE spaces SET deleted_at = 'now' WHERE uri = ?")
            .bind(SPACE)
            .execute(&state.db)
            .await
            .unwrap();
        let delegation = mint_delegation_token(|b| alice.sign(b), ALICE, &space, now);
        for delegation in [Some(delegation.as_str()), None] {
            assert_eq!(
                send(request(SPACE, &key, delegation, None)).await,
                (StatusCode::BAD_REQUEST, "SpaceDeleted".into())
            );
        }
    }

    /// The authority's status gates the mint: `RepoTakendown` / `RepoDeactivated`, as the
    /// reference's `assertActiveSpaceHost` answers, and `SpaceNotFound` with no local account.
    #[tokio::test]
    async fn the_authoritys_status_gates_the_mint() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY).await;
        seed_space(&state, memberspace(true)).await;
        let space = parse_space_ref(SPACE).unwrap();
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let send = || {
            let state = state.clone();
            let delegation = mint_delegation_token(|b| authority.sign(b), AUTHORITY, &space, now);
            let req = request(SPACE, &key, Some(&delegation), None);
            async move { error(app(state).oneshot(req).await.unwrap()).await }
        };

        assert_eq!(send().await.0, StatusCode::OK);
        for (column, code) in [
            ("taken_down_at", "RepoTakendown"),
            ("suspended_at", "RepoTakendown"),
            ("deactivated_at", "RepoDeactivated"),
        ] {
            sqlx::query(&format!(
                "UPDATE accounts SET {column} = 'now' WHERE did = ?"
            ))
            .bind(AUTHORITY)
            .execute(&state.db)
            .await
            .unwrap();
            assert_eq!(
                send().await,
                (StatusCode::BAD_REQUEST, code.into()),
                "{column}"
            );
            sqlx::query(&format!(
                "UPDATE accounts SET {column} = NULL WHERE did = ?"
            ))
            .bind(AUTHORITY)
            .execute(&state.db)
            .await
            .unwrap();
        }

        // A space whose authority has no account here is not ours to answer for.
        let foreign = "at:space/did:plc:elsewhere/org.example.bucket/self";
        let req = request(foreign, &key, None, None);
        assert_eq!(
            error(app(state).oneshot(req).await.unwrap()).await,
            (StatusCode::BAD_REQUEST, "SpaceNotFound".into())
        );
    }

    // ── Client attestation + the app perimeter ───────────────────────────────

    /// A P-256 client authentication key, its published JWK, and the attestations it signs.
    struct ClientKey(p256::ecdsa::SigningKey);

    impl ClientKey {
        fn generate() -> Self {
            Self(p256::ecdsa::SigningKey::generate())
        }

        fn jwk(&self, kid: &str) -> serde_json::Value {
            let point = self.0.verifying_key().to_sec1_point(false);
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

    /// Memberspace's `allowedApps` perimeter, end to end: without a verified client attestation
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
        seed_space(
            &state,
            serde_json::json!({
                "$type": crate::policy::MEMBERSPACE,
                "publicRead": true,
                "allowedApps": [client_id],
            }),
        )
        .await;

        let space = parse_space_ref(SPACE).unwrap();
        let sig_key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let aud = format!("{AUTHORITY}#atproto_pds");
        let mint = |attestation: Option<String>| {
            let state = state.clone();
            let delegation = mint_delegation_token(|b| alice.sign(b), ALICE, &space, now);
            let req = request(SPACE, &sig_key, Some(&delegation), attestation.as_deref());
            async move { app(state).oneshot(req).await.unwrap() }
        };

        // No attestation: the space cannot tell which app is asking, so it refuses on the app.
        assert_eq!(
            error(mint(None).await).await,
            (StatusCode::BAD_REQUEST, "AppNotAuthorized".into())
        );

        // An attestation the allow-listed client actually signed mints the credential.
        let response = mint(Some(key.attest(&client_id, &aud, "att-1", now))).await;
        assert_eq!(response.status(), StatusCode::OK);

        // `publicRead` admits a request naming no account, but `allowedApps` still holds.
        let anonymous = |attestation: Option<String>| {
            let req = request(SPACE, &sig_key, None, attestation.as_deref());
            let state = state.clone();
            async move { app(state).oneshot(req).await.unwrap() }
        };
        assert_eq!(
            error(anonymous(None).await).await,
            (StatusCode::BAD_REQUEST, "AppNotAuthorized".into())
        );
        let response = anonymous(Some(key.attest(&client_id, &aud, "att-anon", now))).await;
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
        let elsewhere = key.attest(&client_id, "did:plc:elsewhere#atproto_pds", "att-2", now);
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

    /// A managedspace hands the per-account decision to its managing app's `checkAccess`, and
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
        let check = "/xrpc/com.atproto.managedspace.checkAccess";
        // Service auth is what tells the app who is asking; a check reached without it would
        // authorize anyone who found the URL.
        Mock::given(method("GET"))
            .and(path(check))
            .and(query_param("space", SPACE))
            .and(query_param("repo", ALICE))
            .and(wiremock::matchers::header_regex(
                "authorization",
                "^Bearer ",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "read": true, "write": false })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(check))
            .and(query_param("repo", BOB))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "read": false, "write": true })),
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
        seed_space(
            &state,
            serde_json::json!({
                "$type": crate::policy::MANAGEDSPACE,
                "managingApp": format!("{APP}#atproto_pds"),
            }),
        )
        .await;

        let space = parse_space_ref(SPACE).unwrap();
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let mint = |did: &'static str, signer: &repo_engine::CommitSigner| {
            let state = state.clone();
            let delegation = mint_delegation_token(|b| signer.sign(b), did, &space, now);
            let req = request(SPACE, &key, Some(&delegation), None);
            async move { app(state).oneshot(req).await.unwrap() }
        };

        let response = mint(ALICE, &alice).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the app authorized alice"
        );

        assert_eq!(
            error(mint(BOB, &bob).await).await,
            (StatusCode::BAD_REQUEST, "AccountNotAuthorized".into())
        );

        // A managing app that publishes no endpoint for the named service cannot be asked, and
        // an unaskable app denies rather than being skipped.
        sqlx::query(
            "UPDATE spaces SET policy = json_set(policy, '$.managingApp', ?) WHERE uri = ?",
        )
        .bind("did:web:managing.example#nosuch")
        .bind(SPACE)
        .execute(&state.db)
        .await
        .unwrap();
        assert_eq!(
            error(mint(ALICE, &alice).await).await,
            (StatusCode::BAD_REQUEST, "AccountNotAuthorized".into())
        );
    }

    #[tokio::test]
    async fn public_policy_admits_anyone_and_the_authority_always_may() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY).await;
        let alice = seed_identity(&state, ALICE).await;
        seed_space(&state, memberspace(true)).await;
        let space = parse_space_ref(SPACE).unwrap();
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();

        for (did, signer) in [(ALICE, &alice), (AUTHORITY, &authority)] {
            let delegation = mint_delegation_token(|b| signer.sign(b), did, &space, now);
            let response = app(state.clone())
                .oneshot(request(SPACE, &key, Some(&delegation), None))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{did}");
        }

        // `publicRead` mints without a delegation token, and the credential reads.
        let response = app(state.clone())
            .oneshot(request(SPACE, &key, None, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let credential = body_json(response).await["credential"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(authenticate_space_read(
            &state,
            &key.credential_headers(&credential, ALICE),
            &Method::GET,
            &"/xrpc/com.atproto.space.getRecord".parse().unwrap(),
            &space,
            ALICE,
        )
        .await
        .is_ok());
    }
}
