// pattern: Imperative Shell
//
// Gathers: headers (delegation token in Authorization, DPoP proof), JSON body (space,
//          clientAttestation), DB pool + master key
// Processes: space-ref parse → space row (local authority, not deleted) → mint-time DPoP proof
//            → delegation token verify + jti spend → issuance policy → load the authority's
//            signer → mint the DPoP-bound credential
// Returns: JSON { credential } on success; ApiError on failure
//
// Implements: POST /xrpc/com.atproto.space.getSpaceCredential

use axum::{extract::State, http::HeaderMap, response::Json};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extract_bearer_token;
use crate::auth::space::{
    authorize_credential_request, mint_space_credential, mint_time_dpop_thumbprint, unix_now,
    verify_delegation_token, SpaceRef,
};
use crate::lexicon::LexiconInput;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSpaceCredentialInput {
    /// The space to read (`space-ref`).
    space: String,
    /// Client attestation JWT, required only when the space gates on app identity. Attestation
    /// verification lands with the allow-list app-access work; until then a space that needs
    /// one refuses to mint, and an unsolicited attestation is ignored.
    #[allow(dead_code)]
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
    let space = SpaceRef::parse(&input.space)
        .map_err(|msg| ApiError::new(ErrorCode::InvalidRequest, msg))?;

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
    // A row with no simplespace config is a space this PDS only hosts repos for; its authority
    // lives elsewhere and is the one to ask.
    if row.policy.is_none() {
        return Err(ApiError::new(
            ErrorCode::SpaceNotFound,
            "this server is not the authority for this space",
        ));
    }

    // Stateless checks first, so a malformed proof doesn't burn the single-use delegation token.
    let jkt = mint_time_dpop_thumbprint(&headers, &state)?;
    let now = unix_now()?;
    // The delegation token rides the Authorization header as a Bearer token (it is the grant
    // being exchanged, not the DPoP-bound credential being minted).
    let delegation_token = extract_bearer_token(&headers)?;
    let delegation = verify_delegation_token(&state, delegation_token, &space, now).await?;

    authorize_credential_request(&state.db, &row, &delegation.user_did).await?;

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
        authenticate_space_read, mint_delegation_token, unix_now, SpaceReader, SpaceRef,
        SPACE_CREDENTIAL_TYP,
    };
    use crate::db::dids::seed_did_document;
    use crate::db::spaces::{insert_space, NewSpace};
    use crate::routes::test_utils::{
        body_json, seed_account_with_repo, state_with_master_key, DpopProofKey,
    };
    use axum::{
        body::Body,
        http::{header::AUTHORIZATION, HeaderMap, HeaderValue, Method, Request, StatusCode},
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use tower::ServiceExt;

    const AUTHORITY: &str = "did:plc:abc234567abc234567abc234";
    const ALICE: &str = "did:plc:alice";
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
        insert_space(
            &state.db,
            &NewSpace {
                uri: SPACE,
                authority_did: AUTHORITY,
                space_type: "org.example.bucket",
                skey: "self",
                policy: Some(policy),
                app_access: Some("open"),
                managing_app: None,
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
        let mut b = Request::builder()
            .method("POST")
            .uri(PATH)
            .header(AUTHORIZATION, format!("Bearer {delegation}"))
            .header("content-type", "application/json");
        if let Some(p) = dpop {
            b = b.header("DPoP", p);
        }
        b.body(Body::from(
            serde_json::json!({ "space": space }).to_string(),
        ))
        .unwrap()
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
        let space = SpaceRef::parse(SPACE).unwrap();
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
            &headers,
            &Method::GET,
            &read_path.parse().unwrap(),
            &state,
            &space,
            Some(ALICE),
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
        let space = SpaceRef::parse(SPACE).unwrap();
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
            &SpaceRef::parse(other).unwrap(),
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

    #[tokio::test]
    async fn public_policy_admits_anyone_and_the_authority_always_may() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY).await;
        let alice = seed_identity(&state, ALICE).await;
        seed_space(&state, "public").await;
        let space = SpaceRef::parse(SPACE).unwrap();
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
