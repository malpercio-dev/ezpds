// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (JWT extractor), query params (space), DB pool + master key
// Processes: OAuth-session check → space-ref parse → covering `space:` read grant → load the
//            account's repo signer → mint the delegation token
// Returns: JSON { token } on success; ApiError on failure
//
// Implements: GET /xrpc/com.atproto.space.getDelegationToken

use axum::{extract::State, response::Json};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::auth::oauth_scopes::{require_space, SpaceOp, SpaceRequest};
use crate::auth::space::{mint_delegation_token, unix_now};

#[derive(Deserialize)]
pub struct GetDelegationTokenQuery {
    /// The space to delegate for (`space-ref`).
    space: String,
}

#[derive(Serialize)]
pub struct GetDelegationTokenResponse {
    token: String,
}

/// GET /xrpc/com.atproto.space.getDelegationToken
///
/// Mint a delegation token for `space` on behalf of the authenticated account — the user's side
/// of the Atproto Spaces credential flow. The app presents it (with a DPoP proof) to the space
/// authority's `getSpaceCredential`. Requires an OAuth (or full-access) session whose grant
/// covers `read` on the space; the token says nothing about membership, which is the
/// authority's call. This PDS need not know the space at all.
pub async fn get_delegation_token(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    crate::lexicon::LexiconParams(params): crate::lexicon::LexiconParams<GetDelegationTokenQuery>,
) -> Result<Json<GetDelegationTokenResponse>, ApiError> {
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InsufficientScope,
            "getDelegationToken requires an OAuth session with a covering space: read grant",
        ));
    }

    crate::auth::space::require_serviceable_caller(&state, &user.did).await?;

    let space = super::space_views::parse_space(&params.space)?;

    // `read` is all-or-nothing at the space boundary and is what confers getDelegationToken;
    // `read_self` does not. The declaration's collections are irrelevant to a read.
    require_space(
        &user.scope_claim,
        &SpaceRequest {
            space_type: &space.space_type,
            authority: &space.authority,
            skey: &space.skey,
            op: SpaceOp::Read,
            account_did: &user.did,
            declared_collections: &[],
        },
    )?;

    // Signed with the account's `#atproto` repo key, like service auth; the authority verifies
    // it against the key in the user's DID document.
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
        crate::auth::signing_key::load_repo_signer(&state.db, &user.did, master_key).await?;
    let token = mint_delegation_token(|bytes| signer.sign(bytes), &user.did, &space, unix_now()?);

    Ok(Json(GetDelegationTokenResponse { token }))
}

#[cfg(test)]
mod tests {
    use crate::app::app;
    use crate::auth::space::DELEGATION_TOKEN_TYP;
    use crate::routes::test_utils::{
        access_jwt, app_pass_jwt, body_json, scoped_access_jwt, seed_account_with_repo,
        state_with_master_key,
    };
    use axum::{
        body::Body,
        http::{header::AUTHORIZATION, Request, StatusCode},
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use tower::ServiceExt;

    const ALICE: &str = "did:plc:alice";
    const SPACE: &str = "at://did:plc:abc234567abc234567abc234/space/org.example.bucket/self";

    fn request(token: &str, space: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(format!(
                "/xrpc/com.atproto.space.getDelegationToken?space={}",
                urlencoding::encode(space)
            ))
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    fn segment(token: &str, i: usize) -> serde_json::Value {
        let b64 = token.split('.').nth(i).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(b64).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn mints_a_delegation_token_for_a_covering_grant() {
        let state = state_with_master_key().await;
        let kp = seed_account_with_repo(&state.db, ALICE).await;
        let token = scoped_access_jwt(
            &state.jwt_secret,
            ALICE,
            "atproto space:org.example.bucket?authority=did:plc:abc234567abc234567abc234",
        );

        let response = app(state).oneshot(request(&token, SPACE)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let delegation = json["token"].as_str().unwrap();

        let header = segment(delegation, 0);
        assert_eq!(header["typ"], DELEGATION_TOKEN_TYP);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "#atproto");
        let claims = segment(delegation, 1);
        assert_eq!(claims["iss"], ALICE);
        assert_eq!(claims["sub"], SPACE);
        assert_eq!(
            claims["aud"],
            "did:plc:abc234567abc234567abc234#atproto_space_host"
        );
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            60
        );
        assert!(claims["jti"].as_str().is_some_and(|j| !j.is_empty()));
        assert!(claims.get("lxm").is_none());

        // Signed by the account's #atproto repo key.
        let signing_input = delegation.rsplit_once('.').unwrap().0;
        let sig: [u8; 64] = URL_SAFE_NO_PAD
            .decode(delegation.rsplit('.').next().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        crypto::verify_did_key_signature(&kp.key_id, signing_input.as_bytes(), &sig).unwrap();
    }

    #[tokio::test]
    async fn legacy_full_session_mints_but_uncovered_and_app_password_sessions_are_refused() {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, ALICE).await;

        let full = access_jwt(&state.jwt_secret, ALICE);
        let response = app(state.clone())
            .oneshot(request(&full, SPACE))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // `read_self` does not confer getDelegationToken; nor does an unrelated grant.
        for scope in [
            "atproto space:org.example.bucket?authority=did:plc:abc234567abc234567abc234&action=read_self",
            "atproto repo:*",
            // Only alice's own spaces (authority=self), not the authority's.
            "atproto space:org.example.bucket",
        ] {
            let token = scoped_access_jwt(&state.jwt_secret, ALICE, scope);
            let response = app(state.clone())
                .oneshot(request(&token, SPACE))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "scope {scope}");
            assert_eq!(body_json(response).await["error"], "InsufficientScope");
        }

        let app_pass = app_pass_jwt(&state.jwt_secret, ALICE, true);
        let response = app(state.clone())
            .oneshot(request(&app_pass, SPACE))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // A malformed space reference is a 400 from the lexicon params layer.
        let full = access_jwt(&state.jwt_secret, ALICE);
        let response = app(state)
            .oneshot(request(
                &full,
                "at://did:plc:abc234567abc234567abc234/not-a-space",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
