// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (JWT extractor), query params (aud, exp, lxm), DB pool + master key
// Processes: scope check → validate aud/exp → load the account's repo signer → mint ES256 token
// Returns: JSON { token } on success; ApiError on failure
//
// Implements: GET /xrpc/com.atproto.server.getServiceAuth

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, response::Json};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::auth::oauth_scopes;
use crate::lexicon::LexiconParams;

/// Max future window for a *method-bound* token (`lxm` present): one hour. Mirrors the reference
/// PDS, which bounds scoped service tokens to a short life so a leaked token expires quickly.
const MAX_TTL_WITH_LXM: u64 = 60 * 60;
/// Max future window for a *method-unrestricted* token (`lxm` absent): one minute. Such a token
/// authorizes any method on the audience, so it is held to a far tighter bound.
const MAX_TTL_WITHOUT_LXM: u64 = 60;
/// Expiry applied when the caller requests none: 60 seconds in the future.
const DEFAULT_TTL: u64 = 60;

/// Account-management methods that must be performed directly on the PDS and are **never** mintable
/// as a service-auth token, for any credential (full access included). Mirrors the reference PDS's
/// `PROTECTED_METHODS` so a service token can't be used to sidestep the session-level access these
/// operations require.
const PROTECTED_METHODS: &[&str] = &[
    "com.atproto.admin.sendEmail",
    "com.atproto.identity.requestPlcOperationSignature",
    "com.atproto.identity.signPlcOperation",
    "com.atproto.identity.updateHandle",
    "com.atproto.server.activateAccount",
    "com.atproto.server.confirmEmail",
    "com.atproto.server.createAppPassword",
    "com.atproto.server.deactivateAccount",
    "com.atproto.server.getAccountInviteCodes",
    "com.atproto.server.getSession",
    "com.atproto.server.listAppPasswords",
    "com.atproto.server.requestAccountDelete",
    "com.atproto.server.requestEmailConfirmation",
    "com.atproto.server.requestEmailUpdate",
    "com.atproto.server.revokeAppPassword",
    "com.atproto.server.updateEmail",
];

/// Methods that require a **privileged** credential (a full-access session or a privileged app
/// password): the `chat.bsky.*` surface plus account creation. A non-privileged app password may
/// not mint service auth for these. Mirrors the reference PDS's `PRIVILEGED_METHODS`.
const PRIVILEGED_METHODS: &[&str] = &[
    "chat.bsky.actor.deleteAccount",
    "chat.bsky.actor.exportAccountData",
    "chat.bsky.convo.deleteMessageForSelf",
    "chat.bsky.convo.getConvo",
    "chat.bsky.convo.getConvoForMembers",
    "chat.bsky.convo.getLog",
    "chat.bsky.convo.getMessages",
    "chat.bsky.convo.leaveConvo",
    "chat.bsky.convo.listConvos",
    "chat.bsky.convo.muteConvo",
    "chat.bsky.convo.sendMessage",
    "chat.bsky.convo.sendMessageBatch",
    "chat.bsky.convo.unmuteConvo",
    "chat.bsky.convo.updateRead",
    "com.atproto.server.createAccount",
];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetServiceAuthQuery {
    /// DID (optionally `did#serviceId`) of the service the token authenticates to.
    aud: String,
    /// Absolute Unix-seconds expiry. Optional; defaults to [`DEFAULT_TTL`] in the future.
    exp: Option<u64>,
    /// Lexicon (XRPC) method to bind the token to. Optional; absent → method-unrestricted.
    lxm: Option<String>,
}

#[derive(Serialize)]
pub struct GetServiceAuthResponse {
    token: String,
}

/// GET /xrpc/com.atproto.server.getServiceAuth
///
/// Mints a short-lived inter-service auth JWT (ES256) on behalf of the authenticated account,
/// signed by the account's `#atproto` repo key, for the requested `aud` service. The client uses
/// it to call that service directly (e.g. video, or AppView calls outside the PDS proxy path).
pub async fn get_service_auth(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    LexiconParams(params): LexiconParams<GetServiceAuthQuery>,
) -> Result<Json<GetServiceAuthResponse>, ApiError> {
    // Deliberately no deactivation check: an outbound-migrating account is expected to mint a
    // token for the destination's createAccount (and retry it) right up to and after the point
    // its own PDS deactivates it — gating on activity here would break exactly the flow this
    // endpoint exists to serve.
    // Refresh tokens never mint service auth. Full-access and app-password sessions are both
    // admitted here; the per-method authorization gate below (once `lxm` is resolved) enforces
    // exactly what each may mint — matching the reference PDS, whose `getServiceAuth` accepts app
    // passwords for non-protected, non-privileged methods (the video-upload path).
    if user.scope == AuthScope::Refresh {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }

    let aud = params.aud.trim();
    if !is_valid_aud(aud) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "aud must be a valid atproto DID or did#serviceId reference",
        ));
    }
    // The token's `aud` is the bare service DID: a `#serviceId` is a DID-document service
    // selector, not part of the audience the receiving service matches against its own DID, so a
    // token carrying the fragment would be rejected. `is_valid_aud` has already rejected empty or
    // multiple fragments, so a single `split_once` cleanly yields the base DID.
    let aud_claim = aud.split_once('#').map_or(aud, |(did, _)| did);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "system clock error"))?;

    // An empty `lxm` is treated as absent (method-unrestricted) rather than a token bound to the
    // empty method, which no service would honour.
    let lxm = params.lxm.as_deref().filter(|s| !s.is_empty());

    let exp = resolve_expiry(params.exp, lxm.is_some(), now)?;

    // A protected method is account management that must be performed directly on the PDS: never
    // mintable as a service-auth token, whatever the credential.
    if let Some(method) = lxm {
        if PROTECTED_METHODS.contains(&method) {
            return Err(ApiError::new(
                ErrorCode::InvalidToken,
                "cannot request a service auth token for a protected method",
            ));
        }
    }

    match &user.scope {
        // A full-access session (legacy `com.atproto.access`) or a granular OAuth grant: the
        // granular scope gate enforces per-audience/method access, and a legacy full-access session
        // short-circuits inside `require_rpc`.
        AuthScope::Access => {
            let required_lxm = lxm.unwrap_or("*");
            oauth_scopes::require_rpc(
                &user.scope_claim,
                required_lxm,
                aud_claim,
                "token scope does not permit service auth for this RPC audience",
            )?;
        }
        // App passwords may mint a *method-bound* token for non-protected methods (the video-upload
        // path). A method-unrestricted token is too broad to grant an app password, and privileged
        // methods (`chat.bsky.*`, account creation) require a privileged credential.
        AuthScope::AppPass | AuthScope::AppPassPrivileged => {
            let Some(method) = lxm else {
                return Err(ApiError::new(
                    ErrorCode::InvalidToken,
                    "an app-password session must request a method-bound (lxm) service auth token",
                ));
            };
            if user.scope == AuthScope::AppPass && PRIVILEGED_METHODS.contains(&method) {
                return Err(ApiError::new(
                    ErrorCode::InvalidToken,
                    "insufficient access to request service auth for this method",
                ));
            }
        }
        // Rejected before parameter validation above.
        AuthScope::Refresh => unreachable!("refresh scope is rejected before authorization"),
    }

    // Sign with the account's per-account repo key (decrypted with the configured master key);
    // the audience service verifies it against the `#atproto` key in the issuer's DID document.
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

    let token = crate::auth::signing_key::mint_account_service_auth(
        &state.db, master_key, &user.did, aud_claim, lxm, now, exp,
    )
    .await?;

    Ok(Json(GetServiceAuthResponse { token }))
}

/// Resolve and bound the requested expiry against `now`. A method-unrestricted token (`!has_lxm`)
/// is held to [`MAX_TTL_WITHOUT_LXM`]; a method-bound one to [`MAX_TTL_WITH_LXM`]. An expiry in
/// the past, or beyond the applicable bound, is a `400`.
fn resolve_expiry(requested: Option<u64>, has_lxm: bool, now: u64) -> Result<u64, ApiError> {
    let Some(exp) = requested else {
        return Ok(now + DEFAULT_TTL);
    };
    if exp <= now {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "expiration is in the past",
        ));
    }
    let max_ttl = if has_lxm {
        MAX_TTL_WITH_LXM
    } else {
        MAX_TTL_WITHOUT_LXM
    };
    if exp > now + max_ttl {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            if has_lxm {
                "cannot request a token more than an hour in the future"
            } else {
                "cannot request a method-less token more than a minute in the future"
            },
        ));
    }
    Ok(exp)
}

/// True when `aud` is an atproto DID (`did:method:id`), optionally suffixed with a single
/// non-empty `#serviceId` fragment. A trailing `#`, an empty fragment, or multiple `#`s are
/// rejected. Deliberately structural, not a full DID-syntax validator — the audience service
/// performs the authoritative check.
fn is_valid_aud(aud: &str) -> bool {
    let did = match aud.split_once('#') {
        // A fragment is allowed only if it is non-empty and itself fragment-free.
        Some((did, fragment)) if !fragment.is_empty() && !fragment.contains('#') => did,
        Some(_) => return false,
        None => aud,
    };
    let mut parts = did.splitn(3, ':');
    parts.next() == Some("did")
        && parts.next().is_some_and(|method| !method.is_empty())
        && parts.next().is_some_and(|id| !id.is_empty())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{DEFAULT_TTL, MAX_TTL_WITH_LXM};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use tower::ServiceExt;

    use crate::app::app;
    use crate::routes::test_utils::{seed_account_with_repo, state_with_master_key};

    const TEST_DID: &str = "did:plc:tester";

    /// Issue a valid HS256 access JWT for `sub` using the state's fixed test secret.
    fn access_jwt(secret: &[u8; 32], sub: &str) -> String {
        scoped_access_jwt(secret, sub, "com.atproto.access")
    }

    fn scoped_access_jwt(secret: &[u8; 32], sub: &str, scope: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "scope": scope,
                "sub": sub,
                "iat": now,
                "exp": now + 7200_u64,
            }),
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn get_request(token: &str, query: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(format!("/xrpc/com.atproto.server.getServiceAuth?{query}"))
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Decode a JWT's header and claims (signature segment ignored).
    fn decode_jwt(token: &str) -> (serde_json::Value, serde_json::Value) {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must be header.payload.signature");
        let header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        (header, claims)
    }

    fn now() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[tokio::test]
    async fn valid_request_mints_es256_token_with_claims() {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = access_jwt(&state.jwt_secret, TEST_DID);

        let response = app(state)
            .oneshot(get_request(
                &token,
                "aud=did:web:api.bsky.app&lxm=app.bsky.feed.getTimeline",
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let minted = json["token"].as_str().expect("token in response");

        let (header, claims) = decode_jwt(minted);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(claims["iss"], TEST_DID);
        assert_eq!(claims["aud"], "did:web:api.bsky.app");
        assert_eq!(claims["lxm"], "app.bsky.feed.getTimeline");
        // Default expiry is ~60s out; allow slack for clock movement across the call.
        let exp = claims["exp"].as_u64().unwrap();
        assert!(
            exp > now() && exp <= now() + DEFAULT_TTL + 5,
            "default expiry should be ~60s out, got exp={exp}"
        );
    }

    #[tokio::test]
    async fn granular_rpc_scope_is_enforced_for_service_auth() {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let repo_only = scoped_access_jwt(
            &state.jwt_secret,
            TEST_DID,
            "atproto repo:app.bsky.feed.post?action=create",
        );

        let denied = app(state.clone())
            .oneshot(get_request(
                &repo_only,
                "aud=did:web:api.bsky.app&lxm=app.bsky.feed.getTimeline",
            ))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let body = body_json(denied).await;
        assert_eq!(body["error"]["code"], "InsufficientScope");

        let rpc_scoped = scoped_access_jwt(
            &state.jwt_secret,
            TEST_DID,
            "atproto rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app",
        );
        let allowed = app(state.clone())
            .oneshot(get_request(
                &rpc_scoped,
                "aud=did:web:api.bsky.app&lxm=app.bsky.feed.getTimeline",
            ))
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);

        let fragment_allowed = app(state)
            .oneshot(get_request(
                &rpc_scoped,
                "aud=did:web:api.bsky.app%23bsky_appview&lxm=app.bsky.feed.getTimeline",
            ))
            .await
            .unwrap();
        assert_eq!(fragment_allowed.status(), StatusCode::OK);
        let body = body_json(fragment_allowed).await;
        let (_, claims) = decode_jwt(body["token"].as_str().unwrap());
        assert_eq!(claims["aud"], "did:web:api.bsky.app");
    }

    #[tokio::test]
    async fn transition_chat_scope_mints_chat_service_auth_only() {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let chat_scoped =
            scoped_access_jwt(&state.jwt_secret, TEST_DID, "atproto transition:chat.bsky");

        let allowed = app(state.clone())
            .oneshot(get_request(
                &chat_scoped,
                "aud=did:web:api.bsky.chat%23bsky_chat&lxm=chat.bsky.convo.listConvos",
            ))
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        let body = body_json(allowed).await;
        let (_, claims) = decode_jwt(body["token"].as_str().unwrap());
        assert_eq!(claims["aud"], "did:web:api.bsky.chat");
        assert_eq!(claims["lxm"], "chat.bsky.convo.listConvos");

        let denied = app(state)
            .oneshot(get_request(
                &chat_scoped,
                "aud=did:web:api.bsky.app&lxm=app.bsky.feed.getTimeline",
            ))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let body = body_json(denied).await;
        assert_eq!(body["error"]["code"], "InsufficientScope");
    }

    #[tokio::test]
    async fn omits_lxm_when_not_requested() {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = access_jwt(&state.jwt_secret, TEST_DID);

        let response = app(state)
            .oneshot(get_request(&token, "aud=did:web:api.bsky.app"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let (_, claims) = decode_jwt(json["token"].as_str().unwrap());
        assert!(
            claims.get("lxm").is_none(),
            "a method-unrestricted token must omit lxm, got {claims}"
        );
    }

    #[tokio::test]
    async fn honors_requested_exp_within_bounds() {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = access_jwt(&state.jwt_secret, TEST_DID);
        let requested = now() + 600; // 10 min out, within the 1h method-bound window

        let response = app(state)
            .oneshot(get_request(
                &token,
                &format!("aud=did:web:api.bsky.app&lxm=app.bsky.feed.getTimeline&exp={requested}"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let (_, claims) = decode_jwt(json["token"].as_str().unwrap());
        assert_eq!(claims["exp"].as_u64().unwrap(), requested);
    }

    #[tokio::test]
    async fn past_exp_is_rejected() {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = access_jwt(&state.jwt_secret, TEST_DID);
        let past = now() - 10;

        let response = app(state)
            .oneshot(get_request(
                &token,
                &format!("aud=did:web:api.bsky.app&exp={past}"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn exp_beyond_one_hour_with_lxm_is_rejected() {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = access_jwt(&state.jwt_secret, TEST_DID);
        let too_far = now() + MAX_TTL_WITH_LXM + 120;

        let response = app(state)
            .oneshot(get_request(
                &token,
                &format!("aud=did:web:api.bsky.app&lxm=app.bsky.feed.getTimeline&exp={too_far}"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn exp_beyond_one_minute_without_lxm_is_rejected() {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = access_jwt(&state.jwt_secret, TEST_DID);
        // 10 minutes out is fine WITH an lxm, but a method-less token is capped at 1 minute.
        let too_far = now() + 600;

        let response = app(state)
            .oneshot(get_request(
                &token,
                &format!("aud=did:web:api.bsky.app&exp={too_far}"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invalid_aud_is_rejected() {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = access_jwt(&state.jwt_secret, TEST_DID);

        let response = app(state)
            .oneshot(get_request(&token, "aud=not-a-did"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn service_fragment_aud_mints_bare_did() {
        // A `did#serviceId` audience is accepted, but the minted token's `aud` claim must be the
        // bare DID — the receiving service matches `aud` against its own DID, not a service ref.
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = access_jwt(&state.jwt_secret, TEST_DID);

        let response = app(state)
            .oneshot(get_request(
                &token,
                "aud=did:web:api.bsky.app%23bsky_appview",
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let (_, claims) = decode_jwt(json["token"].as_str().unwrap());
        assert_eq!(
            claims["aud"], "did:web:api.bsky.app",
            "the #serviceId fragment must be stripped from the minted aud"
        );
    }

    #[tokio::test]
    async fn empty_aud_fragment_is_rejected() {
        // A trailing `#` (empty fragment) is malformed and must be rejected, not silently
        // treated as the bare DID.
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = access_jwt(&state.jwt_secret, TEST_DID);

        let response = app(state)
            .oneshot(get_request(&token, "aud=did:web:api.bsky.app%23"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn multiple_aud_fragments_are_rejected() {
        // More than one `#` is malformed; `is_valid_aud` must reject it rather than splitting on
        // the first and trusting the remainder.
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = access_jwt(&state.jwt_secret, TEST_DID);

        let response = app(state)
            .oneshot(get_request(
                &token,
                "aud=did:web:api.bsky.app%23bsky_appview%23extra",
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_auth_is_rejected() {
        let state = state_with_master_key().await;
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/xrpc/com.atproto.server.getServiceAuth?aud=did:web:api.bsky.app")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── App-password service auth (the bsky-app login path) ───────────────────────

    #[tokio::test]
    async fn app_password_mints_service_auth_for_non_privileged_method() {
        // The bsky app signs into a self-hosted PDS with an app password; video upload requests a
        // service token for a non-privileged method. This must be permitted (the reference PDS
        // allows it) — rejecting it broke video upload for every app-password session.
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = scoped_access_jwt(&state.jwt_secret, TEST_DID, "com.atproto.appPass");

        let response = app(state)
            .oneshot(get_request(
                &token,
                "aud=did:web:video.bsky.app&lxm=app.bsky.video.getUploadLimits",
            ))
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "an app password must mint service auth for a non-privileged method"
        );
        let json = body_json(response).await;
        let (_, claims) = decode_jwt(json["token"].as_str().unwrap());
        assert_eq!(claims["aud"], "did:web:video.bsky.app");
        assert_eq!(claims["lxm"], "app.bsky.video.getUploadLimits");
    }

    #[tokio::test]
    async fn app_password_mints_uploadblob_service_auth() {
        // The second leg of video upload: the transcoded blob is pushed back to the PDS via
        // uploadBlob, a token the client also mints. uploadBlob is non-privileged.
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = scoped_access_jwt(&state.jwt_secret, TEST_DID, "com.atproto.appPass");

        let response = app(state)
            .oneshot(get_request(
                &token,
                "aud=did:web:pds.example.com&lxm=com.atproto.repo.uploadBlob",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn app_password_cannot_mint_service_auth_for_protected_method() {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = scoped_access_jwt(&state.jwt_secret, TEST_DID, "com.atproto.appPass");

        let response = app(state)
            .oneshot(get_request(
                &token,
                "aud=did:web:api.bsky.app&lxm=com.atproto.server.getSession",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn full_access_cannot_mint_service_auth_for_protected_method() {
        // Protected (account-management) methods are blocked for every credential, full access
        // included — a service token must never sidestep the direct-session access they require.
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = access_jwt(&state.jwt_secret, TEST_DID);

        let response = app(state)
            .oneshot(get_request(
                &token,
                "aud=did:web:api.bsky.app&lxm=com.atproto.identity.updateHandle",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn non_privileged_app_password_cannot_mint_service_auth_for_chat() {
        // chat.bsky.* is privileged: a plain app password may not mint service auth for it.
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = scoped_access_jwt(&state.jwt_secret, TEST_DID, "com.atproto.appPass");

        let response = app(state)
            .oneshot(get_request(
                &token,
                "aud=did:web:api.bsky.chat&lxm=chat.bsky.convo.sendMessage",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn privileged_app_password_mints_service_auth_for_chat() {
        // A privileged app password may mint service auth for the privileged chat surface.
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = scoped_access_jwt(&state.jwt_secret, TEST_DID, "com.atproto.appPassPrivileged");

        let response = app(state)
            .oneshot(get_request(
                &token,
                "aud=did:web:api.bsky.chat&lxm=chat.bsky.convo.sendMessage",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn app_password_without_lxm_is_rejected() {
        // A method-unrestricted token is too broad to grant an app password.
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, TEST_DID).await;
        let token = scoped_access_jwt(&state.jwt_secret, TEST_DID, "com.atproto.appPass");

        let response = app(state)
            .oneshot(get_request(&token, "aud=did:web:api.bsky.app"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
