// pattern: Imperative Shell

//! RFC 7523 `private_key_jwt` client authentication for the token endpoint, shared by the
//! `authorization_code` and `refresh_token` grants.
//!
//! The AS metadata has always advertised `private_key_jwt`, but until this module existed a
//! confidential client's `client_assertion` was silently ignored by serde and the client
//! treated as public — meaning a leaked authorization code or refresh token was exchangeable
//! without the client's key (2026-08-03 interop audit, gap 2). The registered
//! `token_endpoint_auth_method` in the client's metadata document now decides what this
//! endpoint requires: `none` clients must not send an assertion, `private_key_jwt` clients
//! must send a valid one.
//!
//! Assertion checks follow RFC 7523 §3 with the atproto OAuth profile's narrowing: ES256
//! only, `iss` = `sub` = `client_id`, `aud` = this AS's issuer (the token-endpoint URL is
//! also accepted — both appear in the wild), and a 30-second clock tolerance (the reference
//! implementation's zero-tolerance `iat` check is a documented interop trap —
//! bluesky-social/atproto#4474). One deliberate divergence from the RFC's letter: `exp` is
//! validated when present but not required. The reference provider requires only `jti` and
//! bounds an assertion's life by `maxTokenAge` over `iat` (its own source notes the RFC 7523
//! non-compliance), so real-world clients mint `iat`-only assertions — attie.ai's logins
//! failed here for exactly that reason (2026-08-28). An assertion without `exp` must instead
//! carry a fresh `iat`. The verification key comes from the metadata's inline
//! `jwks` or its `jwks_uri`; the latter is a client-controlled URL, so it gets the same
//! transport policy as `client_id` itself (https except loopback, no credentials) and is
//! fetched with the SSRF-hardened client, which is the actual guard, and cached
//! (`AppState::oauth_client_jwks_cache`, `[oauth] client_jwks_*` config — see `auth::jwks`'s
//! module doc) rather than repeated on every token request. `jti` presence
//! is required but not replay-tracked: every protected grant is already single-use
//! (authorization codes) or rotation-guarded (refresh tokens), so a replayed assertion alone
//! wins nothing.

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::app::AppState;
use crate::db::oauth::{get_oauth_client, ClientMetadata};
use crate::routes::oauth_errors::OAuthTokenError;

pub(super) const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Clock skew tolerated on the assertion's time claims (RFC 7523 permits a few minutes;
/// 30 seconds covers real-world drift without meaningfully widening the replay window).
const CLOCK_TOLERANCE_SECS: u64 = 30;

/// Maximum age of an `exp`-less assertion, measured from its `iat` (the reference provider's
/// `CLIENT_ASSERTION_MAX_AGE`). Applied on top of [`CLOCK_TOLERANCE_SECS`].
const IAT_MAX_AGE_SECS: i64 = 60;

#[derive(Debug, Deserialize)]
struct ClientAssertionClaims {
    iss: String,
    sub: String,
    jti: Option<String>,
    exp: Option<i64>,
    iat: Option<i64>,
}

fn invalid_client(description: impl Into<String>) -> OAuthTokenError {
    OAuthTokenError::new("invalid_client", description.into())
}

/// Enforce the client's registered `token_endpoint_auth_method` for a token request.
///
/// Reads the client's cached metadata document (resolved and stored at PAR/authorize time;
/// an unknown client or one whose stored metadata predates the extended fields is treated
/// as a public client, matching the pre-existing behavior for every seeded row).
pub(super) async fn authenticate_token_client(
    state: &AppState,
    client_id: &str,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
) -> Result<(), OAuthTokenError> {
    let metadata: ClientMetadata = match get_oauth_client(&state.db, client_id).await {
        Ok(Some(row)) => serde_json::from_str(&row.client_metadata).unwrap_or_default(),
        Ok(None) => ClientMetadata::default(),
        Err(e) => {
            tracing::error!(error = %e, "failed to load client metadata for token auth");
            return Err(OAuthTokenError::new("server_error", "database error"));
        }
    };

    match metadata
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("none")
    {
        "none" => {
            // A public client sending an assertion is a registration/config mismatch the
            // client author needs to hear about, not silently ignore.
            if assertion.is_some() {
                return Err(invalid_client(
                    "client is registered with token_endpoint_auth_method \"none\" \
                     but sent a client_assertion",
                ));
            }
            Ok(())
        }
        "private_key_jwt" => {
            verify_private_key_jwt(state, client_id, &metadata, assertion_type, assertion).await
        }
        other => Err(invalid_client(format!(
            "unsupported token_endpoint_auth_method \"{other}\""
        ))),
    }
}

async fn verify_private_key_jwt(
    state: &AppState,
    client_id: &str,
    metadata: &ClientMetadata,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
) -> Result<(), OAuthTokenError> {
    let assertion = assertion.ok_or_else(|| {
        invalid_client("client authentication required: missing client_assertion")
    })?;
    if assertion_type != Some(CLIENT_ASSERTION_TYPE_JWT_BEARER) {
        return Err(invalid_client(format!(
            "client_assertion_type must be {CLIENT_ASSERTION_TYPE_JWT_BEARER}"
        )));
    }

    let header = jsonwebtoken::decode_header(assertion)
        .map_err(|_| invalid_client("client_assertion is not a well-formed JWT"))?;
    if header.alg != Algorithm::ES256 {
        return Err(invalid_client("client_assertion must be signed with ES256"));
    }

    let key = resolve_client_key(state, metadata, header.kid.as_deref()).await?;

    let issuer = state.config.public_url.trim_end_matches('/').to_string();
    let token_url = format!("{issuer}/oauth/token");
    let mut validation = Validation::new(Algorithm::ES256);
    validation.leeway = CLOCK_TOLERANCE_SECS;
    validation.set_audience(&[issuer, token_url]);
    validation.set_required_spec_claims(&["aud"]);

    let data = jsonwebtoken::decode::<ClientAssertionClaims>(assertion, &key, &validation)
        .map_err(|e| invalid_client(format!("client_assertion rejected: {e}")))?;

    // `exp`, when present, was enforced by the validation above. Without it the assertion
    // would otherwise never lapse, so `iat` must bound its age instead.
    if data.claims.exp.is_none() {
        let iat = data
            .claims
            .iat
            .ok_or_else(|| invalid_client("client_assertion must carry exp or iat"))?;
        let now = crate::time::unix_now_secs();
        if iat > now + CLOCK_TOLERANCE_SECS as i64 {
            return Err(invalid_client("client_assertion iat is in the future"));
        }
        if now > iat + IAT_MAX_AGE_SECS + CLOCK_TOLERANCE_SECS as i64 {
            return Err(invalid_client("client_assertion without exp is too old"));
        }
    }

    if data.claims.iss != client_id || data.claims.sub != client_id {
        return Err(invalid_client(
            "client_assertion iss and sub must both be the client_id",
        ));
    }
    if data.claims.jti.as_deref().is_none_or(|jti| jti.is_empty()) {
        return Err(invalid_client("client_assertion must carry a jti"));
    }
    Ok(())
}

/// Resolve the client's assertion-verification key from its metadata.
///
/// The inline-`jwks`/`jwks_uri` resolution — including the `jwks_uri` transport policy and the
/// cached, SSRF-hardened fetch — is shared with Atproto Spaces client attestations; see
/// [`crate::auth::jwks::client_verification_key`].
async fn resolve_client_key(
    state: &AppState,
    metadata: &ClientMetadata,
    kid: Option<&str>,
) -> Result<DecodingKey, OAuthTokenError> {
    crate::auth::jwks::client_verification_key(
        &state.oauth_client_jwks_cache,
        metadata.jwks.as_ref(),
        metadata.jwks_uri.as_deref(),
        kid,
    )
    .await
    .map_err(|e| {
        if metadata.jwks.is_none() && metadata.jwks_uri.is_none() {
            return invalid_client(
                "client metadata declares private_key_jwt but provides neither jwks nor jwks_uri",
            );
        }
        if let Some(uri) = &metadata.jwks_uri {
            tracing::debug!(jwks_uri = uri, error = %e, "failed to resolve client jwks_uri");
        }
        invalid_client(e)
    })
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand_core::OsRng;

    use super::super::test_support::{dpop_key_to_jwk, now_secs};
    use super::*;
    use crate::app::{test_state, AppState};
    use crate::db::oauth::upsert_oauth_client;

    const CLIENT_ID: &str = "https://app.example.com/client-metadata.json";

    async fn seed_client(state: &AppState, metadata: serde_json::Value) {
        upsert_oauth_client(&state.db, CLIENT_ID, &metadata.to_string())
            .await
            .unwrap();
    }

    fn jwk_with_kid(key: &SigningKey, kid: &str) -> serde_json::Value {
        let mut jwk = dpop_key_to_jwk(key);
        jwk["kid"] = serde_json::Value::String(kid.to_string());
        jwk
    }

    fn confidential_metadata(key: &SigningKey) -> serde_json::Value {
        serde_json::json!({
            "client_id": CLIENT_ID,
            "redirect_uris": ["https://app.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": { "keys": [jwk_with_kid(key, "k1")] },
        })
    }

    fn sign_assertion(key: &SigningKey, kid: &str, claims: serde_json::Value) -> String {
        let header = serde_json::json!({ "alg": "ES256", "kid": kid });
        let hdr = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let pay = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap().as_bytes());
        let sig_input = format!("{hdr}.{pay}");
        let sig: Signature = key.sign(sig_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref() as &[u8]);
        format!("{hdr}.{pay}.{sig_b64}")
    }

    fn valid_claims(iss_sub: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": iss_sub,
            "sub": iss_sub,
            "aud": "https://test.example.com",
            "iat": now_secs(),
            "exp": now_secs() + 60,
            "jti": "assertion-jti-1",
        })
    }

    #[tokio::test]
    async fn public_client_without_assertion_is_accepted() {
        let state = test_state().await;
        seed_client(
            &state,
            serde_json::json!({
                "client_id": CLIENT_ID,
                "redirect_uris": ["https://app.example.com/callback"],
                "token_endpoint_auth_method": "none",
            }),
        )
        .await;
        assert!(authenticate_token_client(&state, CLIENT_ID, None, None)
            .await
            .is_ok());
    }

    /// An unknown client (no cached metadata) keeps the pre-existing public-client behavior.
    #[tokio::test]
    async fn unresolved_client_is_treated_as_public() {
        let state = test_state().await;
        assert!(
            authenticate_token_client(&state, "https://never.example/meta.json", None, None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn public_client_sending_assertion_is_rejected() {
        let state = test_state().await;
        seed_client(
            &state,
            serde_json::json!({
                "client_id": CLIENT_ID,
                "redirect_uris": ["https://app.example.com/callback"],
                "token_endpoint_auth_method": "none",
            }),
        )
        .await;
        let key = SigningKey::random(&mut OsRng);
        let assertion = sign_assertion(&key, "k1", valid_claims(CLIENT_ID));
        let err = authenticate_token_client(
            &state,
            CLIENT_ID,
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
            Some(&assertion),
        )
        .await
        .unwrap_err();
        assert_eq!(err.error, "invalid_client");
    }

    #[tokio::test]
    async fn confidential_client_with_valid_assertion_is_accepted() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        seed_client(&state, confidential_metadata(&key)).await;
        let assertion = sign_assertion(&key, "k1", valid_claims(CLIENT_ID));
        authenticate_token_client(
            &state,
            CLIENT_ID,
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
            Some(&assertion),
        )
        .await
        .expect("valid private_key_jwt assertion must authenticate");
    }

    /// This is the audit's gap 2: a confidential client's token request without its
    /// assertion must be refused, not silently treated as public.
    #[tokio::test]
    async fn confidential_client_missing_assertion_is_rejected() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        seed_client(&state, confidential_metadata(&key)).await;
        let err = authenticate_token_client(&state, CLIENT_ID, None, None)
            .await
            .unwrap_err();
        assert_eq!(err.error, "invalid_client");
    }

    #[tokio::test]
    async fn confidential_client_wrong_key_is_rejected() {
        let state = test_state().await;
        let registered = SigningKey::random(&mut OsRng);
        seed_client(&state, confidential_metadata(&registered)).await;
        let imposter = SigningKey::random(&mut OsRng);
        let assertion = sign_assertion(&imposter, "k1", valid_claims(CLIENT_ID));
        let err = authenticate_token_client(
            &state,
            CLIENT_ID,
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
            Some(&assertion),
        )
        .await
        .unwrap_err();
        assert_eq!(err.error, "invalid_client");
    }

    #[tokio::test]
    async fn assertion_iss_sub_must_be_client_id() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        seed_client(&state, confidential_metadata(&key)).await;
        let assertion = sign_assertion(&key, "k1", valid_claims("https://other.example/meta.json"));
        let err = authenticate_token_client(
            &state,
            CLIENT_ID,
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
            Some(&assertion),
        )
        .await
        .unwrap_err();
        assert_eq!(err.error, "invalid_client");
    }

    #[tokio::test]
    async fn expired_assertion_is_rejected_with_clock_tolerance() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        seed_client(&state, confidential_metadata(&key)).await;

        // Expired well beyond the 30s tolerance: rejected.
        let mut claims = valid_claims(CLIENT_ID);
        claims["exp"] = serde_json::json!(now_secs() - 120);
        let assertion = sign_assertion(&key, "k1", claims);
        let err = authenticate_token_client(
            &state,
            CLIENT_ID,
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
            Some(&assertion),
        )
        .await
        .unwrap_err();
        assert_eq!(err.error, "invalid_client");

        // Expired 10s ago: inside the 30s clock tolerance, accepted (interop with clients
        // whose clocks drift — the reference's zero-tolerance check is a known trap).
        let mut claims = valid_claims(CLIENT_ID);
        claims["exp"] = serde_json::json!(now_secs() - 10);
        let assertion = sign_assertion(&key, "k1", claims);
        authenticate_token_client(
            &state,
            CLIENT_ID,
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
            Some(&assertion),
        )
        .await
        .expect("small clock skew must be tolerated");
    }

    /// The interop case that broke attie.ai: the reference provider never requires `exp`
    /// (only `jti`, with a max age over `iat`), so real-world confidential clients mint
    /// `iat`-only assertions. Those must authenticate while fresh.
    #[tokio::test]
    async fn assertion_without_exp_is_accepted_while_iat_is_fresh() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        seed_client(&state, confidential_metadata(&key)).await;

        let mut claims = valid_claims(CLIENT_ID);
        claims.as_object_mut().unwrap().remove("exp");
        let assertion = sign_assertion(&key, "k1", claims);
        authenticate_token_client(
            &state,
            CLIENT_ID,
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
            Some(&assertion),
        )
        .await
        .expect("an exp-less assertion with a fresh iat must authenticate");
    }

    /// Without `exp` the `iat` bound is the only thing keeping the assertion from being
    /// replayable forever, so a stale one — and one carrying neither claim — must be refused.
    #[tokio::test]
    async fn assertion_without_exp_needs_a_fresh_iat() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        seed_client(&state, confidential_metadata(&key)).await;

        // Stale: iat beyond the 60s max age + 30s tolerance.
        let mut claims = valid_claims(CLIENT_ID);
        claims.as_object_mut().unwrap().remove("exp");
        claims["iat"] = serde_json::json!(now_secs() - 120);
        let assertion = sign_assertion(&key, "k1", claims);
        let err = authenticate_token_client(
            &state,
            CLIENT_ID,
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
            Some(&assertion),
        )
        .await
        .unwrap_err();
        assert_eq!(err.error, "invalid_client");

        // Neither exp nor iat: nothing bounds the assertion's life at all.
        let mut claims = valid_claims(CLIENT_ID);
        let obj = claims.as_object_mut().unwrap();
        obj.remove("exp");
        obj.remove("iat");
        let assertion = sign_assertion(&key, "k1", claims);
        let err = authenticate_token_client(
            &state,
            CLIENT_ID,
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
            Some(&assertion),
        )
        .await
        .unwrap_err();
        assert_eq!(err.error, "invalid_client");
    }

    /// The `jwks_uri` branch: a client that publishes its keys at a URL rather than inline.
    ///
    /// Worth its own test because it is the only path in this module that makes an outbound
    /// request, and it is a *client-controlled* URL — so it runs through the SSRF-hardened
    /// client. Production bakes `allow_loopback = false` into that client, which means this
    /// branch cannot be exercised from the hermetic conformance suite (a loopback jwks_uri is
    /// correctly refused there); a wiremock server plus `test_state`'s loopback-permitting
    /// client is the only place it can be covered at all.
    #[tokio::test]
    async fn confidential_client_key_is_fetched_from_jwks_uri() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [jwk_with_kid(&key, "k1")],
            })))
            .mount(&server)
            .await;

        seed_client(
            &state,
            serde_json::json!({
                "client_id": CLIENT_ID,
                "redirect_uris": ["https://app.example.com/callback"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks_uri": format!("{}/jwks.json", server.uri()),
            }),
        )
        .await;

        let assertion = sign_assertion(&key, "k1", valid_claims(CLIENT_ID));
        authenticate_token_client(
            &state,
            CLIENT_ID,
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
            Some(&assertion),
        )
        .await
        .expect("a key published at jwks_uri must authenticate the assertion");
    }

    /// A `jwks_uri` fetch must be cached rather than repeated on every token request — a
    /// client refreshing on its 15-minute access-token TTL would otherwise add an outbound round
    /// trip to its own key host on every refresh. `.expect(1)` is verified when `server` drops.
    #[tokio::test]
    async fn confidential_client_jwks_uri_is_fetched_once_across_requests() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [jwk_with_kid(&key, "k1")],
            })))
            .expect(1)
            .mount(&server)
            .await;

        seed_client(
            &state,
            serde_json::json!({
                "client_id": CLIENT_ID,
                "redirect_uris": ["https://app.example.com/callback"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks_uri": format!("{}/jwks.json", server.uri()),
            }),
        )
        .await;

        for _ in 0..3 {
            let assertion = sign_assertion(&key, "k1", valid_claims(CLIENT_ID));
            authenticate_token_client(
                &state,
                CLIENT_ID,
                Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
                Some(&assertion),
            )
            .await
            .expect("a cached jwks_uri key must keep authenticating the assertion");
        }
    }

    /// A `jwks_uri` gets the same transport policy as the client_id itself: plain http is
    /// refused for a real host (loopback, the development exception, is covered above).
    #[tokio::test]
    async fn plain_http_jwks_uri_is_refused() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        seed_client(
            &state,
            serde_json::json!({
                "client_id": CLIENT_ID,
                "redirect_uris": ["https://app.example.com/callback"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks_uri": "http://keys.example.com/jwks.json",
            }),
        )
        .await;
        let assertion = sign_assertion(&key, "k1", valid_claims(CLIENT_ID));
        let err = authenticate_token_client(
            &state,
            CLIENT_ID,
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
            Some(&assertion),
        )
        .await
        .unwrap_err();
        assert_eq!(err.error, "invalid_client");
    }

    /// A confidential client that publishes neither `jwks` nor `jwks_uri` has given the server
    /// no way to verify it — that is a broken registration, not an authenticated client.
    #[tokio::test]
    async fn confidential_client_with_no_keys_is_refused() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        seed_client(
            &state,
            serde_json::json!({
                "client_id": CLIENT_ID,
                "redirect_uris": ["https://app.example.com/callback"],
                "token_endpoint_auth_method": "private_key_jwt",
            }),
        )
        .await;
        let assertion = sign_assertion(&key, "k1", valid_claims(CLIENT_ID));
        let err = authenticate_token_client(
            &state,
            CLIENT_ID,
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
            Some(&assertion),
        )
        .await
        .unwrap_err();
        assert_eq!(err.error, "invalid_client");
    }

    /// RFC 7523 requires the assertion to be presented under its own type identifier; a client
    /// sending the JWT with the wrong `client_assertion_type` has not authenticated.
    #[tokio::test]
    async fn wrong_client_assertion_type_is_refused() {
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        seed_client(&state, confidential_metadata(&key)).await;
        let assertion = sign_assertion(&key, "k1", valid_claims(CLIENT_ID));
        let err = authenticate_token_client(
            &state,
            CLIENT_ID,
            Some("urn:ietf:params:oauth:client-assertion-type:saml2-bearer"),
            Some(&assertion),
        )
        .await
        .unwrap_err();
        assert_eq!(err.error, "invalid_client");
    }
}
