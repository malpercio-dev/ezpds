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
//! also accepted — both appear in the wild), `exp` required, and a 30-second clock tolerance
//! (the reference implementation's zero-tolerance `iat` check is a documented interop trap —
//! bluesky-social/atproto#4474). The verification key comes from the metadata's inline
//! `jwks` or its `jwks_uri`; the latter is a client-controlled URL, so it is policy-checked
//! (https, no userinfo/fragment) and fetched with the SSRF-hardened client. `jti` presence
//! is required but not replay-tracked: every protected grant is already single-use
//! (authorization codes) or rotation-guarded (refresh tokens), so a replayed assertion alone
//! wins nothing.

use jsonwebtoken::jwk::JwkSet;
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

#[derive(Debug, Deserialize)]
struct ClientAssertionClaims {
    iss: String,
    sub: String,
    jti: Option<String>,
}

fn invalid_client(description: impl Into<String>) -> OAuthTokenError {
    OAuthTokenError::new_owned("invalid_client", description.into())
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
    validation.set_required_spec_claims(&["exp", "aud"]);

    let data = jsonwebtoken::decode::<ClientAssertionClaims>(assertion, &key, &validation)
        .map_err(|e| invalid_client(format!("client_assertion rejected: {e}")))?;

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

/// Resolve the client's assertion-verification key from its metadata: the inline `jwks`
/// first, else a policy-checked fetch of `jwks_uri` via the SSRF-hardened client.
async fn resolve_client_key(
    state: &AppState,
    metadata: &ClientMetadata,
    kid: Option<&str>,
) -> Result<DecodingKey, OAuthTokenError> {
    if let Some(jwks) = &metadata.jwks {
        let set: JwkSet = serde_json::from_value(jwks.clone())
            .map_err(|_| invalid_client("client metadata jwks is not a valid JWK set"))?;
        return select_key(&set, kid);
    }
    if let Some(url) = &metadata.jwks_uri {
        let parsed = url::Url::parse(url)
            .map_err(|_| invalid_client("client metadata jwks_uri is not a valid URL"))?;
        // The URL comes from a client-authored document: same outbound policy as client_id
        // resolution (https only, no credentials), and the hardened client's connect-time
        // SSRF guard covers the address itself.
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(invalid_client(
                "client metadata jwks_uri must be a plain https URL",
            ));
        }
        let resp = state
            .hardened_http_client
            .get(parsed)
            .send()
            .await
            .map_err(|_| invalid_client("failed to fetch client jwks_uri"))?;
        if !resp.status().is_success() {
            return Err(invalid_client(format!(
                "client jwks_uri returned HTTP {}",
                resp.status()
            )));
        }
        let set: JwkSet = resp
            .json()
            .await
            .map_err(|_| invalid_client("client jwks_uri did not return a valid JWK set"))?;
        return select_key(&set, kid);
    }
    Err(invalid_client(
        "client metadata declares private_key_jwt but provides neither jwks nor jwks_uri",
    ))
}

fn select_key(set: &JwkSet, kid: Option<&str>) -> Result<DecodingKey, OAuthTokenError> {
    let jwk = match kid {
        Some(kid) => set
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid)),
        // No kid on the assertion: unambiguous only when the set holds exactly one key.
        None if set.keys.len() == 1 => set.keys.first(),
        None => None,
    }
    .ok_or_else(|| invalid_client("no matching key in the client's JWK set"))?;
    DecodingKey::from_jwk(jwk).map_err(|_| invalid_client("client JWK is not a usable key"))
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
}
