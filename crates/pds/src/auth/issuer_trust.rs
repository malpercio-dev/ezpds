// pattern: Mixed (unavoidable)
//
// Shared trusted-issuer verification for the auth.md agent surface. A trusted external identity
// provider signs two kinds of token this server accepts:
//
//   - an **ID-JAG** presented at `POST /agent/identity` (the `identity_assertion` flow) — see
//     `routes/agent_identity.rs`; and
//   - a **Security Event Token** (SET, RFC 8417) pushed to `POST /agent/event/notify` to drive
//     provider-initiated revocation — see `routes/agent_event.rs`.
//
// Both are JWTs verified against the *same* `[agent_auth] trusted_issuers` trust list: select the
// issuer by the token's `iss`, resolve its key (inline `public_key_pem` for static trust, or a
// cached `jwks_url` for dynamic trust), then verify the signature plus `iss`/`aud` (and `exp` when
// present). Routes may not import one another (crate hard rule), so this shared machinery lives in
// `auth/` where both handlers can reach it.
//
// Pure key/claim logic (Functional Core) sits alongside the async JWKS fetch (Imperative Shell),
// hence the Mixed pattern. Errors are returned as a neutral enum so each caller maps them into its
// own response vocabulary (auth.md `{error,…}` for the ID-JAG flow, RFC 8935 `{err,…}` for SETs).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use common::{AgentAuthConfig, TrustedIssuer};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::auth::jwks::JwksCache;

/// The WorkOS auth.md event type a provider-driven revocation SET must carry. Advertised as the sole
/// entry of `events_supported` in the AS metadata (`routes/oauth_server_metadata.rs`) and required
/// in a SET's `events` claim by `routes/agent_event.rs` — defined here so the advertised and the
/// enforced value can never drift apart.
pub const REVOKED_EVENT_TYPE: &str =
    "https://schemas.workos.com/events/agent/auth/identity/assertion/revoked";

/// Failure verifying a JWT against a trusted issuer. Each caller maps these into its own error shape.
#[derive(Debug)]
pub enum TrustedJwtError {
    /// Operator misconfiguration (an unusable configured key or unsupported algorithm) or a
    /// transient JWKS fetch/transport failure — the client is not at fault.
    ServerError,
    /// The token's signing key (`kid`) is not present in the issuer's published JWKS.
    UnknownKey,
    /// Signature / `iss` / `aud` / `exp` verification failed. Carries the underlying detail.
    Invalid(String),
}

/// Select the trusted-issuer config entry whose `iss` matches, if any.
pub fn select_issuer<'a>(config: &'a AgentAuthConfig, iss: &str) -> Option<&'a TrustedIssuer> {
    config.trusted_issuers.iter().find(|t| t.issuer == iss)
}

/// Read a single top-level string claim out of a JWT *without* verifying its signature. Used only to
/// pick the trusted issuer (by `iss`) before real verification runs.
pub fn unverified_claim(jwt: &str, key: &str) -> Option<String> {
    let payload_b64 = jwt.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value.get(key)?.as_str().map(str::to_string)
}

/// Verify a JWT signed by a trusted issuer and deserialize its claims into `T`.
///
/// Resolves the issuer's key (inline PEM or cached JWKS), then enforces the signature, `iss`, `aud`
/// (the issuer's configured `audience` or this server's `public_url`), and every claim named in
/// `required`. `exp` is validated whenever it is present; list it in `required` to also make it
/// mandatory (the ID-JAG flow does; a SET does not). Caller-specific post-verification (an ID-JAG's
/// `auth_time` freshness, a SET's `events` payload) stays with the caller.
pub async fn verify_trusted_jwt<T: DeserializeOwned>(
    jwks_cache: &JwksCache,
    issuer: &TrustedIssuer,
    public_url: &str,
    jwt: &str,
    required: &[&str],
) -> Result<T, TrustedJwtError> {
    let (key, alg) = resolve_decoding_key(jwks_cache, issuer, jwt).await?;

    let expected_aud = issuer
        .audience
        .clone()
        .unwrap_or_else(|| public_url.trim_end_matches('/').to_string());

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[&issuer.issuer]);
    validation.set_audience(&[&expected_aud]);
    validation.set_required_spec_claims(required);

    decode::<T>(jwt, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| TrustedJwtError::Invalid(e.to_string()))
}

/// Resolve the decoding key + expected algorithm for a trusted issuer's token.
///
/// A static-trust issuer carries its key inline (`public_key_pem`); a dynamic-trust issuer names a
/// `jwks_url`, whose key set is fetched (cached) and indexed by the token's `kid` header. The
/// expected algorithm is the issuer's configured `algorithm` in both cases (already validated at
/// config load).
async fn resolve_decoding_key(
    jwks_cache: &JwksCache,
    issuer: &TrustedIssuer,
    jwt: &str,
) -> Result<(DecodingKey, Algorithm), TrustedJwtError> {
    if let Some(jwks_url) = issuer.jwks_url.as_deref().filter(|u| !u.is_empty()) {
        let alg = algorithm_from_str(&issuer.algorithm).ok_or_else(|| {
            tracing::error!(issuer = %issuer.issuer, algorithm = %issuer.algorithm, "trusted issuer has an unsupported algorithm");
            TrustedJwtError::ServerError
        })?;
        let kid = decode_header(jwt).ok().and_then(|h| h.kid);
        let key = jwks_cache
            .decoding_key(jwks_url, kid.as_deref())
            .await
            .map_err(|e| {
                tracing::error!(issuer = %issuer.issuer, jwks_url, error = %e, "failed to resolve issuer JWKS");
                TrustedJwtError::ServerError
            })?
            .ok_or(TrustedJwtError::UnknownKey)?;
        Ok((key, alg))
    } else {
        pem_decoding_key(issuer).ok_or_else(|| {
            tracing::error!(issuer = %issuer.issuer, "trusted issuer has an unusable public_key_pem/algorithm");
            TrustedJwtError::ServerError
        })
    }
}

/// Build a `jsonwebtoken` decoding key + algorithm from a trusted issuer's inline PEM. `None` on an
/// absent/unusable PEM or an algorithm outside the supported set (both also rejected at config load).
fn pem_decoding_key(issuer: &TrustedIssuer) -> Option<(DecodingKey, Algorithm)> {
    let pem = issuer.public_key_pem.as_deref()?.as_bytes();
    let alg = algorithm_from_str(&issuer.algorithm)?;
    let key = match alg {
        Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(pem).ok()?,
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            DecodingKey::from_rsa_pem(pem).ok()?
        }
        Algorithm::EdDSA => DecodingKey::from_ed_pem(pem).ok()?,
        _ => return None,
    };
    Some((key, alg))
}

/// Map a JWS algorithm name to a `jsonwebtoken::Algorithm`. `None` outside the supported set
/// (`config::SUPPORTED_IDJAG_ALGORITHMS`, the config-load allowlist this mirrors).
fn algorithm_from_str(alg: &str) -> Option<Algorithm> {
    match alg {
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "EdDSA" => Some(Algorithm::EdDSA),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer(iss: &str) -> TrustedIssuer {
        TrustedIssuer {
            issuer: iss.to_string(),
            audience: None,
            public_key_pem: None,
            jwks_url: None,
            algorithm: "ES256".to_string(),
        }
    }

    #[test]
    fn select_issuer_matches_by_iss() {
        let cfg = AgentAuthConfig {
            trusted_issuers: vec![issuer("https://a.example"), issuer("https://b.example")],
            ..AgentAuthConfig::default()
        };
        assert_eq!(
            select_issuer(&cfg, "https://b.example").map(|t| t.issuer.as_str()),
            Some("https://b.example")
        );
        assert!(select_issuer(&cfg, "https://c.example").is_none());
    }

    #[test]
    fn algorithm_from_str_covers_the_allowlist_and_rejects_others() {
        for name in ["ES256", "ES384", "RS256", "RS384", "RS512", "EdDSA"] {
            assert!(
                algorithm_from_str(name).is_some(),
                "{name} must be supported"
            );
        }
        assert!(algorithm_from_str("HS256").is_none());
        assert!(algorithm_from_str("none").is_none());
    }

    #[test]
    fn unverified_claim_reads_iss_without_verifying() {
        // header.payload.sig — payload carries {"iss":"https://x.example"}.
        let payload = URL_SAFE_NO_PAD.encode(br#"{"iss":"https://x.example","sub":"s"}"#);
        let jwt = format!("aaa.{payload}.bbb");
        assert_eq!(
            unverified_claim(&jwt, "iss").as_deref(),
            Some("https://x.example")
        );
        assert_eq!(unverified_claim(&jwt, "sub").as_deref(), Some("s"));
        assert!(unverified_claim(&jwt, "aud").is_none());
        assert!(unverified_claim("not-a-jwt", "iss").is_none());
    }

    #[test]
    fn pem_decoding_key_rejects_unusable_pem() {
        let bad = TrustedIssuer {
            public_key_pem: Some(
                "-----BEGIN PUBLIC KEY-----\nnot base64\n-----END PUBLIC KEY-----".to_string(),
            ),
            ..issuer("https://x.example")
        };
        assert!(pem_decoding_key(&bad).is_none());
    }
}
