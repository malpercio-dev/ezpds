// pattern: Imperative Shell
//
// Dynamic issuer-key resolution for the auth.md `identity_assertion` flow (ID-JAG verification).
//
// A trusted issuer delivers its signing keys either as an inline PEM (static trust, resolved in
// `routes/agent_identity.rs`) or as a JWKS URL the relay fetches and caches. This module owns the
// dynamic half: a `JwksFetcher` abstraction (production HTTP impl + injectable test mocks, mirroring
// the `dns::TxtResolver` pattern) and a TTL cache (`JwksCache`) keyed by URL that selects an
// ID-JAG's `kid` header out of the issuer's key set and hands back a `DecodingKey`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::DecodingKey;

/// Error fetching or parsing an issuer JWKS.
#[derive(Debug, thiserror::Error)]
#[error("JWKS fetch error: {0}")]
pub struct JwksError(pub String);

/// Abstraction over fetching a JWKS document from an issuer's `jwks_url`.
///
/// Object-safe (uses `Pin<Box<dyn Future>>`) so `dyn JwksFetcher` works behind `Arc`. The
/// production impl is [`HttpJwksFetcher`]; tests inject a mock so no real network I/O runs.
pub trait JwksFetcher: Send + Sync {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<JwkSet, JwksError>> + Send + 'a>>;
}

/// Production [`JwksFetcher`] backed by the shared reqwest client.
pub struct HttpJwksFetcher {
    client: reqwest::Client,
}

impl HttpJwksFetcher {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl JwksFetcher for HttpJwksFetcher {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<JwkSet, JwksError>> + Send + 'a>> {
        Box::pin(async move {
            let resp = self
                .client
                .get(url)
                .send()
                .await
                .map_err(|e| JwksError(format!("request to {url} failed: {e}")))?;
            if !resp.status().is_success() {
                return Err(JwksError(format!(
                    "issuer JWKS endpoint {url} returned HTTP {}",
                    resp.status()
                )));
            }
            resp.json::<JwkSet>()
                .await
                .map_err(|e| JwksError(format!("issuer JWKS at {url} is not a valid JWK set: {e}")))
        })
    }
}

/// One cached JWKS document plus the monotonic instant it was fetched (for TTL expiry).
struct CachedJwks {
    fetched_at: Instant,
    set: JwkSet,
}

/// A TTL cache over a [`JwksFetcher`], keyed by JWKS URL.
///
/// Shared via `Arc` in `AppState`. A verification consults the cache first; on a miss, a stale
/// entry, or a fetched-but-absent `kid` (a rotated key not yet cached), it fetches once and
/// re-selects — so a key rotation is picked up on the first request that names the new `kid`,
/// bounded by one fetch.
pub struct JwksCache {
    fetcher: Arc<dyn JwksFetcher>,
    ttl: Duration,
    entries: Mutex<HashMap<String, CachedJwks>>,
}

impl JwksCache {
    pub fn new(fetcher: Arc<dyn JwksFetcher>, ttl: Duration) -> Self {
        Self {
            fetcher,
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve the decoding key for `(url, kid)`.
    ///
    /// Returns `Ok(Some(key))` when a matching key is found, `Ok(None)` when the (freshly loaded)
    /// key set does not contain `kid` — an unknown signing key, which the caller maps to
    /// `invalid_grant` — or `Err` when the JWKS could not be fetched/parsed (transport/operator
    /// failure, mapped to `server_error`).
    ///
    /// A fresh cached set that already contains `kid` is used without any network call; otherwise
    /// the JWKS is fetched once (never while holding the lock), cached, and the key re-selected.
    pub async fn decoding_key(
        &self,
        url: &str,
        kid: Option<&str>,
    ) -> Result<Option<DecodingKey>, JwksError> {
        // Fast path: a still-fresh cached set that already contains the requested key.
        if let Some(key) = self.cached_key(url, kid) {
            return Ok(Some(key));
        }
        // Miss / stale / rotated key: fetch once (outside the lock), cache, re-select.
        let set = self.fetcher.fetch(url).await?;
        let selected = select_key(&set, kid);
        self.store(url, set);
        Ok(selected)
    }

    /// Look up a still-fresh cached key set and select `kid` from it. `None` on a cache miss, a
    /// stale entry, or a fresh entry that doesn't contain `kid` (forcing a refetch upstream).
    fn cached_key(&self, url: &str, kid: Option<&str>) -> Option<DecodingKey> {
        let entries = self.entries.lock().expect("jwks cache mutex poisoned");
        let cached = entries.get(url)?;
        if cached.fetched_at.elapsed() >= self.ttl {
            return None;
        }
        select_key(&cached.set, kid)
    }

    fn store(&self, url: &str, set: JwkSet) {
        let mut entries = self.entries.lock().expect("jwks cache mutex poisoned");
        entries.insert(
            url.to_string(),
            CachedJwks {
                fetched_at: Instant::now(),
                set,
            },
        );
    }
}

/// Select a decoding key from a JWK set by `kid`. When the ID-JAG carries no `kid`, the choice is
/// unambiguous only if the set holds exactly one key. `None` when no key matches or the matched JWK
/// can't be converted to a decoding key (e.g. an unsupported key type).
fn select_key(set: &JwkSet, kid: Option<&str>) -> Option<DecodingKey> {
    let jwk = match kid {
        Some(kid) => set.find(kid)?,
        None => match set.keys.as_slice() {
            [only] => only,
            _ => return None,
        },
    };
    DecodingKey::from_jwk(jwk).ok()
}

// ── Tests ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;
    use serde_json::json;

    /// A single-key P-256 JWK set carrying `kid`, valid for `DecodingKey::from_jwk`.
    fn jwks_with_kid(kid: &str) -> JwkSet {
        let sk = SigningKey::random(&mut OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
        serde_json::from_value(json!({
            "keys": [{ "kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": kid, "alg": "ES256", "use": "sig" }]
        }))
        .unwrap()
    }

    /// A counting mock fetcher: returns `set` (or an error) and records how many times it ran.
    struct MockFetcher {
        set: JwkSet,
        calls: Arc<AtomicUsize>,
        fail: bool,
    }

    impl JwksFetcher for MockFetcher {
        fn fetch<'a>(
            &'a self,
            _url: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<JwkSet, JwksError>> + Send + 'a>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if self.fail {
                    Err(JwksError("boom".to_string()))
                } else {
                    Ok(self.set.clone())
                }
            })
        }
    }

    fn cache_with(set: JwkSet, fail: bool) -> (JwksCache, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Arc::new(MockFetcher {
            set,
            calls: calls.clone(),
            fail,
        });
        (JwksCache::new(fetcher, Duration::from_secs(3600)), calls)
    }

    #[test]
    fn select_key_by_kid_matches() {
        let set = jwks_with_kid("k1");
        assert!(select_key(&set, Some("k1")).is_some());
    }

    #[test]
    fn select_key_unknown_kid_is_none() {
        let set = jwks_with_kid("k1");
        assert!(select_key(&set, Some("other")).is_none());
    }

    #[test]
    fn select_key_no_kid_single_key_is_ok() {
        let set = jwks_with_kid("k1");
        assert!(select_key(&set, None).is_some());
    }

    #[test]
    fn select_key_no_kid_multiple_keys_is_ambiguous() {
        // Two keys, no kid to disambiguate → refuse rather than guess.
        let mut set = jwks_with_kid("k1");
        set.keys.push(jwks_with_kid("k2").keys.pop().unwrap());
        assert!(select_key(&set, None).is_none());
    }

    #[tokio::test]
    async fn resolves_and_caches_within_ttl() {
        let (cache, calls) = cache_with(jwks_with_kid("k1"), false);
        assert!(cache
            .decoding_key("https://i/jwks", Some("k1"))
            .await
            .unwrap()
            .is_some());
        assert!(cache
            .decoding_key("https://i/jwks", Some("k1"))
            .await
            .unwrap()
            .is_some());
        // Second lookup is served from the cache — the fetcher ran exactly once.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unknown_kid_refetches_then_returns_none() {
        // A kid absent from the cached set forces a refetch (it could be a freshly rotated key);
        // when it's still absent, the resolution is `None` (→ invalid_grant at the call site).
        let (cache, calls) = cache_with(jwks_with_kid("k1"), false);
        // Prime the cache with a hit so an entry exists.
        assert!(cache
            .decoding_key("https://i/jwks", Some("k1"))
            .await
            .unwrap()
            .is_some());
        assert!(cache
            .decoding_key("https://i/jwks", Some("missing"))
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "unknown kid must trigger a refetch"
        );
    }

    #[tokio::test]
    async fn fetch_failure_is_error() {
        let (cache, _calls) = cache_with(jwks_with_kid("k1"), true);
        assert!(cache
            .decoding_key("https://i/jwks", Some("k1"))
            .await
            .is_err());
    }
}
