// pattern: Imperative Shell
//
// Dynamic issuer-key resolution for the auth.md `identity_assertion` flow (ID-JAG verification).
//
// A trusted issuer delivers its signing keys either as an inline PEM (static trust, resolved in
// `routes/agent_identity.rs`) or as a JWKS URL the relay fetches and caches. This module owns the
// dynamic half: a `JwksFetcher` abstraction (production HTTP impl + injectable test mocks, mirroring
// the `dns::TxtResolver` pattern) and a TTL cache (`JwksCache`) keyed by URL that selects an
// ID-JAG's `kid` header out of the issuer's key set and hands back a `DecodingKey`.
//
// The cache is reachable from public, unauthenticated endpoints (`POST /agent/identity`,
// `POST /agent/event/notify`), where the `kid` comes from an *unverified* JWT header. A per-URL
// refetch cooldown bounds how often those requests can force an outbound JWKS fetch — without it,
// a stream of bogus-`kid` tokens naming a trusted issuer would translate one inbound request into
// one outbound fetch (amplification toward the issuer, wasted work here).

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

/// Per-URL cache slot: the last successful fetch (if any) plus the instant of the last fetch
/// *attempt* — success or failure — which drives the refetch cooldown. Tracking attempts rather
/// than successes means a failing issuer (e.g. one timing out) is also retried at most once per
/// cooldown instead of once per inbound request.
struct CacheSlot {
    last_attempt: Instant,
    fetched: Option<CachedJwks>,
}

/// What a locked cache consultation decided; the fetch itself always runs outside the lock.
enum Consult {
    /// A fresh cached set contains the key.
    Key(DecodingKey),
    /// A fresh cached set lacks the key and the cooldown forbids refetching: the `kid` is
    /// negatively cached as unknown until the cooldown lapses.
    KnownAbsent,
    /// No usable cached set and the cooldown forbids refetching (the last attempt failed, or
    /// another request is fetching right now): fail fast instead of piling on.
    FailFast,
    /// The caller may fetch; the attempt has already been stamped into the slot.
    Fetch,
}

/// A TTL cache over a [`JwksFetcher`], keyed by JWKS URL.
///
/// Shared via `Arc` in `AppState`. A verification consults the cache first; on a miss, a stale
/// entry, or a fetched-but-absent `kid` (a rotated key not yet cached), it fetches and re-selects —
/// so a key rotation is picked up by the first request that names the new `kid` once the refetch
/// cooldown (below) allows it.
///
/// `refetch_cooldown` is the minimum interval between fetch *attempts* for a given URL, bounding
/// the outbound amplification available to unauthenticated requests that name arbitrary `kid`s
/// (see the module header). Within the cooldown an unknown `kid` resolves from the last fetched
/// set (→ `Ok(None)`) and a fetch failure keeps failing fast (→ `Err`). The cooldown should stay
/// well below `ttl`; a genuine key rotation is picked up after at most one cooldown of
/// `invalid_grant` responses. Zero disables the cooldown (every miss fetches).
pub struct JwksCache {
    fetcher: Arc<dyn JwksFetcher>,
    ttl: Duration,
    refetch_cooldown: Duration,
    entries: Mutex<HashMap<String, CacheSlot>>,
}

impl JwksCache {
    pub fn new(fetcher: Arc<dyn JwksFetcher>, ttl: Duration, refetch_cooldown: Duration) -> Self {
        Self {
            fetcher,
            ttl,
            refetch_cooldown,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve the decoding key for `(url, kid)`.
    ///
    /// Returns `Ok(Some(key))` when a matching key is found, `Ok(None)` when the cached-or-fetched
    /// key set does not contain `kid` — an unknown signing key, which the caller maps to
    /// `invalid_grant` — or `Err` when the JWKS could not be fetched/parsed (transport/operator
    /// failure, mapped to `server_error`) or a recent failed attempt is still inside the refetch
    /// cooldown.
    ///
    /// A fresh cached set that already contains `kid` is used without any network call; otherwise
    /// the JWKS is fetched at most once per `refetch_cooldown` (never while holding the lock),
    /// cached, and the key re-selected.
    pub async fn decoding_key(
        &self,
        url: &str,
        kid: Option<&str>,
    ) -> Result<Option<DecodingKey>, JwksError> {
        match self.consult(url, kid) {
            Consult::Key(key) => Ok(Some(key)),
            Consult::KnownAbsent => Ok(None),
            Consult::FailFast => Err(JwksError(format!(
                "JWKS fetch for {url} suppressed by refetch cooldown (recent attempt failed or is in flight)"
            ))),
            Consult::Fetch => {
                let set = self.fetcher.fetch(url).await?;
                let selected = select_key(&set, kid);
                self.store(url, set);
                Ok(selected)
            }
        }
    }

    /// Consult the cache under one lock acquisition and decide how to resolve `(url, kid)`.
    ///
    /// When the decision is [`Consult::Fetch`], the attempt is stamped *before* the lock drops, so
    /// concurrent requests inside the cooldown window collapse onto one outbound fetch (the losers
    /// resolve from the cached set or fail fast rather than dogpiling the issuer).
    fn consult(&self, url: &str, kid: Option<&str>) -> Consult {
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("jwks cache mutex poisoned");
        let Some(slot) = entries.get_mut(url) else {
            entries.insert(
                url.to_string(),
                CacheSlot {
                    last_attempt: now,
                    fetched: None,
                },
            );
            return Consult::Fetch;
        };
        let in_cooldown = now.duration_since(slot.last_attempt) < self.refetch_cooldown;
        let fresh = slot
            .fetched
            .as_ref()
            .filter(|cached| now.duration_since(cached.fetched_at) < self.ttl);
        if let Some(cached) = fresh {
            if let Some(key) = select_key(&cached.set, kid) {
                return Consult::Key(key);
            }
            // Fresh set without the kid: refetch (a rotation may have published it) unless the
            // cooldown says this kid stays negatively cached for now.
            if in_cooldown {
                return Consult::KnownAbsent;
            }
        } else if in_cooldown {
            // No usable set and too soon to try again — the last attempt failed (or is still in
            // flight), so answer like that failure instead of hammering the issuer.
            return Consult::FailFast;
        }
        slot.last_attempt = now;
        Consult::Fetch
    }

    fn store(&self, url: &str, set: JwkSet) {
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("jwks cache mutex poisoned");
        entries.insert(
            url.to_string(),
            CacheSlot {
                last_attempt: now,
                fetched: Some(CachedJwks {
                    fetched_at: now,
                    set,
                }),
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

    /// A counting mock fetcher: returns the current `set` (or an error) and records how many times
    /// it ran. The set sits behind a `Mutex` so a test can swap it mid-flight (key rotation).
    struct MockFetcher {
        set: Arc<Mutex<JwkSet>>,
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
                    Ok(self.set.lock().unwrap().clone())
                }
            })
        }
    }

    /// A cache over a mock fetcher with the given refetch cooldown (TTL fixed at 1h). Returns the
    /// swappable set handle and the fetch-call counter.
    fn cache_with_cooldown(
        set: JwkSet,
        fail: bool,
        cooldown: Duration,
    ) -> (JwksCache, Arc<Mutex<JwkSet>>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let set = Arc::new(Mutex::new(set));
        let fetcher = Arc::new(MockFetcher {
            set: set.clone(),
            calls: calls.clone(),
            fail,
        });
        (
            JwksCache::new(fetcher, Duration::from_secs(3600), cooldown),
            set,
            calls,
        )
    }

    fn cache_with(set: JwkSet, fail: bool) -> (JwksCache, Arc<AtomicUsize>) {
        // Cooldown disabled: these tests exercise TTL/selection behavior, not the cooldown.
        let (cache, _set, calls) = cache_with_cooldown(set, fail, Duration::ZERO);
        (cache, calls)
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
        // With the cooldown disabled, a kid absent from the cached set forces a refetch (it could
        // be a freshly rotated key); when it's still absent, the resolution is `None`
        // (→ invalid_grant at the call site).
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

    #[tokio::test]
    async fn unknown_kid_burst_is_bounded_by_cooldown() {
        // The MM-274 amplification vector: a stream of bogus kids for a trusted issuer. Within the
        // cooldown each one resolves negatively from the cached set — no outbound fetch per request.
        let (cache, _set, calls) =
            cache_with_cooldown(jwks_with_kid("k1"), false, Duration::from_secs(3600));
        assert!(cache
            .decoding_key("https://i/jwks", Some("k1"))
            .await
            .unwrap()
            .is_some());
        for i in 0..10 {
            assert!(cache
                .decoding_key("https://i/jwks", Some(&format!("bogus-{i}")))
                .await
                .unwrap()
                .is_none());
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "unknown kids within the cooldown must not refetch"
        );
        // A known key keeps resolving from the cache throughout.
        assert!(cache
            .decoding_key("https://i/jwks", Some("k1"))
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn rotated_key_is_picked_up_after_cooldown() {
        // A genuine rotation publishes a new kid. Within the cooldown it reads as unknown; once
        // the cooldown lapses, the next request naming it triggers the refetch and resolves.
        let cooldown = Duration::from_millis(50);
        let (cache, set, calls) = cache_with_cooldown(jwks_with_kid("k1"), false, cooldown);
        assert!(cache
            .decoding_key("https://i/jwks", Some("k1"))
            .await
            .unwrap()
            .is_some());
        *set.lock().unwrap() = jwks_with_kid("k2");
        assert!(
            cache
                .decoding_key("https://i/jwks", Some("k2"))
                .await
                .unwrap()
                .is_none(),
            "inside the cooldown the rotated kid is still negatively cached"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::sleep(cooldown + Duration::from_millis(20)).await;
        assert!(
            cache
                .decoding_key("https://i/jwks", Some("k2"))
                .await
                .unwrap()
                .is_some(),
            "after the cooldown the rotated kid must resolve via a refetch"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn fetch_failures_fail_fast_within_cooldown() {
        // A failing issuer (outage, timeout) is retried at most once per cooldown; requests inside
        // the window fail fast instead of each waiting out an outbound attempt.
        let (cache, _set, calls) =
            cache_with_cooldown(jwks_with_kid("k1"), true, Duration::from_secs(3600));
        for _ in 0..3 {
            assert!(cache
                .decoding_key("https://i/jwks", Some("k1"))
                .await
                .is_err());
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "repeat requests after a failed fetch must not retry within the cooldown"
        );
    }

    #[tokio::test]
    async fn fetch_failure_retries_after_cooldown() {
        let cooldown = Duration::from_millis(50);
        let (cache, _set, calls) = cache_with_cooldown(jwks_with_kid("k1"), true, cooldown);
        assert!(cache
            .decoding_key("https://i/jwks", Some("k1"))
            .await
            .is_err());
        tokio::time::sleep(cooldown + Duration::from_millis(20)).await;
        assert!(cache
            .decoding_key("https://i/jwks", Some("k1"))
            .await
            .is_err());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a lapsed cooldown must allow the retry"
        );
    }
}
