// pattern: Imperative Shell

//! Outbound `com.atproto.sync.requestCrawl` notifications.
//!
//! After every repo commit the relay tells each configured crawler (a relay/BGS such as
//! `bsky.network`) that new content is available, so the crawler pulls this PDS promptly
//! rather than waiting for its next scheduled sweep. The relay holds a single
//! `Arc<CrawlerNotifier>` in `AppState`; the firehose emit path calls [`CrawlerNotifier::notify`]
//! once per commit.
//!
//! **Fire-and-forget.** `notify` never blocks the commit: it picks the crawlers that are due
//! (rate limiting), then spawns one detached task per crawler to POST the request with retry.
//! A failure to reach a crawler is logged and dropped — the commit is already durable, and the
//! crawler will still discover the content on its next sweep or via the firehose.
//!
//! **Rate limiting.** Each crawler is notified at most once per [`min_interval`](CrawlerNotifier)
//! (30s by default). A burst of commits collapses into a single notification per crawler per
//! window; the crawler then pulls everything that accumulated.
//!
//! **Retry.** Each notification is retried with exponential backoff up to `max_attempts` times
//! (3 by default) before giving up, covering transient network failures and crawler restarts.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Minimum interval between notifications to the same crawler.
const DEFAULT_MIN_INTERVAL: Duration = Duration::from_secs(30);
/// Total send attempts per notification (initial try plus retries).
const DEFAULT_MAX_ATTEMPTS: u32 = 3;
/// Base delay for the exponential retry backoff (doubles each attempt).
const DEFAULT_BASE_BACKOFF: Duration = Duration::from_millis(500);

/// Notifies configured crawlers via `com.atproto.sync.requestCrawl` after new content.
pub struct CrawlerNotifier {
    client: reqwest::Client,
    /// The relay's own hostname, sent as the `hostname` field of the request body.
    hostname: String,
    /// Normalised crawler base URLs (scheme + authority, no trailing slash), de-duplicated.
    crawlers: Vec<String>,
    /// Last time each crawler was notified, for rate limiting. Keyed by base URL.
    /// `std::sync::Mutex` is sufficient: the critical section only touches the map.
    last_notified: Mutex<HashMap<String, Instant>>,
    min_interval: Duration,
    max_attempts: u32,
    base_backoff: Duration,
}

impl CrawlerNotifier {
    /// Build a notifier for the given crawler base URLs with production defaults
    /// (30s rate limit, 3 attempts, 500ms base backoff).
    ///
    /// `urls` are normalised (trailing slashes trimmed, blanks dropped, duplicates removed);
    /// an empty resulting list makes [`notify`](Self::notify) a no-op.
    pub fn new(client: reqwest::Client, hostname: String, urls: &[String]) -> Self {
        Self::with_settings(
            client,
            hostname,
            urls,
            DEFAULT_MIN_INTERVAL,
            DEFAULT_MAX_ATTEMPTS,
            DEFAULT_BASE_BACKOFF,
        )
    }

    fn with_settings(
        client: reqwest::Client,
        hostname: String,
        urls: &[String],
        min_interval: Duration,
        max_attempts: u32,
        base_backoff: Duration,
    ) -> Self {
        Self {
            client,
            hostname,
            crawlers: normalize_urls(urls),
            last_notified: Mutex::new(HashMap::new()),
            min_interval,
            max_attempts,
            base_backoff,
        }
    }

    /// Notify every crawler that is currently outside its rate-limit window.
    ///
    /// Returns immediately: due crawlers are notified on detached background tasks. With no
    /// configured crawlers (or all of them rate-limited) this spawns nothing.
    ///
    /// Returns the spawned task handles. Production callers ignore them (fire-and-forget —
    /// dropping a [`JoinHandle`](tokio::task::JoinHandle) does not cancel its task), while tests
    /// await them to observe the notification deterministically.
    pub fn notify(self: &Arc<Self>) -> Vec<tokio::task::JoinHandle<()>> {
        if self.crawlers.is_empty() {
            return Vec::new();
        }
        self.select_due(Instant::now())
            .into_iter()
            .map(|base_url| {
                let this = Arc::clone(self);
                tokio::spawn(async move {
                    this.send_with_retry(&base_url).await;
                })
            })
            .collect()
    }

    /// Return the crawlers due for notification at `now`, recording `now` as their last-notified
    /// time so a subsequent call within `min_interval` skips them. Pure with respect to I/O —
    /// only the rate-limit map is touched — so the rate-limiting policy is unit-testable.
    fn select_due(&self, now: Instant) -> Vec<String> {
        let mut last = self
            .last_notified
            .lock()
            .expect("crawler rate-limit mutex poisoned");
        let mut due = Vec::new();
        for url in &self.crawlers {
            let allowed = match last.get(url) {
                Some(prev) => now.saturating_duration_since(*prev) >= self.min_interval,
                None => true,
            };
            if allowed {
                last.insert(url.clone(), now);
                due.push(url.clone());
            }
        }
        due
    }

    /// POST `requestCrawl` to one crawler, retrying with exponential backoff. Best-effort: all
    /// outcomes (success, rejection, transport error, exhaustion) are logged, never propagated.
    async fn send_with_retry(&self, base_url: &str) {
        let endpoint = format!("{base_url}/xrpc/com.atproto.sync.requestCrawl");
        let body = serde_json::json!({ "hostname": self.hostname });

        for attempt in 1..=self.max_attempts {
            match self.client.post(&endpoint).json(&body).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!(crawler = %base_url, "requestCrawl accepted");
                    return;
                }
                // A 4xx means the request itself is wrong or unauthorised: the crawler has
                // rejected it permanently, so retrying would only repeat the same failure.
                Ok(resp) if resp.status().is_client_error() => {
                    tracing::warn!(
                        crawler = %base_url,
                        status = %resp.status(),
                        "requestCrawl rejected with a client error; not retrying"
                    );
                    return;
                }
                Ok(resp) => {
                    tracing::warn!(
                        crawler = %base_url,
                        status = %resp.status(),
                        attempt,
                        "requestCrawl rejected by crawler"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        crawler = %base_url,
                        error = %e,
                        attempt,
                        "requestCrawl request failed"
                    );
                }
            }
            if attempt < self.max_attempts {
                tokio::time::sleep(self.backoff_for(attempt)).await;
            }
        }
        tracing::warn!(
            crawler = %base_url,
            attempts = self.max_attempts,
            "requestCrawl gave up after exhausting retries"
        );
    }

    /// Exponential backoff for a 1-based attempt number: `base * 2^(attempt - 1)`.
    fn backoff_for(&self, attempt: u32) -> Duration {
        self.base_backoff * 2u32.pow(attempt.saturating_sub(1))
    }
}

/// Extract the `host[:port]` authority from a service URL for use as the requestCrawl
/// `hostname`. Strips the scheme and any path/query/fragment.
pub fn host_from_url(url: &str) -> String {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme)
        .trim_end_matches('.')
        .to_string()
}

/// Normalise crawler base URLs: trim trailing slashes and whitespace, drop blanks, and
/// de-duplicate while preserving order.
fn normalize_urls(urls: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for url in urls {
        let trimmed = url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("test http client")
    }

    fn notifier(urls: &[String]) -> Arc<CrawlerNotifier> {
        // Tiny backoff so retry tests don't sleep for real.
        Arc::new(CrawlerNotifier::with_settings(
            test_client(),
            "pds.example.com".to_string(),
            urls,
            DEFAULT_MIN_INTERVAL,
            DEFAULT_MAX_ATTEMPTS,
            Duration::from_millis(1),
        ))
    }

    #[test]
    fn host_from_url_strips_scheme_and_path() {
        assert_eq!(host_from_url("https://bsky.network"), "bsky.network");
        assert_eq!(host_from_url("http://localhost:8080"), "localhost:8080");
        assert_eq!(
            host_from_url("https://pds.example.com/xrpc/foo"),
            "pds.example.com"
        );
        assert_eq!(host_from_url("https://pds.example.com/"), "pds.example.com");
        assert_eq!(host_from_url("pds.example.com"), "pds.example.com");
    }

    #[test]
    fn normalize_trims_dedupes_and_drops_blanks() {
        let input = vec![
            "https://a.example/".to_string(),
            "  https://b.example  ".to_string(),
            "https://a.example".to_string(), // dup of the first after normalisation
            String::new(),
            "   ".to_string(),
        ];
        assert_eq!(
            normalize_urls(&input),
            vec!["https://a.example", "https://b.example"]
        );
    }

    #[test]
    fn select_due_enforces_rate_limit_window() {
        let n = notifier(&[
            "https://a.example".to_string(),
            "https://b.example".to_string(),
        ]);
        let t0 = Instant::now();

        // First pass: both crawlers are due.
        assert_eq!(n.select_due(t0).len(), 2);
        // Within the window: none are due.
        assert!(n.select_due(t0 + Duration::from_secs(10)).is_empty());
        // Just before the window closes: still none.
        assert!(n.select_due(t0 + Duration::from_secs(29)).is_empty());
        // After the window: both are due again.
        assert_eq!(n.select_due(t0 + Duration::from_secs(31)).len(), 2);
    }

    #[test]
    fn select_due_is_empty_without_crawlers() {
        let n = notifier(&[]);
        assert!(n.select_due(Instant::now()).is_empty());
    }

    #[tokio::test]
    async fn send_posts_requestcrawl_with_hostname() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.sync.requestCrawl"))
            .and(body_json(
                serde_json::json!({ "hostname": "pds.example.com" }),
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let n = notifier(&[server.uri()]);
        n.send_with_retry(n.crawlers[0].as_str()).await;
        // `expect(1)` is verified on drop.
    }

    #[tokio::test]
    async fn send_retries_on_failure_up_to_max_attempts() {
        let server = MockServer::start().await;
        // Always fail: the notifier should try exactly max_attempts (3) times before giving up.
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.sync.requestCrawl"))
            .respond_with(ResponseTemplate::new(503))
            .expect(3)
            .mount(&server)
            .await;

        let n = notifier(&[server.uri()]);
        n.send_with_retry(n.crawlers[0].as_str()).await;
    }

    #[tokio::test]
    async fn send_does_not_retry_on_client_error() {
        let server = MockServer::start().await;
        // A 4xx is a permanent rejection: exactly one request, no retries.
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.sync.requestCrawl"))
            .respond_with(ResponseTemplate::new(400))
            .expect(1)
            .mount(&server)
            .await;

        let n = notifier(&[server.uri()]);
        n.send_with_retry(n.crawlers[0].as_str()).await;
    }

    #[tokio::test]
    async fn send_stops_retrying_after_success() {
        let server = MockServer::start().await;
        // First attempt fails, second succeeds: exactly 2 requests, no third.
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.sync.requestCrawl"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.sync.requestCrawl"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let n = notifier(&[server.uri()]);
        n.send_with_retry(n.crawlers[0].as_str()).await;
    }

    #[tokio::test]
    async fn notify_skips_rate_limited_crawler() {
        let server = MockServer::start().await;
        // Only one request should arrive despite two notify() calls in the same window.
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.sync.requestCrawl"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let n = notifier(&[server.uri()]);
        let handles = n.notify();
        // Second call is inside the rate-limit window: the crawler is skipped, so no task
        // is spawned and no second request is sent.
        assert!(
            n.notify().is_empty(),
            "a rate-limited crawler must not be notified again"
        );
        // Await the first call's task so the assertion is deterministic (no fixed sleep).
        assert_eq!(handles.len(), 1);
        for handle in handles {
            handle.await.expect("crawler notify task panicked");
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn notify_with_no_crawlers_is_noop() {
        let n = notifier(&[]);
        assert!(n.notify().is_empty(), "no crawlers means nothing spawned");
    }
}
