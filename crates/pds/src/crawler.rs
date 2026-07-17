// pattern: Imperative Shell

//! Outbound `com.atproto.sync.requestCrawl` notifications.
//!
//! After every firehose emission — repo commits **and** the `#account`/`#identity`/`#sync`
//! lifecycle frames — the PDS tells each configured crawler (a relay/BGS such as `bsky.network`)
//! that it has new content, so the crawler pulls this PDS promptly rather than waiting for its next
//! scheduled sweep. The PDS holds a single `Arc<CrawlerNotifier>` in `AppState`; the firehose's
//! single fan-out choke point ([`Firehose::broadcast`](crate::firehose::Firehose)) calls
//! [`CrawlerNotifier::notify`] once per broadcast frame, and `main.rs` fires one on startup so a
//! fresh deploy re-invites any relay that dropped its subscription while this PDS was quiet.
//! Notifying on the non-commit frames is the load-bearing property: a lifecycle frame emitted to no
//! listener (an activation after a migration) is exactly what leaves a relay's view of a DID stale.
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

/// How one `requestCrawl` attempt ended. The automatic [`notify`](CrawlerNotifier::notify) path
/// discards this (fire-and-forget); the explicit operator action
/// [`request_crawl_now`](CrawlerNotifier::request_crawl_now) reports it back to the admin.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CrawlOutcome {
    /// The crawler accepted the request (2xx).
    Accepted,
    /// The crawler rejected it permanently (4xx) — carries a short reason.
    Rejected(String),
    /// Every attempt failed (transport error or 5xx) up to `max_attempts`.
    Exhausted,
}

impl CrawlOutcome {
    /// A short operator-facing reason when the request did not succeed; `None` on acceptance.
    fn reason(&self) -> Option<String> {
        match self {
            Self::Accepted => None,
            Self::Rejected(reason) => Some(reason.clone()),
            Self::Exhausted => Some("crawler did not accept after retries".to_string()),
        }
    }
}

/// The result of one crawler in an explicit "Request crawl" action, for the admin readout.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrawlAttempt {
    /// The crawler host (bare, scheme stripped) the request targeted.
    pub host: String,
    /// Whether the crawler accepted the `requestCrawl`.
    pub accepted: bool,
    /// A short reason when `accepted` is false; `null` on success.
    pub detail: Option<String>,
}

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
    /// Counts notification outcomes into `relay_crawl_requests_total`. `None` for bare test
    /// constructions; `main.rs`/`test_state()` attach the shared handle before Arc-wrapping.
    metrics: Option<Arc<crate::metrics::Metrics>>,
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
            metrics: None,
        }
    }

    /// Attach the shared metrics handle so notification outcomes are counted. Called before
    /// the notifier is Arc-wrapped into `AppState`; constructions that never attach (bare
    /// unit tests) simply record nothing.
    pub fn attach_metrics(&mut self, metrics: Arc<crate::metrics::Metrics>) {
        self.metrics = Some(metrics);
    }

    /// Count one finished notification into `relay_crawl_requests_total{outcome=...}`.
    fn count_outcome(&self, outcome: &'static str) {
        if let Some(metrics) = &self.metrics {
            metrics.relay_crawl_requests.add(
                1,
                &[crate::metrics::label(
                    crate::metrics::names::LABEL_OUTCOME,
                    outcome,
                )],
            );
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
                    // Fire-and-forget: the automatic path discards the outcome (it is logged and
                    // counted inside `send_with_retry`).
                    let _ = this.send_with_retry(&base_url).await;
                })
            })
            .collect()
    }

    /// Send `requestCrawl` to every configured crawler **now**, bypassing the rate-limit window,
    /// and await the outcomes. This is the explicit operator "Request crawl" action, distinct from
    /// the automatic, rate-limited, fire-and-forget [`notify`](Self::notify): the admin is asking
    /// on purpose and wants to see whether each relay accepted. Sends run concurrently.
    ///
    /// Returns one [`CrawlAttempt`] per configured crawler (empty when none are configured). It
    /// deliberately ignores the rate-limit map — an operator's explicit request is never throttled.
    pub async fn request_crawl_now(self: &Arc<Self>) -> Vec<CrawlAttempt> {
        let handles: Vec<_> = self
            .crawlers
            .iter()
            .cloned()
            .map(|base_url| {
                let this = Arc::clone(self);
                tokio::spawn(async move {
                    let outcome = this.send_with_retry(&base_url).await;
                    CrawlAttempt {
                        host: host_from_url(&base_url),
                        accepted: outcome == CrawlOutcome::Accepted,
                        detail: outcome.reason(),
                    }
                })
            })
            .collect();

        let mut attempts = Vec::with_capacity(handles.len());
        for handle in handles {
            // A join error means the send task panicked; report it rather than dropping the crawler
            // silently from the readout.
            match handle.await {
                Ok(attempt) => attempts.push(attempt),
                Err(e) => {
                    tracing::error!(error = %e, "requestCrawl task panicked");
                    attempts.push(CrawlAttempt {
                        host: "unknown".to_string(),
                        accepted: false,
                        detail: Some("crawl request task failed".to_string()),
                    });
                }
            }
        }
        attempts
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
    /// outcomes are logged and counted here, never propagated as an error. Returns the
    /// [`CrawlOutcome`] so an explicit caller ([`request_crawl_now`](Self::request_crawl_now)) can
    /// report it; the automatic [`notify`](Self::notify) path discards it.
    async fn send_with_retry(&self, base_url: &str) -> CrawlOutcome {
        let endpoint = format!("{base_url}/xrpc/com.atproto.sync.requestCrawl");
        let body = serde_json::json!({ "hostname": self.hostname });

        for attempt in 1..=self.max_attempts {
            match self.client.post(&endpoint).json(&body).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(crawler = %base_url, "requestCrawl accepted");
                    self.count_outcome("ok");
                    return CrawlOutcome::Accepted;
                }
                // A 4xx means the request itself is wrong or unauthorised: the crawler has
                // rejected it permanently, so retrying would only repeat the same failure.
                Ok(resp) if resp.status().is_client_error() => {
                    let status = resp.status();
                    tracing::warn!(
                        crawler = %base_url,
                        status = %status,
                        "requestCrawl rejected with a client error; not retrying"
                    );
                    self.count_outcome("rejected");
                    return CrawlOutcome::Rejected(format!(
                        "crawler rejected the request (HTTP {})",
                        status.as_u16()
                    ));
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
        self.count_outcome("exhausted");
        CrawlOutcome::Exhausted
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

    #[tokio::test]
    async fn request_crawl_now_reports_accepted_per_crawler() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.sync.requestCrawl"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let n = notifier(&[server.uri()]);
        let attempts = n.request_crawl_now().await;
        assert_eq!(attempts.len(), 1);
        assert!(attempts[0].accepted, "a 200 must report accepted");
        assert_eq!(attempts[0].detail, None);
        assert_eq!(attempts[0].host, host_from_url(&server.uri()));
    }

    #[tokio::test]
    async fn request_crawl_now_reports_rejection_with_detail() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.sync.requestCrawl"))
            .respond_with(ResponseTemplate::new(400))
            .expect(1) // a 4xx is permanent: exactly one attempt, no retries
            .mount(&server)
            .await;

        let n = notifier(&[server.uri()]);
        let attempts = n.request_crawl_now().await;
        assert_eq!(attempts.len(), 1);
        assert!(!attempts[0].accepted);
        assert!(
            attempts[0].detail.is_some(),
            "a rejection must carry a reason"
        );
    }

    #[tokio::test]
    async fn request_crawl_now_bypasses_the_rate_limit_window() {
        let server = MockServer::start().await;
        // Two requests must arrive: the automatic notify AND the explicit request_crawl_now, even
        // though they fall inside the same rate-limit window.
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.sync.requestCrawl"))
            .respond_with(ResponseTemplate::new(200))
            .expect(2)
            .mount(&server)
            .await;

        let n = notifier(&[server.uri()]);
        // Automatic notify records the crawler as recently-notified.
        for handle in n.notify() {
            handle.await.expect("notify task panicked");
        }
        // The explicit action still sends despite the window being open.
        let attempts = n.request_crawl_now().await;
        assert_eq!(attempts.len(), 1);
        assert!(attempts[0].accepted);
        server.verify().await;
    }

    #[tokio::test]
    async fn request_crawl_now_is_empty_without_crawlers() {
        let n = notifier(&[]);
        assert!(n.request_crawl_now().await.is_empty());
    }
}
