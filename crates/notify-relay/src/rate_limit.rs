// pattern: Mixed (Functional Core + process-level state)
//
// Per-node token buckets. In-memory only: a restart forgives everyone, which is the right
// trade for a relay whose entire state is re-derivable by re-enrollment — persisting a
// limiter would buy an attacker nothing and cost every restart a write amplification.
//
// The bucket arithmetic is pure (`TokenBucket::take_at`), so exhaustion and refill are
// tested against an explicit clock rather than by sleeping.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::RateLimitConfig;

/// A classic token bucket: `capacity` tokens, refilled at `per_second`.
#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(capacity),
            last_refill: now,
        }
    }

    /// Refill for the elapsed time, then take one token if there is one.
    fn take_at(&mut self, capacity: u32, per_second: f64, now: Instant) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * per_second).min(f64::from(capacity));
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Which budget a request spends from. Registration RPCs and pushes are separate so a
/// chatty push load can never lock a node out of dropping a dead handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bucket {
    Registration,
    Push,
}

/// The process-level limiter: one bucket per (node id, bucket kind).
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Mutex<HashMap<(String, Bucket), TokenBucket>>,
}

/// How long an untouched bucket is kept before the next sweep drops it. Well past a full
/// refill at any sane rate, so pruning can never hand back budget.
const IDLE_EVICTION: Duration = Duration::from_secs(6 * 3600);

/// Prune when the map grows past this, so a flood of one-shot node ids cannot grow it
/// without bound between real requests.
const PRUNE_THRESHOLD: usize = 1024;

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// The (capacity, refill-per-second) pair for a bucket kind. A per-hour rate of zero
    /// disables the limiter entirely.
    fn limits(&self, bucket: Bucket) -> Option<(u32, f64)> {
        let (per_hour, burst) = match bucket {
            Bucket::Registration => (
                self.config.registrations_per_hour,
                self.config.registrations_burst,
            ),
            Bucket::Push => (self.config.pushes_per_hour, self.config.pushes_burst),
        };
        if per_hour == 0 {
            return None;
        }
        Some((burst, f64::from(per_hour) / 3600.0))
    }

    /// Charge one request to `node_id`, returning false when the budget is exhausted.
    pub fn check(&self, node_id: &str, bucket: Bucket) -> bool {
        self.check_at(node_id, bucket, Instant::now())
    }

    /// `check` against an explicit clock, so the exhaustion/refill behaviour is testable
    /// without sleeping.
    pub fn check_at(&self, node_id: &str, bucket: Bucket, now: Instant) -> bool {
        let Some((capacity, per_second)) = self.limits(bucket) else {
            return true;
        };
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if buckets.len() > PRUNE_THRESHOLD {
            buckets.retain(|_, b| now.saturating_duration_since(b.last_refill) < IDLE_EVICTION);
        }
        let entry = buckets
            .entry((node_id.to_owned(), bucket))
            .or_insert_with(|| TokenBucket::new(capacity, now));
        entry.take_at(capacity, per_second, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(registrations: u32, burst: u32) -> RateLimiter {
        RateLimiter::new(RateLimitConfig {
            registrations_per_hour: registrations,
            registrations_burst: burst,
            pushes_per_hour: 3600,
            pushes_burst: 2,
        })
    }

    #[test]
    fn a_burst_is_allowed_then_exhausted() {
        let limiter = limiter(3600, 3);
        let now = Instant::now();
        for i in 0..3 {
            assert!(
                limiter.check_at("node-a", Bucket::Registration, now),
                "request {i} of the burst must be allowed"
            );
        }
        assert!(
            !limiter.check_at("node-a", Bucket::Registration, now),
            "the bucket must be empty once the burst is spent"
        );
    }

    #[test]
    fn tokens_refill_over_time() {
        let limiter = limiter(3600, 1); // one per second
        let start = Instant::now();
        assert!(limiter.check_at("node-a", Bucket::Registration, start));
        assert!(!limiter.check_at("node-a", Bucket::Registration, start));
        assert!(limiter.check_at(
            "node-a",
            Bucket::Registration,
            start + Duration::from_secs(2)
        ));
    }

    #[test]
    fn budgets_are_per_node_and_per_bucket() {
        let limiter = limiter(3600, 1);
        let now = Instant::now();
        assert!(limiter.check_at("node-a", Bucket::Registration, now));
        assert!(
            limiter.check_at("node-b", Bucket::Registration, now),
            "one node's spending must not charge another"
        );
        assert!(
            limiter.check_at("node-a", Bucket::Push, now),
            "a spent registration budget must not close the push budget"
        );
    }

    #[test]
    fn a_zero_rate_disables_the_limiter() {
        let limiter = limiter(0, 0);
        let now = Instant::now();
        for _ in 0..100 {
            assert!(limiter.check_at("node-a", Bucket::Registration, now));
        }
    }
}
