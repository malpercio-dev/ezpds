// pattern: Functional Core
//
// Sliding-window rate limiter for login failure tracking.
// All state is passed in as arguments; no global state, no I/O.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub(crate) const RATE_LIMIT_WINDOW_SECS: u64 = 60;
pub(crate) const RATE_LIMIT_MAX_FAILURES: usize = 5;

/// Returns `true` if `identifier` has had ≥ `RATE_LIMIT_MAX_FAILURES` failed login
/// attempts within the last `RATE_LIMIT_WINDOW_SECS` seconds (sliding window).
///
/// Prunes expired entries from the front of the deque during the check, keeping
/// memory bounded without a separate background task.
pub(crate) fn is_rate_limited(
    attempts: &mut HashMap<String, VecDeque<Instant>>,
    identifier: &str,
) -> bool {
    let deque = attempts.get_mut(identifier);
    if let Some(deque) = deque {
        let now = Instant::now();
        while let Some(&oldest) = deque.front() {
            if now - oldest > Duration::from_secs(RATE_LIMIT_WINDOW_SECS) {
                deque.pop_front();
            } else {
                break;
            }
        }
        return deque.len() >= RATE_LIMIT_MAX_FAILURES;
    }
    false
}

/// Record a new failed attempt timestamp for `identifier`.
pub(crate) fn record_failure(attempts: &mut HashMap<String, VecDeque<Instant>>, identifier: &str) {
    attempts
        .entry(identifier.to_string())
        .or_default()
        .push_back(Instant::now());
}

/// Clear the failure history for `identifier` on successful authentication.
pub(crate) fn clear_failures(attempts: &mut HashMap<String, VecDeque<Instant>>, identifier: &str) {
    attempts.remove(identifier);
}

/// One `(window, max_points)` constraint within a [`MultiWindowLimiter`].
///
/// A request costs some number of *points* (1 for a plain request; create=3/update=2/delete=1 for
/// repo writes, mirroring the reference PDS). The window rejects a request when the points
/// consumed within the trailing `window` plus the new request's cost would exceed `max_points`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Window {
    pub window: Duration,
    pub max_points: u64,
}

/// The outcome of a [`MultiWindowLimiter::check`], carrying everything the HTTP layer needs to
/// build the standard `RateLimit-*` / `Retry-After` headers. All fields describe the
/// *most-constrained* window (the one with the least headroom), which is the window a client must
/// respect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RateLimitDecision {
    /// Whether the request is permitted (and, if so, was recorded).
    pub allowed: bool,
    /// `max_points` of the most-constrained window (`RateLimit-Limit`).
    pub limit: u64,
    /// Points still available in the most-constrained window after this request
    /// (`RateLimit-Remaining`). Zero when rejected.
    pub remaining: u64,
    /// Seconds until the most-constrained window frees capacity — the value for `Retry-After` on a
    /// rejection and the basis for `RateLimit-Reset`. Always ≥ 1 on a rejection so a client never
    /// busy-retries.
    pub reset_after_secs: u64,
}

/// A pure sliding-window rate limiter supporting several windows at once (e.g. an hourly *and* a
/// daily budget for the same key). All state lives in `entries`; the caller owns it and passes the
/// current `Instant` in, so this stays a Functional Core with no clock or I/O of its own.
///
/// Each key maps to a deque of `(timestamp, cost)` samples ordered oldest-first. A `check` prunes
/// everything older than the longest window, then evaluates every window against the survivors.
pub(crate) struct MultiWindowLimiter {
    windows: Vec<Window>,
    max_window: Duration,
    entries: HashMap<String, VecDeque<(Instant, u64)>>,
}

impl MultiWindowLimiter {
    /// Build a limiter from its windows. Windows with `max_points == 0` are dropped (that budget is
    /// disabled); a limiter with no remaining windows always allows (a pure pass-through).
    pub(crate) fn new(windows: impl IntoIterator<Item = Window>) -> Self {
        let windows: Vec<Window> = windows.into_iter().filter(|w| w.max_points > 0).collect();
        let max_window = windows
            .iter()
            .map(|w| w.window)
            .max()
            .unwrap_or(Duration::ZERO);
        Self {
            windows,
            max_window,
            entries: HashMap::new(),
        }
    }

    /// Evaluate `cost` points against `key` at `now`; record the sample when allowed.
    ///
    /// Rejection records nothing (so a blocked client doesn't dig its own hole deeper), matching
    /// the reference limiter's "consume on success" behaviour for the over-limit case.
    pub(crate) fn check(&mut self, key: &str, cost: u64, now: Instant) -> RateLimitDecision {
        // No active windows → unlimited.
        if self.windows.is_empty() {
            return RateLimitDecision {
                allowed: true,
                limit: 0,
                remaining: 0,
                reset_after_secs: 0,
            };
        }

        let deque = self.entries.entry(key.to_string()).or_default();

        // Prune samples older than the longest window; they can't affect any window.
        while let Some(&(ts, _)) = deque.front() {
            if now.duration_since(ts) > self.max_window {
                deque.pop_front();
            } else {
                break;
            }
        }

        // Evaluate every window; track the most-constrained one (least headroom) for the headers
        // and whether any window forbids the request.
        let mut allowed = true;
        let mut binding_limit = u64::MAX;
        let mut binding_remaining = u64::MAX;
        let mut binding_reset = 0u64;

        for w in &self.windows {
            let cutoff = now.checked_sub(w.window);
            // Consumed points within this window, and the oldest in-window sample (its expiry sets
            // the reset time for this window).
            let mut consumed = 0u64;
            let mut oldest_in_window: Option<Instant> = None;
            for &(ts, points) in deque.iter() {
                let in_window = match cutoff {
                    Some(c) => ts >= c,
                    // Window longer than the process has been up: everything counts.
                    None => true,
                };
                if in_window {
                    consumed = consumed.saturating_add(points);
                    if oldest_in_window.is_none() {
                        oldest_in_window = Some(ts);
                    }
                }
            }

            let remaining_before = w.max_points.saturating_sub(consumed);
            if consumed.saturating_add(cost) > w.max_points {
                allowed = false;
            }

            // Seconds until this window frees the oldest in-window sample (i.e. capacity opens).
            let reset = oldest_in_window
                .map(|ts| {
                    let elapsed = now.duration_since(ts);
                    w.window.saturating_sub(elapsed).as_secs()
                })
                .unwrap_or(0);

            // The binding window is the one with the least headroom; on ties the tighter reset wins.
            if remaining_before < binding_remaining
                || (remaining_before == binding_remaining && reset > binding_reset)
            {
                binding_limit = w.max_points;
                binding_remaining = remaining_before;
                binding_reset = reset;
            }
        }

        if allowed {
            deque.push_back((now, cost));
            RateLimitDecision {
                allowed: true,
                limit: binding_limit,
                remaining: binding_remaining.saturating_sub(cost),
                reset_after_secs: binding_reset,
            }
        } else {
            RateLimitDecision {
                allowed: false,
                limit: binding_limit,
                remaining: 0,
                // Never hand back 0 on a rejection: a client that retries immediately would just be
                // rejected again. Fall back to the longest window if no sample sets a reset (e.g. a
                // single op costs more than the whole budget — a misconfiguration, but bounded).
                reset_after_secs: binding_reset.max(1).min(self.max_window.as_secs().max(1)),
            }
        }
    }
}

#[cfg(test)]
mod window_tests {
    use super::*;

    fn win(secs: u64, max: u64) -> Window {
        Window {
            window: Duration::from_secs(secs),
            max_points: max,
        }
    }

    #[test]
    fn allows_up_to_limit_then_rejects() {
        let mut l = MultiWindowLimiter::new([win(300, 3)]);
        let now = Instant::now();
        for i in 0..3 {
            let d = l.check("ip", 1, now);
            assert!(d.allowed, "request {i} should be allowed");
            assert_eq!(d.limit, 3);
        }
        let d = l.check("ip", 1, now);
        assert!(!d.allowed);
        assert_eq!(d.remaining, 0);
        assert!(d.reset_after_secs >= 1);
    }

    #[test]
    fn reports_remaining_after_each_request() {
        let mut l = MultiWindowLimiter::new([win(300, 5)]);
        let now = Instant::now();
        assert_eq!(l.check("ip", 1, now).remaining, 4);
        assert_eq!(l.check("ip", 1, now).remaining, 3);
    }

    #[test]
    fn keys_are_independent() {
        let mut l = MultiWindowLimiter::new([win(300, 1)]);
        let now = Instant::now();
        assert!(l.check("a", 1, now).allowed);
        // Second hit on `a` is over limit, but `b` is untouched.
        assert!(!l.check("a", 1, now).allowed);
        assert!(l.check("b", 1, now).allowed);
    }

    #[test]
    fn capacity_frees_after_window_elapses() {
        let mut l = MultiWindowLimiter::new([win(300, 1)]);
        let start = Instant::now();
        assert!(l.check("ip", 1, start).allowed);
        assert!(!l.check("ip", 1, start).allowed);
        // Just past the window: the old sample has expired.
        let later = start + Duration::from_secs(301);
        assert!(l.check("ip", 1, later).allowed);
    }

    #[test]
    fn write_points_cost_is_weighted() {
        // create = 3 points; a 5-point budget admits one create (3) then rejects the next (would be 6).
        let mut l = MultiWindowLimiter::new([win(3600, 5)]);
        let now = Instant::now();
        let d = l.check("did", 3, now);
        assert!(d.allowed);
        assert_eq!(d.remaining, 2);
        assert!(!l.check("did", 3, now).allowed);
        // A cheaper op (delete = 1) still fits within the remaining 2.
        assert!(l.check("did", 1, now).allowed);
    }

    #[test]
    fn most_constrained_window_binds() {
        // Hourly 100 / daily 3: the daily window is far tighter and must drive the decision.
        let mut l = MultiWindowLimiter::new([win(3600, 100), win(86400, 3)]);
        let now = Instant::now();
        for _ in 0..3 {
            assert!(l.check("did", 1, now).allowed);
        }
        let d = l.check("did", 1, now);
        assert!(!d.allowed);
        assert_eq!(d.limit, 3, "the daily window is the binding one");
    }

    #[test]
    fn no_windows_is_unlimited() {
        // All-zero knobs → no windows → pass-through.
        let mut l = MultiWindowLimiter::new([win(300, 0)]);
        let now = Instant::now();
        for _ in 0..1000 {
            assert!(l.check("ip", 1, now).allowed);
        }
    }
}
