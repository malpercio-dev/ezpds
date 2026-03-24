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
