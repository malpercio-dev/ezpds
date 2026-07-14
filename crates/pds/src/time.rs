// pattern: Functional Core

//! Shared time helpers.
//!
//! Small epoch/RFC-3339 conversions that were previously copy-pasted across routes and
//! modules. Routes may not import one another, so their common time helpers are homed here.
//! Each variant differs in return type and pre-epoch handling by design — pick the one whose
//! contract matches the call site.

use std::time::{SystemTime, UNIX_EPOCH};

use common::{ApiError, ErrorCode};

/// Current Unix time in seconds, erroring on a pre-epoch system clock.
///
/// Used where a bad clock must surface as a `500` rather than silently produce a nonsense
/// timestamp (e.g. service-auth `exp` validation).
pub(crate) fn unix_now() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| {
            tracing::error!(error = %e, "system clock is before Unix epoch");
            ApiError::new(ErrorCode::InternalError, "system clock error")
        })
}

/// Current Unix time in seconds, clamping a pre-epoch clock to 0 rather than erroring.
///
/// Used where the caller applies its own timestamp-window check, which such a request fails
/// anyway, so there is no need to distinguish the clock error.
pub(crate) fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Current UTC time as an RFC 3339 / ISO-8601 string with millisecond precision.
pub(crate) fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Render a SQLite `datetime('now', …)` value (`YYYY-MM-DD HH:MM:SS`, UTC, no zone)
/// as an unambiguous RFC 3339 / ISO-8601 UTC instant. Unlike most timestamps the API
/// returns informationally, values that drive client-side validity math must carry an
/// explicit zone designator rather than relying on an implied UTC convention.
pub(crate) fn to_rfc3339_utc(sqlite_datetime: &str) -> String {
    format!("{}Z", sqlite_datetime.replace(' ', "T"))
}
