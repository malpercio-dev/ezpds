// pattern: Functional Core

//! Pure validation helpers shared across route handlers.
//!
//! These functions perform format/shape checks and small lock-acquisition
//! plumbing with no I/O of their own. Each returns either a plain boolean,
//! a `Result<_, &'static str>` (so callers map the message into their own
//! `ApiError` code), or a locked guard mapped to a caller-specified `ApiError`.

use std::collections::{HashMap, VecDeque};
use std::sync::MutexGuard;
use std::time::Instant;

use common::{ApiError, ErrorCode};

use crate::app::FailedLoginStore;

/// Returns `true` if `did` satisfies ATProto's general DID syntax profile.
///
/// DID-method-specific validation remains layered on top when the DID is resolved.
pub fn is_valid_did(did: &str) -> bool {
    crate::identity::did::is_valid_did(did)
}

/// Maximum allowed length for a device public key string.
///
/// A P-256 uncompressed public key in base64 is ~88 chars; 512 is generous
/// enough to accommodate any standard encoding without accepting unbounded input.
pub const MAX_DEVICE_PUBLIC_KEY_LEN: usize = 512;

/// Validate a device public key string: must be non-empty and at most
/// [`MAX_DEVICE_PUBLIC_KEY_LEN`] characters.
///
/// Returns the offending message on failure so each caller can wrap it in the
/// `ApiError` code it already uses. The oversize message is owned (`String`)
/// because it interpolates the limit.
pub fn validate_device_public_key(public_key: &str) -> Result<(), String> {
    if public_key.is_empty() {
        return Err("devicePublicKey must not be empty".to_string());
    }
    if public_key.len() > MAX_DEVICE_PUBLIC_KEY_LEN {
        return Err(format!(
            "devicePublicKey must be at most {MAX_DEVICE_PUBLIC_KEY_LEN} characters"
        ));
    }
    Ok(())
}

/// Lock the shared failed-login store, mapping a poisoned mutex to
/// `ApiError(InternalError, "internal error")`.
///
/// `phase` is logged as the `phase` field when present (matching the
/// provisioning-session call sites); when `None`, the log carries no `phase`
/// field (matching the create-session call sites). Either way the message text
/// is identical to the inlined boilerplate it replaces.
pub fn lock_failed_login_attempts<'a>(
    store: &'a FailedLoginStore,
    phase: Option<&str>,
) -> Result<MutexGuard<'a, HashMap<String, VecDeque<Instant>>>, ApiError> {
    store.lock().map_err(|_| {
        match phase {
            Some(phase) => tracing::error!(phase, "failed_login_attempts mutex is poisoned"),
            None => tracing::error!("failed_login_attempts mutex is poisoned"),
        }
        ApiError::new(ErrorCode::InternalError, "internal error")
    })
}

/// Validate the self-describing ATProto string formats inside a record value before it is
/// written, so a malformed datetime or AT-URI is rejected on ingestion the way the reference
/// PDS rejects it for a lexicon it knows.
///
/// Custos does not vendor the `app.bsky.*` lexicons the reference validates records against, so
/// it cannot do schema-driven field typing. Two signals need no schema, so they are checked here:
///
/// * the record's **top-level `createdAt`** — the timestamp field present in essentially every
///   ATProto record type (post, like, repost, follow, block, list, profile, …) — must be a valid
///   ATProto datetime. Only the record root is checked: a nested `createdAt` inside some
///   third-party embed carries no such guarantee, and the reference fails open on lexicons it
///   doesn't bundle, so validating it could reject a record bsky.social accepts.
/// * every **`at://`-scheme string**, at any depth, must parse as a syntactically valid AT-URI —
///   the scheme is self-describing, so an `at://` value is unambiguously an AT-URI attempt.
///
/// Returns the offending message on failure so the caller can wrap it in the `ApiError` code it
/// already uses. Reads and CAR imports are deliberately untouched — this is a write-time
/// ingestion gate only. Full parity for arbitrary third-party lexicons would need their schemas;
/// that residual gap is the same fail-open behaviour the reference shows for unbundled lexicons.
pub fn validate_record_formats(record: &serde_json::Value) -> Result<(), String> {
    if let Some(serde_json::Value::String(created_at)) = record.get("createdAt") {
        if !repo_engine::is_valid_datetime(created_at) {
            return Err(format!(
                "createdAt is not a valid ATProto datetime: {created_at}"
            ));
        }
    }

    validate_at_uris(record)
}

/// Recursively assert that every `at://`-scheme string in `value` parses as a valid AT-URI.
fn validate_at_uris(value: &serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::String(s) => {
            if s.starts_with("at://") && repo_engine::AtUri::parse(s).is_err() {
                // Echo a bounded prefix — an AT-URI may be up to 8 KiB, and the client already
                // holds the full value it sent.
                let shown: String = s.chars().take(96).collect();
                return Err(format!("record contains a malformed AT-URI: {shown}"));
            }
            Ok(())
        }
        serde_json::Value::Array(items) => items.iter().try_for_each(validate_at_uris),
        serde_json::Value::Object(map) => map.values().try_for_each(validate_at_uris),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_well_formed_record() {
        let record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "hello",
            "createdAt": "2026-07-17T12:00:00.000Z",
            "reply": { "parent": { "uri": "at://did:plc:abc123/app.bsky.feed.post/xyz" } }
        });
        assert!(validate_record_formats(&record).is_ok());
    }

    #[test]
    fn rejects_a_malformed_top_level_created_at() {
        let record = serde_json::json!({
            "text": "hello",
            "createdAt": "2026-07-17 12:00:00" // space instead of `T`, no timezone
        });
        assert!(validate_record_formats(&record).is_err());
    }

    #[test]
    fn ignores_a_missing_or_non_string_created_at() {
        // Absent createdAt: nothing to check.
        assert!(validate_record_formats(&serde_json::json!({ "text": "hi" })).is_ok());
        // A non-string createdAt is a shape error a lexicon would catch; without the schema we
        // fail open rather than guess, so it passes the format gate.
        assert!(validate_record_formats(&serde_json::json!({ "createdAt": 12345 })).is_ok());
    }

    #[test]
    fn only_the_top_level_created_at_is_datetime_checked() {
        // A nested `createdAt` (inside a value the record's lexicon may not type as a datetime)
        // is left alone — matching the reference's fail-open on unbundled lexicons.
        let record = serde_json::json!({
            "createdAt": "2026-07-17T12:00:00Z",
            "embed": { "createdAt": "not a date at all" }
        });
        assert!(validate_record_formats(&record).is_ok());
    }

    #[test]
    fn rejects_a_malformed_nested_at_uri() {
        let record = serde_json::json!({
            "createdAt": "2026-07-17T12:00:00Z",
            "subject": { "uri": "at://not a valid authority/x" }
        });
        assert!(validate_record_formats(&record).is_err());
    }

    #[test]
    fn rejects_a_malformed_at_uri_inside_an_array() {
        let record = serde_json::json!({
            "links": ["at://did:plc:ok/app.bsky.feed.post/a", "at://bad authority"]
        });
        assert!(validate_record_formats(&record).is_err());
    }

    #[test]
    fn ignores_non_at_uri_strings() {
        // A plain DID subject (follow), an https URL, and free text are not `at://` strings.
        let record = serde_json::json!({
            "subject": "did:plc:whoever",
            "site": "https://example.com/at://looks-nested-but-not-a-scheme",
            "text": "meet me at://the park"
        });
        assert!(validate_record_formats(&record).is_ok());
    }
}
