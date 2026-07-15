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
