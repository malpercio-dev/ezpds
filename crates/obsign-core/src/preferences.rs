// pattern: Imperative Shell

//! The in-app appearance preference ([`APPEARANCE_ACCOUNT`]): `"system"`, `"light"`, or
//! `"dark"`. The Keychain is the durable truth; the frontend mirrors it in localStorage only so
//! the choice can apply before first paint. A corrupt stored value reads as absent.

use crate::keystore::{self, KeyStoreError};
use serde::Serialize;

/// The appearance preference; mirrored pre-paint in localStorage under the same key.
pub const APPEARANCE_ACCOUNT: &str = "appearance-preference";

/// Persist the in-app appearance preference (`"system"`, `"light"`, or `"dark"`).
pub fn store_appearance_preference(preference: &str) -> Result<(), KeyStoreError> {
    keystore::store_item(APPEARANCE_ACCOUNT, preference.as_bytes())
}

/// Retrieve the stored appearance preference.
///
/// Returns `None` if no preference has been saved yet (follow the system).
pub fn load_appearance_preference() -> Option<String> {
    match keystore::get_item(APPEARANCE_ACCOUNT) {
        Ok(bytes) => String::from_utf8(bytes)
            .map_err(|e| {
                tracing::error!(error = ?e, "appearance preference in Keychain is not valid UTF-8; treating as absent");
            })
            .ok(),
        Err(e) if keystore::is_not_found(&e) => None,
        Err(e) => {
            tracing::error!(error = ?e, "Keychain error loading appearance preference");
            None
        }
    }
}

/// Remove the appearance preference from the Keychain. Test-only; used to
/// reset state between tests that share the Keychain mock store.
#[cfg(test)]
pub fn delete_appearance_preference_test_only() {
    let _ = keystore::delete_item(APPEARANCE_ACCOUNT);
}

/// The three values the in-app appearance setting can take. `"system"` means
/// no override (the WebView follows the iOS appearance via `color-scheme`).
const APPEARANCE_PREFERENCES: [&str; 3] = ["system", "light", "dark"];

/// Error returned by `set_appearance_preference`.
///
/// Serializes as `{ "code": "INVALID_PREFERENCE" | "KEYCHAIN_ERROR" }` for the frontend.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AppearanceError {
    #[error("appearance preference must be \"system\", \"light\", or \"dark\"")]
    InvalidPreference,
    #[error("failed to save appearance preference to device storage")]
    KeychainError,
}

/// Return the saved appearance preference (`"system"`, `"light"`, or `"dark"`),
/// or `None` if never set — both mean "follow the system".
///
/// A corrupt or unrecognized stored value is treated as absent rather than an
/// error: the worst outcome of losing this preference is following the system
/// appearance, which is the default anyway.
pub fn get_appearance_preference() -> Option<String> {
    load_appearance_preference().filter(|p| APPEARANCE_PREFERENCES.contains(&p.as_str()))
}

/// Validate and persist the appearance preference to the Keychain.
///
/// The frontend applies the appearance instantly before calling this; the
/// Keychain write is what makes the choice survive app restarts.
pub fn set_appearance_preference(preference: String) -> Result<(), AppearanceError> {
    if !APPEARANCE_PREFERENCES.contains(&preference.as_str()) {
        return Err(AppearanceError::InvalidPreference);
    }
    store_appearance_preference(&preference).map_err(|e| {
        tracing::error!(error = %e, "failed to save appearance preference to Keychain");
        AppearanceError::KeychainError
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- appearance preference --

    #[test]
    fn get_appearance_preference_returns_none_before_save() {
        crate::keystore::clear_for_test();
        assert!(get_appearance_preference().is_none());
    }

    #[test]
    fn appearance_preference_round_trips_through_keychain() {
        crate::keystore::clear_for_test();
        set_appearance_preference("dark".to_string()).unwrap();
        assert_eq!(get_appearance_preference().as_deref(), Some("dark"));
        set_appearance_preference("system".to_string()).unwrap();
        assert_eq!(get_appearance_preference().as_deref(), Some("system"));
        delete_appearance_preference_test_only();
    }

    #[test]
    fn set_appearance_preference_rejects_unknown_values() {
        crate::keystore::clear_for_test();
        let err = set_appearance_preference("sepia".to_string()).unwrap_err();
        assert!(matches!(err, AppearanceError::InvalidPreference));
        assert!(get_appearance_preference().is_none());
    }

    #[test]
    fn get_appearance_preference_treats_corrupt_value_as_absent() {
        crate::keystore::clear_for_test();
        // A value written outside set_appearance_preference's validation
        // (or corrupted) must read back as "follow the system", not an error.
        store_appearance_preference("neon").unwrap();
        assert!(get_appearance_preference().is_none());
        delete_appearance_preference_test_only();
    }

    #[test]
    fn appearance_error_serializes_as_code() {
        let json = serde_json::to_value(AppearanceError::InvalidPreference).unwrap();
        assert_eq!(json["code"], "INVALID_PREFERENCE");
        let json = serde_json::to_value(AppearanceError::KeychainError).unwrap();
        assert_eq!(json["code"], "KEYCHAIN_ERROR");
    }
}
