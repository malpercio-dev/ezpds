//! iOS Keychain storage for identity-wallet credentials.
//!
//! All items are stored as `kSecClassGenericPassword` under
//! service `"ezpds-identity-wallet"`. Use the `SERVICE` constant
//! to ensure consistency.
//!
//! In test builds (`#[cfg(test)]`), all Keychain operations are redirected to an
//! in-memory store so that tests never touch the real macOS Keychain and never
//! trigger a password prompt.

#[cfg(not(test))]
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

pub const SERVICE: &str = "ezpds-identity-wallet";

#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("keychain error: {0}")]
    Security(#[from] security_framework::base::Error),
    /// Returned by the in-memory test store when an item is not found.
    #[cfg(test)]
    #[error("item not found")]
    NotFound,
}

/// Store arbitrary bytes in the Keychain under the given account name.
///
/// Creates the entry if it doesn't exist, or updates it if it does.
pub fn store_item(account: &str, data: &[u8]) -> Result<(), KeychainError> {
    #[cfg(test)]
    {
        test_store::set(account, data.to_vec());
        Ok(())
    }
    #[cfg(not(test))]
    set_generic_password(SERVICE, account, data).map_err(KeychainError::Security)
}

/// Retrieve bytes from the Keychain for the given account name.
///
/// Returns `Err` with `errSecItemNotFound` if no entry exists.
pub fn get_item(account: &str) -> Result<Vec<u8>, KeychainError> {
    #[cfg(test)]
    {
        test_store::get(account).ok_or(KeychainError::NotFound)
    }
    #[cfg(not(test))]
    get_generic_password(SERVICE, account).map_err(KeychainError::Security)
}

/// Delete an item from the Keychain by account name.
///
/// Returns `Ok(())` on successful deletion, or `Err` if the item doesn't exist.
pub fn delete_item(account: &str) -> Result<(), KeychainError> {
    #[cfg(test)]
    {
        test_store::delete(account);
        Ok(())
    }
    #[cfg(not(test))]
    delete_generic_password(SERVICE, account).map_err(KeychainError::Security)
}

/// Returns true if the error is errSecItemNotFound (OS status -25300).
/// Use this to distinguish "item does not exist" from transient OS errors.
pub fn is_not_found(err: &KeychainError) -> bool {
    match err {
        KeychainError::Security(e) => e.code() == -25300,
        #[cfg(test)]
        KeychainError::NotFound => true,
    }
}

// ── OAuth Keychain helpers ─────────────────────────────────────────────────────

const DPOP_KEY_PRIV_ACCOUNT: &str = "oauth-dpop-key-priv";
const OAUTH_ACCESS_TOKEN_ACCOUNT: &str = "oauth-access-token";
const OAUTH_REFRESH_TOKEN_ACCOUNT: &str = "oauth-refresh-token";
const PDS_URL_ACCOUNT: &str = "relay-base-url";
const APPEARANCE_ACCOUNT: &str = "appearance-preference";

/// Store the DPoP private key scalar (32 bytes) in the Keychain.
pub fn store_dpop_key(private_bytes: &[u8]) -> Result<(), KeychainError> {
    store_item(DPOP_KEY_PRIV_ACCOUNT, private_bytes)
}

/// Load the DPoP private key scalar from the Keychain.
///
/// Returns `None` if no key has been stored yet (first run).
/// The returned bytes are wrapped in `Zeroizing` to ensure they are cleared on drop.
pub fn load_dpop_key() -> Option<zeroize::Zeroizing<[u8; 32]>> {
    match get_item(DPOP_KEY_PRIV_ACCOUNT) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(zeroize::Zeroizing::new(arr))
        }
        Ok(_) => {
            tracing::warn!("DPoP key in Keychain has unexpected length; treating as absent");
            None
        }
        Err(e) if is_not_found(&e) => None,
        Err(e) => {
            tracing::error!(error = ?e, "Keychain error loading DPoP key");
            None
        }
    }
}

/// Store the OAuth access token and refresh token in the Keychain.
pub fn store_oauth_tokens(access_token: &str, refresh_token: &str) -> Result<(), KeychainError> {
    store_item(OAUTH_ACCESS_TOKEN_ACCOUNT, access_token.as_bytes())?;
    store_item(OAUTH_REFRESH_TOKEN_ACCOUNT, refresh_token.as_bytes())?;
    Ok(())
}

/// Load the OAuth access token and refresh token from the Keychain.
///
/// Returns `None` if either token is missing (not yet authenticated).
pub fn load_oauth_tokens() -> Option<(String, String)> {
    let access = match get_item(OAUTH_ACCESS_TOKEN_ACCOUNT) {
        Ok(b) => match String::from_utf8(b) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = ?e, "UTF-8 error decoding access token from Keychain");
                return None;
            }
        },
        Err(e) if is_not_found(&e) => return None,
        Err(e) => {
            tracing::error!(error = ?e, "Keychain error loading access token");
            return None;
        }
    };
    let refresh = match get_item(OAUTH_REFRESH_TOKEN_ACCOUNT) {
        Ok(b) => match String::from_utf8(b) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = ?e, "UTF-8 error decoding refresh token from Keychain");
                return None;
            }
        },
        Err(e) if is_not_found(&e) => return None,
        Err(e) => {
            tracing::error!(error = ?e, "Keychain error loading refresh token");
            return None;
        }
    };
    Some((access, refresh))
}

/// Persist the user-configured PDS base URL to the Keychain.
///
/// Overwrites any previously stored URL.
pub fn store_pds_url(url: &str) -> Result<(), KeychainError> {
    store_item(PDS_URL_ACCOUNT, url.as_bytes())
}

/// Retrieve the user-configured PDS base URL from the Keychain.
///
/// Returns `None` if no URL has been saved yet (first run or after logout).
pub fn load_pds_url() -> Option<String> {
    match get_item(PDS_URL_ACCOUNT) {
        Ok(bytes) => String::from_utf8(bytes)
            .map_err(|e| {
                tracing::error!(error = ?e, "PDS URL in Keychain is not valid UTF-8; treating as absent");
            })
            .ok(),
        Err(e) if is_not_found(&e) => None,
        Err(e) => {
            tracing::error!(error = ?e, "Keychain error loading PDS URL");
            None
        }
    }
}

/// Remove the PDS URL from the Keychain. Test-only; used to reset state
/// between tests that share the Keychain mock store.
#[cfg(test)]
pub fn delete_pds_url_test_only() {
    let _ = delete_item(PDS_URL_ACCOUNT);
}

/// Persist the in-app appearance preference (`"system"`, `"light"`, or `"dark"`).
///
/// The Keychain is the durable source of truth; the frontend keeps a
/// localStorage mirror purely so the preference can apply before first paint
/// (an async IPC read would land after the WebView has already painted).
pub fn store_appearance_preference(preference: &str) -> Result<(), KeychainError> {
    store_item(APPEARANCE_ACCOUNT, preference.as_bytes())
}

/// Retrieve the stored appearance preference.
///
/// Returns `None` if no preference has been saved yet (follow the system).
pub fn load_appearance_preference() -> Option<String> {
    match get_item(APPEARANCE_ACCOUNT) {
        Ok(bytes) => String::from_utf8(bytes)
            .map_err(|e| {
                tracing::error!(error = ?e, "appearance preference in Keychain is not valid UTF-8; treating as absent");
            })
            .ok(),
        Err(e) if is_not_found(&e) => None,
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
    let _ = delete_item(APPEARANCE_ACCOUNT);
}

/// Reset the in-memory Keychain to a clean state.
///
/// Call this at the start of every test that touches the Keychain so that
/// sequential tests sharing the same OS thread start with an empty store.
#[cfg(test)]
pub fn clear_for_test() {
    test_store::clear_all();
}

/// In-memory Keychain substitute used exclusively in test builds.
///
/// Thread-local storage ensures tests on different threads are fully isolated.
/// Call `clear_for_test()` at the start of each test to handle sequential
/// reuse of the same OS thread by the Rust test harness.
#[cfg(test)]
mod test_store {
    use std::cell::RefCell;
    use std::collections::HashMap;

    thread_local! {
        static STORE: RefCell<HashMap<String, Vec<u8>>> = RefCell::new(HashMap::new());
    }

    pub fn get(account: &str) -> Option<Vec<u8>> {
        STORE.with(|s| s.borrow().get(account).cloned())
    }

    pub fn set(account: &str, data: Vec<u8>) {
        STORE.with(|s| {
            s.borrow_mut().insert(account.to_string(), data);
        });
    }

    pub fn delete(account: &str) {
        STORE.with(|s| {
            s.borrow_mut().remove(account);
        });
    }

    pub fn clear_all() {
        STORE.with(|s| s.borrow_mut().clear());
    }
}
