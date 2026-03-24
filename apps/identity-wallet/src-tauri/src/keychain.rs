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
        test_store::get()
            .lock()
            .unwrap()
            .insert(account.to_string(), data.to_vec());
        return Ok(());
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
        return test_store::get()
            .lock()
            .unwrap()
            .get(account)
            .cloned()
            .ok_or(KeychainError::NotFound);
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
        test_store::get().lock().unwrap().remove(account);
        return Ok(());
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

/// Store the DPoP private key scalar (32 bytes) in the Keychain.
pub fn store_dpop_key(private_bytes: &[u8]) -> Result<(), KeychainError> {
    store_item(DPOP_KEY_PRIV_ACCOUNT, private_bytes)
}

/// Load the DPoP private key scalar from the Keychain.
///
/// Returns `None` if no key has been stored yet (first run).
pub fn load_dpop_key() -> Option<[u8; 32]> {
    match get_item(DPOP_KEY_PRIV_ACCOUNT) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
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
        Ok(b) => String::from_utf8(b).ok()?,
        Err(e) if is_not_found(&e) => return None,
        Err(e) => {
            tracing::error!(error = ?e, "Keychain error loading access token");
            return None;
        }
    };
    let refresh = match get_item(OAUTH_REFRESH_TOKEN_ACCOUNT) {
        Ok(b) => String::from_utf8(b).ok()?,
        Err(e) if is_not_found(&e) => return None,
        Err(e) => {
            tracing::error!(error = ?e, "Keychain error loading refresh token");
            return None;
        }
    };
    Some((access, refresh))
}

/// In-memory Keychain substitute used exclusively in test builds.
#[cfg(test)]
mod test_store {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static STORE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();

    pub fn get() -> &'static Mutex<HashMap<String, Vec<u8>>> {
        STORE.get_or_init(|| Mutex::new(HashMap::new()))
    }
}
