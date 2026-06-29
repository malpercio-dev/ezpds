//! iOS Keychain storage for admin-companion credentials.
//!
//! All items are stored as `kSecClassGenericPassword` under service
//! `"ezpds-admin-companion"`. Use the `SERVICE` constant to ensure consistency.
//!
//! This is the operator console's analogue of the identity-wallet Keychain
//! module ([`apps/identity-wallet/src-tauri/src/keychain.rs`]). It is trimmed to
//! the device-key primitives the Phase 6 scaffold needs; the relay-URL and
//! `device_id` helpers arrive with the pairing client in Phase 7.
//!
//! In test builds (`#[cfg(test)]`), all Keychain operations are redirected to an
//! in-memory store so that tests never touch the real macOS Keychain and never
//! trigger a password prompt.

#[cfg(not(test))]
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

/// Keychain service namespace. Distinct from identity-wallet's
/// `"ezpds-identity-wallet"` so the two apps never collide on a shared device.
//
// Referenced only by the `#[cfg(not(test))]` function bodies below — the test build
// swaps in the in-memory store and never touches it — so the test-target lib build
// sees it as unused. Real (non-test) builds use it on every Keychain call.
#[allow(dead_code)]
pub const SERVICE: &str = "ezpds-admin-companion";

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
//
// Part of the Keychain primitive surface. Exercised on the Secure Enclave path
// (key-creation rollback) and by Phase 7 (unpair / self-revoke); the macOS/simulator
// software path never deletes, so the host non-test lib build sees it as unused.
#[allow(dead_code)]
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
