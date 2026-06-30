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
    /// A stored value could not be decoded as UTF-8. Only the string-valued accounts
    /// (pairing state) can produce this; the device-key accounts store raw bytes.
    #[error("stored keychain value was not valid UTF-8")]
    InvalidUtf8,
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
        KeychainError::InvalidUtf8 => false,
        #[cfg(test)]
        KeychainError::NotFound => true,
    }
}

// ── Pairing state (Phase 7) ──────────────────────────────────────────────────
//
// Once a device pairs (`POST /v1/admin/devices`), it persists the relay-assigned
// `device_id` and the relay's base URL so every later signed request can address the
// relay and identify itself via the `X-Admin-Device` header. Neither value is a secret
// (the device_id is a public identifier, the URL is public), but they live in the
// Keychain alongside the device key so a single "unpair" clears all device state at once.

/// Keychain account holding the relay-assigned device id (sent as `X-Admin-Device`).
const DEVICE_ID_ACCOUNT: &str = "admin-device-id";
/// Keychain account holding the paired relay's base URL (e.g. `https://relay.example`).
const RELAY_URL_ACCOUNT: &str = "admin-relay-url";

/// The persisted result of a successful pairing: which relay this device is paired to
/// and the id the relay knows it by. Serializes camelCase for the `pairing_state` IPC.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pairing {
    pub device_id: String,
    pub relay_url: String,
}

/// Persist the pairing produced by a successful device registration.
pub fn store_pairing(device_id: &str, relay_url: &str) -> Result<(), KeychainError> {
    store_item(DEVICE_ID_ACCOUNT, device_id.as_bytes())?;
    store_item(RELAY_URL_ACCOUNT, relay_url.as_bytes())?;
    Ok(())
}

/// Read the current pairing, or `None` if this device has not paired yet.
///
/// A missing `device_id` *or* `relay_url` is treated as "not paired" (`None`); only a
/// transient/permission error propagates. This mirrors `device_key`'s discipline of
/// never letting a flaky Keychain read masquerade as a clean "absent" state.
pub fn get_pairing() -> Result<Option<Pairing>, KeychainError> {
    match (
        get_string(DEVICE_ID_ACCOUNT)?,
        get_string(RELAY_URL_ACCOUNT)?,
    ) {
        (Some(device_id), Some(relay_url)) => Ok(Some(Pairing {
            device_id,
            relay_url,
        })),
        _ => Ok(None),
    }
}

/// Forget the current pairing (the companion app's "unpair"). Idempotent: clearing an
/// already-absent pairing succeeds. Does **not** delete the device key — a re-pair
/// reuses the same key so the relay can recognise a returning device by its public key.
pub fn clear_pairing() -> Result<(), KeychainError> {
    for account in [DEVICE_ID_ACCOUNT, RELAY_URL_ACCOUNT] {
        match delete_item(account) {
            Ok(()) => {}
            Err(e) if is_not_found(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Read a single Keychain item as a UTF-8 string, mapping a genuine not-found to
/// `Ok(None)` and surfacing any other (transient/permission) error. Invalid UTF-8 in a
/// stored value is reported as a keychain error rather than silently lost.
fn get_string(account: &str) -> Result<Option<String>, KeychainError> {
    match get_item(account) {
        Ok(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| KeychainError::InvalidUtf8),
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(e),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_get_pairing_round_trips() {
        clear_for_test();
        store_pairing("device-123", "https://relay.example").expect("store");
        let pairing = get_pairing().expect("read").expect("paired");
        assert_eq!(pairing.device_id, "device-123");
        assert_eq!(pairing.relay_url, "https://relay.example");
    }

    #[test]
    fn get_pairing_is_none_when_unpaired() {
        clear_for_test();
        assert_eq!(get_pairing().expect("read"), None);
    }

    #[test]
    fn get_pairing_is_none_when_only_one_half_present() {
        // A half-written pairing (device id but no relay URL) must read as "not paired",
        // never as a malformed Some — the signed-request path can then fail closed.
        clear_for_test();
        store_item(DEVICE_ID_ACCOUNT, b"device-123").expect("store id only");
        assert_eq!(get_pairing().expect("read"), None);
    }

    #[test]
    fn clear_pairing_forgets_and_is_idempotent() {
        clear_for_test();
        store_pairing("device-123", "https://relay.example").expect("store");
        clear_pairing().expect("first clear");
        assert_eq!(get_pairing().expect("read"), None);
        // Clearing an already-absent pairing is a no-op success (unpair is idempotent).
        clear_pairing().expect("second clear is a no-op");
    }
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
