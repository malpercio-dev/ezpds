// pattern: Imperative Shell
//
//! The operator console's device admin key: this app's Keychain and account names bound to
//! the shared `ios-device-key` implementation (Secure Enclave on a real device, software key
//! on macOS and the Simulator — that crate's module docs are the authority on both paths).
//!
//! Where the identity wallet's copy of this key signs did:plc rotation operations, here it is
//! the device's *admin credential*: the relay stores only the public key (as a `did:key`) and
//! verifies the signature on each request, so no replayable secret ever sits on the phone.
//! Request-envelope signing (binding method, path, timestamp, nonce, and a body hash) is
//! layered on top in `relay_client.rs`; this module owns only the key's identity.

use ios_device_key::{DeviceKeyAccounts, KeychainStore};

pub use ios_device_key::{DeviceKeyError, DevicePublicKey};

// ── Admin device-key Keychain account names ─────────────────────────────────
//
// The single admin device key for this app. Software path uses only the private-scalar
// account; the Secure Enclave path uses the pub + app-label metadata accounts (the SE private
// key never leaves the enclave). Distinct from the wallet's names so the two apps never
// collide on a shared device.
const ACCOUNTS: DeviceKeyAccounts = DeviceKeyAccounts {
    private_scalar: "admin-device-key-priv",
    public_key: "admin-device-key-pub",
    application_label: "admin-device-key-app-label",
    secure_enclave_label: "ezpds-admin-device-key",
};

/// The console's Keychain, as the shared implementation's store. The `#[cfg(test)]` in-memory
/// redirection lives in `keychain.rs` and applies through this impl.
struct AdminKeychain;

impl KeychainStore for AdminKeychain {
    type Error = crate::keychain::KeychainError;

    fn get(account: &str) -> Result<Vec<u8>, Self::Error> {
        crate::keychain::get_item(account)
    }

    fn store(account: &str, data: &[u8]) -> Result<(), Self::Error> {
        crate::keychain::store_item(account, data)
    }

    fn delete(account: &str) -> Result<(), Self::Error> {
        crate::keychain::delete_item(account)
    }

    fn is_not_found(error: &Self::Error) -> bool {
        crate::keychain::is_not_found(error)
    }
}

/// Return this device's admin key, generating one on first call.
pub fn get_or_create() -> Result<DevicePublicKey, DeviceKeyError> {
    ios_device_key::get_or_create::<AdminKeychain>(&ACCOUNTS)
}

/// Sign `data` with this device's admin key, returning raw 64-byte `r||s`.
pub fn sign(data: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    ios_device_key::sign::<AdminKeychain>(&ACCOUNTS, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wiring this module owns: the shared implementation reaches the console's Keychain,
    /// and it does so under these exact account names. Key generation, signing, and the IPC
    /// error shape are covered by `ios-device-key`'s own tests.
    #[test]
    fn the_key_round_trips_through_the_console_keychain() {
        crate::keychain::clear_for_test();

        let key = get_or_create().expect("get_or_create must succeed");
        assert!(key.key_id.starts_with("did:key:z"));
        assert_eq!(
            get_or_create().expect("second call").multibase,
            key.multibase,
            "the key must be idempotent across calls"
        );

        assert!(
            crate::keychain::get_item(ACCOUNTS.private_scalar).is_ok(),
            "the software path must store the scalar under the pinned account name"
        );

        crate::keychain::delete_item(ACCOUNTS.private_scalar).expect("delete");
        assert!(matches!(sign(b"no key"), Err(DeviceKeyError::KeyNotFound)));
    }
}
