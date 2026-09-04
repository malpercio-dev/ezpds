//! The wallet's global P-256 device key: this app's Keychain and account names bound to the
//! shared `ios-device-key` implementation (Secure Enclave on a real device, software key on
//! macOS and the Simulator — that crate's module docs are the authority on both paths).
//!
//! Public API: [`get_or_create`] (idempotent — every call returns the same key, which is what
//! makes `create_account` retries safe: the PDS sees one device key per device) and [`sign`]
//! (raw 64-byte `r||s` ECDSA, low-S normalized).
//!
//! The create flow signs its did:plc genesis op with this key, before any DID exists to
//! namespace a per-DID key under. The `pub(crate)` account-name consts are the single source
//! of those names; changing any of them orphans existing keys.
//! `IdentityStore::adopt_global_device_key` copies whichever of these accounts exists into the
//! per-DID slots, for identities whose genesis op was signed with this global key before the
//! DID existed.

use ios_device_key::{DeviceKeyAccounts, KeychainStore};

pub use ios_device_key::{DeviceKeyError, DevicePublicKey};

/// Shared with `identity_store.rs`, which derives per-DID keys needing the same encoding.
pub(crate) use ios_device_key::make_device_public_key;

// ── Global device-key Keychain account names ────────────────────────────────
//
// Software path uses only the private-scalar account; the Secure Enclave path uses the pub +
// app-label metadata accounts (the SE private key never leaves the enclave).
pub(crate) const DEVICE_KEY_PRIV_ACCOUNT: &str = "device-rotation-key-priv";
pub(crate) const DEVICE_KEY_PUB_ACCOUNT: &str = "device-rotation-key-pub";
pub(crate) const DEVICE_KEY_APP_LABEL_ACCOUNT: &str = "device-rotation-key-app-label";

const ACCOUNTS: DeviceKeyAccounts = DeviceKeyAccounts {
    private_scalar: DEVICE_KEY_PRIV_ACCOUNT,
    public_key: DEVICE_KEY_PUB_ACCOUNT,
    application_label: DEVICE_KEY_APP_LABEL_ACCOUNT,
    secure_enclave_label: "ezpds-device-rotation-key",
};

/// The wallet's device-local Keychain, as the shared implementation's store. The
/// `#[cfg(test)]` in-memory redirection lives in `keychain.rs` and applies through this impl.
struct WalletKeychain;

impl KeychainStore for WalletKeychain {
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

/// Return this device's key, generating one on first call.
pub fn get_or_create() -> Result<DevicePublicKey, DeviceKeyError> {
    ios_device_key::get_or_create::<WalletKeychain>(&ACCOUNTS)
}

/// Sign `data` with this device's key, returning raw 64-byte `r||s`.
pub fn sign(data: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    ios_device_key::sign::<WalletKeychain>(&ACCOUNTS, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wiring this module owns: the shared implementation reaches the wallet's Keychain,
    /// and it does so under these exact account names. Key generation, signing, and the IPC
    /// error shape are covered by `ios-device-key`'s own tests.
    #[test]
    fn the_key_round_trips_through_the_wallet_keychain() {
        crate::keychain::clear_for_test();

        let key = get_or_create().expect("get_or_create must succeed");
        assert!(key.key_id.starts_with("did:key:z"));
        assert_eq!(
            get_or_create().expect("second call").multibase,
            key.multibase,
            "the key must be idempotent across calls"
        );

        assert!(
            crate::keychain::get_item(DEVICE_KEY_PRIV_ACCOUNT).is_ok(),
            "the software path must store the scalar under the pinned account name"
        );

        crate::keychain::delete_item(DEVICE_KEY_PRIV_ACCOUNT).expect("delete");
        assert!(matches!(sign(b"no key"), Err(DeviceKeyError::KeyNotFound)));
    }
}
