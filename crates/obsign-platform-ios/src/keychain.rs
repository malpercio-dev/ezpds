//! [`AppleKeychain`], the iOS/macOS Keychain as a [`KeyStore`].
//!
//! Items are `kSecClassGenericPassword` under the app's service name. The device-local
//! namespace is the default store; the cloud slot is the `kSecAttrSynchronizable` store (iCloud
//! Keychain), a separate record under the same account name. No accessor sets
//! `kSecAttrAccessGroup`: the app's entitlement order decides the write group and reads search
//! every entitled group (see the wallet's `keychain.rs` and ADR-0030).

use obsign_core::keystore::{Accessibility, KeyStore, KeyStoreError};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{
    delete_generic_password, delete_generic_password_options, generic_password,
    get_generic_password, set_generic_password, set_generic_password_options, PasswordOptions,
};

/// `errSecItemNotFound` — the Security framework's "no such item" status.
///
/// Callers that hold a raw `security_framework` error rather than a `KeyStoreError`
/// (a direct `ItemSearchOptions` query, for instance) compare against this instead of
/// re-spelling the magic number.
pub const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

/// The Keychain, under one app's service name. Changing the service orphans every item.
pub struct AppleKeychain {
    service: &'static str,
}

impl AppleKeychain {
    pub fn new(service: &'static str) -> Self {
        Self { service }
    }

    /// Query targeting the synchronizable store for `account`.
    ///
    /// `Some(true)` (never `None`) so every operation addresses exactly one store: with
    /// `None`, a set would prefer the device-local store and a get could not say which store
    /// answered.
    fn synced_options(&self, account: &str) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(self.service, account);
        options.set_access_synchronized(Some(true));
        options
    }
}

fn from_security(e: security_framework::base::Error) -> KeyStoreError {
    if e.code() == ERR_SEC_ITEM_NOT_FOUND {
        KeyStoreError::NotFound
    } else {
        KeyStoreError::Platform {
            code: e.code(),
            message: e.to_string(),
        }
    }
}

impl KeyStore for AppleKeychain {
    fn get(&self, account: &str) -> Result<Vec<u8>, KeyStoreError> {
        get_generic_password(self.service, account).map_err(from_security)
    }

    fn set(&self, account: &str, data: &[u8], class: Accessibility) -> Result<(), KeyStoreError> {
        match class {
            Accessibility::WhenUnlocked => {
                set_generic_password(self.service, account, data).map_err(from_security)
            }
            // Delete-then-add rather than add-or-update: `SecItemUpdate` cannot change an
            // existing item's protection class, and this write's whole contract is the class.
            // The class is a `SecAccessControl` with the protection mode and no constraint
            // flags, so the headless notification extension reads it with no user-presence
            // check.
            Accessibility::AfterFirstUnlock => {
                // Not-found is the ordinary first-write case; any other failure surfaces on
                // the add below.
                let _ = delete_generic_password(self.service, account);
                let control = SecAccessControl::create_with_protection(
                    Some(ProtectionMode::AccessibleAfterFirstUnlock),
                    0,
                )
                .map_err(from_security)?;
                let mut options = PasswordOptions::new_generic_password(self.service, account);
                options.set_access_control(control);
                set_generic_password_options(data, options).map_err(from_security)
            }
        }
    }

    fn delete(&self, account: &str) -> Result<(), KeyStoreError> {
        delete_generic_password(self.service, account).map_err(from_security)
    }

    fn get_synced(&self, account: &str) -> Result<Vec<u8>, KeyStoreError> {
        generic_password(self.synced_options(account)).map_err(from_security)
    }

    fn set_synced(&self, account: &str, data: &[u8]) -> Result<(), KeyStoreError> {
        set_generic_password_options(data, self.synced_options(account)).map_err(from_security)
    }

    fn delete_synced(&self, account: &str) -> Result<(), KeyStoreError> {
        delete_generic_password_options(self.synced_options(account)).map_err(from_security)
    }
}
