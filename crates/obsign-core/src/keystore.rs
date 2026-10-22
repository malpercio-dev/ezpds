//! Keychain-class storage: the [`KeyStore`] trait a shell implements, and the free functions
//! the core calls it through.
//!
//! # Two stores, not one attribute
//!
//! A store has two namespaces. `store_item`/`get_item`/`delete_item` address the
//! **device-local** one: its items never reach a second device by any route the wallet uses.
//! `store_item_synced`/`get_item_synced`/`delete_item_synced` address the **cloud-synchronized**
//! one (iCloud Keychain on iOS). The same account in both is two independent records, and
//! neither accessor family sees the other's value; moving a value between them means copying
//! it, never flipping it in place. That is how Apple's `SecItem.h` defines the iOS store, and
//! every implementation must keep it.
//!
//! The cloud slot is **optional**. A platform without one leaves the `*_synced` trait methods
//! at their defaults, which return [`KeyStoreError::NoCloudSlot`].
//!
//! Only per-DID Share 1 (`recovery-share-1:{did}`) may enter the cloud slot. The allowlist is
//! enforced here, before any implementation is reached: see [`syncs_to_icloud`].
//!
//! # Accessibility is not a third store
//!
//! [`store_item_after_first_unlock`] writes into the same device-local namespace as
//! [`store_item`] and differs only in protection class (see [`Accessibility`]). Either write is
//! found by the same [`get_item`] and removed by the same [`delete_item`].
//!
//! # Installation
//!
//! The shell calls [`install`] once at startup, before anything touches storage. Until then
//! every call fails with [`KeyStoreError::NotInstalled`], which is not an absence verdict, so
//! callers fail closed rather than conclude an item was never stored.
//!
//! With the `test-support` feature (and in this crate's own tests), an uninstalled store falls back to a thread-local in-memory
//! store instead, so each test thread starts isolated (call [`clear_for_test`] at the top of a
//! test to reset it). The feature is enabled only from a dependent's `[dev-dependencies]`,
//! which resolver 2 keeps out of normal builds, and it refuses to compile without
//! `debug_assertions`: an in-memory key store in a release build would lose every key on exit.

use std::sync::OnceLock;

#[cfg(all(feature = "test-support", not(debug_assertions)))]
compile_error!("obsign-core's `test-support` feature must never reach a release build");

/// The protection class an item is written under.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Accessibility {
    /// Readable only while the device is unlocked. The default for everything.
    WhenUnlocked,
    /// Readable once the device has been unlocked at least once since boot, so a notification
    /// extension can read it on a locked screen. Notification material only.
    AfterFirstUnlock,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// No item under that account. The only variant [`is_not_found`] accepts.
    #[error("item not found")]
    NotFound,
    /// The platform store refused the call. `code` is the platform's status (an `OSStatus` on
    /// iOS); `message` is diagnostic only.
    #[error("keychain error: {message}")]
    Platform { code: i32, message: String },
    /// A cloud-slot call for an account outside the allowlist. No shipped call site reaches
    /// this; the guard keeps a future caller from widening what leaves the device.
    #[error("account {account} is not permitted in the iCloud-synchronizable keychain")]
    SyncNotPermitted { account: String },
    /// This platform's store has no cloud-synchronized slot.
    #[error("this platform has no cloud-synchronized key store")]
    NoCloudSlot,
    /// The shell never called [`install`].
    #[error("no key store installed")]
    NotInstalled,
}

/// Keychain-class storage for one app, addressed by account name.
pub trait KeyStore: Send + Sync {
    /// Read the device-local item under `account`.
    fn get(&self, account: &str) -> Result<Vec<u8>, KeyStoreError>;

    /// Create or replace the device-local item under `account`, written under `class`.
    ///
    /// For [`Accessibility::AfterFirstUnlock`] the class must actually be applied to an
    /// existing item, not left at whatever the first write set: on iOS that means
    /// delete-then-add, because `SecItemUpdate` cannot change a protection class.
    fn set(&self, account: &str, data: &[u8], class: Accessibility) -> Result<(), KeyStoreError>;

    /// Remove the device-local item under `account`.
    fn delete(&self, account: &str) -> Result<(), KeyStoreError>;

    /// Read the cloud-synchronized item under `account`.
    fn get_synced(&self, _account: &str) -> Result<Vec<u8>, KeyStoreError> {
        Err(KeyStoreError::NoCloudSlot)
    }

    /// Create or replace the cloud-synchronized item under `account`. Success means the item
    /// was written carrying the sync attribute, not that it reached the user's cloud account.
    fn set_synced(&self, _account: &str, _data: &[u8]) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::NoCloudSlot)
    }

    /// Remove the cloud-synchronized item under `account`, leaving any device-local item of the
    /// same name untouched.
    fn delete_synced(&self, _account: &str) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::NoCloudSlot)
    }
}

static INSTALLED: OnceLock<Box<dyn KeyStore>> = OnceLock::new();

/// Install the process-wide store. The second and later calls are refused and hand the store
/// back.
pub fn install(store: Box<dyn KeyStore>) -> Result<(), Box<dyn KeyStore>> {
    INSTALLED.set(store)
}

fn store() -> &'static dyn KeyStore {
    match INSTALLED.get() {
        Some(store) => store.as_ref(),
        None => &UNINSTALLED,
    }
}

#[cfg(not(any(test, feature = "test-support")))]
const UNINSTALLED: Uninstalled = Uninstalled;
#[cfg(any(test, feature = "test-support"))]
const UNINSTALLED: memory::MemKeyStore = memory::MemKeyStore;

#[cfg(not(any(test, feature = "test-support")))]
struct Uninstalled;

#[cfg(not(any(test, feature = "test-support")))]
impl KeyStore for Uninstalled {
    fn get(&self, _: &str) -> Result<Vec<u8>, KeyStoreError> {
        Err(KeyStoreError::NotInstalled)
    }
    fn set(&self, _: &str, _: &[u8], _: Accessibility) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::NotInstalled)
    }
    fn delete(&self, _: &str) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::NotInstalled)
    }
}

// ── The cloud-slot allowlist ────────────────────────────────────────────────

const RECOVERY_SHARE1_PREFIX: &str = "recovery-share-1:";

/// The per-DID account holding an identity's Share 1.
///
/// Per-DID (never one app-global slot) so writing one identity's Share 1 can never overwrite a
/// sibling's.
pub fn recovery_share1_account(did: &str) -> String {
    format!("{RECOVERY_SHARE1_PREFIX}{did}")
}

/// Whether `account` names a per-DID Share 1 slot.
pub fn is_recovery_share1_account(account: &str) -> bool {
    account
        .strip_prefix(RECOVERY_SHARE1_PREFIX)
        .is_some_and(|did| !did.is_empty())
}

/// Whether `account` may enter the cloud-synchronized slot.
///
/// Exactly one account family: per-DID Share 1, the only secret whose job is to survive the
/// loss of the device that created it. Every other exclusion is load-bearing:
///
/// * **the device key** (`device-rotation-key-*`, `{did}:device-key*`): hardware-bound on a
///   real device, and the software fallback must not be more portable than what it stands in
///   for. It is `rotationKeys[0]`; one device, one key, is what makes the 72-hour PLC override
///   meaningful.
/// * **`{did}:oauth-tokens`**: a live bearer session for one device, with no recovery value.
/// * **`{did}:recovery-signing-key`**: signs repo commits, so a second live copy is a fork
///   risk, not a backup.
/// * **`ceremony-staging` / `recovery-epilogue`**: in-flight ceremony records owned by one
///   device, holding the seed (or two shares at once) until teardown. Syncing them would put a
///   reconstructable secret in the cloud and collapse the 2-of-3 threshold.
pub fn syncs_to_icloud(account: &str) -> bool {
    is_recovery_share1_account(account)
}

fn guard_sync_allowed(account: &str) -> Result<(), KeyStoreError> {
    if syncs_to_icloud(account) {
        Ok(())
    } else {
        Err(KeyStoreError::SyncNotPermitted {
            account: account.to_string(),
        })
    }
}

// ── Accessors ───────────────────────────────────────────────────────────────

/// Create or replace the device-local item under `account`.
pub fn store_item(account: &str, data: &[u8]) -> Result<(), KeyStoreError> {
    store().set(account, data, Accessibility::WhenUnlocked)
}

/// Create or replace the device-local item under `account` as
/// [`Accessibility::AfterFirstUnlock`]. Notification material only. Callers that need the
/// value to be durable should read it back.
pub fn store_item_after_first_unlock(account: &str, data: &[u8]) -> Result<(), KeyStoreError> {
    store().set(account, data, Accessibility::AfterFirstUnlock)
}

/// Read the device-local item under `account`. Never returns a value written by
/// [`store_item_synced`].
pub fn get_item(account: &str) -> Result<Vec<u8>, KeyStoreError> {
    store().get(account)
}

/// Remove the device-local item under `account`. A missing item is
/// [`KeyStoreError::NotFound`].
pub fn delete_item(account: &str) -> Result<(), KeyStoreError> {
    store().delete(account)
}

/// Create or replace the cloud-synchronized item under an allowlisted `account`.
pub fn store_item_synced(account: &str, data: &[u8]) -> Result<(), KeyStoreError> {
    guard_sync_allowed(account)?;
    store().set_synced(account, data)
}

/// Read the cloud-synchronized item under an allowlisted `account`. An empty cloud slot is
/// [`KeyStoreError::NotFound`] even when a device-local item of the same name exists.
pub fn get_item_synced(account: &str) -> Result<Vec<u8>, KeyStoreError> {
    guard_sync_allowed(account)?;
    store().get_synced(account)
}

/// Remove the cloud-synchronized item under an allowlisted `account`.
pub fn delete_item_synced(account: &str) -> Result<(), KeyStoreError> {
    guard_sync_allowed(account)?;
    store().delete_synced(account)
}

/// Whether `err` means the item does not exist, as opposed to a refusal or a transient
/// failure.
pub fn is_not_found(err: &KeyStoreError) -> bool {
    matches!(err, KeyStoreError::NotFound)
}

/// The installed store as `ios_device_key`'s [`KeychainStore`](ios_device_key::KeychainStore):
/// the device key and the DPoP key (`custos_client::DpopKeypair`) are stored through it. The
/// account-name parameter on that trait's associated functions is what lets one impl serve
/// several keys.
pub struct WalletKeychain;

impl ios_device_key::KeychainStore for WalletKeychain {
    type Error = KeyStoreError;

    fn get(account: &str) -> Result<Vec<u8>, Self::Error> {
        get_item(account)
    }

    fn store(account: &str, data: &[u8]) -> Result<(), Self::Error> {
        store_item(account, data)
    }

    fn delete(account: &str) -> Result<(), Self::Error> {
        delete_item(account)
    }

    fn is_not_found(error: &Self::Error) -> bool {
        is_not_found(error)
    }
}

#[cfg(any(test, feature = "test-support"))]
pub use memory::{accessibility_of, clear_for_test};

/// The in-memory store used when nothing is installed under `test-support`.
///
/// Thread-local, so tests on different threads are isolated. Keys are `(cloud, account)`,
/// modelling the two-namespace split; each value carries the class its last write set, which
/// is an attribute, never part of the address.
#[cfg(any(test, feature = "test-support"))]
mod memory {
    use super::{Accessibility, KeyStore, KeyStoreError};
    use std::cell::RefCell;
    use std::collections::HashMap;

    type Item = (Vec<u8>, Accessibility);

    thread_local! {
        static STORE: RefCell<HashMap<(bool, String), Item>> = RefCell::new(HashMap::new());
    }

    pub struct MemKeyStore;

    fn get(cloud: bool, account: &str) -> Result<Vec<u8>, KeyStoreError> {
        STORE.with(|s| {
            s.borrow()
                .get(&(cloud, account.to_string()))
                .map(|(data, _)| data.clone())
                .ok_or(KeyStoreError::NotFound)
        })
    }

    fn set(cloud: bool, account: &str, data: &[u8], class: Accessibility) {
        STORE.with(|s| {
            s.borrow_mut()
                .insert((cloud, account.to_string()), (data.to_vec(), class));
        });
    }

    // Deleting a missing item succeeds here, unlike on iOS. Kept from the wallet's original
    // test double, whose tests rely on idempotent cleanup.
    fn delete(cloud: bool, account: &str) {
        STORE.with(|s| {
            s.borrow_mut().remove(&(cloud, account.to_string()));
        });
    }

    impl KeyStore for MemKeyStore {
        fn get(&self, account: &str) -> Result<Vec<u8>, KeyStoreError> {
            get(false, account)
        }
        fn set(
            &self,
            account: &str,
            data: &[u8],
            class: Accessibility,
        ) -> Result<(), KeyStoreError> {
            set(false, account, data, class);
            Ok(())
        }
        fn delete(&self, account: &str) -> Result<(), KeyStoreError> {
            delete(false, account);
            Ok(())
        }
        fn get_synced(&self, account: &str) -> Result<Vec<u8>, KeyStoreError> {
            get(true, account)
        }
        fn set_synced(&self, account: &str, data: &[u8]) -> Result<(), KeyStoreError> {
            set(true, account, data, Accessibility::WhenUnlocked);
            Ok(())
        }
        fn delete_synced(&self, account: &str) -> Result<(), KeyStoreError> {
            delete(true, account);
            Ok(())
        }
    }

    /// Reset this thread's store. Call at the top of every test that touches storage.
    pub fn clear_for_test() {
        STORE.with(|s| s.borrow_mut().clear());
    }

    /// The class `account` was last written under in the device-local namespace. Test-only:
    /// iOS applies the class on fetch and never reports it, so the double is the only place it
    /// can be asserted.
    pub fn accessibility_of(account: &str) -> Option<Accessibility> {
        STORE.with(|s| {
            s.borrow()
                .get(&(false, account.to_string()))
                .map(|(_, class)| *class)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:plc:sync0123456789abcdefghij";

    #[test]
    fn a_store_without_a_cloud_slot_says_so() {
        struct LocalOnly;
        impl KeyStore for LocalOnly {
            fn get(&self, _: &str) -> Result<Vec<u8>, KeyStoreError> {
                Err(KeyStoreError::NotFound)
            }
            fn set(&self, _: &str, _: &[u8], _: Accessibility) -> Result<(), KeyStoreError> {
                Ok(())
            }
            fn delete(&self, _: &str) -> Result<(), KeyStoreError> {
                Ok(())
            }
        }
        let err = LocalOnly
            .get_synced(&recovery_share1_account(DID))
            .unwrap_err();
        assert!(matches!(err, KeyStoreError::NoCloudSlot));
        assert!(!is_not_found(&err));
    }

    /// The allowlist admits exactly the per-DID Share 1 slot — not the bare prefix, and not
    /// the deprecated app-global `recovery-share-1` account (a pre-unification install's
    /// Share 1 is read from there but never written back into iCloud under that name).
    #[test]
    fn only_per_did_share1_syncs() {
        assert!(syncs_to_icloud(&recovery_share1_account(DID)));
        assert!(!syncs_to_icloud("recovery-share-1"));
        assert!(!syncs_to_icloud("recovery-share-1:"));
        assert!(!syncs_to_icloud(&format!("{DID}:recovery-signing-key")));
    }

    /// A refused sync call is not an "item absent" verdict — a caller must not mistake it
    /// for one and conclude the share was never stored.
    #[test]
    fn sync_not_permitted_is_not_not_found() {
        assert!(!is_not_found(&KeyStoreError::SyncNotPermitted {
            account: "device-rotation-key-priv".to_string(),
        }));
    }

    /// The whole point of the accessor: the item lands under the class a locked-screen
    /// extension can read, while an ordinary `store_item` write does not.
    #[test]
    fn after_first_unlock_writes_carry_the_locked_screen_class() {
        clear_for_test();

        store_item("ordinary", b"x").unwrap();
        assert_eq!(
            accessibility_of("ordinary"),
            Some(Accessibility::WhenUnlocked)
        );

        store_item_after_first_unlock("notification", b"y").unwrap();
        assert_eq!(
            accessibility_of("notification"),
            Some(Accessibility::AfterFirstUnlock)
        );
    }

    /// Accessibility is an attribute, not an address. The pinned sender-key set is rewritten on
    /// every Custos contact, so a second write must replace the first in place — and must not
    /// quietly demote the class back to the default the way a `SecItemUpdate` would.
    #[test]
    fn rewriting_keeps_one_record_and_holds_its_class() {
        clear_for_test();

        store_item_after_first_unlock("pinned", b"first").unwrap();
        store_item_after_first_unlock("pinned", b"second").unwrap();

        assert_eq!(get_item("pinned").unwrap(), b"second");
        assert_eq!(
            accessibility_of("pinned"),
            Some(Accessibility::AfterFirstUnlock),
            "a re-pin must not weaken the class the extension depends on"
        );

        delete_item("pinned").unwrap();
        assert!(get_item("pinned").is_err_and(|e| is_not_found(&e)));
        assert_eq!(accessibility_of("pinned"), None);
    }

    /// It is the same store: the ordinary read and delete reach it, so no notification account
    /// needs a parallel accessor family (and the module docs say so).
    #[test]
    fn the_ordinary_accessors_reach_after_first_unlock_items() {
        clear_for_test();
        store_item_after_first_unlock("shared-slot", b"value").unwrap();

        assert_eq!(get_item("shared-slot").unwrap(), b"value");
        // ...and it is emphatically *not* in the synchronizable store.
        assert!(matches!(
            get_item_synced("shared-slot"),
            Err(KeyStoreError::SyncNotPermitted { .. })
        ));
    }

    /// The two stores are independent records under one account name — the property the
    /// copy-never-flip backfill and the synced-first read path both rest on.
    #[test]
    fn synced_and_local_slots_are_distinct_records() {
        clear_for_test();
        let account = recovery_share1_account(DID);

        store_item(&account, b"LEGACY").unwrap();
        assert!(get_item_synced(&account).is_err_and(|e| is_not_found(&e)));

        store_item_synced(&account, b"SYNCED").unwrap();
        assert_eq!(get_item(&account).unwrap(), b"LEGACY");
        assert_eq!(get_item_synced(&account).unwrap(), b"SYNCED");

        // Deleting one store leaves the other intact.
        delete_item_synced(&account).unwrap();
        assert_eq!(get_item(&account).unwrap(), b"LEGACY");
    }
}
