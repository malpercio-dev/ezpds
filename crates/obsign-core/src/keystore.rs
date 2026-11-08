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
//! # Ownership
//!
//! [`Core`](crate::oauth::Core) owns the store a shell hands it and reaches it through
//! [`Keys`], the accessor every module calls (`core.keys()`). Tests build a `Core` over
//! [`MemKeyStore`](crate::test_support::MemKeyStore), so each test owns its store.

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

/// The accessors over one [`KeyStore`]: what every module calls, through `core.keys()`. The
/// cloud-slot calls check the allowlist here, before the store is reached.
#[derive(Clone, Copy)]
pub struct Keys<'a>(&'a dyn KeyStore);

impl<'a> Keys<'a> {
    pub fn new(store: &'a dyn KeyStore) -> Self {
        Self(store)
    }

    /// Create or replace the device-local item under `account`.
    pub fn store_item(self, account: &str, data: &[u8]) -> Result<(), KeyStoreError> {
        self.0.set(account, data, Accessibility::WhenUnlocked)
    }

    /// Create or replace the device-local item under `account` as
    /// [`Accessibility::AfterFirstUnlock`]. Notification material only. Callers that need the
    /// value to be durable should read it back.
    pub fn store_item_after_first_unlock(
        self,
        account: &str,
        data: &[u8],
    ) -> Result<(), KeyStoreError> {
        self.0.set(account, data, Accessibility::AfterFirstUnlock)
    }

    /// Read the device-local item under `account`. Never returns a value written by
    /// [`Keys::store_item_synced`].
    pub fn get_item(self, account: &str) -> Result<Vec<u8>, KeyStoreError> {
        self.0.get(account)
    }

    /// Remove the device-local item under `account`. A missing item is
    /// [`KeyStoreError::NotFound`].
    pub fn delete_item(self, account: &str) -> Result<(), KeyStoreError> {
        self.0.delete(account)
    }

    /// Create or replace the cloud-synchronized item under an allowlisted `account`.
    pub fn store_item_synced(self, account: &str, data: &[u8]) -> Result<(), KeyStoreError> {
        guard_sync_allowed(account)?;
        self.0.set_synced(account, data)
    }

    /// Read the cloud-synchronized item under an allowlisted `account`. An empty cloud slot is
    /// [`KeyStoreError::NotFound`] even when a device-local item of the same name exists.
    pub fn get_item_synced(self, account: &str) -> Result<Vec<u8>, KeyStoreError> {
        guard_sync_allowed(account)?;
        self.0.get_synced(account)
    }

    /// Remove the cloud-synchronized item under an allowlisted `account`.
    pub fn delete_item_synced(self, account: &str) -> Result<(), KeyStoreError> {
        guard_sync_allowed(account)?;
        self.0.delete_synced(account)
    }
}

/// Whether `err` means the item does not exist, as opposed to a refusal or a transient
/// failure.
pub fn is_not_found(err: &KeyStoreError) -> bool {
    matches!(err, KeyStoreError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::MemKeyStore;

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
        let store = MemKeyStore::default();
        let keys = Keys::new(&store);

        keys.store_item("ordinary", b"x").unwrap();
        assert_eq!(
            store.accessibility_of("ordinary"),
            Some(Accessibility::WhenUnlocked)
        );

        keys.store_item_after_first_unlock("notification", b"y")
            .unwrap();
        assert_eq!(
            store.accessibility_of("notification"),
            Some(Accessibility::AfterFirstUnlock)
        );
    }

    /// Accessibility is an attribute, not an address. The pinned sender-key set is rewritten on
    /// every Custos contact, so a second write must replace the first in place — and must not
    /// quietly demote the class back to the default the way a `SecItemUpdate` would.
    #[test]
    fn rewriting_keeps_one_record_and_holds_its_class() {
        let store = MemKeyStore::default();
        let keys = Keys::new(&store);

        keys.store_item_after_first_unlock("pinned", b"first")
            .unwrap();
        keys.store_item_after_first_unlock("pinned", b"second")
            .unwrap();

        assert_eq!(keys.get_item("pinned").unwrap(), b"second");
        assert_eq!(
            store.accessibility_of("pinned"),
            Some(Accessibility::AfterFirstUnlock),
            "a re-pin must not weaken the class the extension depends on"
        );

        keys.delete_item("pinned").unwrap();
        assert!(keys.get_item("pinned").is_err_and(|e| is_not_found(&e)));
        assert_eq!(store.accessibility_of("pinned"), None);
    }

    /// It is the same store: the ordinary read and delete reach it, so no notification account
    /// needs a parallel accessor family (and the module docs say so).
    #[test]
    fn the_ordinary_accessors_reach_after_first_unlock_items() {
        let store = MemKeyStore::default();
        let keys = Keys::new(&store);
        keys.store_item_after_first_unlock("shared-slot", b"value")
            .unwrap();

        assert_eq!(keys.get_item("shared-slot").unwrap(), b"value");
        // ...and it is emphatically *not* in the synchronizable store.
        assert!(matches!(
            keys.get_item_synced("shared-slot"),
            Err(KeyStoreError::SyncNotPermitted { .. })
        ));
    }

    /// The two stores are independent records under one account name — the property the
    /// copy-never-flip backfill and the synced-first read path both rest on.
    #[test]
    fn synced_and_local_slots_are_distinct_records() {
        let store = MemKeyStore::default();
        let keys = Keys::new(&store);
        let account = recovery_share1_account(DID);

        keys.store_item(&account, b"LEGACY").unwrap();
        assert!(keys
            .get_item_synced(&account)
            .is_err_and(|e| is_not_found(&e)));

        keys.store_item_synced(&account, b"SYNCED").unwrap();
        assert_eq!(keys.get_item(&account).unwrap(), b"LEGACY");
        assert_eq!(keys.get_item_synced(&account).unwrap(), b"SYNCED");

        // Deleting one store leaves the other intact.
        keys.delete_item_synced(&account).unwrap();
        assert_eq!(keys.get_item(&account).unwrap(), b"LEGACY");
    }

    /// Deleting a missing item is a not-found verdict, as the Keychain reports it, so the
    /// `is_not_found` branch after every production delete is exercised by the fake too.
    #[test]
    fn deleting_a_missing_item_is_not_found() {
        let store = MemKeyStore::default();
        let keys = Keys::new(&store);
        assert!(keys.delete_item("absent").is_err_and(|e| is_not_found(&e)));
        let account = recovery_share1_account(DID);
        assert!(keys
            .delete_item_synced(&account)
            .is_err_and(|e| is_not_found(&e)));
    }
}
