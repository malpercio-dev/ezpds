//! iOS Keychain storage for identity-wallet credentials.
//!
//! All items are stored as `kSecClassGenericPassword` under
//! service `"ezpds-identity-wallet"`. Use the `SERVICE` constant
//! to ensure consistency.
//!
//! # Two stores, not one attribute
//!
//! The module exposes two families of accessors. `store_item`/`get_item`/`delete_item`
//! address the **device-local** store: those items reach a second device by no route the
//! wallet uses (iCloud Backup re-encrypts the keychain to the device UID and restores only
//! to the same device). `store_item_synced`/`get_item_synced`/`delete_item_synced` address
//! the **iCloud-synchronizable** store by setting `kSecAttrSynchronizable`.
//!
//! These are genuinely different stores, not one item with a flag: Apple's `SecItem.h` is
//! explicit that an item is identified by its service + account **and** its synchronizable
//! option, and that "if the key is not supplied … no synchronizable items will be added or
//! returned." A value written with `store_item` is therefore invisible to `get_item_synced`
//! and vice versa. Nothing in `SecItem.h` documents changing an existing item's
//! synchronizability, so moving a value between the stores means copying it, never flipping
//! it in place.
//!
//! Accessibility is left at the framework default (`kSecAttrAccessibleWhenUnlocked`) for
//! synchronizable items — the `…ThisDeviceOnly` accessibility classes are mutually exclusive
//! with syncing.
//!
//! # Which access group items land in
//!
//! An item's address has a third dimension beyond service + account: the **access group**.
//! With no `keychain-access-groups` entitlement it defaults to the implicit
//! `$(AppIdentifierPrefix)<bundle-id>` group — i.e. the access group *is* the bundle id,
//! and renaming the bundle makes every stored item invisible with no error and no recovery
//! path short of the share ceremony.
//!
//! `Entitlements.ios.plist` therefore declares the group explicitly, and the array order is
//! the mechanism: iOS files an item into the **first** entitled group when a write does not
//! name one, and searches **every** entitled group when a read does not name one. Because no
//! accessor here sets `kSecAttrAccessGroup`, writes land in [`STABLE_ACCESS_GROUP`] and reads
//! span stable-then-legacy for free. That is deliberate — resolving the literal group string
//! in Rust would mean discovering the team's `AppIdentifierPrefix` at runtime, adding a
//! failure mode to every Keychain call to re-implement what the OS already guarantees.
//!
//! The invariant that *is* worth enforcing is the entitlement's shape, which no call site can
//! observe; `entitlement_declares_stable_group_first` asserts it against the tracked plist at
//! compile time, and `just bundle-identity-check` re-asserts it alongside the bundle id and
//! the iCloud container. See ADR-0030.
//!
//! In test builds (`#[cfg(test)]`), all Keychain operations are redirected to an
//! in-memory store so that tests never touch the real macOS Keychain and never
//! trigger a password prompt. The test store models the two-store split faithfully —
//! the same account in the synced and device-local namespaces is two independent values.

#[cfg(not(test))]
use security_framework::passwords::{
    delete_generic_password, delete_generic_password_options, generic_password,
    get_generic_password, set_generic_password, set_generic_password_options, PasswordOptions,
};

pub const SERVICE: &str = "ezpds-identity-wallet";

/// The Keychain access group every new item is written to, minus the team's
/// `$(AppIdentifierPrefix)`.
///
/// Deliberately not derived from the bundle id, so a `dev.malpercio.*` → `org.obsign.*`
/// rename cannot move it. Must stay **first** in `Entitlements.ios.plist`'s
/// `keychain-access-groups` array — that position is what makes it the write target.
pub const STABLE_ACCESS_GROUP: &str = "org.obsign.shared";

/// The group items were written to before [`STABLE_ACCESS_GROUP`] existed: the implicit
/// `$(AppIdentifierPrefix)<bundle-id>` group of the original `dev.malpercio.identitywallet`
/// bundle.
///
/// Pinned as a literal rather than read from `tauri.conf.json`'s current identifier —
/// deriving it would let a rename quietly redefine "legacy" to the new bundle id and orphan
/// exactly the items this exists to keep reachable. It must remain declared for as long as
/// any install may still hold items there, which is indefinitely: an install that never
/// updates never migrates.
pub const LEGACY_ACCESS_GROUP: &str = "dev.malpercio.identitywallet";

#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("keychain error: {0}")]
    Security(#[from] security_framework::base::Error),
    /// A synchronizable-store accessor was called for an account that is not on the
    /// iCloud allowlist. Never reachable from the shipped call sites — the guard exists so
    /// a future caller cannot quietly widen what leaves the device.
    #[error("account {account} is not permitted in the iCloud-synchronizable keychain")]
    SyncNotPermitted { account: String },
    /// Returned by the in-memory test store when an item is not found.
    #[cfg(test)]
    #[error("item not found")]
    NotFound,
}

/// Whether `account` is permitted in the **iCloud-synchronizable** Keychain store.
///
/// A deliberate allowlist of exactly one account family — the per-DID Shamir Share 1 slot
/// `recovery-share-1:{did}` — because Share 1 is the only wallet secret whose entire job is
/// to survive the loss of the device that created it. Everything else the wallet holds is
/// device-local by design, and each exclusion is load-bearing rather than incidental:
///
/// * **the device key** (`device-rotation-key-*`, `{did}:device-key*`) — on a real device it
///   is a Secure Enclave key that *cannot* leave the hardware, and the software fallback must
///   not be more portable than the thing it stands in for. It is `rotationKeys[0]`: one
///   device, one key, is what makes the 72-hour PLC override meaningful.
/// * **`{did}:oauth-tokens`** — a bearer session for one device. Syncing it would put a live
///   credential in the Apple account for no recovery benefit; a recovered wallet mints its
///   own via sovereign login.
/// * **`{did}:recovery-signing-key`** — the self-controlled `atproto` repo signing key. It
///   signs commits, so a second live copy is a fork risk, not a backup.
/// * **`ceremony-staging` / `recovery-epilogue`** — in-flight ceremony records whose whole
///   contract is fail-closed single-device ownership. Two devices resuming one epilogue is a
///   correctness hazard, not a convenience: each would drive the same rotation independently
///   against a record it believes it owns. They also hold the *seed* (or two shares at once)
///   until teardown, so syncing them would place a reconstructable secret in iCloud,
///   collapsing the 2-of-3 threshold this whole design exists to hold.
///
/// Asserted by `deny_list_accounts_never_sync` below.
pub fn syncs_to_icloud(account: &str) -> bool {
    crate::rekey::is_recovery_share1_account(account)
}

/// Reject a synchronizable-store call for a non-allowlisted account.
fn guard_sync_allowed(account: &str) -> Result<(), KeychainError> {
    if syncs_to_icloud(account) {
        Ok(())
    } else {
        Err(KeychainError::SyncNotPermitted {
            account: account.to_string(),
        })
    }
}

/// Store bytes in the **iCloud-synchronizable** Keychain store.
///
/// Writes a record distinct from any same-named `store_item` record; it does not migrate,
/// replace, or delete the device-local one. Only allowlisted accounts (see
/// [`syncs_to_icloud`]) are accepted.
///
/// A successful return means the item was written carrying `kSecAttrSynchronizable` — **not**
/// that it reached the user's Apple account. iOS exposes no delivery callback, and with
/// iCloud Keychain switched off the attribute is recorded and propagates nowhere (enabling it
/// later syncs the item with no further involvement from this app). User-facing copy must
/// claim only the former.
pub fn store_item_synced(account: &str, data: &[u8]) -> Result<(), KeychainError> {
    guard_sync_allowed(account)?;
    #[cfg(test)]
    {
        test_store::set(test_store::Scope::Synced, account, data.to_vec());
        Ok(())
    }
    #[cfg(not(test))]
    set_generic_password_options(data, synced_options(account)).map_err(KeychainError::Security)
}

/// Retrieve bytes from the **iCloud-synchronizable** Keychain store.
///
/// Returns `Err` with `errSecItemNotFound` when the synced slot is empty, even if a
/// device-local item with the same account exists.
pub fn get_item_synced(account: &str) -> Result<Vec<u8>, KeychainError> {
    guard_sync_allowed(account)?;
    #[cfg(test)]
    {
        test_store::get(test_store::Scope::Synced, account).ok_or(KeychainError::NotFound)
    }
    #[cfg(not(test))]
    generic_password(synced_options(account)).map_err(KeychainError::Security)
}

/// Delete an item from the **iCloud-synchronizable** Keychain store, leaving any
/// device-local item of the same name untouched.
#[cfg_attr(test, allow(dead_code))]
pub fn delete_item_synced(account: &str) -> Result<(), KeychainError> {
    guard_sync_allowed(account)?;
    #[cfg(test)]
    {
        test_store::delete(test_store::Scope::Synced, account);
        Ok(())
    }
    #[cfg(not(test))]
    delete_generic_password_options(synced_options(account)).map_err(KeychainError::Security)
}

/// Query targeting the synchronizable store for `account`.
///
/// `Some(true)` (never `None`) so every operation addresses exactly one store: with `None`,
/// a set would prefer the device-local store and a get could not say which store answered.
#[cfg(not(test))]
fn synced_options(account: &str) -> PasswordOptions {
    let mut options = PasswordOptions::new_generic_password(SERVICE, account);
    options.set_access_synchronized(Some(true));
    options
}

/// Store arbitrary bytes in the **device-local** Keychain store under the given account name.
///
/// Creates the entry if it doesn't exist, or updates it if it does. The value stays on this
/// device; see [`store_item_synced`] for the iCloud-synchronizable store.
pub fn store_item(account: &str, data: &[u8]) -> Result<(), KeychainError> {
    #[cfg(test)]
    {
        test_store::set(test_store::Scope::Local, account, data.to_vec());
        Ok(())
    }
    #[cfg(not(test))]
    set_generic_password(SERVICE, account, data).map_err(KeychainError::Security)
}

/// Retrieve bytes from the **device-local** Keychain store for the given account name.
///
/// Returns `Err` with `errSecItemNotFound` if no entry exists. Never returns a value written
/// by [`store_item_synced`].
pub fn get_item(account: &str) -> Result<Vec<u8>, KeychainError> {
    #[cfg(test)]
    {
        test_store::get(test_store::Scope::Local, account).ok_or(KeychainError::NotFound)
    }
    #[cfg(not(test))]
    get_generic_password(SERVICE, account).map_err(KeychainError::Security)
}

/// Delete an item from the **device-local** Keychain store by account name.
///
/// Returns `Ok(())` on successful deletion, or `Err` if the item doesn't exist.
pub fn delete_item(account: &str) -> Result<(), KeychainError> {
    #[cfg(test)]
    {
        test_store::delete(test_store::Scope::Local, account);
        Ok(())
    }
    #[cfg(not(test))]
    delete_generic_password(SERVICE, account).map_err(KeychainError::Security)
}

/// `errSecItemNotFound` — the Security framework's "no such item" status.
///
/// Callers that hold a raw `security_framework` error rather than a `KeychainError`
/// (a direct `ItemSearchOptions` query, for instance) compare against this instead of
/// re-spelling the magic number.
pub const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

/// Returns true if the error is errSecItemNotFound (OS status -25300).
/// Use this to distinguish "item does not exist" from transient OS errors.
pub fn is_not_found(err: &KeychainError) -> bool {
    match err {
        KeychainError::Security(e) => e.code() == ERR_SEC_ITEM_NOT_FOUND,
        // Not an absence claim — the account was never addressed.
        KeychainError::SyncNotPermitted { .. } => false,
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
///
/// Keys are `(scope, account)`, mirroring the real Keychain's two-store split: the same
/// account in `Local` and `Synced` is two independent records, and neither accessor family
/// can see the other's value. Tests that assert the launch backfill depend on that.
#[cfg(test)]
mod test_store {
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// Which of the two Keychain stores a call addresses.
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub enum Scope {
        /// The default, device-local store.
        Local,
        /// The `kSecAttrSynchronizable` (iCloud Keychain) store.
        Synced,
    }

    thread_local! {
        static STORE: RefCell<HashMap<(Scope, String), Vec<u8>>> = RefCell::new(HashMap::new());
    }

    pub fn get(scope: Scope, account: &str) -> Option<Vec<u8>> {
        STORE.with(|s| s.borrow().get(&(scope, account.to_string())).cloned())
    }

    pub fn set(scope: Scope, account: &str, data: Vec<u8>) {
        STORE.with(|s| {
            s.borrow_mut().insert((scope, account.to_string()), data);
        });
    }

    pub fn delete(scope: Scope, account: &str) {
        STORE.with(|s| {
            s.borrow_mut().remove(&(scope, account.to_string()));
        });
    }

    pub fn clear_all() {
        STORE.with(|s| s.borrow_mut().clear());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:plc:sync0123456789abcdefghij";

    /// The tracked entitlements, embedded at compile time so this assertion cannot drift
    /// from the file that actually ships (`ios-postinit`'s Patch H installs this exact
    /// content into the generated project).
    const ENTITLEMENTS: &str = include_str!("../Entitlements.ios.plist");

    /// The `<string>` values of the `keychain-access-groups` array, in declaration order.
    fn declared_access_groups() -> Vec<String> {
        let after_key = ENTITLEMENTS
            .split_once("<key>keychain-access-groups</key>")
            .expect("Entitlements.ios.plist declares no keychain-access-groups")
            .1;
        let array = after_key
            .split_once("<array>")
            .and_then(|(_, rest)| rest.split_once("</array>"))
            .expect("keychain-access-groups is not followed by an <array>")
            .0;
        array
            .split("<string>")
            .skip(1)
            .map(|entry| {
                entry
                    .split_once("</string>")
                    .expect("unterminated <string> in keychain-access-groups")
                    .0
                    .trim()
                    .to_string()
            })
            .collect()
    }

    /// The entitlement's shape is the whole mechanism, and no Rust call site can observe it:
    /// the stable group must be FIRST (iOS writes new items to the first entitled group) and
    /// the legacy group must still be present (a read that names no group searches every
    /// entitled group, which is what keeps pre-rename items reachable). Dropping or
    /// reordering either entry orphans live identity material silently.
    #[test]
    fn entitlement_declares_stable_group_first() {
        let groups = declared_access_groups();
        assert_eq!(
            groups.first().map(String::as_str),
            Some(format!("$(AppIdentifierPrefix){STABLE_ACCESS_GROUP}").as_str()),
            "the stable group must be first — it is what makes it the write target; got {groups:?}"
        );
        assert!(
            groups.contains(&format!("$(AppIdentifierPrefix){LEGACY_ACCESS_GROUP}")),
            "the legacy group must stay declared or pre-rename items become unreachable; got {groups:?}"
        );
    }

    /// The stable group must not track the bundle id — if it did, a rename would move it and
    /// the entitlement would be decoration.
    #[test]
    fn stable_group_is_not_the_bundle_id() {
        assert_ne!(STABLE_ACCESS_GROUP, LEGACY_ACCESS_GROUP);
        assert!(!ENTITLEMENTS.contains("$(CFBundleIdentifier)"));
    }

    /// The allowlist admits exactly the per-DID Share 1 slot — not the bare prefix, and not
    /// the deprecated app-global `recovery-share-1` account (a pre-unification install's
    /// Share 1 is read from there but never written back into iCloud under that name).
    #[test]
    fn only_per_did_share1_syncs() {
        assert!(syncs_to_icloud(&crate::rekey::recovery_share1_account(DID)));
        assert!(!syncs_to_icloud("recovery-share-1"));
        assert!(!syncs_to_icloud("recovery-share-1:"));
    }

    /// Every secret the design keeps device-local must stay off the synchronizable store.
    /// Adding an account here without a design decision is the failure this guards.
    #[test]
    fn deny_list_accounts_never_sync() {
        let denied = [
            // Device key — Secure Enclave on device; `rotationKeys[0]`.
            "device-rotation-key-priv",
            "device-rotation-key-pub",
            "device-rotation-key-app-label",
            &format!("{DID}:device-key"),
            &format!("{DID}:device-key-pub"),
            &format!("{DID}:device-key-app-label"),
            // Live per-device credentials and the repo signing key.
            &format!("{DID}:oauth-tokens"),
            &format!("{DID}:recovery-signing-key"),
            // In-flight ceremony records — these hold reconstructable seed material.
            crate::share_ceremony::STAGING_ACCOUNT,
            crate::share_recovery::EPILOGUE_ACCOUNT,
            &format!("rekey-staging:{DID}"),
            &format!("self-held-kit-staging:{DID}"),
            // The self-held-kit marker: not secret, but nothing outside the Share 1
            // family belongs in the synchronizable store.
            &crate::self_held_kit::self_held_kit_account(DID),
            // Everything else the wallet stores, for completeness.
            "oauth-dpop-key-priv",
            "oauth-access-token",
            "oauth-refresh-token",
            "session-token",
            "device-token",
            "did",
            "managed-dids",
            "forgotten-dids",
            "pending-removals",
            "monitor-history",
            "relay-base-url",
            "appearance-preference",
            &format!("{DID}:did-doc"),
            &format!("{DID}:plc-log"),
        ];
        for account in denied {
            assert!(
                !syncs_to_icloud(account),
                "{account} must never be written to the iCloud-synchronizable keychain"
            );
            assert!(
                matches!(
                    store_item_synced(account, b"x"),
                    Err(KeychainError::SyncNotPermitted { .. })
                ),
                "{account} must be refused by the synchronizable write path"
            );
            assert!(matches!(
                get_item_synced(account),
                Err(KeychainError::SyncNotPermitted { .. })
            ));
            assert!(matches!(
                delete_item_synced(account),
                Err(KeychainError::SyncNotPermitted { .. })
            ));
        }
    }

    /// A refused sync call is not an "item absent" verdict — a caller must not mistake it
    /// for one and conclude the share was never stored.
    #[test]
    fn sync_not_permitted_is_not_not_found() {
        assert!(!is_not_found(&KeychainError::SyncNotPermitted {
            account: "device-rotation-key-priv".to_string(),
        }));
    }

    /// The two stores are independent records under one account name — the property the
    /// copy-never-flip backfill and the synced-first read path both rest on.
    #[test]
    fn synced_and_local_slots_are_distinct_records() {
        clear_for_test();
        let account = crate::rekey::recovery_share1_account(DID);

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
