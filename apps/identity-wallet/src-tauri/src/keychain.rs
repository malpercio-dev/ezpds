//! The wallet's Keychain: its service name, access groups, every account name, and the
//! cleanup of the retired OAuth-client items. `run()` hands its `Core`
//! `obsign_platform_ios::keychain::AppleKeychain` under [`SERVICE`].
//!
//! The accessors every module calls (`Keys`: `store_item`, `get_item`, the `*_synced` family;
//! `is_not_found`) and the cloud-slot allowlist live in `obsign_core::keystore`; that module
//! doc owns the two-store and protection-class semantics. This file owns what is specific to
//! iOS and to this app.
//!
//! All items are `kSecClassGenericPassword` under service [`SERVICE`]. The cloud slot is the
//! `kSecAttrSynchronizable` store (iCloud Keychain); the `…ThisDeviceOnly` accessibility classes
//! are mutually exclusive with syncing, so synchronizable items keep the framework default
//! `kSecAttrAccessibleWhenUnlocked`. `AccessibleAfterFirstUnlock` exists for the Notification
//! Service Extension, which must decrypt a push on a locked screen; it protects notification
//! content, never identity material.
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
//! # Account inventory
//!
//! Every account the wallet stores, with the module whose constant or helper owns its
//! naming in parentheses (that module's docs carry the account's contract). App-global,
//! device-local unless noted:
//!
//! * `relay-base-url` (`pds_config`) — configured PDS base URL.
//! * `appearance-preference` (`preferences`) — `"system"`/`"light"`/`"dark"`; mirrored
//!   pre-paint in localStorage under the same key.
//! * `device-rotation-key-priv` / `-pub` / `-app-label` (`device_key`) — the global
//!   device key: priv on the software path, pub + app-label as Secure Enclave metadata.
//! * `device-token` / `session-token` / `did` (`create_flow`) — the create flow's
//!   cross-step state: the device token, the pending-then-upgraded session token, and
//!   the legacy primary-DID marker.
//! * `ceremony-staging` (`share_ceremony::STAGING_ACCOUNT`) — the in-flight create
//!   ceremony's share set; fail-closed.
//! * `recovery-epilogue` (`share_recovery::EPILOGUE_ACCOUNT`) — the in-flight recovery
//!   rotation epilogue; fail-closed.
//! * `monitor-history` (`plc_monitor`) — the monitor's sweep log; fail-open.
//! * `managed-dids` / `forgotten-dids` (`identity_store`) — the managed-DID index and
//!   the deliberate-removal record launch reconciliation consults.
//! * `pending-removals` (`identity_removal`) — DIDs whose post-delete tombstone/wipe
//!   is unfinished; fail-open.
//! * `oauth-dpop-key-priv`, `oauth-access-token`, `oauth-refresh-token` — retired; no code
//!   reads or writes them. [`retire_legacy_oauth_items`] deletes them on launch
//!   ([`RETIRED_OAUTH_ACCOUNTS`]).
//! * the five `notification-*` accounts (`notifications::NOTIFICATION_ACCOUNTS` is the
//!   inventory) — the key, the pinned sender-key document, and the extension's failure
//!   log are written via `Keys::store_item_after_first_unlock`; none of the five ever syncs.
//! * `blob-backup-settings` and `background-backup-next-mirror` (`bg_backup`) — the
//!   background-sweep policy and its mirror-alternation turn.
//! * `recovery-share-1` — the deprecated app-global Share 1 slot, read only by the
//!   launch migration and the recovery auto-load fallback.
//!
//! Per-DID accounts follow `"{did}:suffix"` with thirteen suffixes: `device-key`,
//! `device-key-pub`, `device-key-app-label`, `did-doc`, `plc-log`, `plc-alerts`, `oauth-tokens`,
//! `recovery-signing-key`, `delegation-seed`, `child-index` (all `identity_store`;
//! `recovery-signing-key` written by `disaster_recovery`, `delegation-seed` by the
//! create ceremony and by share verification), `blob-backup-enabled` (`blob_backup`),
//! `repo-backup-enabled` (`repo_backup`), and `self-held-kit` (`self_held_kit`). Three more per-DID slots
//! use a prefix form: `recovery-share-1:{did}` (`rekey::recovery_share1_account` —
//! the only account family `keystore::syncs_to_icloud` admits to the synchronizable store) and
//! the staging pair `rekey-staging:{did}` / `self-held-kit-staging:{did}`
//! (`share_ceremony`). Changing [`SERVICE`] or any account name orphans previously
//! stored items; `account_names_are_pinned` holds every name above against a literal.
//!

use obsign_core::keystore;

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

// ── Retired legacy OAuth-client items ──────────────────────────────────────────

/// The global OAuth-client accounts no code reads or writes any more: the DPoP proof key and
/// the access/refresh token pair of the retired create-flow OAuth login.
///
/// ADR-0030 freezes Keychain account names, so these are deleted by
/// [`retire_legacy_oauth_items`] rather than renamed. Keep the literals (and
/// `account_names_are_pinned`'s check of them) until that cleanup has shipped to every install
/// that could still hold the items; after that the list can go.
pub(crate) const RETIRED_OAUTH_ACCOUNTS: [&str; 3] = [
    "oauth-dpop-key-priv",
    "oauth-access-token",
    "oauth-refresh-token",
];

/// Delete the orphaned [`RETIRED_OAUTH_ACCOUNTS`] items. Idempotent and best-effort: an absent
/// item is the normal case, and a failed delete only leaves an unread item behind, so it is
/// logged and never blocks launch.
pub fn retire_legacy_oauth_items(core: &crate::oauth::Core) {
    for account in RETIRED_OAUTH_ACCOUNTS {
        match core.keys().delete_item(account) {
            Ok(()) => tracing::info!(account, "deleted retired OAuth Keychain item"),
            Err(e) if keystore::is_not_found(&e) => {}
            Err(e) => {
                tracing::warn!(account, error = ?e, "could not delete retired OAuth Keychain item")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use obsign_core::keystore::{syncs_to_icloud, KeyStoreError, Keys};
    use obsign_core::test_support::MemKeyStore;

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

    /// Frozen contract "Device / Keychain account names" (docs/architecture/frozen-contracts.md).
    /// Left: the code's own constant or helper. Right: a literal, and whether the account is
    /// admitted to the iCloud-synchronizable store. Editing a literal here is a wire-contract
    /// change — a renamed account is an unreachable item on every installed phone, no error.
    #[test]
    fn account_names_are_pinned() {
        use crate::{
            bg_backup, blob_backup, device_key, identity_removal, identity_store as ids,
            notifications, plc_monitor, rekey, repo_backup, self_held_kit, share_ceremony,
            share_recovery,
        };
        use obsign_core::create_flow::{
            DEVICE_TOKEN_ACCOUNT, LEGACY_DID_ACCOUNT, SESSION_TOKEN_ACCOUNT,
        };
        use obsign_core::pds_config::PDS_URL_ACCOUNT;
        use obsign_core::preferences::APPEARANCE_ACCOUNT;
        let d = DID;

        assert_eq!(SERVICE, "ezpds-identity-wallet");
        // Retired accounts: no live constant owns them, so the cleanup list is the pin.
        assert_eq!(
            RETIRED_OAUTH_ACCOUNTS,
            [
                "oauth-dpop-key-priv",
                "oauth-access-token",
                "oauth-refresh-token"
            ]
        );
        assert_eq!(
            device_key::DEVICE_KEY_HARDWARE_LABEL,
            "ezpds-device-rotation-key"
        );

        let mut golden: Vec<(String, String, bool)> = [
            (PDS_URL_ACCOUNT, "relay-base-url"),
            (APPEARANCE_ACCOUNT, "appearance-preference"),
            (DEVICE_TOKEN_ACCOUNT, "device-token"),
            (SESSION_TOKEN_ACCOUNT, "session-token"),
            (LEGACY_DID_ACCOUNT, "did"),
            (
                device_key::DEVICE_KEY_PRIV_ACCOUNT,
                "device-rotation-key-priv",
            ),
            (
                device_key::DEVICE_KEY_PUB_ACCOUNT,
                "device-rotation-key-pub",
            ),
            (
                device_key::DEVICE_KEY_APP_LABEL_ACCOUNT,
                "device-rotation-key-app-label",
            ),
            (share_ceremony::STAGING_ACCOUNT, "ceremony-staging"),
            (share_recovery::EPILOGUE_ACCOUNT, "recovery-epilogue"),
            (share_recovery::RECOVERY_SHARE1_ACCOUNT, "recovery-share-1"),
            (plc_monitor::HISTORY_ACCOUNT, "monitor-history"),
            (ids::MANAGED_DIDS_ACCOUNT, "managed-dids"),
            (ids::FORGOTTEN_DIDS_ACCOUNT, "forgotten-dids"),
            (
                identity_removal::PENDING_REMOVALS_ACCOUNT,
                "pending-removals",
            ),
            (bg_backup::SETTINGS_ACCOUNT, "blob-backup-settings"),
            (
                bg_backup::NEXT_MIRROR_ACCOUNT,
                "background-backup-next-mirror",
            ),
        ]
        .into_iter()
        .map(|(actual, expected)| (actual.to_string(), expected.to_string(), false))
        .collect();

        // The five notification accounts, in `NOTIFICATION_ACCOUNTS` order.
        let notification = [
            "notification-device-uuid",
            "notification-key-priv",
            "notification-sender-keys",
            "notification-apns-token",
            "notification-failures",
        ];
        assert_eq!(
            notifications::NOTIFICATION_ACCOUNTS.len(),
            notification.len()
        );
        for (actual, expected) in notifications::NOTIFICATION_ACCOUNTS
            .iter()
            .zip(notification)
        {
            golden.push((actual.to_string(), expected.to_string(), false));
        }

        // Per-DID templates.
        golden.extend([
            (ids::device_key_account(d), format!("{d}:device-key"), false),
            (
                ids::device_key_pub_account(d),
                format!("{d}:device-key-pub"),
                false,
            ),
            (
                ids::device_key_app_label_account(d),
                format!("{d}:device-key-app-label"),
                false,
            ),
            (ids::did_doc_account(d), format!("{d}:did-doc"), false),
            (ids::plc_log_account(d), format!("{d}:plc-log"), false),
            (ids::plc_alerts_account(d), format!("{d}:plc-alerts"), false),
            (
                ids::oauth_tokens_account(d),
                format!("{d}:oauth-tokens"),
                false,
            ),
            (
                ids::recovery_signing_key_account(d),
                format!("{d}:recovery-signing-key"),
                false,
            ),
            (
                ids::delegation_seed_account(d),
                format!("{d}:delegation-seed"),
                false,
            ),
            (
                ids::child_index_account(d),
                format!("{d}:child-index"),
                false,
            ),
            (
                blob_backup::backup_enabled_account(d),
                format!("{d}:blob-backup-enabled"),
                false,
            ),
            (
                repo_backup::backup_enabled_account(d),
                format!("{d}:repo-backup-enabled"),
                false,
            ),
            (
                self_held_kit::self_held_kit_account(d),
                format!("{d}:self-held-kit"),
                false,
            ),
            (
                share_ceremony::rekey_staging_account(d),
                format!("rekey-staging:{d}"),
                false,
            ),
            (
                share_ceremony::self_held_kit_staging_account(d),
                format!("self-held-kit-staging:{d}"),
                false,
            ),
            // The one synchronizable account family.
            (
                rekey::recovery_share1_account(d),
                format!("recovery-share-1:{d}"),
                true,
            ),
        ]);

        for (actual, expected, syncs) in &golden {
            assert_eq!(actual, expected, "Keychain account name drifted");
            assert_eq!(
                syncs_to_icloud(actual),
                *syncs,
                "sync admission drifted for {actual}"
            );
        }
    }

    /// The notification slots, read from the module that owns them so a new one cannot be added
    /// without this covering it.
    ///
    /// The private key is the exclusion worth naming: it is readable on a locked screen, so
    /// syncing it would put a key that needs no passcode into the Apple account. It opens
    /// notification content, nothing else, and a replacement device mints its own on its first
    /// registration — there is no recovery story it could serve.
    #[test]
    fn notification_material_never_syncs() {
        for account in crate::notifications::NOTIFICATION_ACCOUNTS {
            assert!(
                !syncs_to_icloud(account),
                "{account} must never reach the iCloud-synchronizable keychain"
            );
            assert!(matches!(
                Keys::new(&MemKeyStore::default()).store_item_synced(account, b"x"),
                Err(KeyStoreError::SyncNotPermitted { .. })
            ));
        }
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
            &format!("{DID}:plc-alerts"),
        ];
        for account in denied {
            assert!(
                !syncs_to_icloud(account),
                "{account} must never be written to the iCloud-synchronizable keychain"
            );
            assert!(
                matches!(
                    Keys::new(&MemKeyStore::default()).store_item_synced(account, b"x"),
                    Err(KeyStoreError::SyncNotPermitted { .. })
                ),
                "{account} must be refused by the synchronizable write path"
            );
            assert!(matches!(
                Keys::new(&MemKeyStore::default()).get_item_synced(account),
                Err(KeyStoreError::SyncNotPermitted { .. })
            ));
            assert!(matches!(
                Keys::new(&MemKeyStore::default()).delete_item_synced(account),
                Err(KeyStoreError::SyncNotPermitted { .. })
            ));
        }
    }
}

/// The wallet's `custos_client` observer adapter, end to end, plus the retired-item cleanup.
#[cfg(test)]
mod adapters {
    use super::*;
    use crate::diagnostics::WalletTransportObserver;
    use custos_client::OAuthClient;
    use obsign_core::oauth::OAuthError;
    use std::sync::Arc;

    #[test]
    fn retire_legacy_oauth_items_deletes_only_the_retired_accounts() {
        let core = &obsign_core::test_support::core();
        for account in RETIRED_OAUTH_ACCOUNTS {
            core.keys().store_item(account, b"orphan").unwrap();
        }
        core.keys()
            .store_item("relay-base-url", b"https://pds.example")
            .unwrap();

        retire_legacy_oauth_items(core);

        for account in RETIRED_OAUTH_ACCOUNTS {
            assert!(keystore::is_not_found(
                &core.keys().get_item(account).unwrap_err()
            ));
        }
        assert_eq!(
            core.keys().get_item("relay-base-url").unwrap(),
            b"https://pds.example"
        );

        // A second run, with nothing left to delete (every delete reports not-found), is a
        // no-op.
        retire_legacy_oauth_items(core);
    }

    /// End-to-end check of the redaction pipeline through the wallet's real
    /// `WalletTransportObserver` and `crate::diagnostics::export_diagnostics()`: a lazy-refresh
    /// transport failure must record a breadcrumb, and the exported report must never contain
    /// the access/refresh tokens. The secret assertions are the point of this test and use
    /// uniquely-named markers (safe under the process-global sink shared with tests running in
    /// parallel); the `"oauthBearerRefresh"` recorded-check is a shared op name, so under parallel
    /// execution a sibling test's breadcrumb could satisfy it — a weaker signal than the secret
    /// checks. The `"private-identity-oauthrs-test"` marker (in the request path) can never reach
    /// the report here: the lazy refresh fails before that request is built.
    #[tokio::test]
    async fn lazy_refresh_transport_failure_records_a_redacted_breadcrumb() {
        // A bound-then-dropped listener: a real, briefly-valid port that is guaranteed closed
        // by the time the client connects, so the transport failure is deterministic across
        // platforms (unlike a fixed low port number, which may be filtered rather than refused).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);

        // A non-JWT access token has no `exp`, so the client treats it as due for refresh.
        let client = OAuthClient::new_bearer_with_observer(
            "private-access-token-oauthrs-test".to_string(),
            "private-refresh-token-oauthrs-test".to_string(),
            base_url,
            Arc::new(WalletTransportObserver),
        )
        .unwrap();

        let error = client
            .get("/resource?did=did:plc:private-identity-oauthrs-test")
            .await
            .unwrap_err();
        assert!(matches!(error, OAuthError::TokenRefreshFailed));

        let report = crate::diagnostics::export_diagnostics();
        assert!(
            report.contains("oauthBearerRefresh"),
            "the transport failure must be recorded"
        );
        for marker in [
            "private-access-token-oauthrs-test",
            "private-refresh-token-oauthrs-test",
            "private-identity-oauthrs-test",
        ] {
            assert!(
                !report.contains(marker),
                "test marker leaked into diagnostics report: {marker}"
            );
        }
    }
}
