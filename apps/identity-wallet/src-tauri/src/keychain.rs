//! The wallet's Keychain: its service name, access groups, every account name, and the
//! legacy OAuth-client token helpers. `run()` installs
//! `obsign_platform_ios::keychain::AppleKeychain` under [`SERVICE`] into `obsign_core::keystore`.
//!
//! The accessors every module calls (`store_item`, `get_item`, the `*_synced` family,
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
//! * `oauth-dpop-key-priv` (loaded via `custos_client::DpopKeypair::get_or_create` over
//!   `device_key::WalletKeychain`, at [`DPOP_KEY_PRIV_ACCOUNT`]), `oauth-access-token`,
//!   `oauth-refresh-token` — the retained but currently dead legacy OAuth-client items
//!   ([`store_oauth_tokens`]).
//! * the five `notification-*` accounts (`notifications::NOTIFICATION_ACCOUNTS` is the
//!   inventory) — the key, the pinned sender-key document, and the extension's failure
//!   log are written via `keystore::store_item_after_first_unlock`; none of the five ever syncs.
//! * `blob-backup-settings` and `background-backup-next-mirror` (`bg_backup`) — the
//!   background-sweep policy and its mirror-alternation turn.
//! * `recovery-share-1` — the deprecated app-global Share 1 slot, read only by the
//!   launch migration and the recovery auto-load fallback.
//!
//! Per-DID accounts follow `"{did}:suffix"` with twelve suffixes: `device-key`,
//! `device-key-pub`, `device-key-app-label`, `did-doc`, `plc-log`, `oauth-tokens`,
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

use obsign_core::keystore::{self, KeyStoreError};

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

// ── OAuth Keychain helpers ─────────────────────────────────────────────────────

/// The wallet's DPoP proof-signing key (see the module doc's account inventory). Read by
/// `oauth.rs` through `custos_client::DpopKeypair::get_or_create::<device_key::WalletKeychain>`
/// rather than a dedicated load/store pair — that generic path is the one implementation of
/// "load or mint a Keychain-backed key" this crate needs. `#[cfg(test)]`: `OAuthClient::new`
/// (DPoP mode) has no production caller today (see `oauth.rs`'s module doc), so this account is
/// currently reachable only from `oauth::test_dpop_keypair`.
#[cfg(test)]
pub(crate) use obsign_core::oauth::DPOP_KEY_PRIV_ACCOUNT;
const OAUTH_ACCESS_TOKEN_ACCOUNT: &str = "oauth-access-token";
const OAUTH_REFRESH_TOKEN_ACCOUNT: &str = "oauth-refresh-token";
/// Store the OAuth access token and refresh token in the Keychain.
pub fn store_oauth_tokens(access_token: &str, refresh_token: &str) -> Result<(), KeyStoreError> {
    keystore::store_item(OAUTH_ACCESS_TOKEN_ACCOUNT, access_token.as_bytes())?;
    keystore::store_item(OAUTH_REFRESH_TOKEN_ACCOUNT, refresh_token.as_bytes())?;
    Ok(())
}

/// Load the OAuth access token and refresh token from the Keychain.
///
/// Returns `None` if either token is missing (not yet authenticated).
pub fn load_oauth_tokens() -> Option<(String, String)> {
    let access = match keystore::get_item(OAUTH_ACCESS_TOKEN_ACCOUNT) {
        Ok(b) => match String::from_utf8(b) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = ?e, "UTF-8 error decoding access token from Keychain");
                return None;
            }
        },
        Err(e) if keystore::is_not_found(&e) => return None,
        Err(e) => {
            tracing::error!(error = ?e, "Keychain error loading access token");
            return None;
        }
    };
    let refresh = match keystore::get_item(OAUTH_REFRESH_TOKEN_ACCOUNT) {
        Ok(b) => match String::from_utf8(b) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = ?e, "UTF-8 error decoding refresh token from Keychain");
                return None;
            }
        },
        Err(e) if keystore::is_not_found(&e) => return None,
        Err(e) => {
            tracing::error!(error = ?e, "Keychain error loading refresh token");
            return None;
        }
    };
    Some((access, refresh))
}

#[cfg(test)]
mod tests {
    use super::*;
    use obsign_core::keystore::{
        delete_item_synced, get_item_synced, store_item_synced, syncs_to_icloud, KeyStoreError,
    };

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
        assert_eq!(
            device_key::ACCOUNTS.secure_enclave_label,
            "ezpds-device-rotation-key"
        );

        let mut golden: Vec<(String, String, bool)> = [
            (PDS_URL_ACCOUNT, "relay-base-url"),
            (APPEARANCE_ACCOUNT, "appearance-preference"),
            (DEVICE_TOKEN_ACCOUNT, "device-token"),
            (SESSION_TOKEN_ACCOUNT, "session-token"),
            (LEGACY_DID_ACCOUNT, "did"),
            (DPOP_KEY_PRIV_ACCOUNT, "oauth-dpop-key-priv"),
            (OAUTH_ACCESS_TOKEN_ACCOUNT, "oauth-access-token"),
            (OAUTH_REFRESH_TOKEN_ACCOUNT, "oauth-refresh-token"),
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
                store_item_synced(account, b"x"),
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
        ];
        for account in denied {
            assert!(
                !syncs_to_icloud(account),
                "{account} must never be written to the iCloud-synchronizable keychain"
            );
            assert!(
                matches!(
                    store_item_synced(account, b"x"),
                    Err(KeyStoreError::SyncNotPermitted { .. })
                ),
                "{account} must be refused by the synchronizable write path"
            );
            assert!(matches!(
                get_item_synced(account),
                Err(KeyStoreError::SyncNotPermitted { .. })
            ));
            assert!(matches!(
                delete_item_synced(account),
                Err(KeyStoreError::SyncNotPermitted { .. })
            ));
        }
    }
}

/// The wallet's own `custos_client` adapters, end to end: the DPoP key through the installed
/// store, breadcrumbs into the diagnostics log, and refreshed tokens into the legacy global
/// OAuth-client accounts above.
#[cfg(test)]
mod dpop_adapter {
    use super::*;
    use obsign_core::oauth::{OAuthError, OAuthSession};

    // ── custos_client adapters ───────────────────────────────────────────────────
    //
    // `OAuthClient` is Tauri-free; it takes its diagnostics and token-persistence seams as
    // trait objects rather than calling `crate::diagnostics`/`crate::keychain` directly.

    /// Persists a DPoP-mode refreshed token pair to the wallet's legacy global OAuth-client
    /// Keychain item (see `keychain.rs`'s module doc). Test-only: only `OAuthClient::new`
    /// (DPoP mode) would call this, and that constructor has no production caller today.
    pub struct WalletTokenPersister;

    impl custos_client::TokenPersister for WalletTokenPersister {
        fn store_tokens(&self, access_token: &str, refresh_token: &str) -> Result<(), String> {
            store_oauth_tokens(access_token, refresh_token).map_err(|e| e.to_string())
        }
    }

    mod tests {
        use super::*;
        use crate::diagnostics::WalletTransportObserver;
        use custos_client::OAuthClient;
        use httpmock::prelude::*;
        use obsign_core::oauth::test_dpop_keypair;
        use std::sync::{Arc, Mutex};

        /// End-to-end check of the wallet's own adapters (not `custos_client`'s internals, which
        /// the crate's own test suite covers): a DPoP-mode `OAuthClient` built with
        /// `device_key::WalletKeychain`, `WalletTransportObserver`, and `WalletTokenPersister`
        /// refreshes a token and the new pair lands in the wallet's real (test-mode in-memory)
        /// Keychain via `keychain::load_oauth_tokens`.
        #[tokio::test]
        async fn refresh_persists_tokens_through_wallet_keychain_adapter() {
            obsign_core::keystore::clear_for_test();

            let server = MockServer::start();
            server.mock(|when, then| {
                when.method(POST).path("/oauth/token");
                then.status(200).json_body(serde_json::json!({
                    "access_token": "wallet-new-access",
                    "token_type": "DPoP",
                    "expires_in": 300,
                    "refresh_token": "wallet-new-refresh",
                    "scope": "atproto"
                }));
            });

            let keypair = test_dpop_keypair().expect("keypair must exist");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let session = Arc::new(Mutex::new(OAuthSession {
                access_token: "wallet-old-access".to_string(),
                refresh_token: "wallet-old-refresh".to_string(),
                expires_at: now, // already due for refresh
                dpop_nonce: None,
            }));
            let client = OAuthClient::new(
                keypair,
                "test-client-id".to_string(),
                session,
                server.base_url(),
                Arc::new(WalletTransportObserver),
                Arc::new(WalletTokenPersister),
            );

            client.refresh_token().await.expect("refresh must succeed");

            let (access, refresh) = load_oauth_tokens().expect("tokens must be persisted");
            assert_eq!(access, "wallet-new-access");
            assert_eq!(refresh, "wallet-new-refresh");
        }

        /// End-to-end check of the redaction pipeline through the wallet's real
        /// `WalletTransportObserver` and `crate::diagnostics::export_diagnostics()`: a lazy-refresh
        /// transport failure must record a breadcrumb, and the exported report must never contain
        /// the access/refresh tokens. The three secret assertions are the point of this test and use
        /// uniquely-named markers (safe under the process-global sink shared with tests running in
        /// parallel); the `"oauthRefresh"` recorded-check is the shared, hardcoded op name every
        /// DPoP-mode refresh failure uses, so under parallel execution it could in principle be
        /// satisfied by a sibling test's own breadcrumb rather than this call's — a weaker signal
        /// than the secret checks, kept for readability rather than as the test's real assertion.
        /// The `"private-identity-oauthrs-test"` marker (embedded in the `/resource?did=...` path)
        /// can never actually leak here: the lazy refresh fails before that request is built, so
        /// this assertion cannot fail either. Covering a leak from the *resource* request itself
        /// would need a scenario where the refresh succeeds and the follow-up request fails —
        /// not this one.
        #[tokio::test]
        async fn lazy_refresh_transport_failure_records_a_redacted_breadcrumb() {
            // A bound-then-dropped listener: a real, briefly-valid port that is guaranteed closed
            // by the time the client connects, so the transport failure is deterministic across
            // platforms (unlike a fixed low port number, which may be filtered rather than refused).
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            drop(listener);

            let keypair = test_dpop_keypair().expect("keypair must exist");
            let session = Arc::new(Mutex::new(OAuthSession {
                access_token: "private-access-token-oauthrs-test".to_string(),
                refresh_token: "private-refresh-token-oauthrs-test".to_string(),
                expires_at: 0, // already due for refresh
                dpop_nonce: None,
            }));
            let client = OAuthClient::new(
                keypair,
                "test-client-id".to_string(),
                session,
                base_url,
                Arc::new(WalletTransportObserver),
                Arc::new(WalletTokenPersister),
            );

            let error = client
                .get("/resource?did=did:plc:private-identity-oauthrs-test")
                .await
                .unwrap_err();
            assert!(matches!(error, OAuthError::TokenRefreshFailed));

            let report = crate::diagnostics::export_diagnostics();
            assert!(
                report.contains("oauthRefresh"),
                "the transport failure must be recorded"
            );
            // Fake markers planted in the request; none may reach the exported report.
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
}
