// pattern: Imperative Shell

//! The startup reconcile: the pass at launch that moves Share 1 and the created-identity
//! record into their current slots. Every hop is additive, idempotent, and best-effort — a
//! Keychain fault is logged and skipped, never allowed to block launch.
//!
//! [`run`] is the one entry point a shell calls once, after the platform adapters are
//! installed. Its order is load-bearing: the Share 1 hops first (app-global → per-DID
//! device-local → per-DID synchronizable), then the created-identity re-registration, which
//! reads the same legacy `did` item the first hop keys on.

use crate::create_flow::LEGACY_DID_ACCOUNT;
use crate::{identity_store, rekey, share_recovery};

/// Run every launch hop, in order. See the module doc for why the order matters.
pub fn run() {
    reconcile_share1_slots();
    reconcile_created_identity();
}

/// Best-effort one-time migration of a pre-unification install's global `recovery-share-1` slot
/// into the primary identity's per-DID slot.
///
/// Installs that onboarded before the per-DID unification wrote Share 1 to a single app-global
/// `recovery-share-1` slot; the recovery ceremony now reads `recovery-share-1:{did}`. This copies
/// that global share into the per-DID slot for the primary DID (the create flow persists it under
/// the legacy `"did"` Keychain item) so those users keep share-based recovery once the ceremony
/// switches to the per-DID slot. Additive and idempotent: it never deletes the global slot and
/// skips when the per-DID slot already holds a value. Fully best-effort — any Keychain hiccup is
/// logged and swallowed, never blocking launch.
fn migrate_global_share1_to_per_did() {
    // The legacy global slot; absent on a fresh (post-unification) install — nothing to migrate.
    let global = match crate::keystore::get_item(share_recovery::RECOVERY_SHARE1_ACCOUNT) {
        // Sensitive key material — wipe the in-memory copy when this scope ends.
        Ok(bytes) if !bytes.is_empty() => zeroize::Zeroizing::new(bytes),
        Ok(_) => return,
        Err(ref e) if crate::keystore::is_not_found(e) => return,
        Err(e) => {
            tracing::warn!(error = %e, "share1 migration: global slot read failed; skipping");
            return;
        }
    };
    // The primary identity's DID (the create/did:web flow persists it under "did").
    let did = match crate::keystore::get_item(LEGACY_DID_ACCOUNT) {
        Ok(bytes) if !bytes.is_empty() => match String::from_utf8(bytes) {
            Ok(did) => did,
            Err(_) => {
                tracing::warn!("share1 migration: stored DID is not valid UTF-8; skipping");
                return;
            }
        },
        // No primary DID recorded yet: nothing to key the per-DID slot on.
        _ => return,
    };
    let per_did = rekey::recovery_share1_account(&did);
    // Never clobber an already-populated per-DID slot — a newer ceremony or re-key owns it.
    match crate::keystore::get_item(&per_did) {
        Ok(bytes) if !bytes.is_empty() => return,
        Ok(_) => {}
        Err(ref e) if crate::keystore::is_not_found(e) => {}
        Err(e) => {
            tracing::warn!(error = %e, "share1 migration: per-DID slot read failed; skipping");
            return;
        }
    }
    match crate::keystore::store_item(&per_did, &global) {
        Ok(()) => tracing::info!(
            "migrated global recovery-share-1 into the per-DID slot for the primary identity"
        ),
        Err(e) => tracing::warn!(error = %e, "share1 migration: per-DID slot write failed"),
    }
}

/// Reconcile every managed identity's Share 1 into the two Keychain slots it should occupy.
///
/// Runs the two additive hops in order, so a single launch can carry a pre-unification install
/// all the way: app-global → per-DID device-local ([`migrate_global_share1_to_per_did`]), then
/// per-DID device-local → per-DID iCloud-synchronizable ([`backfill_synced_share1`]).
fn reconcile_share1_slots() {
    migrate_global_share1_to_per_did();
    backfill_synced_share1();
}

/// Best-effort launch repair: register the primary DID in `IdentityStore` if the create flow
/// finished without it.
///
/// The create flow persists its DID under the legacy `"did"` account during the ceremony
/// (`perform_did_ceremony`, step 7) and only later registers it in the managed index via
/// `register_created_identity`. The home screen lists identities from the managed index alone,
/// so if that later step does not land — a Keychain fault, or the app never reaching it — the
/// identity exists, is funded with keys and shares, and is invisible. Nothing retried it: the
/// state survived relaunch, and the only exit was the share-recovery ceremony, which re-adds
/// the DID as a side effect of rebuilding an identity that was never actually lost.
///
/// This closes that hole from the other side. The DID is written *before* the fragile step, so
/// it is always on hand; re-registering it is idempotent and additive.
///
/// **Never resurrects a forgotten identity.** Nothing clears the legacy `"did"` account — not
/// local removal, not migration — so "absent from the managed index" alone cannot distinguish
/// a stranded create from a deliberate `forget_identity_locally`. The tombstone index
/// (`IdentityStore::is_forgotten`) carries that intent, and it fails closed: an unreadable
/// tombstone index means no re-registration.
///
/// The DID document is deliberately not rebuilt here. `IdentityListHome` already treats a
/// missing document as a refresh trigger and re-fetches it from plc.directory on first render,
/// which needs neither the handle nor the PDS URL at launch.
fn reconcile_created_identity() {
    let did = match crate::keystore::get_item(LEGACY_DID_ACCOUNT) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(did) if !did.is_empty() => did,
            Ok(_) => return,
            Err(_) => {
                tracing::warn!("identity reconcile: stored DID is not valid UTF-8; skipping");
                return;
            }
        },
        // No primary DID recorded: a fresh install, or an import-only wallet.
        _ => return,
    };

    let store = identity_store::IdentityStore;
    match store.list_identities() {
        Ok(dids) if dids.contains(&did) => return,
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "identity reconcile: managed-DID index unreadable; skipping");
            return;
        }
    }

    if store.is_forgotten(&did) {
        tracing::debug!(
            did = %did,
            "identity reconcile: DID was unregistered on purpose; leaving it out"
        );
        return;
    }

    if let Err(e) = store.add_identity(&did) {
        tracing::warn!(did = %did, error = %e, "identity reconcile: add_identity failed");
        return;
    }

    // Mirrors `register_created_identity`: the create flow's genesis op was signed with the
    // global device key, so alias the per-DID key to it. Non-fatal — the identity lists either
    // way; only the "root key" badge and PLC-monitor classification degrade without it.
    if let Err(e) = store.adopt_global_device_key(&did) {
        tracing::warn!(did = %did, error = %e, "identity reconcile: adopt_global_device_key failed");
    }

    tracing::info!(
        did = %did,
        "identity reconcile: re-registered a created identity missing from the managed index"
    );
}

/// Best-effort launch backfill: copy each managed identity's device-local Share 1 into the
/// iCloud-synchronizable slot.
///
/// Wallet builds before the synchronizable write path wrote Share 1 with no
/// `kSecAttrSynchronizable` attribute, which meant it never left the device that created it —
/// so the escrow-assisted recovery path (Share 1 from iCloud + Share 2 from escrow, no
/// user-held secret) was unavailable on a replacement device. This puts an existing share into
/// the store that can travel.
///
/// **Copy, never flip.** The synchronizable and device-local records are distinct items, and
/// `SecItem.h` documents the key for *targeting* synced items in update/delete but never for
/// changing an item's synchronizability — so an in-place flip is unsupported. Copying is the
/// safer shape regardless: the device-local slot may be the share's only surviving copy, and
/// it is preserved untouched.
///
/// Additive and idempotent: a populated synchronizable slot is never overwritten, and only a
/// device-local value that decodes as a valid v2 index-1 envelope is copied (a bare
/// pre-envelope share cannot auto-load into the recovery ceremony anyway, so syncing it would
/// spend an iCloud secret for no recovery benefit). Fully best-effort — any Keychain hiccup is
/// logged and swallowed, never blocking launch.
///
/// **What this cannot reach.** It runs on-device, so it only helps a device that still holds
/// Share 1 *and* opens this build at least once. A user whose device is already lost is not
/// helped and stays on Share 2 + Share 3 for the life of that identity. And with iCloud
/// Keychain switched off, the item is written carrying the attribute and propagates nowhere;
/// enabling it later syncs it with no further involvement from this app.
fn backfill_synced_share1() {
    for did in share1_backfill_dids() {
        // Never overwrite a populated synchronizable slot — a ceremony, re-key, or recovery
        // epilogue owns it, and it is by definition at least as current as the local one.
        match rekey::read_share1_synced(&did) {
            Ok(bytes) if !bytes.is_empty() => continue,
            Ok(_) => {}
            Err(ref e) if crate::keystore::is_not_found(e) => {}
            Err(e) => {
                tracing::warn!(error = %e, "share1 backfill: synced slot read failed; skipping");
                continue;
            }
        }
        // Sensitive key material — wipe the in-memory copy when this scope ends.
        let local = match crate::keystore::get_item(&rekey::recovery_share1_account(&did)) {
            Ok(bytes) if !bytes.is_empty() => zeroize::Zeroizing::new(bytes),
            Ok(_) => continue,
            Err(ref e) if crate::keystore::is_not_found(e) => continue,
            Err(e) => {
                tracing::warn!(error = %e, "share1 backfill: local slot read failed; skipping");
                continue;
            }
        };
        if share_recovery::decode_share1_envelope(&local).is_none() {
            tracing::debug!("share1 backfill: local slot is not a v2 Share 1 envelope; skipping");
            continue;
        }
        match rekey::store_share1(&did, &local) {
            Ok(()) => tracing::info!("backfilled Share 1 into the iCloud-synchronizable slot"),
            Err(e) => tracing::warn!(error = %e, "share1 backfill: synced slot write failed"),
        }
    }
}

/// The DIDs the backfill sweeps: every identity in `IdentityStore`, plus the legacy primary
/// DID under the `"did"` account. The union matters because a pre-unification install may hold
/// a share for a DID that was never registered in the managed-DIDs index.
fn share1_backfill_dids() -> Vec<String> {
    let mut dids = identity_store::IdentityStore
        .list_identities()
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "share1 backfill: managed-DID index unreadable");
            Vec::new()
        });
    if let Ok(bytes) = crate::keystore::get_item(LEGACY_DID_ACCOUNT) {
        if let Ok(did) = String::from_utf8(bytes) {
            if !did.is_empty() && !dids.contains(&did) {
                dids.push(did);
            }
        }
    }
    dids
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share_ceremony;

    // -- legacy global -> per-DID Share 1 migration --
    #[test]
    fn migrate_global_share1_copies_into_primary_per_did_slot() {
        crate::keystore::clear_for_test();
        let did = "did:plc:legacyprimary";

        // Pre-unification install: Share 1 in the global slot, primary DID under "did", and no
        // per-DID slot yet.
        crate::keystore::store_item("recovery-share-1", b"LEGACY1").unwrap();
        crate::keystore::store_item("did", did.as_bytes()).unwrap();

        migrate_global_share1_to_per_did();

        // The per-DID slot now mirrors the global one; the global slot is left intact.
        assert_eq!(
            crate::keystore::get_item(&rekey::recovery_share1_account(did)).unwrap(),
            b"LEGACY1"
        );
        assert_eq!(
            crate::keystore::get_item("recovery-share-1").unwrap(),
            b"LEGACY1"
        );
    }

    #[test]
    fn migrate_global_share1_never_clobbers_existing_per_did_slot() {
        crate::keystore::clear_for_test();
        let did = "did:plc:legacyprimary";

        // A per-DID slot already populated by a fresh ceremony/re-key must win over any stale
        // global slot left behind.
        crate::keystore::store_item("recovery-share-1", b"STALE_GLOBAL").unwrap();
        crate::keystore::store_item("did", did.as_bytes()).unwrap();
        crate::keystore::store_item(&rekey::recovery_share1_account(did), b"CURRENT_PER_DID")
            .unwrap();

        migrate_global_share1_to_per_did();

        assert_eq!(
            crate::keystore::get_item(&rekey::recovery_share1_account(did)).unwrap(),
            b"CURRENT_PER_DID"
        );
    }

    #[test]
    fn migrate_global_share1_noop_without_global_slot() {
        crate::keystore::clear_for_test();
        let did = "did:plc:freshinstall";
        crate::keystore::store_item("did", did.as_bytes()).unwrap();

        // Fresh (post-unification) install has no global slot: nothing is written.
        migrate_global_share1_to_per_did();

        assert!(matches!(
            crate::keystore::get_item(&rekey::recovery_share1_account(did)),
            Err(ref e) if crate::keystore::is_not_found(e)
        ));
    }

    // -- device-local -> iCloud-synchronizable Share 1 backfill --

    /// A real v2 index-1 Share 1 envelope, produced the way the ceremony produces one.
    /// The backfill only copies bytes that decode as such, so fixtures must be genuine.
    fn ceremony_share1() -> String {
        let set =
            share_ceremony::load_or_create("alice.example.com", "https://pds.example.com").unwrap();
        let share1 = set.share1.to_string();
        share_ceremony::clear_staging().unwrap();
        share1
    }

    #[test]
    fn backfill_copies_local_share1_into_the_synced_slot_and_keeps_the_local_one() {
        crate::keystore::clear_for_test();
        let did = "did:plc:preSyncInstall";
        let share1 = ceremony_share1();

        // A build from before the synchronizable write path: Share 1 exists, but only in the
        // device-local store, where it can never reach a replacement device.
        identity_store::IdentityStore.add_identity(did).unwrap();
        crate::keystore::store_item(&rekey::recovery_share1_account(did), share1.as_bytes())
            .unwrap();
        assert!(rekey::read_share1_synced(did).is_err());

        backfill_synced_share1();

        assert_eq!(rekey::read_share1_synced(did).unwrap(), share1.as_bytes());
        // Copy, never move: the local slot may be the share's only surviving copy.
        assert_eq!(
            crate::keystore::get_item(&rekey::recovery_share1_account(did)).unwrap(),
            share1.as_bytes()
        );

        // Idempotent: a second launch changes nothing.
        backfill_synced_share1();
        assert_eq!(rekey::read_share1_synced(did).unwrap(), share1.as_bytes());
    }

    #[test]
    fn backfill_never_overwrites_a_populated_synced_slot() {
        crate::keystore::clear_for_test();
        let did = "did:plc:alreadysynced";

        // A re-key or recovery epilogue owns the synchronizable slot; a stale local copy from
        // before that rotation must not be allowed to overwrite it.
        identity_store::IdentityStore.add_identity(did).unwrap();
        rekey::store_share1(did, ceremony_share1().as_bytes()).unwrap();
        let current = rekey::read_share1_synced(did).unwrap();
        crate::keystore::store_item(&rekey::recovery_share1_account(did), b"STALE_LOCAL").unwrap();

        backfill_synced_share1();

        assert_eq!(rekey::read_share1_synced(did).unwrap(), current);
    }

    #[test]
    fn backfill_skips_a_local_slot_that_is_not_a_v2_share1_envelope() {
        crate::keystore::clear_for_test();
        let did = "did:plc:bareshareinstall";

        // did:web ceremonies stored a bare base32 share, which the recovery ceremony's
        // auto-load cannot use anyway — syncing it would spend an iCloud secret for nothing.
        identity_store::IdentityStore.add_identity(did).unwrap();
        crate::keystore::store_item(&rekey::recovery_share1_account(did), b"NOTANENVELOPE")
            .unwrap();

        backfill_synced_share1();

        assert!(matches!(
            rekey::read_share1_synced(did),
            Err(ref e) if crate::keystore::is_not_found(e)
        ));
    }

    #[test]
    fn backfill_reaches_a_legacy_primary_did_absent_from_the_managed_index() {
        crate::keystore::clear_for_test();
        let did = "did:plc:legacyprimaryonly";
        let share1 = ceremony_share1();

        // Pre-unification install: the global slot plus a primary DID that was never
        // registered in `managed-dids`. One launch must carry it through both hops.
        crate::keystore::store_item("recovery-share-1", share1.as_bytes()).unwrap();
        crate::keystore::store_item("did", did.as_bytes()).unwrap();

        reconcile_share1_slots();

        assert_eq!(rekey::read_share1_synced(did).unwrap(), share1.as_bytes());
        // Neither source slot is disturbed.
        assert_eq!(
            crate::keystore::get_item("recovery-share-1").unwrap(),
            share1.as_bytes()
        );
        assert_eq!(
            crate::keystore::get_item(&rekey::recovery_share1_account(did)).unwrap(),
            share1.as_bytes()
        );
    }

    // -- created-identity reconciliation --

    #[test]
    fn reconcile_registers_a_created_identity_missing_from_the_managed_index() {
        crate::keystore::clear_for_test();
        let did = "did:plc:strandedcreate";

        // The state the reported bug leaves behind: the ceremony persisted the DID, but
        // `register_created_identity` never landed, so the home screen lists nothing.
        crate::keystore::store_item("did", did.as_bytes()).unwrap();
        assert!(identity_store::IdentityStore
            .list_identities()
            .unwrap()
            .is_empty());

        reconcile_created_identity();

        assert_eq!(
            identity_store::IdentityStore.list_identities().unwrap(),
            vec![did.to_string()]
        );
    }

    #[test]
    fn reconcile_never_resurrects_a_deliberately_forgotten_identity() {
        crate::keystore::clear_for_test();
        let did = "did:plc:forgottenonpurpose";

        // Forgetting an identity locally leaves the legacy "did" slot untouched, so the
        // tombstone is the only thing standing between the user's decision and a relaunch
        // putting the identity straight back on the home screen.
        crate::keystore::store_item("did", did.as_bytes()).unwrap();
        identity_store::IdentityStore.add_identity(did).unwrap();
        identity_store::IdentityStore.remove_identity(did).unwrap();

        reconcile_created_identity();

        assert!(identity_store::IdentityStore
            .list_identities()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn reconcile_is_idempotent_and_never_duplicates() {
        crate::keystore::clear_for_test();
        let did = "did:plc:idempotentreconcile";
        crate::keystore::store_item("did", did.as_bytes()).unwrap();

        reconcile_created_identity();
        reconcile_created_identity();

        assert_eq!(
            identity_store::IdentityStore.list_identities().unwrap(),
            vec![did.to_string()]
        );
    }

    #[test]
    fn reconcile_is_a_no_op_without_a_primary_did() {
        crate::keystore::clear_for_test();

        // A fresh install, or an import-only wallet: nothing to reconcile from.
        reconcile_created_identity();

        assert!(identity_store::IdentityStore
            .list_identities()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn reconcile_leaves_an_already_registered_identity_alone() {
        crate::keystore::clear_for_test();
        let did = "did:plc:alreadyregistered";
        crate::keystore::store_item("did", did.as_bytes()).unwrap();
        identity_store::IdentityStore.add_identity(did).unwrap();

        reconcile_created_identity();

        assert_eq!(
            identity_store::IdentityStore.list_identities().unwrap(),
            vec![did.to_string()]
        );
    }
}
