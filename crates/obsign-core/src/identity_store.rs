// pattern: Imperative Shell

//! Per-DID identity storage layer with Keychain-based persistence.
//!
//! `IdentityStore` is a stateless unit struct — all state lives in the Keychain, and
//! methods take `&self`. A top-level `"managed-dids"` entry maintains a JSON array
//! index of all managed DIDs; per-DID entries use the `"{did}:suffix"` naming (device
//! keys, DID documents, PLC audit logs, sessions — the full account inventory is in
//! `keychain`'s module docs). Per-DID methods require the DID to be registered first
//! (`IdentityNotFound` otherwise); the index-level calls (`add_identity`,
//! `list_identities`) do not. [`IdentityStoreError`] serializes as
//! `{ code: "SCREAMING_SNAKE_CASE" }`.
//!
//! Device keys are lazily generated on first [`IdentityStore::get_or_create_device_key`]
//! — never at registration — with the same `#[cfg]` dispatch as `device_key.rs`
//! (software P-256 on macOS/simulator, Secure Enclave on a real device) but per-DID
//! account namespacing (`"{did}:device-key"` instead of `"device-rotation-key-priv"`).
//! On the Secure Enclave path the fast path **probes the enclave before trusting
//! cached metadata** ([`classify_se_fast_path`], kept `cfg`-free so it is host-tested):
//! the two metadata items restore from an encrypted device backup while the enclave key
//! never does, so "both items present" is exactly the state a restored device wakes up
//! in. A dead probe returns `DeviceKeyUnusable` and must NOT mint a replacement — a
//! fresh key is absent from the DID's `rotationKeys`, and recovery is the destination;
//! only positive probe verdicts are cached in-process.
//!
//! [`IdentityStore::adopt_global_device_key`] aliases the per-DID key to the global
//! `device_key.rs` key by copying its Keychain material — the create flow signs its
//! genesis op with the global key before the DID exists, and without adoption the
//! "root key" badge and `plc_monitor`'s signature checks would both be wrong.
//! [`IdentityStore::remove_identity`] records the `forgotten-dids` tombstone first
//! (fail-closed — the window where a DID is unmanaged but untombstoned must never open,
//! or launch reconciliation re-registers it), then removes the DID from `managed-dids`,
//! then best-effort deletes every per-DID entry — deliberately excluding both
//! `recovery-share-1:{did}` slots:
//! removal is also reached from `forget_identity_locally`, which promises only to
//! remove the identity from THIS device, and deleting the synchronizable slot would
//! reach every device under the Apple account and destroy a share the user may still
//! need.
//!
//! The free functions at the end are the IPC reads over the store (`list_identities`,
//! `get_stored_did_doc`, `get_device_key_id`, and `refresh_did_doc`, the cache self-heal).
//!
//! [`SovereignTokenRecord`] is the versioned full-access Bearer session stored in
//! `{did}:oauth-tokens` — written by `sovereign_session::sovereign_login`,
//! `password_unlock`, and the migration cutover, read by `session_provider`. That
//! shared shape is the contract: a change must keep all writers and the reader in step.
//!
//! All Keychain operations use the shared `keychain::SERVICE` prefix.

use crate::device_key::DevicePublicKey;
use crate::signer::SignerError;
use serde::{Deserialize, Serialize};

// ── Constants ──────────────────────────────────────────────────────────────────

pub const MANAGED_DIDS_ACCOUNT: &str = "managed-dids";

/// Index of DIDs the user has deliberately unregistered from *this* device.
///
/// Launch-time reconciliation re-registers an identity whose DID is still recorded in the
/// legacy `"did"` slot but is absent from [`MANAGED_DIDS_ACCOUNT`] — the state a create flow
/// leaves behind when its registration step fails. Nothing clears the legacy slot on removal,
/// so without a record of intent that reconciliation could not tell "never finished
/// registering" from "removed on purpose", and would resurrect a forgotten identity on the
/// next app open. This is that record.
///
/// Holds no secret — only DIDs, which are public identifiers — and stays device-local:
/// forgetting an identity here is a statement about this device, not about the Apple account.
pub const FORGOTTEN_DIDS_ACCOUNT: &str = "forgotten-dids";

// ── Error types ────────────────────────────────────────────────────────────────

/// Errors returned by `IdentityStore` operations.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE" }` — matches the
/// `CreateAccountError` and `DeviceKeyError` patterns.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityStoreError {
    #[error("identity not found")]
    IdentityNotFound,
    #[error("identity already exists")]
    IdentityAlreadyExists,
    #[error("keychain error: {message}")]
    KeychainError { message: String },
    #[error("key generation failed")]
    KeyGenerationFailed,
    #[error("serialization error: {message}")]
    SerializationError { message: String },
    /// The DID's device-key metadata is present but the key it names is gone from
    /// the Secure Enclave — the state a device restored from an encrypted backup
    /// lands in, since the metadata items restore and an enclave key never can.
    ///
    /// Reported instead of a public key (which would claim custody of a rotation
    /// key nothing can sign with) and instead of a freshly-minted key (which is
    /// absent from the DID's `rotationKeys`, so it would claim authority the DID
    /// document does not grant). Recovery is the honest destination: it mints a
    /// new enclave key and rotates it into `rotationKeys[0]`.
    #[error("device key is no longer usable on this device")]
    DeviceKeyUnusable,
    /// A delegation seed is already stored for this DID and differs from the one being
    /// written. Refused rather than overwritten: every child account's rotation key is
    /// derived from this seed, so replacing it would orphan every child the DID owns.
    /// Reached when shares from a superseded backup set are used to provision.
    #[error("a different delegation seed is already stored for this identity")]
    DelegationSeedConflict,
}

/// Versioned full-access Bearer session stored in a managed DID's `oauth-tokens` slot.
///
/// The hosting PDS travels with the credentials so a restored session cannot be
/// accidentally presented to another identity's host. Expiry values are copied
/// from the JWT payloads for launch-time/session-lifecycle decisions without
/// treating the unverified payload as authorization data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SovereignTokenRecord {
    pub version: u8,
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub pds_url: String,
    pub server_did: String,
    pub access_expires_at: Option<u64>,
    pub refresh_expires_at: Option<u64>,
    pub stored_at: u64,
}

impl SovereignTokenRecord {
    pub const VERSION: u8 = 1;
}

// ── Per-DID account name helpers ───────────────────────────────────────────────

/// Per-DID account holding the media-backup opt-in flag (`"true"` / `"false"`).
pub fn blob_backup_enabled_account(did: &str) -> String {
    format!("{did}:blob-backup-enabled")
}

/// Per-DID account holding the posts-backup opt-in flag (`"true"` / `"false"`).
pub fn repo_backup_enabled_account(did: &str) -> String {
    format!("{did}:repo-backup-enabled")
}

/// Per-DID account marking that this identity's recovery kit is self-held (see the wallet's
/// `self_held_kit`).
pub fn self_held_kit_account(did: &str) -> String {
    format!("{did}:self-held-kit")
}

/// Returns the Keychain account name for a DID's device key (private scalar).
pub fn device_key_account(did: &str) -> String {
    format!("{did}:device-key")
}

/// Returns the Keychain account name for a DID's device key public key.
pub fn device_key_pub_account(did: &str) -> String {
    format!("{did}:device-key-pub")
}

/// Returns the Keychain account name for a DID's device key SE app label.
pub fn device_key_app_label_account(did: &str) -> String {
    format!("{did}:device-key-app-label")
}

/// Returns the Keychain account name for a DID's DID document.
pub fn did_doc_account(did: &str) -> String {
    format!("{did}:did-doc")
}

/// Returns the Keychain account name for a DID's PLC audit log.
pub fn plc_log_account(did: &str) -> String {
    format!("{did}:plc-log")
}

/// Returns the Keychain account name for a DID's OAuth tokens.
pub fn oauth_tokens_account(did: &str) -> String {
    format!("{did}:oauth-tokens")
}

/// Returns the Keychain account name for a DID's self-controlled disaster-recovery
/// `atproto` signing key (raw P-256 scalar), enrolled by the sovereign
/// disaster-recovery flow so the wallet can mint service-auth JWTs offline.
pub fn recovery_signing_key_account(did: &str) -> String {
    format!("{did}:recovery-signing-key")
}

/// Returns the Keychain account name for a DID's delegation seed — the at-rest root
/// from which every child (agent) account's rotation key is HD-derived.
pub fn delegation_seed_account(did: &str) -> String {
    format!("{did}:delegation-seed")
}

/// Returns the Keychain account name for a DID's next child-account index.
pub fn child_index_account(did: &str) -> String {
    format!("{did}:child-index")
}

// ── IdentityStore ──────────────────────────────────────────────────────────────

/// Unit struct for multi-identity Keychain management.
///
/// All methods are stateless — the Keychain is globally accessible.
/// Methods take `&self` to allow future phases to hold `IdentityStore` in `AppState`.
pub struct IdentityStore;

impl IdentityStore {
    // ── Private helpers ────────────────────────────────────────────────────────

    /// Load the current list of managed DIDs from the Keychain.
    ///
    /// Returns an empty list if the entry doesn't exist.
    /// Returns `Err` if the entry exists but contains invalid JSON (data corruption).
    fn load_managed_dids(&self) -> Result<Vec<String>, IdentityStoreError> {
        match crate::keystore::get_item(MANAGED_DIDS_ACCOUNT) {
            Ok(bytes) => serde_json::from_slice::<Vec<String>>(&bytes).map_err(|e| {
                tracing::error!(error = %e, "managed-dids Keychain entry contains invalid JSON");
                IdentityStoreError::SerializationError {
                    message: format!("failed to deserialize managed-dids: {e}"),
                }
            }),
            Err(e) if crate::keystore::is_not_found(&e) => Ok(vec![]),
            Err(e) => Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            }),
        }
    }

    /// Save the managed DIDs list to the Keychain.
    fn save_managed_dids(&self, dids: &[String]) -> Result<(), IdentityStoreError> {
        let json =
            serde_json::to_vec(dids).map_err(|e| IdentityStoreError::SerializationError {
                message: format!("failed to serialize managed-dids: {e}"),
            })?;
        crate::keystore::store_item(MANAGED_DIDS_ACCOUNT, &json).map_err(|e| {
            IdentityStoreError::KeychainError {
                message: e.to_string(),
            }
        })
    }

    /// Check whether a DID is in the managed list.
    ///
    /// Returns `Err` if a Keychain error occurs (propagates transient failures).
    fn is_managed(&self, did: &str) -> Result<bool, IdentityStoreError> {
        let dids = self.load_managed_dids()?;
        Ok(dids.contains(&did.to_string()))
    }

    /// Load the tombstone index of deliberately-forgotten DIDs.
    ///
    /// Returns an empty list if the entry doesn't exist. Propagates read and parse failures
    /// rather than defaulting to empty: the only writer is [`Self::remove_identity`], and
    /// saving an empty list over an unreadable one would silently drop every other
    /// tombstone. Removal is retryable; a lost tombstone is not.
    fn load_forgotten_dids(&self) -> Result<Vec<String>, IdentityStoreError> {
        match crate::keystore::get_item(FORGOTTEN_DIDS_ACCOUNT) {
            Ok(bytes) => serde_json::from_slice::<Vec<String>>(&bytes).map_err(|e| {
                tracing::error!(error = %e, "forgotten-dids Keychain entry contains invalid JSON");
                IdentityStoreError::SerializationError {
                    message: format!("failed to deserialize forgotten-dids: {e}"),
                }
            }),
            Err(e) if crate::keystore::is_not_found(&e) => Ok(Vec::new()),
            Err(e) => Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            }),
        }
    }

    /// Save the tombstone index.
    fn save_forgotten_dids(&self, dids: &[String]) -> Result<(), IdentityStoreError> {
        let json =
            serde_json::to_vec(dids).map_err(|e| IdentityStoreError::SerializationError {
                message: format!("failed to serialize forgotten-dids: {e}"),
            })?;
        crate::keystore::store_item(FORGOTTEN_DIDS_ACCOUNT, &json).map_err(|e| {
            IdentityStoreError::KeychainError {
                message: e.to_string(),
            }
        })
    }

    /// Whether the user has deliberately unregistered this DID from this device.
    ///
    /// Consulted only by launch-time reconciliation. A DID that is currently managed is
    /// never affected by its tombstone — [`Self::add_identity`] clears one on re-registration.
    ///
    /// Fails safe: an unreadable index reports `true`, so a Keychain hiccup can never let
    /// reconciliation resurrect an identity the user removed on purpose. Withholding a
    /// re-registration is recoverable (the user can import the identity again); resurrecting
    /// one the user deliberately wiped from this device is not.
    pub fn is_forgotten(&self, did: &str) -> bool {
        match self.load_forgotten_dids() {
            Ok(dids) => dids.iter().any(|d| d == did),
            Err(e) => {
                tracing::warn!(did = did, error = %e, "forgotten-dids unreadable; treating DID as forgotten");
                true
            }
        }
    }

    // ── Public API ─────────────────────────────────────────────────────────────

    /// Register a new managed identity by DID.
    ///
    /// Appends the DID to the managed-dids index and saves it to the Keychain.
    /// Does NOT eagerly generate a device key — see [`Self::get_or_create_device_key`].
    ///
    /// Returns `Err(IdentityAlreadyExists)` if the DID is already registered.
    pub fn add_identity(&self, did: &str) -> Result<(), IdentityStoreError> {
        let mut dids = self.load_managed_dids()?;

        if dids.contains(&did.to_string()) {
            return Err(IdentityStoreError::IdentityAlreadyExists);
        }

        dids.push(did.to_string());
        self.save_managed_dids(&dids)?;

        // Registering an identity retracts any prior "forgotten on this device" statement.
        // Best-effort: a surviving tombstone cannot affect a managed DID (reconciliation
        // only ever considers DIDs absent from the managed index), so this is hygiene —
        // it keeps the index from growing without bound and from contradicting itself.
        self.clear_tombstone(did);

        Ok(())
    }

    /// Drop `did` from the tombstone index, if present. Never fails the caller.
    fn clear_tombstone(&self, did: &str) {
        let forgotten = match self.load_forgotten_dids() {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(did = did, error = %e, "could not read forgotten-dids to clear tombstone");
                return;
            }
        };
        if !forgotten.iter().any(|d| d == did) {
            return;
        }
        let remaining: Vec<String> = forgotten.into_iter().filter(|d| d != did).collect();
        if let Err(e) = self.save_forgotten_dids(&remaining) {
            tracing::warn!(did = did, error = %e, "could not clear tombstone for re-registered identity");
        }
    }

    /// Remove a managed identity and all associated Keychain entries.
    ///
    /// Updates the managed-dids index first, then performs best-effort deletion
    /// of all per-DID prefixed entries. Index-first ordering ensures that on
    /// partial failure the DID is unregistered (orphaned entries are benign)
    /// rather than registered-but-empty (confusing for callers).
    ///
    /// Returns `Err(IdentityNotFound)` if the DID is not in the managed list.
    pub fn remove_identity(&self, did: &str) -> Result<(), IdentityStoreError> {
        let mut dids = self.load_managed_dids()?;

        if !dids.contains(&did.to_string()) {
            return Err(IdentityStoreError::IdentityNotFound);
        }

        // Record the intent BEFORE touching the managed index, and fail closed if it cannot
        // be recorded. Nothing clears the legacy `"did"` slot, so a DID removed without a
        // tombstone is indistinguishable from one whose create flow never finished
        // registering — and launch-time reconciliation would put it straight back. Ordering
        // this first means the window where the DID is unmanaged and untombstoned never
        // opens; a tombstone left behind by a removal that then fails is inert, because a
        // still-managed DID is never a reconciliation candidate and re-registering clears it.
        let mut forgotten = self.load_forgotten_dids()?;
        if !forgotten.iter().any(|d| d == did) {
            forgotten.push(did.to_string());
            self.save_forgotten_dids(&forgotten)?;
        }

        // Remove DID from index — this is the authoritative state change.
        dids.retain(|d| d != did);
        self.save_managed_dids(&dids)?;

        // Best-effort cleanup of per-DID Keychain entries. Not-found errors are
        // expected (entry may never have been created). Transient OS errors are
        // logged but do not fail the operation — the DID is already unregistered.
        //
        // `recovery-share-1:{did}` is deliberately absent from this list, in both the
        // device-local and the iCloud-synchronizable store. Removal is reached from
        // `forget_identity_locally` too, which promises only to remove the identity from
        // THIS device — deleting the synchronizable slot would reach every device under the
        // Apple account and destroy a share the user may still need. A leftover share is one
        // of three; a share deleted from every device is unrecoverable.
        let entries = [
            device_key_account(did),
            device_key_pub_account(did),
            device_key_app_label_account(did),
            did_doc_account(did),
            plc_log_account(did),
            oauth_tokens_account(did),
            recovery_signing_key_account(did),
            delegation_seed_account(did),
            child_index_account(did),
            blob_backup_enabled_account(did),
            repo_backup_enabled_account(did),
            self_held_kit_account(did),
        ];

        for entry in entries {
            if let Err(e) = crate::keystore::delete_item(&entry) {
                if !crate::keystore::is_not_found(&e) {
                    tracing::warn!(did = did, entry = entry, error = %e, "transient Keychain error during identity cleanup");
                }
            }
        }

        Ok(())
    }

    /// List all managed identities.
    ///
    /// Returns the current list of registered DIDs.
    pub fn list_identities(&self) -> Result<Vec<String>, IdentityStoreError> {
        self.load_managed_dids()
    }

    /// Get or create a per-DID device key.
    ///
    /// On first call, generates a new P-256 keypair and stores the private key
    /// (or SE metadata on real iOS) in the Keychain. On subsequent calls, returns
    /// the same public key.
    ///
    /// Returns `Err(IdentityNotFound)` if the DID is not registered via [`Self::add_identity`].
    /// Returns `Err(KeyGenerationFailed)` if key generation fails.
    /// Returns `Err(KeychainError)` if Keychain operations fail.
    pub fn get_or_create_device_key(
        &self,
        did: &str,
    ) -> Result<DevicePublicKey, IdentityStoreError> {
        // Guard: DID must be managed.
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }

        get_or_create_per_did_device_key(did)
    }

    /// Adopt the app's global device key ([`crate::device_key`]) as this
    /// identity's per-DID device key, by copying its Keychain material into the
    /// per-DID accounts.
    ///
    /// The create flow signs its did:plc genesis op with the *global* device key
    /// (a did:plc is the hash of its own genesis op, so the rotation key must
    /// exist before the DID does — a per-DID key cannot be namespaced in
    /// advance). Without adoption, [`Self::get_or_create_device_key`] would
    /// lazily mint a *new* per-DID key that does not match the DID document's
    /// `rotationKeys[0]`, which would (a) render a misleading "Not root" badge in
    /// `IdentityListHome` and (b) make `plc_monitor` flag the user's own
    /// operations as unauthorized (it verifies audit-log signatures against the
    /// per-DID key).
    ///
    /// Copying is platform-agnostic and best-effort per account: the software
    /// path has a private-scalar account; the Secure Enclave path has pub +
    /// app-label metadata accounts (the SE private key itself never moves — the
    /// per-DID SE lookup finds the same hardware key via the copied app-label).
    /// Idempotent: re-running overwrites the per-DID accounts with identical bytes.
    ///
    /// Returns `Err(IdentityNotFound)` if the DID is not registered.
    pub fn adopt_global_device_key(&self, did: &str) -> Result<(), IdentityStoreError> {
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }

        // (global account, per-DID account) pairs. Only the accounts that exist
        // on the current platform are present: the software path has the private
        // scalar; the SE path has the pub key + app-label. The rest are absent.
        let mappings = [
            (
                crate::device_key::DEVICE_KEY_PRIV_ACCOUNT,
                device_key_account(did),
            ),
            (
                crate::device_key::DEVICE_KEY_PUB_ACCOUNT,
                device_key_pub_account(did),
            ),
            (
                crate::device_key::DEVICE_KEY_APP_LABEL_ACCOUNT,
                device_key_app_label_account(did),
            ),
        ];

        let mut copied = 0;
        for (global_account, per_did_account) in mappings {
            match crate::keystore::get_item(global_account) {
                Ok(bytes) => {
                    crate::keystore::store_item(&per_did_account, &bytes).map_err(|e| {
                        IdentityStoreError::KeychainError {
                            message: e.to_string(),
                        }
                    })?;
                    copied += 1;
                }
                // Account absent on this platform — expected; skip it.
                Err(e) if crate::keystore::is_not_found(&e) => {}
                Err(e) => {
                    return Err(IdentityStoreError::KeychainError {
                        message: e.to_string(),
                    })
                }
            }
        }

        if copied == 0 {
            // No global device key exists to adopt. Surface it rather than
            // silently letting a lazily-minted per-DID key diverge from the DID
            // document's rotationKeys[0].
            tracing::warn!(
                did = did,
                "adopt_global_device_key: no global device key material found to adopt"
            );
            return Err(IdentityStoreError::KeyGenerationFailed);
        }

        Ok(())
    }

    /// Store a DID document for a managed identity.
    ///
    /// The document is stored as opaque JSON bytes.
    ///
    /// Returns `Err(IdentityNotFound)` if the DID is not registered.
    pub fn store_did_doc(&self, did: &str, doc_json: &str) -> Result<(), IdentityStoreError> {
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }

        crate::keystore::store_item(&did_doc_account(did), doc_json.as_bytes()).map_err(|e| {
            IdentityStoreError::KeychainError {
                message: e.to_string(),
            }
        })
    }

    /// Retrieve a DID document for a managed identity.
    ///
    /// Returns `Ok(None)` if the document has not been stored.
    /// Returns `Err(IdentityNotFound)` if the DID is not registered.
    pub fn get_did_doc(&self, did: &str) -> Result<Option<String>, IdentityStoreError> {
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }

        match crate::keystore::get_item(&did_doc_account(did)) {
            Ok(bytes) => {
                let doc_json = String::from_utf8(bytes).map_err(|e| {
                    IdentityStoreError::SerializationError {
                        message: format!("UTF-8 error decoding DID document: {e}"),
                    }
                })?;
                Ok(Some(doc_json))
            }
            Err(e) if crate::keystore::is_not_found(&e) => Ok(None),
            Err(e) => Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            }),
        }
    }

    /// Store a PLC audit log for a managed identity.
    ///
    /// The log is stored as opaque JSON bytes.
    ///
    /// Returns `Err(IdentityNotFound)` if the DID is not registered.
    pub fn store_plc_log(&self, did: &str, log_json: &str) -> Result<(), IdentityStoreError> {
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }

        crate::keystore::store_item(&plc_log_account(did), log_json.as_bytes()).map_err(|e| {
            IdentityStoreError::KeychainError {
                message: e.to_string(),
            }
        })
    }

    /// Retrieve a PLC audit log for a managed identity.
    ///
    /// Returns `Ok(None)` if the log has not been stored.
    /// Returns `Err(IdentityNotFound)` if the DID is not registered.
    pub fn get_plc_log(&self, did: &str) -> Result<Option<String>, IdentityStoreError> {
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }

        match crate::keystore::get_item(&plc_log_account(did)) {
            Ok(bytes) => {
                let log_json = String::from_utf8(bytes).map_err(|e| {
                    IdentityStoreError::SerializationError {
                        message: format!("UTF-8 error decoding PLC log: {e}"),
                    }
                })?;
                Ok(Some(log_json))
            }
            Err(e) if crate::keystore::is_not_found(&e) => Ok(None),
            Err(e) => Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            }),
        }
    }

    /// Persist the DID's self-controlled disaster-recovery `atproto` signing key
    /// (raw P-256 scalar) with a read-back verify — the write convention for anything
    /// holding key material. This scalar is what mints the offline service-auth JWT
    /// once the corresponding did:key is enrolled as the DID's `atproto` verification
    /// method, so it must be durably in place *before* the enroll op is submitted.
    ///
    /// Returns `Err(IdentityNotFound)` if the DID is not registered.
    pub fn store_recovery_signing_key(
        &self,
        did: &str,
        scalar: &[u8; 32],
    ) -> Result<(), IdentityStoreError> {
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }
        let account = recovery_signing_key_account(did);
        crate::keystore::store_item(&account, scalar).map_err(|e| {
            IdentityStoreError::KeychainError {
                message: e.to_string(),
            }
        })?;
        // Read-back verify: the enroll op is only safe to submit once the key that
        // will sign the offline JWT is provably durable.
        let read_back =
            zeroize::Zeroizing::new(crate::keystore::get_item(&account).map_err(|e| {
                IdentityStoreError::KeychainError {
                    message: format!("read-back verify failed: {e}"),
                }
            })?);
        if read_back.as_slice() != scalar {
            return Err(IdentityStoreError::KeychainError {
                message: "read-back verify mismatch for recovery signing key".to_string(),
            });
        }
        Ok(())
    }

    /// Load the DID's disaster-recovery `atproto` signing key scalar, if enrolled.
    ///
    /// Returns `Err(IdentityNotFound)` if the DID is not registered.
    pub fn load_recovery_signing_key(
        &self,
        did: &str,
    ) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>, IdentityStoreError> {
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }
        match crate::keystore::get_item(&recovery_signing_key_account(did)) {
            Ok(bytes) => {
                let bytes = zeroize::Zeroizing::new(bytes);
                let scalar: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    IdentityStoreError::SerializationError {
                        message: format!(
                            "recovery signing key has {} bytes, expected 32",
                            bytes.len()
                        ),
                    }
                })?;
                Ok(Some(zeroize::Zeroizing::new(scalar)))
            }
            Err(e) if crate::keystore::is_not_found(&e) => Ok(None),
            Err(e) => Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            }),
        }
    }

    /// Persist the DID's delegation seed — the at-rest root from which every child
    /// (agent) account's rotation key is HD-derived — with a read-back verify.
    ///
    /// **Write-once.** A seed already stored under a *different* value is never
    /// overwritten (`DelegationSeedConflict`); rewriting it would orphan every child
    /// account already minted under the old one, since a child's rotation key is a pure
    /// function of this seed plus its index and nothing but this seed can re-derive it.
    /// Re-writing the identical value is a no-op, which is what makes provisioning
    /// idempotent across repeated share verifications. Note that the seed deliberately
    /// does NOT follow the account's recovery seed through a re-key or a recovery
    /// epilogue: those install a *new* recovery seed, and re-deriving from it would be
    /// exactly the orphaning this guard exists to prevent.
    ///
    /// Unlike [`Self::store_recovery_signing_key`] this does not require the DID to be
    /// registered: the create ceremony's only chance to write it is inside
    /// `perform_did_ceremony`, one command before `register_created_identity` runs.
    pub fn store_delegation_seed(
        &self,
        did: &str,
        seed: &[u8; 32],
    ) -> Result<(), IdentityStoreError> {
        if let Some(existing) = self.load_delegation_seed(did)? {
            return if existing.as_slice() == seed.as_slice() {
                Ok(())
            } else {
                Err(IdentityStoreError::DelegationSeedConflict)
            };
        }
        let account = delegation_seed_account(did);
        crate::keystore::store_item(&account, seed).map_err(|e| {
            IdentityStoreError::KeychainError {
                message: e.to_string(),
            }
        })?;
        // Read-back verify: a child minted against a seed that never reached the
        // Keychain would be unrecoverable on the next launch.
        let read_back =
            zeroize::Zeroizing::new(crate::keystore::get_item(&account).map_err(|e| {
                IdentityStoreError::KeychainError {
                    message: format!("read-back verify failed: {e}"),
                }
            })?);
        if read_back.as_slice() != seed.as_slice() {
            return Err(IdentityStoreError::KeychainError {
                message: "read-back verify mismatch for delegation seed".to_string(),
            });
        }
        Ok(())
    }

    /// Load the DID's delegation seed, if the identity has been provisioned for child
    /// (agent) accounts.
    pub fn load_delegation_seed(
        &self,
        did: &str,
    ) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>, IdentityStoreError> {
        match crate::keystore::get_item(&delegation_seed_account(did)) {
            Ok(bytes) => {
                let bytes = zeroize::Zeroizing::new(bytes);
                let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    IdentityStoreError::SerializationError {
                        message: format!("delegation seed has {} bytes, expected 32", bytes.len()),
                    }
                })?;
                Ok(Some(zeroize::Zeroizing::new(seed)))
            }
            Err(e) if crate::keystore::is_not_found(&e) => Ok(None),
            Err(e) => Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            }),
        }
    }

    /// Whether the DID is provisioned for child (agent) accounts.
    pub fn is_delegation_provisioned(&self, did: &str) -> Result<bool, IdentityStoreError> {
        Ok(self.load_delegation_seed(did)?.is_some())
    }

    /// The DID's next child-account index, or 0 when none has been minted.
    ///
    /// A local optimization only — the PDS child list is authoritative — so an absent
    /// or malformed slot reads as 0 rather than failing.
    pub fn load_child_index(&self, did: &str) -> Result<u32, IdentityStoreError> {
        match crate::keystore::get_item(&child_index_account(did)) {
            Ok(bytes) => Ok(bytes
                .as_slice()
                .try_into()
                .map(u32::from_be_bytes)
                .unwrap_or(0)),
            Err(e) if crate::keystore::is_not_found(&e) => Ok(0),
            Err(e) => Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            }),
        }
    }

    /// Record the DID's next child-account index.
    pub fn store_child_index(&self, did: &str, index: u32) -> Result<(), IdentityStoreError> {
        crate::keystore::store_item(&child_index_account(did), &index.to_be_bytes()).map_err(|e| {
            IdentityStoreError::KeychainError {
                message: e.to_string(),
            }
        })
    }

    /// Persist a full-access session in the selected DID's namespaced Keychain slot.
    pub fn store_oauth_tokens(
        &self,
        did: &str,
        record: &SovereignTokenRecord,
    ) -> Result<(), IdentityStoreError> {
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }
        if record.version != SovereignTokenRecord::VERSION {
            return Err(IdentityStoreError::SerializationError {
                message: format!("unsupported oauth token record version {}", record.version),
            });
        }
        let json =
            serde_json::to_vec(record).map_err(|e| IdentityStoreError::SerializationError {
                message: format!("failed to serialize oauth token record: {e}"),
            })?;
        crate::keystore::store_item(&oauth_tokens_account(did), &json).map_err(|e| {
            IdentityStoreError::KeychainError {
                message: e.to_string(),
            }
        })
    }

    /// Load the selected DID's full-access session, if one has been stored.
    pub fn load_oauth_tokens(
        &self,
        did: &str,
    ) -> Result<Option<SovereignTokenRecord>, IdentityStoreError> {
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }
        let bytes = match crate::keystore::get_item(&oauth_tokens_account(did)) {
            Ok(bytes) => bytes,
            Err(e) if crate::keystore::is_not_found(&e) => return Ok(None),
            Err(e) => {
                return Err(IdentityStoreError::KeychainError {
                    message: e.to_string(),
                })
            }
        };
        let record: SovereignTokenRecord =
            serde_json::from_slice(&bytes).map_err(|e| IdentityStoreError::SerializationError {
                message: format!("failed to deserialize oauth token record: {e}"),
            })?;
        if record.version != SovereignTokenRecord::VERSION {
            return Err(IdentityStoreError::SerializationError {
                message: format!("unsupported oauth token record version {}", record.version),
            });
        }
        Ok(Some(record))
    }

    /// Delete the selected DID's full-access session without removing the identity.
    pub fn delete_oauth_tokens(&self, did: &str) -> Result<(), IdentityStoreError> {
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }
        match crate::keystore::delete_item(&oauth_tokens_account(did)) {
            Ok(()) => Ok(()),
            Err(e) if crate::keystore::is_not_found(&e) => Ok(()),
            Err(e) => Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            }),
        }
    }
}

// ── Per-DID device key ──────────────────────────────────────────────────────────
//
// Each identity's device key is held by the installed `Signer` (Secure Enclave on a real
// device, software everywhere else; see `crate::signer`). These two functions are the only
// way the rest of the wallet reaches it.

impl From<SignerError> for IdentityStoreError {
    fn from(e: SignerError) -> Self {
        match e {
            SignerError::GenerationFailed => IdentityStoreError::KeyGenerationFailed,
            SignerError::Unusable => IdentityStoreError::DeviceKeyUnusable,
            SignerError::InvalidKey { message } => {
                IdentityStoreError::SerializationError { message }
            }
            other => IdentityStoreError::KeychainError {
                message: other.to_string(),
            },
        }
    }
}

fn get_or_create_per_did_device_key(did: &str) -> Result<DevicePublicKey, IdentityStoreError> {
    let compressed = crate::signer::signer().public_key(did)?;
    Ok(crate::device_key::make_device_public_key(&compressed))
}

/// Error from constructing a per-DID device-key signing closure.
///
/// Neutral to any one command's error enum so a single implementation can serve
/// both `recovery.rs` and `migrate.rs`; each caller translates this into its own
/// module error. The two variants preserve the only distinction the callers make:
/// a missing device key (a benign "identity not found") versus any other failure
/// while loading the key or preparing the signer (a genuine signing failure).
#[derive(Debug)]
pub enum PerDidSignError {
    /// The DID's device-key material is absent from the Keychain.
    DeviceKeyNotFound { message: String },
    /// Loading the key or preparing the signer failed for any other reason.
    SigningSetupFailed { message: String },
}

/// Build a signing closure over a managed identity's per-DID device key: a raw 64-byte
/// `r || s` ECDSA signature, low-S normalized (the encoding plc.directory requires).
///
/// Setup failures are reported here, signing failures by the closure, so a caller can map
/// a missing key and a refused signature to different errors.
pub fn per_did_sign_closure(
    did: &str,
) -> Result<impl FnOnce(&[u8]) -> Result<Vec<u8>, crypto::CryptoError>, PerDidSignError> {
    let sign = crate::signer::signer().signer(did).map_err(|e| match e {
        SignerError::NotFound { message } => PerDidSignError::DeviceKeyNotFound { message },
        other => PerDidSignError::SigningSetupFailed {
            message: other.to_string(),
        },
    })?;
    Ok(move |data: &[u8]| sign(data).map_err(|e| crypto::CryptoError::PlcOperation(e.to_string())))
}

// ── Tests ──────────────────────────────────────────────────────────────────────

// ── IPC reads over the store ────────────────────────────────────────────────

/// Return the list of managed DIDs currently stored in the Keychain.
///
/// Returns an empty list if no identities have been claimed. Returns an error only if
/// the Keychain entry exists but contains invalid data (data corruption).
///
/// The frontend calls this on mount to check for existing identities and decide whether
/// to skip the mode selector.
pub fn list_identities() -> Result<Vec<String>, IdentityStoreError> {
    IdentityStore.list_identities()
}

/// Retrieve the stored DID document for a claimed identity.
///
/// Returns the DID document as parsed JSON, or None if the DID is not registered or
/// the document has not been stored yet.
///
/// The frontend uses this to extract identity information (handle, PDS URL) for
/// multi-identity card display in IdentityListHome.
pub fn get_stored_did_doc(did: String) -> Result<Option<serde_json::Value>, IdentityStoreError> {
    let store = IdentityStore;
    match store.get_did_doc(&did)? {
        Some(json_str) => {
            let value: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| {
                IdentityStoreError::SerializationError {
                    message: e.to_string(),
                }
            })?;
            Ok(Some(value))
        }
        None => Ok(None),
    }
}

/// Errors from [`refresh_did_doc`], serialized as `{ code: "SCREAMING_SNAKE_CASE" }`
/// like every other IPC error enum so the frontend gets a branchable contract.
#[derive(Debug, serde::Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RefreshDidDocError {
    /// plc.directory fetch failed (network, 404, or parse).
    #[error("failed to fetch PLC data document: {message}")]
    FetchFailed { message: String },
    /// Serializing or persisting the refreshed document failed.
    #[error("failed to store DID document: {message}")]
    StorageFailed { message: String },
}

/// Re-fetch a claimed identity's PLC data document from plc.directory and re-store it
/// in the per-identity cache, returning the fresh document.
///
/// The cache self-heal: earlier builds cached the W3C DID document (or a doc with
/// empty `rotationKeys`) after claim/migration/recovery, which starves the home
/// card's custody badge and hides the migrate entry. `IdentityListHome` calls this
/// (best-effort) whenever a cached doc is missing or has no `rotationKeys`, so stale
/// caches repair on the next home load without user action.
pub async fn refresh_did_doc(
    state: &crate::oauth::Core,
    did: String,
) -> Result<serde_json::Value, RefreshDidDocError> {
    let did_doc = state
        .pds_client()
        .fetch_plc_data_document(&did)
        .await
        .map_err(|e| RefreshDidDocError::FetchFailed {
            message: e.to_string(),
        })?;
    let json = serde_json::to_string(&did_doc).map_err(|e| RefreshDidDocError::StorageFailed {
        message: format!("failed to serialize DID document: {e}"),
    })?;
    IdentityStore
        .store_did_doc(&did, &json)
        .map_err(|e| RefreshDidDocError::StorageFailed {
            message: e.to_string(),
        })?;
    Ok(did_doc)
}

/// Retrieve the device key ID (did:key URI) for a claimed identity.
///
/// Returns the device key's did:key URI, which can be compared against rotation keys
/// in the DID document to determine if the device key is the primary rotation key.
///
/// The frontend uses this in IdentityListHome to show rotation key status badges.
pub fn get_device_key_id(did: String) -> Result<String, IdentityStoreError> {
    let store = IdentityStore;
    let device_key = store.get_or_create_device_key(&did)?;
    Ok(device_key.key_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clear_managed_dids() {
        let _ = crate::keystore::delete_item(MANAGED_DIDS_ACCOUNT);
    }

    fn clear_per_did_entries(did: &str) {
        let _ = crate::keystore::delete_item(&device_key_account(did));
        let _ = crate::keystore::delete_item(&device_key_pub_account(did));
        let _ = crate::keystore::delete_item(&device_key_app_label_account(did));
        let _ = crate::keystore::delete_item(&did_doc_account(did));
        let _ = crate::keystore::delete_item(&plc_log_account(did));
        let _ = crate::keystore::delete_item(&oauth_tokens_account(did));
    }

    // adopt_global_device_key must make the per-DID device key resolve to the
    // same key the create flow's genesis op signed with (the global device key),
    // so the DID doc's rotationKeys[0] matches getDeviceKeyId ("Root key" badge
    // is honest) and PLC monitoring does not flag the user's own operations.
    #[test]
    fn adopt_global_device_key_aliases_per_did_key_to_global() {
        clear_managed_dids();
        let did = "did:plc:adoptglobal";
        clear_per_did_entries(did);
        let _ = crate::keystore::delete_item(crate::device_key::DEVICE_KEY_PRIV_ACCOUNT);

        // The global device key — what perform_did_ceremony uses as rotationKeys[0].
        let global = crate::device_key::get_or_create().expect("global device key");

        let store = IdentityStore;
        store.add_identity(did).expect("add_identity");
        store
            .adopt_global_device_key(did)
            .expect("adopt_global_device_key");

        let per_did = store
            .get_or_create_device_key(did)
            .expect("per-DID device key");
        assert_eq!(
            per_did.key_id, global.key_id,
            "per-DID device key must resolve to the global key after adoption"
        );
        assert_eq!(per_did.multibase, global.multibase);

        clear_per_did_entries(did);
        clear_managed_dids();
        let _ = crate::keystore::delete_item(crate::device_key::DEVICE_KEY_PRIV_ACCOUNT);
    }

    // ── Forgotten-DID tombstones ──────────────────────────────────────────────

    #[test]
    fn removing_an_identity_tombstones_it() {
        crate::keystore::clear_for_test();
        let store = IdentityStore;
        let did = "did:plc:tombstoned";

        assert!(!store.is_forgotten(did), "nothing is forgotten by default");
        store.add_identity(did).expect("add_identity");
        store.remove_identity(did).expect("remove_identity");

        assert!(store.is_forgotten(did));
    }

    #[test]
    fn re_registering_a_forgotten_identity_retracts_its_tombstone() {
        crate::keystore::clear_for_test();
        let store = IdentityStore;
        let did = "did:plc:forgottenthenreadded";

        store.add_identity(did).expect("add_identity");
        store.remove_identity(did).expect("remove_identity");
        assert!(store.is_forgotten(did));

        // Importing the identity again is a retraction of "not on this device". Leaving the
        // tombstone would blacklist the DID for good — a later stranded create for the same
        // identity could never be reconciled.
        store.add_identity(did).expect("re-add_identity");
        assert!(!store.is_forgotten(did));
    }

    #[test]
    fn a_tombstone_names_only_the_removed_identity() {
        crate::keystore::clear_for_test();
        let store = IdentityStore;

        store.add_identity("did:plc:goes").expect("add goes");
        store.add_identity("did:plc:stays").expect("add stays");
        store.remove_identity("did:plc:goes").expect("remove goes");

        assert!(store.is_forgotten("did:plc:goes"));
        assert!(!store.is_forgotten("did:plc:stays"));
    }

    #[test]
    fn an_unreadable_tombstone_index_reports_every_did_as_forgotten() {
        crate::keystore::clear_for_test();
        let store = IdentityStore;

        // Fail closed. Withholding a re-registration is recoverable — the user can import
        // the identity again — but resurrecting one they deliberately wiped from this device
        // is not, so corruption must never read as "safe to re-register".
        crate::keystore::store_item(FORGOTTEN_DIDS_ACCOUNT, b"{not json").unwrap();

        assert!(store.is_forgotten("did:plc:anything"));
    }

    #[test]
    fn removal_fails_closed_when_the_tombstone_cannot_be_recorded() {
        crate::keystore::clear_for_test();
        let store = IdentityStore;
        let did = "did:plc:tombstonewritefails";
        store.add_identity(did).expect("add_identity");

        // A corrupt tombstone index cannot be appended to without dropping the tombstones it
        // already holds. Removal must refuse rather than unregister the DID untombstoned —
        // that is exactly the state launch reconciliation would undo.
        crate::keystore::store_item(FORGOTTEN_DIDS_ACCOUNT, b"{not json").unwrap();

        assert!(store.remove_identity(did).is_err());
        assert_eq!(
            store.list_identities().expect("list_identities"),
            vec![did.to_string()],
            "the DID must still be managed after a refused removal"
        );
    }

    // ── Identity lifecycle (add / remove / list) ──────────────────────────────

    #[test]
    fn add_identity_and_list() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:test1").is_ok());
        let identities = store.list_identities().expect("list_identities failed");
        assert_eq!(identities, vec!["did:plc:test1"]);
    }

    #[test]
    fn list_multiple_identities() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:alice").is_ok());
        assert!(store.add_identity("did:plc:bob").is_ok());
        assert!(store.add_identity("did:plc:charlie").is_ok());

        let identities = store.list_identities().expect("list_identities failed");
        assert_eq!(
            identities,
            vec!["did:plc:alice", "did:plc:bob", "did:plc:charlie"]
        );
    }

    #[test]
    fn remove_identity_from_list() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:alice").is_ok());
        assert!(store.add_identity("did:plc:bob").is_ok());

        assert!(store.remove_identity("did:plc:alice").is_ok());

        let identities = store.list_identities().expect("list_identities failed");
        assert_eq!(identities, vec!["did:plc:bob"]);
    }

    #[test]
    fn add_identity_duplicate_fails() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:test1").is_ok());

        let result = store.add_identity("did:plc:test1");
        assert!(matches!(
            result,
            Err(IdentityStoreError::IdentityAlreadyExists)
        ));
    }

    #[test]
    fn remove_identity_not_found() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.remove_identity("did:plc:ghost");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    #[test]
    fn error_serialization() {
        // Verify that errors serialize as { "code": "SCREAMING_SNAKE_CASE" }
        let err1 = IdentityStoreError::IdentityNotFound;
        let json1 = serde_json::to_string(&err1).expect("serialization failed");
        assert!(json1.contains(r#""code":"IDENTITY_NOT_FOUND""#));

        let err2 = IdentityStoreError::IdentityAlreadyExists;
        let json2 = serde_json::to_string(&err2).expect("serialization failed");
        assert!(json2.contains(r#""code":"IDENTITY_ALREADY_EXISTS""#));

        let err3 = IdentityStoreError::KeyGenerationFailed;
        let json3 = serde_json::to_string(&err3).expect("serialization failed");
        assert!(json3.contains(r#""code":"KEY_GENERATION_FAILED""#));

        let err4 = IdentityStoreError::KeychainError {
            message: "test error".into(),
        };
        let json4 = serde_json::to_string(&err4).expect("serialization failed");
        assert!(json4.contains(r#""code":"KEYCHAIN_ERROR""#));

        let err5 = IdentityStoreError::SerializationError {
            message: "test error".into(),
        };
        let json5 = serde_json::to_string(&err5).expect("serialization failed");
        assert!(json5.contains(r#""code":"SERIALIZATION_ERROR""#));

        let err6 = IdentityStoreError::DeviceKeyUnusable;
        let json6 = serde_json::to_string(&err6).expect("serialization failed");
        assert!(json6.contains(r#""code":"DEVICE_KEY_UNUSABLE""#));
    }

    // ── Per-DID device key ─────────────────────────────────────────────────────

    #[test]
    fn get_or_create_device_key_success() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:test1").is_ok());
        clear_per_did_entries("did:plc:test1");

        let result = store.get_or_create_device_key("did:plc:test1");
        assert!(result.is_ok());

        let key = result.unwrap();
        assert!(key.multibase.starts_with('z'));
        assert!(key.key_id.starts_with("did:key:z"));

        // Validate multibase decoding to 33 bytes
        let (_, decoded) = multibase::decode(&key.multibase).expect("multibase decode failed");
        assert_eq!(
            decoded.len(),
            33,
            "compressed P-256 point should be 33 bytes"
        );
    }

    #[test]
    fn get_or_create_device_key_idempotent() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:test1").is_ok());
        clear_per_did_entries("did:plc:test1");

        let key1 = store
            .get_or_create_device_key("did:plc:test1")
            .expect("first call failed");
        let key2 = store
            .get_or_create_device_key("did:plc:test1")
            .expect("second call failed");

        assert_eq!(key1.multibase, key2.multibase);
        assert_eq!(key1.key_id, key2.key_id);
    }

    #[test]
    fn get_or_create_device_key_different_dids() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:alice").is_ok());
        assert!(store.add_identity("did:plc:bob").is_ok());
        clear_per_did_entries("did:plc:alice");
        clear_per_did_entries("did:plc:bob");

        let key_alice = store
            .get_or_create_device_key("did:plc:alice")
            .expect("alice key failed");
        let key_bob = store
            .get_or_create_device_key("did:plc:bob")
            .expect("bob key failed");

        assert_ne!(key_alice.multibase, key_bob.multibase);
        assert_ne!(key_alice.key_id, key_bob.key_id);
    }

    #[test]
    fn get_or_create_device_key_unregistered_did_fails() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.get_or_create_device_key("did:plc:unregistered");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    // ── Document and log persistence ───────────────────────────────────────────

    #[test]
    fn did_doc_round_trip() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;
        let did = "did:plc:test1";

        assert!(store.add_identity(did).is_ok());
        clear_per_did_entries(did);

        let doc = r#"{"id":"did:plc:test1","alsoKnownAs":["at://alice.test"]}"#;
        assert!(store.store_did_doc(did, doc).is_ok());

        let retrieved = store
            .get_did_doc(did)
            .expect("get_did_doc failed")
            .expect("document not found");
        assert_eq!(retrieved, doc);
    }

    #[test]
    fn plc_log_round_trip() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;
        let did = "did:plc:test1";

        assert!(store.add_identity(did).is_ok());
        clear_per_did_entries(did);

        let log = r#"[{"cid":"bafy...","operation":{}}]"#;
        assert!(store.store_plc_log(did, log).is_ok());

        let retrieved = store
            .get_plc_log(did)
            .expect("get_plc_log failed")
            .expect("log not found");
        assert_eq!(retrieved, log);
    }

    fn token_record(pds_url: &str) -> SovereignTokenRecord {
        SovereignTokenRecord {
            version: SovereignTokenRecord::VERSION,
            access_jwt: "access.jwt.value".into(),
            refresh_jwt: "refresh.jwt.value".into(),
            pds_url: pds_url.into(),
            server_did: "did:web:pds.example.com".into(),
            access_expires_at: Some(1_720_003_600),
            refresh_expires_at: Some(1_720_086_400),
            stored_at: 1_720_000_000,
        }
    }

    #[test]
    fn oauth_tokens_round_trip_and_delete() {
        crate::keystore::clear_for_test();
        let store = IdentityStore;
        let did = "did:plc:tokens";
        store.add_identity(did).unwrap();
        let expected = token_record("https://pds.example.com");

        store.store_oauth_tokens(did, &expected).unwrap();
        assert_eq!(store.load_oauth_tokens(did).unwrap(), Some(expected));

        store.delete_oauth_tokens(did).unwrap();
        assert_eq!(store.load_oauth_tokens(did).unwrap(), None);
    }

    #[test]
    fn oauth_tokens_are_isolated_per_did_and_never_use_legacy_accounts() {
        crate::keystore::clear_for_test();
        let store = IdentityStore;
        let alice = "did:plc:alice";
        let bob = "did:plc:bob";
        store.add_identity(alice).unwrap();
        store.add_identity(bob).unwrap();
        let alice_record = token_record("https://alice-pds.example.com");
        let bob_record = token_record("https://bob-pds.example.com");

        store.store_oauth_tokens(alice, &alice_record).unwrap();
        store.store_oauth_tokens(bob, &bob_record).unwrap();

        assert_eq!(store.load_oauth_tokens(alice).unwrap(), Some(alice_record));
        assert_eq!(store.load_oauth_tokens(bob).unwrap(), Some(bob_record));
        assert!(crate::keystore::get_item("oauth-access-token").is_err());
        assert!(crate::keystore::get_item("oauth-refresh-token").is_err());
    }

    #[test]
    fn oauth_tokens_reject_unknown_record_version() {
        crate::keystore::clear_for_test();
        let store = IdentityStore;
        let did = "did:plc:versioned";
        store.add_identity(did).unwrap();
        crate::keystore::store_item(
            &oauth_tokens_account(did),
            br#"{"version":2,"accessJwt":"a","refreshJwt":"r","pdsUrl":"https://pds.example.com","serverDid":"did:web:pds.example.com","accessExpiresAt":null,"refreshExpiresAt":null,"storedAt":1}"#,
        )
        .unwrap();

        assert!(matches!(
            store.load_oauth_tokens(did),
            Err(IdentityStoreError::SerializationError { .. })
        ));
    }

    #[test]
    fn remove_identity_deletes_oauth_tokens_record() {
        crate::keystore::clear_for_test();
        let store = IdentityStore;
        let did = "did:plc:removedtokens";
        store.add_identity(did).unwrap();
        store
            .store_oauth_tokens(did, &token_record("https://pds.example.com"))
            .unwrap();

        store.remove_identity(did).unwrap();
        assert!(crate::keystore::get_item(&oauth_tokens_account(did)).is_err());
    }

    #[test]
    fn get_did_doc_returns_none_if_not_stored() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;
        let did = "did:plc:test1";

        assert!(store.add_identity(did).is_ok());
        clear_per_did_entries(did);

        let retrieved = store.get_did_doc(did).expect("get_did_doc failed");
        assert!(retrieved.is_none());
    }

    #[test]
    fn get_plc_log_returns_none_if_not_stored() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;
        let did = "did:plc:test1";

        assert!(store.add_identity(did).is_ok());
        clear_per_did_entries(did);

        let retrieved = store.get_plc_log(did).expect("get_plc_log failed");
        assert!(retrieved.is_none());
    }

    #[test]
    fn store_did_doc_unregistered_did_fails() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.store_did_doc("did:plc:ghost", "{}");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    #[test]
    fn get_did_doc_unregistered_did_fails() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.get_did_doc("did:plc:ghost");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    #[test]
    fn store_plc_log_unregistered_did_fails() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.store_plc_log("did:plc:ghost", "[]");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    #[test]
    fn get_plc_log_unregistered_did_fails() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.get_plc_log("did:plc:ghost");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    #[test]
    fn remove_identity_cleans_up_all_entries() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;
        let did = "did:plc:test1";

        assert!(store.add_identity(did).is_ok());
        clear_per_did_entries(did);

        // Store some data and generate a device key.
        let doc = r#"{"id":"did:plc:test1"}"#;
        let log = r#"[]"#;
        assert!(store.store_did_doc(did, doc).is_ok());
        assert!(store.store_plc_log(did, log).is_ok());

        // Record the device key before removal so we can verify cleanup.
        let key_before = store
            .get_or_create_device_key(did)
            .expect("device key generation failed");

        // Remove the identity.
        assert!(store.remove_identity(did).is_ok());

        // Re-add the same DID and verify all entries are gone.
        assert!(store.add_identity(did).is_ok());
        assert!(store.get_did_doc(did).unwrap().is_none());
        assert!(store.get_plc_log(did).unwrap().is_none());

        // A new device key should be generated (different from the old one),
        // proving the old key material was cleaned up.
        let key_after = store
            .get_or_create_device_key(did)
            .expect("device key generation after re-add failed");
        assert_ne!(
            key_before.multibase, key_after.multibase,
            "device key should differ after remove + re-add"
        );
    }

    // ── Delegation seed + child index (agent child accounts) ───────────────────

    #[test]
    fn delegation_seed_round_trips_and_reports_provisioned() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;
        let did = "did:plc:delegation";

        assert!(!store.is_delegation_provisioned(did).unwrap());
        assert!(store.load_delegation_seed(did).unwrap().is_none());

        let seed = [0x5a_u8; 32];
        store.store_delegation_seed(did, &seed).unwrap();

        assert!(store.is_delegation_provisioned(did).unwrap());
        assert_eq!(
            store.load_delegation_seed(did).unwrap().unwrap().as_slice(),
            seed
        );
    }

    #[test]
    fn delegation_seed_is_write_once() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;
        let did = "did:plc:writeonce";

        store.store_delegation_seed(did, &[0x11_u8; 32]).unwrap();
        // Re-writing the same value is the idempotent case repeated provisioning hits.
        store.store_delegation_seed(did, &[0x11_u8; 32]).unwrap();
        // A different value would orphan every child derived from the stored one.
        assert!(matches!(
            store.store_delegation_seed(did, &[0x22_u8; 32]),
            Err(IdentityStoreError::DelegationSeedConflict)
        ));
        assert_eq!(
            store.load_delegation_seed(did).unwrap().unwrap().as_slice(),
            [0x11_u8; 32]
        );
    }

    #[test]
    fn child_index_defaults_to_zero_and_round_trips() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;
        let did = "did:plc:childindex";

        assert_eq!(store.load_child_index(did).unwrap(), 0);
        store.store_child_index(did, 7).unwrap();
        assert_eq!(store.load_child_index(did).unwrap(), 7);
    }

    #[test]
    fn remove_identity_deletes_delegation_seed_and_child_index() {
        crate::keystore::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;
        let did = "did:plc:delegationremoval";

        store.add_identity(did).unwrap();
        clear_per_did_entries(did);
        store.store_delegation_seed(did, &[0x33_u8; 32]).unwrap();
        store.store_child_index(did, 3).unwrap();

        store.remove_identity(did).unwrap();

        // Both slots are gone — proven by the write-once guard accepting a *different*
        // seed on re-add, which it could not do if the old one had survived.
        store.add_identity(did).unwrap();
        assert!(!store.is_delegation_provisioned(did).unwrap());
        assert_eq!(store.load_child_index(did).unwrap(), 0);
        store.store_delegation_seed(did, &[0x44_u8; 32]).unwrap();
    }
}
