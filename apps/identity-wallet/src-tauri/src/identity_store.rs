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
//! [`SovereignTokenRecord`] is the versioned full-access Bearer session stored in
//! `{did}:oauth-tokens` — written by `sovereign_session::sovereign_login`,
//! `password_unlock`, and the migration cutover, read by `session_provider`. That
//! shared shape is the contract: a change must keep all writers and the reader in step.
//!
//! All Keychain operations use the shared `keychain::SERVICE` prefix.

use crate::device_key::DevicePublicKey;
use serde::{Deserialize, Serialize};

// ── Constants ──────────────────────────────────────────────────────────────────

const MANAGED_DIDS_ACCOUNT: &str = "managed-dids";

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
const FORGOTTEN_DIDS_ACCOUNT: &str = "forgotten-dids";

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

/// Returns the Keychain account name for a DID's device key (private scalar).
fn device_key_account(did: &str) -> String {
    format!("{did}:device-key")
}

/// Returns the Keychain account name for a DID's device key public key.
fn device_key_pub_account(did: &str) -> String {
    format!("{did}:device-key-pub")
}

/// Returns the Keychain account name for a DID's device key SE app label.
fn device_key_app_label_account(did: &str) -> String {
    format!("{did}:device-key-app-label")
}

/// Returns the Keychain account name for a DID's DID document.
fn did_doc_account(did: &str) -> String {
    format!("{did}:did-doc")
}

/// Returns the Keychain account name for a DID's PLC audit log.
fn plc_log_account(did: &str) -> String {
    format!("{did}:plc-log")
}

/// Returns the Keychain account name for a DID's OAuth tokens.
fn oauth_tokens_account(did: &str) -> String {
    format!("{did}:oauth-tokens")
}

/// Returns the Keychain account name for a DID's self-controlled disaster-recovery
/// `atproto` signing key (raw P-256 scalar), enrolled by the sovereign
/// disaster-recovery flow so the wallet can mint service-auth JWTs offline.
fn recovery_signing_key_account(did: &str) -> String {
    format!("{did}:recovery-signing-key")
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
        match crate::keychain::get_item(MANAGED_DIDS_ACCOUNT) {
            Ok(bytes) => serde_json::from_slice::<Vec<String>>(&bytes).map_err(|e| {
                tracing::error!(error = %e, "managed-dids Keychain entry contains invalid JSON");
                IdentityStoreError::SerializationError {
                    message: format!("failed to deserialize managed-dids: {e}"),
                }
            }),
            Err(e) if crate::keychain::is_not_found(&e) => Ok(vec![]),
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
        crate::keychain::store_item(MANAGED_DIDS_ACCOUNT, &json).map_err(|e| {
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
        match crate::keychain::get_item(FORGOTTEN_DIDS_ACCOUNT) {
            Ok(bytes) => serde_json::from_slice::<Vec<String>>(&bytes).map_err(|e| {
                tracing::error!(error = %e, "forgotten-dids Keychain entry contains invalid JSON");
                IdentityStoreError::SerializationError {
                    message: format!("failed to deserialize forgotten-dids: {e}"),
                }
            }),
            Err(e) if crate::keychain::is_not_found(&e) => Ok(Vec::new()),
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
        crate::keychain::store_item(FORGOTTEN_DIDS_ACCOUNT, &json).map_err(|e| {
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
            crate::blob_backup::backup_enabled_account(did),
            crate::repo_backup::backup_enabled_account(did),
            crate::self_held_kit::self_held_kit_account(did),
        ];

        for entry in entries {
            if let Err(e) = crate::keychain::delete_item(&entry) {
                if !crate::keychain::is_not_found(&e) {
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
            match crate::keychain::get_item(global_account) {
                Ok(bytes) => {
                    crate::keychain::store_item(&per_did_account, &bytes).map_err(|e| {
                        IdentityStoreError::KeychainError {
                            message: e.to_string(),
                        }
                    })?;
                    copied += 1;
                }
                // Account absent on this platform — expected; skip it.
                Err(e) if crate::keychain::is_not_found(&e) => {}
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

        crate::keychain::store_item(&did_doc_account(did), doc_json.as_bytes()).map_err(|e| {
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

        match crate::keychain::get_item(&did_doc_account(did)) {
            Ok(bytes) => {
                let doc_json = String::from_utf8(bytes).map_err(|e| {
                    IdentityStoreError::SerializationError {
                        message: format!("UTF-8 error decoding DID document: {e}"),
                    }
                })?;
                Ok(Some(doc_json))
            }
            Err(e) if crate::keychain::is_not_found(&e) => Ok(None),
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

        crate::keychain::store_item(&plc_log_account(did), log_json.as_bytes()).map_err(|e| {
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

        match crate::keychain::get_item(&plc_log_account(did)) {
            Ok(bytes) => {
                let log_json = String::from_utf8(bytes).map_err(|e| {
                    IdentityStoreError::SerializationError {
                        message: format!("UTF-8 error decoding PLC log: {e}"),
                    }
                })?;
                Ok(Some(log_json))
            }
            Err(e) if crate::keychain::is_not_found(&e) => Ok(None),
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
        crate::keychain::store_item(&account, scalar).map_err(|e| {
            IdentityStoreError::KeychainError {
                message: e.to_string(),
            }
        })?;
        // Read-back verify: the enroll op is only safe to submit once the key that
        // will sign the offline JWT is provably durable.
        let read_back =
            zeroize::Zeroizing::new(crate::keychain::get_item(&account).map_err(|e| {
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
        match crate::keychain::get_item(&recovery_signing_key_account(did)) {
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
            Err(e) if crate::keychain::is_not_found(&e) => Ok(None),
            Err(e) => Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            }),
        }
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
        crate::keychain::store_item(&oauth_tokens_account(did), &json).map_err(|e| {
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
        let bytes = match crate::keychain::get_item(&oauth_tokens_account(did)) {
            Ok(bytes) => bytes,
            Err(e) if crate::keychain::is_not_found(&e) => return Ok(None),
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
        match crate::keychain::delete_item(&oauth_tokens_account(did)) {
            Ok(()) => Ok(()),
            Err(e) if crate::keychain::is_not_found(&e) => Ok(()),
            Err(e) => Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            }),
        }
    }
}

// ── Secure Enclave fast-path decision ──────────────────────────────────────────
//
// The enclave branch below only compiles for a real iOS device, so its decision
// logic is factored out here — free of `cfg`, Keychain, and `security-framework`
// — and unit-tested on the host. The branch supplies the effects (two Keychain
// reads and the enclave lookup); this decides what they mean.

/// Normalized outcome of one Keychain metadata read.
// Constructed only by the Secure-Enclave branch (real iOS device) and by tests;
// the host build compiles it for those tests alone.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum MetadataItem {
    Present(Vec<u8>),
    Absent,
    /// A transient OS failure — distinct from `Absent`, which would otherwise
    /// license overwriting live key material.
    Failed(String),
}

/// What the Secure Enclave fast path should do after reading its metadata.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SeFastPath {
    /// Metadata present and the enclave still holds the key it names.
    UseCached(Vec<u8>),
    /// No usable metadata — mint a fresh enclave key.
    Generate,
}

/// Decide the fast path from the two metadata reads and an enclave liveness probe.
///
/// `enclave_holds` is called only when both metadata items are present, and only
/// then does its verdict matter — the probe is a Keychain query rather than a
/// signing operation, so it costs no biometric prompt.
///
/// A partially-present pair (one item without the other) cannot sign either, but
/// it is not the restore scenario (a restore brings both back together): it is a
/// half-finished generation, whose other half this same function is about to
/// write. Generating is the existing behavior and the correct one.
#[allow(dead_code)]
pub(crate) fn classify_se_fast_path(
    pub_item: MetadataItem,
    label_item: MetadataItem,
    enclave_holds: impl FnOnce(&[u8]) -> Result<bool, String>,
) -> Result<SeFastPath, IdentityStoreError> {
    match (pub_item, label_item) {
        (MetadataItem::Failed(message), _) | (_, MetadataItem::Failed(message)) => {
            Err(IdentityStoreError::KeychainError { message })
        }
        (MetadataItem::Present(compressed), MetadataItem::Present(app_label)) => {
            match enclave_holds(&app_label) {
                Ok(true) => Ok(SeFastPath::UseCached(compressed)),
                Ok(false) => Err(IdentityStoreError::DeviceKeyUnusable),
                Err(message) => Err(IdentityStoreError::KeychainError { message }),
            }
        }
        _ => Ok(SeFastPath::Generate),
    }
}

// ── Per-DID device key implementation ──────────────────────────────────────────

#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
fn get_or_create_per_did_device_key(did: &str) -> Result<DevicePublicKey, IdentityStoreError> {
    use p256::ecdsa::SigningKey;

    let account = device_key_account(did);

    // Try to load existing private key bytes from Keychain.
    let private_bytes: Vec<u8> = match crate::keychain::get_item(&account) {
        Ok(bytes) => bytes,
        Err(e) if crate::keychain::is_not_found(&e) => {
            // No key yet — generate a new P-256 keypair via the crypto crate.
            let keypair = crypto::generate_p256_keypair().map_err(|e| {
                tracing::error!(did = did, error = %e, "P-256 key generation failed");
                IdentityStoreError::KeyGenerationFailed
            })?;
            // to_vec(): Deref gives &[u8; 32], coerces to &[u8], allocates into Vec<u8>.
            let bytes = keypair.private_key_bytes.to_vec();
            crate::keychain::store_item(&account, &bytes).map_err(|e| {
                IdentityStoreError::KeychainError {
                    message: e.to_string(),
                }
            })?;
            bytes
        }
        Err(e) => {
            return Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            })
        }
    };

    // Reconstruct the public key from stored private bytes.
    let signing_key =
        SigningKey::from_slice(&private_bytes).map_err(|e| {
            tracing::error!(did = did, error = %e, "stored device key bytes are not a valid P-256 scalar");
            IdentityStoreError::SerializationError {
                message: "invalid stored key bytes".into(),
            }
        })?;
    let encoded = signing_key.verifying_key().to_encoded_point(true); // compressed (33 bytes)
    let compressed = encoded.as_bytes();

    Ok(crate::device_key::make_device_public_key(compressed))
}

/// Normalize a Keychain read into the `classify_se_fast_path` input.
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
fn read_metadata(account: &str) -> MetadataItem {
    match crate::keychain::get_item(account) {
        Ok(bytes) => MetadataItem::Present(bytes),
        Err(e) if crate::keychain::is_not_found(&e) => MetadataItem::Absent,
        Err(e) => MetadataItem::Failed(e.to_string()),
    }
}

/// Ask the enclave whether it still holds the key `app_label` names — the same
/// `ItemSearchOptions` lookup `per_did_sign_closure` performs at signing time,
/// minus the signature. `Ok(false)` means the query succeeded and found nothing.
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
fn enclave_holds_key(app_label: &[u8]) -> Result<bool, String> {
    use security_framework::item::{ItemClass, ItemSearchOptions, Reference, SearchResult};

    match ItemSearchOptions::new()
        .class(ItemClass::key())
        .application_label(app_label)
        .load_refs(true)
        .search()
    {
        Ok(results) => Ok(matches!(
            results.into_iter().next(),
            Some(SearchResult::Ref(Reference::Key(_)))
        )),
        // A raw `security_framework` error here, not the `KeychainError` wrapper
        // `is_not_found` takes — this queries the Security framework directly.
        Err(e) if e.code() == crate::keychain::ERR_SEC_ITEM_NOT_FOUND => Ok(false),
        Err(e) => Err(format!("SE key lookup failed: {e}")),
    }
}

/// DIDs whose enclave key has been confirmed present this launch.
///
/// Only *positive* verdicts are cached. A cached negative would outlive the
/// recovery ceremony that mints a fresh enclave key in the same session, leaving
/// the wallet insisting it cannot sign with a key it just created.
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
static ENCLAVE_PROBE_PASSED: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashSet<String>>,
> = std::sync::OnceLock::new();

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
fn enclave_probe_cached(did: &str) -> bool {
    ENCLAVE_PROBE_PASSED
        .get_or_init(Default::default)
        .lock()
        .map(|seen| seen.contains(did))
        .unwrap_or(false)
}

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
fn remember_enclave_probe(did: &str) {
    if let Ok(mut seen) = ENCLAVE_PROBE_PASSED.get_or_init(Default::default).lock() {
        seen.insert(did.to_string());
    }
}

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
fn get_or_create_per_did_device_key(did: &str) -> Result<DevicePublicKey, IdentityStoreError> {
    use security_framework::{
        access_control::{ProtectionMode, SecAccessControl},
        item::Location,
        key::{GenerateKeyOptions, KeyType, SecKey, Token},
    };

    let pub_account = device_key_pub_account(did);
    let label_account = device_key_app_label_account(did);

    // Fast path: read both metadata accounts, then confirm the enclave still holds
    // the key the label names before reporting it. The metadata items are ordinary
    // generic-password entries and restore from an encrypted device backup; the
    // enclave key does not and never will, so "metadata present" is not proof of
    // key existence — it is exactly the state a restored device wakes up in.
    let verdict = classify_se_fast_path(
        read_metadata(&pub_account),
        read_metadata(&label_account),
        |app_label| {
            if enclave_probe_cached(did) {
                return Ok(true);
            }
            let holds = enclave_holds_key(app_label)?;
            if holds {
                remember_enclave_probe(did);
            }
            Ok(holds)
        },
    )?;

    if let SeFastPath::UseCached(compressed) = verdict {
        return Ok(crate::device_key::make_device_public_key(&compressed));
    }

    // Generate a new SE-backed P-256 key.
    // set_location(DataProtectionKeychain) is required — without it, security_framework sets
    // kSecAttrIsPermanent = false, meaning the key is not persisted to the Keychain and will
    // not survive app restart.
    // set_access_control with PRIVATE_KEY_USAGE is required for SE keys — the SE enforces
    // that only explicitly-authorized operations can use the private key for signing.
    // The PRIVATE_KEY_USAGE flag is kSecAccessControlPrivateKeyUsage = 1 << 30.
    let access_control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        1 << 30, // kSecAccessControlPrivateKeyUsage
    )
    .map_err(|e| {
        tracing::error!(did = did, error = %e, "SecAccessControl creation failed");
        IdentityStoreError::KeyGenerationFailed
    })?;

    let mut opts = GenerateKeyOptions::default();
    opts.set_key_type(KeyType::ec())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_label(&format!("ezpds-device-key-{did}"))
        .set_location(Location::DataProtectionKeychain)
        .set_access_control(access_control); // takes ownership (by value)

    let priv_key = SecKey::new(&opts).map_err(|e| {
        tracing::error!(did = did, error = %e, "Secure Enclave key generation failed");
        IdentityStoreError::KeyGenerationFailed
    })?;

    // Retrieve the public key and its external representation.
    // SecKeyCopyExternalRepresentation on the *public* key returns the uncompressed
    // 65-byte X9.62 point (0x04 || x[32] || y[32]).
    let pub_key = priv_key
        .public_key()
        .ok_or(IdentityStoreError::KeyGenerationFailed)?;
    let pub_repr = pub_key
        .external_representation()
        .ok_or(IdentityStoreError::KeyGenerationFailed)?;
    let uncompressed: Vec<u8> = pub_repr.to_vec(); // 65 bytes

    // Compress: prefix byte = 0x02 (even y) or 0x03 (odd y); keep x[32].
    // The last byte of the y coordinate determines parity.
    let mut compressed = [0u8; 33];
    compressed[0] = if uncompressed[64] & 1 == 0 {
        0x02
    } else {
        0x03
    };
    compressed[1..].copy_from_slice(&uncompressed[1..33]);

    // Store the compressed public key for the fast path on future calls.
    crate::keychain::store_item(&pub_account, &compressed).map_err(|e| {
        IdentityStoreError::KeychainError {
            message: e.to_string(),
        }
    })?;

    // Get and store application_label. Roll back pub_account if this fails.
    let app_label = priv_key.application_label().ok_or_else(|| {
        tracing::error!(
            did = did,
            "SE key created but application_label returned None"
        );
        let _ = crate::keychain::delete_item(&pub_account);
        IdentityStoreError::KeychainError {
            message: "SE key created but application_label returned None; do not retry".into(),
        }
    })?;
    crate::keychain::store_item(&label_account, &app_label).map_err(|e| {
        let _ = crate::keychain::delete_item(&pub_account);
        IdentityStoreError::KeychainError {
            message: e.to_string(),
        }
    })?;

    // The key was just created in this process, so the fast path may trust it for
    // the rest of the launch without re-querying.
    remember_enclave_probe(did);

    Ok(crate::device_key::make_device_public_key(&compressed))
}

// ── Per-DID device-key signing closure ─────────────────────────────────────────
//
// The read-side counterpart to `get_or_create_per_did_device_key`: it builds a
// closure that signs CBOR bytes with a managed identity's device key. Both
// `recovery.rs` and `migrate.rs` self-sign PLC operations with this key, so the
// signing primitive lives here (the single owner of per-DID Keychain material)
// rather than being copy-pasted into each command module.

/// Error from constructing a per-DID device-key signing closure.
///
/// Neutral to any one command's error enum so a single implementation can serve
/// both `recovery.rs` and `migrate.rs`; each caller translates this into its own
/// module error. The two variants preserve the only distinction the callers make:
/// a missing device key (a benign "identity not found") versus any other failure
/// while loading the key or preparing the signer (a genuine signing failure).
#[derive(Debug)]
pub(crate) enum PerDidSignError {
    /// The DID's device-key material is absent from the Keychain.
    DeviceKeyNotFound { message: String },
    /// Loading the key or preparing the signer failed for any other reason.
    SigningSetupFailed { message: String },
}

/// Build a signing closure over a managed identity's per-DID device key.
///
/// Software path (macOS / iOS simulator): reads the raw P-256 private scalar from
/// the Keychain and returns a closure that signs with RFC 6979 deterministic
/// ECDSA, low-S normalized. The signature is a raw 64-byte `r || s` — the encoding
/// plc.directory requires.
#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
pub(crate) fn per_did_sign_closure(
    did: &str,
) -> Result<impl FnOnce(&[u8]) -> Result<Vec<u8>, crypto::CryptoError>, PerDidSignError> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    let account = device_key_account(did);
    // Hold the raw P-256 scalar in a Zeroizing buffer so it is scrubbed from the
    // heap the moment `signing_key` has been reconstructed from it.
    let private_bytes =
        zeroize::Zeroizing::new(crate::keychain::get_item(&account).map_err(|e| {
            if crate::keychain::is_not_found(&e) {
                PerDidSignError::DeviceKeyNotFound {
                    message: "device key not found in Keychain".to_string(),
                }
            } else {
                PerDidSignError::SigningSetupFailed {
                    message: format!("Keychain error: {e}"),
                }
            }
        })?);

    let signing_key = SigningKey::from_slice(&private_bytes).map_err(|_| {
        PerDidSignError::SigningSetupFailed {
            message: "invalid P-256 private key in Keychain".to_string(),
        }
    })?;

    Ok(move |data: &[u8]| -> Result<Vec<u8>, crypto::CryptoError> {
        let signature: Signature = signing_key.sign(data);
        let signature = signature.normalize_s().unwrap_or(signature);
        Ok(signature.to_bytes().to_vec())
    })
}

/// Build a signing closure over a managed identity's per-DID device key.
///
/// Secure Enclave path (real iOS device): looks up the SE key by its stored app
/// label and returns a closure that signs via the Secure Enclave. The signature is
/// decoded from DER and returned as a raw 64-byte `r || s`, low-S normalized.
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub(crate) fn per_did_sign_closure(
    did: &str,
) -> Result<impl FnOnce(&[u8]) -> Result<Vec<u8>, crypto::CryptoError>, PerDidSignError> {
    use p256::ecdsa::Signature;

    let app_label_account = device_key_app_label_account(did);
    let app_label = crate::keychain::get_item(&app_label_account).map_err(|e| {
        if crate::keychain::is_not_found(&e) {
            PerDidSignError::DeviceKeyNotFound {
                message: "device key app label not found in Keychain".to_string(),
            }
        } else {
            PerDidSignError::SigningSetupFailed {
                message: format!("Keychain error: {e}"),
            }
        }
    })?;

    Ok(move |data: &[u8]| -> Result<Vec<u8>, crypto::CryptoError> {
        use security_framework::item::{ItemClass, ItemSearchOptions, Reference, SearchResult};
        use security_framework::key::Algorithm;

        let query_results = ItemSearchOptions::new()
            .class(ItemClass::key())
            .application_label(&app_label)
            .load_refs(true)
            .search()
            .map_err(|e| crypto::CryptoError::PlcOperation(format!("SE key lookup failed: {e}")))?;

        let sec_key = match query_results.into_iter().next() {
            Some(SearchResult::Ref(Reference::Key(key))) => key,
            _ => return Err(crypto::CryptoError::PlcOperation("SE key not found".into())),
        };

        let der_sig = sec_key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
            .map_err(|e| crypto::CryptoError::PlcOperation(format!("SE signing failed: {e}")))?;

        let sig = Signature::from_der(&der_sig)
            .map_err(|e| crypto::CryptoError::PlcOperation(format!("DER decode failed: {e}")))?;
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().to_vec())
    })
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn clear_managed_dids() {
        let _ = crate::keychain::delete_item(MANAGED_DIDS_ACCOUNT);
    }

    fn clear_per_did_entries(did: &str) {
        let _ = crate::keychain::delete_item(&device_key_account(did));
        let _ = crate::keychain::delete_item(&device_key_pub_account(did));
        let _ = crate::keychain::delete_item(&device_key_app_label_account(did));
        let _ = crate::keychain::delete_item(&did_doc_account(did));
        let _ = crate::keychain::delete_item(&plc_log_account(did));
        let _ = crate::keychain::delete_item(&oauth_tokens_account(did));
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
        let _ = crate::keychain::delete_item(crate::device_key::DEVICE_KEY_PRIV_ACCOUNT);

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
        let _ = crate::keychain::delete_item(crate::device_key::DEVICE_KEY_PRIV_ACCOUNT);
    }

    // ── Forgotten-DID tombstones ──────────────────────────────────────────────

    #[test]
    fn removing_an_identity_tombstones_it() {
        crate::keychain::clear_for_test();
        let store = IdentityStore;
        let did = "did:plc:tombstoned";

        assert!(!store.is_forgotten(did), "nothing is forgotten by default");
        store.add_identity(did).expect("add_identity");
        store.remove_identity(did).expect("remove_identity");

        assert!(store.is_forgotten(did));
    }

    #[test]
    fn re_registering_a_forgotten_identity_retracts_its_tombstone() {
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
        let store = IdentityStore;

        store.add_identity("did:plc:goes").expect("add goes");
        store.add_identity("did:plc:stays").expect("add stays");
        store.remove_identity("did:plc:goes").expect("remove goes");

        assert!(store.is_forgotten("did:plc:goes"));
        assert!(!store.is_forgotten("did:plc:stays"));
    }

    #[test]
    fn an_unreadable_tombstone_index_reports_every_did_as_forgotten() {
        crate::keychain::clear_for_test();
        let store = IdentityStore;

        // Fail closed. Withholding a re-registration is recoverable — the user can import
        // the identity again — but resurrecting one they deliberately wiped from this device
        // is not, so corruption must never read as "safe to re-register".
        crate::keychain::store_item(FORGOTTEN_DIDS_ACCOUNT, b"{not json").unwrap();

        assert!(store.is_forgotten("did:plc:anything"));
    }

    #[test]
    fn removal_fails_closed_when_the_tombstone_cannot_be_recorded() {
        crate::keychain::clear_for_test();
        let store = IdentityStore;
        let did = "did:plc:tombstonewritefails";
        store.add_identity(did).expect("add_identity");

        // A corrupt tombstone index cannot be appended to without dropping the tombstones it
        // already holds. Removal must refuse rather than unregister the DID untombstoned —
        // that is exactly the state launch reconciliation would undo.
        crate::keychain::store_item(FORGOTTEN_DIDS_ACCOUNT, b"{not json").unwrap();

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
        crate::keychain::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:test1").is_ok());
        let identities = store.list_identities().expect("list_identities failed");
        assert_eq!(identities, vec!["did:plc:test1"]);
    }

    #[test]
    fn list_multiple_identities() {
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
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

    // ── Secure Enclave fast-path decision ─────────────────────────────────────
    //
    // The enclave branch itself compiles only for a real iOS device; these cover
    // the decision it delegates here, on every host.

    // The restore case: an encrypted-backup restore brings both metadata items
    // back while leaving the enclave key behind. Reporting the cached public key
    // would claim custody of rotationKeys[0] that no signature can back, and
    // minting a fresh key would claim authority the DID document never granted.
    #[test]
    fn se_fast_path_metadata_present_but_enclave_empty_is_unusable() {
        let result = classify_se_fast_path(
            MetadataItem::Present(vec![0x02; 33]),
            MetadataItem::Present(b"app-label".to_vec()),
            |_| Ok(false),
        );

        assert!(
            matches!(result, Err(IdentityStoreError::DeviceKeyUnusable)),
            "expected DeviceKeyUnusable, got {result:?}"
        );
    }

    #[test]
    fn se_fast_path_returns_cached_key_when_enclave_resolves() {
        let result = classify_se_fast_path(
            MetadataItem::Present(vec![0x03; 33]),
            MetadataItem::Present(b"app-label".to_vec()),
            |label| {
                assert_eq!(label, b"app-label");
                Ok(true)
            },
        );

        assert_eq!(result.unwrap(), SeFastPath::UseCached(vec![0x03; 33]));
    }

    // No metadata means no key was ever generated for this DID — nothing to
    // probe, and nothing a fresh key could contradict.
    #[test]
    fn se_fast_path_generates_when_metadata_absent() {
        let result = classify_se_fast_path(MetadataItem::Absent, MetadataItem::Absent, |_| {
            panic!("enclave must not be probed when there is no label to probe with")
        });

        assert_eq!(result.unwrap(), SeFastPath::Generate);
    }

    // Half-written metadata is an interrupted generation, not a restore; the
    // pair always returns together from a backup.
    #[test]
    fn se_fast_path_generates_when_metadata_is_partial() {
        let result = classify_se_fast_path(
            MetadataItem::Present(vec![0x02; 33]),
            MetadataItem::Absent,
            |_| panic!("enclave must not be probed without a label"),
        );

        assert_eq!(result.unwrap(), SeFastPath::Generate);
    }

    // A transient OS failure must never be read as "absent" — that would license
    // overwriting a key that is merely temporarily unreadable.
    #[test]
    fn se_fast_path_surfaces_keychain_failure_instead_of_generating() {
        let result = classify_se_fast_path(
            MetadataItem::Failed("errSecInteractionNotAllowed".into()),
            MetadataItem::Present(b"app-label".to_vec()),
            |_| panic!("enclave must not be probed after a failed metadata read"),
        );

        assert!(matches!(
            result,
            Err(IdentityStoreError::KeychainError { .. })
        ));
    }

    // A failed probe is not a verdict of absence either.
    #[test]
    fn se_fast_path_failed_probe_is_not_unusable() {
        let result = classify_se_fast_path(
            MetadataItem::Present(vec![0x02; 33]),
            MetadataItem::Present(b"app-label".to_vec()),
            |_| Err("SE key lookup failed".into()),
        );

        assert!(matches!(
            result,
            Err(IdentityStoreError::KeychainError { .. })
        ));
    }

    // ── Per-DID device key ─────────────────────────────────────────────────────

    #[test]
    fn get_or_create_device_key_success() {
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.get_or_create_device_key("did:plc:unregistered");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    // ── Document and log persistence ───────────────────────────────────────────

    #[test]
    fn did_doc_round_trip() {
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
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
        assert!(crate::keychain::get_item("oauth-access-token").is_err());
        assert!(crate::keychain::get_item("oauth-refresh-token").is_err());
    }

    #[test]
    fn oauth_tokens_reject_unknown_record_version() {
        crate::keychain::clear_for_test();
        let store = IdentityStore;
        let did = "did:plc:versioned";
        store.add_identity(did).unwrap();
        crate::keychain::store_item(
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
        crate::keychain::clear_for_test();
        let store = IdentityStore;
        let did = "did:plc:removedtokens";
        store.add_identity(did).unwrap();
        store
            .store_oauth_tokens(did, &token_record("https://pds.example.com"))
            .unwrap();

        store.remove_identity(did).unwrap();
        assert!(crate::keychain::get_item(&oauth_tokens_account(did)).is_err());
    }

    #[test]
    fn get_did_doc_returns_none_if_not_stored() {
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.store_did_doc("did:plc:ghost", "{}");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    #[test]
    fn get_did_doc_unregistered_did_fails() {
        crate::keychain::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.get_did_doc("did:plc:ghost");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    #[test]
    fn store_plc_log_unregistered_did_fails() {
        crate::keychain::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.store_plc_log("did:plc:ghost", "[]");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    #[test]
    fn get_plc_log_unregistered_did_fails() {
        crate::keychain::clear_for_test();
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.get_plc_log("did:plc:ghost");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    #[test]
    fn remove_identity_cleans_up_all_entries() {
        crate::keychain::clear_for_test();
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
}
