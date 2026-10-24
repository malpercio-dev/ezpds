//! The Secure Enclave [`Signer`]: on a real iOS device, each identity's device key is an
//! enclave key that never leaves the hardware. The wallet installs [`EnclaveSigner`] there and
//! `obsign_core::signer::SoftwareSigner` everywhere else (macOS, the Simulator).
//!
//! The Keychain holds only metadata: the compressed public point (`{did}:device-key-pub`) and
//! the enclave-assigned application label (`{did}:device-key-app-label`) the key is found by.
//! Those items restore from an encrypted device backup; the enclave key never does. So
//! "metadata present" is not proof the key exists, and [`classify_se_fast_path`] decides what
//! the metadata reads plus a liveness probe mean. That decision is free of `cfg` and
//! Security.framework so it is unit-tested on every host.

use obsign_core::signer::SignerError;
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
use obsign_core::signer::{SignFn, Signer};

// ── Secure Enclave fast-path decision ──────────────────────────────────────────

/// Normalized outcome of one Keychain metadata read.
// Constructed only by the enclave branch (real iOS device) and by tests; the host build
// compiles it for those tests alone.
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
) -> Result<SeFastPath, SignerError> {
    match (pub_item, label_item) {
        (MetadataItem::Failed(message), _) | (_, MetadataItem::Failed(message)) => {
            Err(SignerError::Storage { message })
        }
        (MetadataItem::Present(compressed), MetadataItem::Present(app_label)) => {
            match enclave_holds(&app_label) {
                Ok(true) => Ok(SeFastPath::UseCached(compressed)),
                Ok(false) => Err(SignerError::Unusable),
                Err(message) => Err(SignerError::Storage { message }),
            }
        }
        _ => Ok(SeFastPath::Generate),
    }
}

// ── The enclave signer (real iOS device only) ──────────────────────────────────

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub use device::EnclaveSigner;

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
mod device {
    use super::*;
    use obsign_core::identity_store::{device_key_app_label_account, device_key_pub_account};
    use obsign_core::keystore;

    pub struct EnclaveSigner;

    /// Normalize a Keychain read into the `classify_se_fast_path` input.
    fn read_metadata(account: &str) -> MetadataItem {
        match keystore::get_item(account) {
            Ok(bytes) => MetadataItem::Present(bytes),
            Err(e) if keystore::is_not_found(&e) => MetadataItem::Absent,
            Err(e) => MetadataItem::Failed(e.to_string()),
        }
    }

    /// Ask the enclave whether it still holds the key `app_label` names — the same
    /// `ItemSearchOptions` lookup signing performs, minus the signature. `Ok(false)` means
    /// the query succeeded and found nothing.
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
            // A raw `security_framework` error here, not the `KeyStoreError` wrapper
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
    static ENCLAVE_PROBE_PASSED: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashSet<String>>,
    > = std::sync::OnceLock::new();

    fn enclave_probe_cached(did: &str) -> bool {
        ENCLAVE_PROBE_PASSED
            .get_or_init(Default::default)
            .lock()
            .map(|seen| seen.contains(did))
            .unwrap_or(false)
    }

    fn remember_enclave_probe(did: &str) {
        if let Ok(mut seen) = ENCLAVE_PROBE_PASSED.get_or_init(Default::default).lock() {
            seen.insert(did.to_string());
        }
    }

    impl Signer for EnclaveSigner {
        fn public_key(&self, did: &str) -> Result<Vec<u8>, SignerError> {
            use security_framework::{
                access_control::{ProtectionMode, SecAccessControl},
                item::Location,
                key::{GenerateKeyOptions, KeyType, SecKey, Token},
            };

            let pub_account = device_key_pub_account(did);
            let label_account = device_key_app_label_account(did);

            // Fast path: read both metadata accounts, then confirm the enclave still holds
            // the key the label names before reporting it (see the module doc).
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
                return Ok(compressed);
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
                SignerError::GenerationFailed
            })?;

            let mut opts = GenerateKeyOptions::default();
            opts.set_key_type(KeyType::ec())
                .set_size_in_bits(256)
                .set_token(Token::SecureEnclave)
                .set_label(format!("ezpds-device-key-{did}"))
                .set_location(Location::DataProtectionKeychain)
                .set_access_control(access_control); // takes ownership (by value)

            let priv_key = SecKey::new(&opts).map_err(|e| {
                tracing::error!(did = did, error = %e, "Secure Enclave key generation failed");
                SignerError::GenerationFailed
            })?;

            // SecKeyCopyExternalRepresentation on the *public* key returns the uncompressed
            // 65-byte X9.62 point (0x04 || x[32] || y[32]).
            let pub_key = priv_key.public_key().ok_or(SignerError::GenerationFailed)?;
            let pub_repr = pub_key
                .external_representation()
                .ok_or(SignerError::GenerationFailed)?;
            let uncompressed: Vec<u8> = pub_repr.to_vec(); // 65 bytes

            // Compress: prefix byte = 0x02 (even y) or 0x03 (odd y); keep x[32].
            let mut compressed = [0u8; 33];
            compressed[0] = if uncompressed[64] & 1 == 0 {
                0x02
            } else {
                0x03
            };
            compressed[1..].copy_from_slice(&uncompressed[1..33]);

            // Store the compressed public key for the fast path on future calls.
            keystore::store_item(&pub_account, &compressed).map_err(|e| SignerError::Storage {
                message: e.to_string(),
            })?;

            // Get and store application_label. Roll back pub_account if this fails.
            let app_label = priv_key.application_label().ok_or_else(|| {
                tracing::error!(
                    did = did,
                    "SE key created but application_label returned None"
                );
                let _ = keystore::delete_item(&pub_account);
                SignerError::Storage {
                    message: "SE key created but application_label returned None; do not retry"
                        .into(),
                }
            })?;
            keystore::store_item(&label_account, &app_label).map_err(|e| {
                let _ = keystore::delete_item(&pub_account);
                SignerError::Storage {
                    message: e.to_string(),
                }
            })?;

            // The key was just created in this process, so the fast path may trust it for
            // the rest of the launch without re-querying.
            remember_enclave_probe(did);

            Ok(compressed.to_vec())
        }

        fn signer(&self, did: &str) -> Result<SignFn, SignerError> {
            use p256::ecdsa::Signature;

            let app_label =
                keystore::get_item(&device_key_app_label_account(did)).map_err(|e| {
                    if keystore::is_not_found(&e) {
                        SignerError::NotFound {
                            message: "device key app label not found in Keychain".to_string(),
                        }
                    } else {
                        SignerError::Storage {
                            message: format!("Keychain error: {e}"),
                        }
                    }
                })?;

            Ok(Box::new(move |data: &[u8]| {
                use security_framework::item::{
                    ItemClass, ItemSearchOptions, Reference, SearchResult,
                };
                use security_framework::key::Algorithm;

                let signing = |message: String| SignerError::Signing { message };

                let query_results = ItemSearchOptions::new()
                    .class(ItemClass::key())
                    .application_label(&app_label)
                    .load_refs(true)
                    .search()
                    .map_err(|e| signing(format!("SE key lookup failed: {e}")))?;

                let sec_key = match query_results.into_iter().next() {
                    Some(SearchResult::Ref(Reference::Key(key))) => key,
                    _ => return Err(signing("SE key not found".into())),
                };

                let der_sig = sec_key
                    .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
                    .map_err(|e| signing(format!("SE signing failed: {e}")))?;

                let sig = Signature::from_der(&der_sig)
                    .map_err(|e| signing(format!("DER decode failed: {e}")))?;
                let sig = sig.normalize_s();
                Ok(sig.to_bytes().to_vec())
            }))
        }

        fn is_hardware_bound(&self) -> bool {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            matches!(result, Err(SignerError::Unusable)),
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

        assert!(matches!(result, Err(SignerError::Storage { .. })));
    }

    // A failed probe is not a verdict of absence either.
    #[test]
    fn se_fast_path_failed_probe_is_not_unusable() {
        let result = classify_se_fast_path(
            MetadataItem::Present(vec![0x02; 33]),
            MetadataItem::Present(b"app-label".to_vec()),
            |_| Err("SE key lookup failed".into()),
        );

        assert!(matches!(result, Err(SignerError::Storage { .. })));
    }
}
