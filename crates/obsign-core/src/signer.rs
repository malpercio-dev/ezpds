//! The device keys: the [`Signer`] trait a shell implements, and [`SoftwareSigner`], the
//! implementation for every target without hardware-bound keys.
//!
//! A key is addressed by a [`KeyId`]: one per managed identity, plus the app-global key the
//! create flow signs a genesis op with before its DID exists (see [`device_key`]). Every key
//! takes the same path through the one installed implementation, so the restore-liveness
//! probe a hardware signer runs (see `obsign-platform-ios`'s `enclave_signer`) covers the
//! global key too; the core never reaches a hardware key on its own. Which Keychain accounts
//! a key occupies is decided here, by [`KeyId::accounts`], so an implementation only differs
//! in where the private half lives.
//!
//! Getting a key's public half mints the key on first use; signing is two-phase, so a caller
//! can tell "this key does not exist here" (reported by [`Signer::signer`]) from "the key
//! refused to sign" (reported by the returned function).
//!
//! Installation follows [`keystore`](crate::keystore): the shell calls [`install`] once at
//! startup, every call fails with [`SignerError::NotInstalled`] until then, and the
//! `test-support` feature (or this crate's own tests) falls back to [`SoftwareSigner`] instead.
//! A device that silently fell back to a software key would mint keys that are not the ones
//! its DID documents name, so production never falls back.

use std::sync::OnceLock;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};

use crate::device_key;
use crate::identity_store::{
    device_key_account, device_key_app_label_account, device_key_pub_account,
};
use crate::keystore;

/// Which device key a [`Signer`] call addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyId<'a> {
    /// The app-global key. It signs a did:plc genesis op before the DID exists (a per-DID key
    /// cannot be namespaced in advance), so it is `rotationKeys[0]` of every identity the
    /// create flow minted.
    Global,
    /// A managed identity's own key, by DID.
    Identity(&'a str),
}

/// The Keychain accounts one key occupies. Frozen contract "Keychain account names"
/// (`docs/architecture/frozen-contracts.md`): the names are the app's, pinned in its shell.
#[derive(Debug)]
pub struct KeyAccounts {
    /// Software keys: the raw private scalar.
    pub private_scalar: String,
    /// Hardware keys: the cached compressed public point, so the fast path needs no hardware
    /// round trip.
    pub public_key: String,
    /// Hardware keys: the label the hardware assigned, which the private key is found by.
    pub application_label: String,
    /// Hardware keys: the label the generated key carries (`kSecAttrLabel` on iOS).
    pub hardware_label: String,
}

impl KeyId<'_> {
    /// The accounts this key is stored under.
    pub fn accounts(self) -> KeyAccounts {
        match self {
            KeyId::Global => KeyAccounts {
                private_scalar: device_key::DEVICE_KEY_PRIV_ACCOUNT.to_string(),
                public_key: device_key::DEVICE_KEY_PUB_ACCOUNT.to_string(),
                application_label: device_key::DEVICE_KEY_APP_LABEL_ACCOUNT.to_string(),
                hardware_label: device_key::DEVICE_KEY_HARDWARE_LABEL.to_string(),
            },
            KeyId::Identity(did) => KeyAccounts {
                private_scalar: device_key_account(did),
                public_key: device_key_pub_account(did),
                application_label: device_key_app_label_account(did),
                hardware_label: format!("ezpds-device-key-{did}"),
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// The key does not exist on this device.
    #[error("{message}")]
    NotFound { message: String },
    /// The key's metadata is present but the hardware no longer holds the key it names: the
    /// state a device restored from an encrypted backup lands in.
    #[error("device key is no longer usable on this device")]
    Unusable,
    #[error("key generation failed")]
    GenerationFailed,
    /// Storage refused a read or write. `message` is diagnostic only.
    #[error("{message}")]
    Storage { message: String },
    /// The stored key material does not decode as a P-256 key.
    #[error("{message}")]
    InvalidKey { message: String },
    /// The key refused to produce a signature.
    #[error("{message}")]
    Signing { message: String },
    /// The shell never called [`install`].
    #[error("no signer installed")]
    NotInstalled,
}

/// Signs one message with a device key: a raw 64-byte `r||s` ECDSA signature, low-S
/// normalized (plc.directory requires both).
pub type SignFn = Box<dyn FnOnce(&[u8]) -> Result<Vec<u8>, SignerError> + Send>;

/// The device-bound P-256 keys, one per [`KeyId`].
pub trait Signer: Send + Sync {
    /// The compressed SEC1 public point for `key`, minting it on first use.
    fn public_key(&self, key: KeyId<'_>) -> Result<Vec<u8>, SignerError>;

    /// Prepare to sign with the existing `key`. Never mints one.
    fn signer(&self, key: KeyId<'_>) -> Result<SignFn, SignerError>;

    /// Whether the private keys live in hardware they cannot leave (Secure Enclave,
    /// StrongBox), so the UI can say so truthfully.
    fn is_hardware_bound(&self) -> bool;
}

static INSTALLED: OnceLock<Box<dyn Signer>> = OnceLock::new();

/// Install the process-wide signer. The second and later calls are refused and hand the
/// signer back.
pub fn install(signer: Box<dyn Signer>) -> Result<(), Box<dyn Signer>> {
    INSTALLED.set(signer)
}

/// The installed signer.
pub fn signer() -> &'static dyn Signer {
    match INSTALLED.get() {
        Some(signer) => signer.as_ref(),
        None => &UNINSTALLED,
    }
}

#[cfg(not(any(test, feature = "test-support")))]
const UNINSTALLED: Uninstalled = Uninstalled;
#[cfg(any(test, feature = "test-support"))]
const UNINSTALLED: SoftwareSigner = SoftwareSigner;

#[cfg(not(any(test, feature = "test-support")))]
struct Uninstalled;

#[cfg(not(any(test, feature = "test-support")))]
impl Signer for Uninstalled {
    fn public_key(&self, _: KeyId<'_>) -> Result<Vec<u8>, SignerError> {
        Err(SignerError::NotInstalled)
    }
    fn signer(&self, _: KeyId<'_>) -> Result<SignFn, SignerError> {
        Err(SignerError::NotInstalled)
    }
    fn is_hardware_bound(&self) -> bool {
        false
    }
}

/// A software P-256 key per [`KeyId`], its private scalar stored in the installed
/// [`KeyStore`](crate::keystore::KeyStore) under the key's `private_scalar` account. Signs
/// with RFC 6979 deterministic ECDSA.
pub struct SoftwareSigner;

impl Signer for SoftwareSigner {
    fn public_key(&self, key: KeyId<'_>) -> Result<Vec<u8>, SignerError> {
        let account = key.accounts().private_scalar;

        let private_bytes = match keystore::get_item(&account) {
            Ok(bytes) => bytes,
            Err(e) if keystore::is_not_found(&e) => {
                let keypair = crypto::generate_p256_keypair().map_err(|e| {
                    tracing::error!(key = ?key, error = %e, "P-256 key generation failed");
                    SignerError::GenerationFailed
                })?;
                let bytes = keypair.private_key_bytes.to_vec();
                keystore::store_item(&account, &bytes).map_err(|e| SignerError::Storage {
                    message: e.to_string(),
                })?;
                bytes
            }
            Err(e) => {
                return Err(SignerError::Storage {
                    message: e.to_string(),
                })
            }
        };

        let signing_key = SigningKey::from_slice(&private_bytes).map_err(|e| {
            tracing::error!(key = ?key, error = %e, "stored device key bytes are not a valid P-256 scalar");
            SignerError::InvalidKey {
                message: "invalid stored key bytes".into(),
            }
        })?;
        Ok(signing_key
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec())
    }

    fn signer(&self, key: KeyId<'_>) -> Result<SignFn, SignerError> {
        // Zeroizing, so the raw scalar is scrubbed once `signing_key` is rebuilt from it.
        let account = key.accounts().private_scalar;
        let private_bytes = zeroize::Zeroizing::new(keystore::get_item(&account).map_err(|e| {
            if keystore::is_not_found(&e) {
                SignerError::NotFound {
                    message: "device key not found in Keychain".to_string(),
                }
            } else {
                SignerError::Storage {
                    message: format!("Keychain error: {e}"),
                }
            }
        })?);
        let signing_key =
            SigningKey::from_slice(&private_bytes).map_err(|_| SignerError::InvalidKey {
                message: "invalid P-256 private key in Keychain".to_string(),
            })?;

        Ok(Box::new(move |data: &[u8]| {
            let signature: Signature = signing_key.sign(data);
            let signature = signature.normalize_s();
            Ok(signature.to_bytes().to_vec())
        }))
    }

    fn is_hardware_bound(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;

    const DID: &str = "did:plc:signer0123456789abcdefgh";
    const KEY: KeyId<'static> = KeyId::Identity(DID);

    /// The routing the shell's pin test cannot see: each key reaches its own accounts, and
    /// the per-DID templates match the frozen contract.
    #[test]
    fn key_ids_route_to_their_own_accounts() {
        let global = KeyId::Global.accounts();
        assert_eq!(global.private_scalar, device_key::DEVICE_KEY_PRIV_ACCOUNT);
        assert_eq!(global.public_key, device_key::DEVICE_KEY_PUB_ACCOUNT);
        assert_eq!(
            global.application_label,
            device_key::DEVICE_KEY_APP_LABEL_ACCOUNT
        );
        assert_eq!(global.hardware_label, device_key::DEVICE_KEY_HARDWARE_LABEL);

        let per_did = KEY.accounts();
        assert_eq!(per_did.private_scalar, format!("{DID}:device-key"));
        assert_eq!(per_did.public_key, format!("{DID}:device-key-pub"));
        assert_eq!(
            per_did.application_label,
            format!("{DID}:device-key-app-label")
        );
        assert_eq!(per_did.hardware_label, format!("ezpds-device-key-{DID}"));
    }

    /// The global key is its own key, not an alias of any identity's.
    #[test]
    fn global_and_per_did_keys_are_distinct() {
        keystore::clear_for_test();
        let global = SoftwareSigner.public_key(KeyId::Global).unwrap();
        assert_eq!(global, SoftwareSigner.public_key(KeyId::Global).unwrap());
        assert_ne!(global, SoftwareSigner.public_key(KEY).unwrap());
        assert!(
            keystore::get_item(device_key::DEVICE_KEY_PRIV_ACCOUNT).is_ok(),
            "the global scalar lands under its frozen account"
        );
    }

    #[test]
    fn software_key_is_stable_and_verifies_low_s() {
        keystore::clear_for_test();
        let public = SoftwareSigner.public_key(KEY).unwrap();
        assert_eq!(public, SoftwareSigner.public_key(KEY).unwrap());

        let signature = (SoftwareSigner.signer(KEY).unwrap())(b"op").unwrap();
        let signature = Signature::from_slice(&signature).unwrap();
        assert!(
            signature.normalize_s() == signature,
            "signature must be low-S"
        );
        VerifyingKey::from_sec1_bytes(&public)
            .unwrap()
            .verify(b"op", &signature)
            .unwrap();
    }

    #[test]
    fn signing_never_mints_a_key() {
        keystore::clear_for_test();
        assert!(matches!(
            SoftwareSigner.signer(KEY),
            Err(SignerError::NotFound { .. })
        ));
    }
}
