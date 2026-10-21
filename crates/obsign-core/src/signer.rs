//! Each managed identity's device key: the [`Signer`] trait a shell implements, and
//! [`SoftwareSigner`], the implementation for every target without hardware-bound keys.
//!
//! A key is addressed by its identity's DID. Getting its public half mints the key on first
//! use; signing is two-phase, so a caller can tell "this identity has no key here" (reported
//! by [`Signer::signer`]) from "the key refused to sign" (reported by the returned function).
//!
//! Installation follows [`keystore`](crate::keystore): the shell calls [`install`] once at
//! startup, every call fails with [`SignerError::NotInstalled`] until then, and the
//! `test-support` feature (or this crate's own tests) falls back to [`SoftwareSigner`] instead.
//! A device that silently fell back to a software key would mint keys that are not the ones
//! its DID documents name, so production never falls back.

use std::sync::OnceLock;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};

use crate::identity_store::device_key_account;
use crate::keystore;

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// The identity has no device key on this device.
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

/// Signs one message with an identity's device key: a raw 64-byte `r||s` ECDSA signature,
/// low-S normalized (plc.directory requires both).
pub type SignFn = Box<dyn FnOnce(&[u8]) -> Result<Vec<u8>, SignerError> + Send>;

/// Each managed identity's device-bound P-256 key.
pub trait Signer: Send + Sync {
    /// The compressed SEC1 public point for `did`'s key, minting the key on first use.
    fn public_key(&self, did: &str) -> Result<Vec<u8>, SignerError>;

    /// Prepare to sign with `did`'s existing key. Never mints one.
    fn signer(&self, did: &str) -> Result<SignFn, SignerError>;

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
    fn public_key(&self, _: &str) -> Result<Vec<u8>, SignerError> {
        Err(SignerError::NotInstalled)
    }
    fn signer(&self, _: &str) -> Result<SignFn, SignerError> {
        Err(SignerError::NotInstalled)
    }
    fn is_hardware_bound(&self) -> bool {
        false
    }
}

/// A software P-256 key per identity, its private scalar stored in the installed
/// [`KeyStore`](crate::keystore::KeyStore) under `{did}:device-key`. Signs with RFC 6979
/// deterministic ECDSA.
pub struct SoftwareSigner;

impl Signer for SoftwareSigner {
    fn public_key(&self, did: &str) -> Result<Vec<u8>, SignerError> {
        let account = device_key_account(did);

        let private_bytes = match keystore::get_item(&account) {
            Ok(bytes) => bytes,
            Err(e) if keystore::is_not_found(&e) => {
                let keypair = crypto::generate_p256_keypair().map_err(|e| {
                    tracing::error!(did = did, error = %e, "P-256 key generation failed");
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
            tracing::error!(did = did, error = %e, "stored device key bytes are not a valid P-256 scalar");
            SignerError::InvalidKey {
                message: "invalid stored key bytes".into(),
            }
        })?;
        Ok(signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec())
    }

    fn signer(&self, did: &str) -> Result<SignFn, SignerError> {
        // Zeroizing, so the raw scalar is scrubbed once `signing_key` is rebuilt from it.
        let private_bytes =
            zeroize::Zeroizing::new(keystore::get_item(&device_key_account(did)).map_err(|e| {
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
            let signature = signature.normalize_s().unwrap_or(signature);
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

    #[test]
    fn software_key_is_stable_and_verifies_low_s() {
        keystore::clear_for_test();
        let public = SoftwareSigner.public_key(DID).unwrap();
        assert_eq!(public, SoftwareSigner.public_key(DID).unwrap());

        let signature = (SoftwareSigner.signer(DID).unwrap())(b"op").unwrap();
        let signature = Signature::from_slice(&signature).unwrap();
        assert!(signature.normalize_s().is_none(), "signature must be low-S");
        VerifyingKey::from_sec1_bytes(&public)
            .unwrap()
            .verify(b"op", &signature)
            .unwrap();
    }

    #[test]
    fn signing_never_mints_a_key() {
        keystore::clear_for_test();
        assert!(matches!(
            SoftwareSigner.signer(DID),
            Err(SignerError::NotFound { .. })
        ));
    }
}
