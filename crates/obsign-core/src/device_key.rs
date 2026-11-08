//! The wallet's global P-256 device key: [`KeyId::Global`] on the `Core`'s
//! [`Signer`](crate::signer::Signer), whose module doc owns why every key shares one
//! implementation. This module owns what makes the global key distinct: its frozen Keychain
//! account names, and the two convenience calls over the signer.
//!
//! The create flow signs its did:plc genesis op with this key, before any DID exists to
//! namespace a per-DID key under; `IdentityStore::adopt_global_device_key` then copies these
//! accounts into the per-DID slots so the identity's own key resolves to the one its DID
//! document names. [`get_or_create`] is idempotent (every call returns the same key, which is
//! what makes `create_account` retries safe: the PDS sees one device key per device) and
//! [`sign`] returns raw 64-byte `r||s` ECDSA, low-S normalized.
//!
//! Changing any account name orphans existing keys; the shell's `account_names_are_pinned`
//! test holds each one against a literal.

use crate::signer::{KeyId, Signer, SignerError};

// ── Global device-key Keychain account names ────────────────────────────────
//
// Software keys use only the private-scalar account; hardware keys use the pub + app-label
// metadata accounts (the private key never leaves the hardware).
pub const DEVICE_KEY_PRIV_ACCOUNT: &str = "device-rotation-key-priv";
pub const DEVICE_KEY_PUB_ACCOUNT: &str = "device-rotation-key-pub";
pub const DEVICE_KEY_APP_LABEL_ACCOUNT: &str = "device-rotation-key-app-label";
/// The label the generated hardware key carries (`kSecAttrLabel` on iOS).
pub const DEVICE_KEY_HARDWARE_LABEL: &str = "ezpds-device-rotation-key";

/// A device key's public half as the IPC reports it; `identity_store.rs` encodes per-DID keys
/// through the same function.
pub use crypto::{make_device_public_key, DevicePublicKey};

/// Return this device's global key, generating one on first call.
pub fn get_or_create(signer: &dyn Signer) -> Result<DevicePublicKey, SignerError> {
    let compressed = signer.public_key(KeyId::Global)?;
    Ok(make_device_public_key(&compressed))
}

/// Sign `data` with this device's global key, returning raw 64-byte `r||s`.
pub fn sign(signer: &dyn Signer, data: &[u8]) -> Result<Vec<u8>, SignerError> {
    (signer.signer(KeyId::Global)?)(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wiring this module owns: the global key reaches the signer, under these
    /// exact account names. Key generation and signing are covered by `signer`'s own tests.
    #[test]
    fn the_key_round_trips_through_the_signer() {
        let core = crate::test_support::core();

        let key = get_or_create(core.signer()).expect("get_or_create must succeed");
        assert!(key.key_id.starts_with("did:key:z"));
        assert_eq!(
            get_or_create(core.signer()).expect("second call").multibase,
            key.multibase,
            "the key must be idempotent across calls"
        );

        assert!(
            core.keys().get_item(DEVICE_KEY_PRIV_ACCOUNT).is_ok(),
            "the software path must store the scalar under the pinned account name"
        );

        core.keys()
            .delete_item(DEVICE_KEY_PRIV_ACCOUNT)
            .expect("delete");
        assert!(matches!(
            sign(core.signer(), b"no key"),
            Err(SignerError::NotFound { .. })
        ));
    }
}
