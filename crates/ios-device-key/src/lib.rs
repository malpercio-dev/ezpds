//! The operator console's per-device P-256 key, `#[cfg]`-dispatched between two compile-time
//! paths sharing one public API. A real iOS device uses the Secure Enclave via
//! `security-framework`: the private key never leaves the enclave, and only the compressed
//! public key and the SE-assigned `application_label` (a SHA-1) are stored in the Keychain
//! for lookup. Every other target — macOS, the iOS Simulator, and the Linux CI host — uses a
//! software key via the `crypto` crate, with the private scalar stored in the Keychain.
//!
//! The identity wallet's device keys are `obsign_core::signer`'s (that module doc says why);
//! nothing in the wallet depends on this crate.
//!
//! Public API: [`get_or_create`] (idempotent — every call returns the same key) and [`sign`]
//! (raw 64-byte `r||s` ECDSA). Signatures are **low-S normalized on both paths** —
//! ATProto/plc.directory requires low-S, and RFC 6979 (which makes the software path
//! deterministic) only fixes the nonce, so normalization is an explicit step, not a byproduct.
//!
//! # What the caller supplies
//!
//! The crate owns the key, not the Keychain. The app passes its own store as a
//! [`KeychainStore`] implementation and its own account names as [`DeviceKeyAccounts`] (the
//! console's key is the device's admin credential). Keeping the store behind a trait is also
//! what lets the app keep its own `#[cfg(test)]` in-memory Keychain — a `#[cfg(test)]` switch
//! inside this crate would not apply to a dependent crate's test build, and a Cargo feature
//! that did would ship an in-memory Keychain into a release build the day it leaked.

use std::fmt;

use serde::Serialize;

mod device_key;

pub use device_key::{get_or_create, sign};

/// The Keychain a [`get_or_create`] / [`sign`] call reads and writes.
///
/// Associated functions rather than methods: each app's Keychain is a module of free
/// functions over one process-wide store, so there is no instance to carry.
pub trait KeychainStore {
    /// The app's Keychain error type. Surfaced to the caller through
    /// [`DeviceKeyError::KeychainError`], so it must be renderable.
    type Error: fmt::Display;

    /// Read the bytes stored under `account`.
    fn get(account: &str) -> Result<Vec<u8>, Self::Error>;

    /// Write `data` under `account`, creating or replacing the entry.
    fn store(account: &str, data: &[u8]) -> Result<(), Self::Error>;

    /// Remove `account`.
    fn delete(account: &str) -> Result<(), Self::Error>;

    /// Whether `error` means the item genuinely does not exist, as opposed to a transient
    /// or permission failure.
    ///
    /// Load-bearing: [`get_or_create`] mints a key only on a true absence. Reporting a
    /// locked-Keychain or permission error as "not found" would orphan the device's real
    /// key and re-enrol it as a stranger.
    fn is_not_found(error: &Self::Error) -> bool;
}

/// The Keychain account names one app's device key occupies, and the label its Secure
/// Enclave key carries.
///
/// Changing any of them orphans existing keys. Const-constructible so each app pins its own
/// set as a single source of truth.
pub struct DeviceKeyAccounts {
    /// Software path only: the raw private scalar.
    pub private_scalar: &'static str,
    /// Secure Enclave path: the cached compressed public point, so the fast path needs no
    /// enclave round trip.
    pub public_key: &'static str,
    /// Secure Enclave path: the SE-assigned `application_label` the private key is found by.
    pub application_label: &'static str,
    /// Secure Enclave path: `kSecAttrLabel` on the generated key.
    pub secure_enclave_label: &'static str,
}

/// The key's public half, in the two encodings the frontend and the network need; shared
/// with the wallet's device keys through `crypto`, so the two apps encode one point alike.
pub use crypto::{make_device_public_key, DevicePublicKey};

/// Errors returned by device key operations.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE" }` — the IPC error shape both apps'
/// TypeScript `DeviceKeyError` unions mirror.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeviceKeyError {
    #[error("key generation failed")]
    KeyGenerationFailed,
    #[error("key not found; call get_or_create before sign")]
    KeyNotFound,
    #[error("signing failed")]
    SigningFailed,
    /// DER → r||s parse failed. Secure Enclave path only; the software path never
    /// DER-parses, but the variant stays in the serialized contract either way.
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("keychain error: {message}")]
    KeychainError { message: String },
}

/// Wrap any display-able error as [`DeviceKeyError::KeychainError`].
fn keychain_err(e: impl fmt::Display) -> DeviceKeyError {
    DeviceKeyError::KeychainError {
        message: e.to_string(),
    }
}
