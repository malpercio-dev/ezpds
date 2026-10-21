//! The four platform traits besides [`KeyStore`](crate::keystore::KeyStore).
//!
//! Each is declared ahead of the extraction step that wires it (the order lives in
//! `docs/implementation-plans/2026-10-21-obsign-core-extraction.md`); a signature may still
//! change in that PR, when its first real caller and implementation arrive.

use std::time::{Duration, SystemTime};

/// A platform call that failed. `message` is diagnostic only.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct PlatformError {
    pub message: String,
}

/// A device-bound P-256 key, addressed by the Keychain account that names it (the global
/// device key's, or an identity's `{did}:device-key`).
pub trait Signer: Send + Sync {
    /// The compressed SEC1 public point, minting the key on first use.
    fn public_key(&self, key: &str) -> Result<Vec<u8>, PlatformError>;

    /// A raw 64-byte `r||s` ECDSA signature, low-S normalized.
    fn sign(&self, key: &str, data: &[u8]) -> Result<Vec<u8>, PlatformError>;

    /// Whether the private key lives in hardware it cannot leave (Secure Enclave, StrongBox),
    /// so the UI can say so truthfully.
    fn is_hardware_bound(&self) -> bool;
}

/// Events from the core to the UI. Fire-and-forget: a UI that is not listening is not an
/// error the core can act on.
pub trait EventSink: Send + Sync {
    fn emit(&self, event: &str, payload: serde_json::Value);
}

/// The background work the core asks the platform to run. The core says what and how often;
/// the platform decides how (BGTaskScheduler, WorkManager).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BackgroundJob {
    /// Sweep every did:plc identity's PLC log.
    PlcCheck,
    /// Top up the user-held media and repo backups.
    BackupMirror,
}

pub trait Scheduler: Send + Sync {
    /// Ask for `job` to run no more often than `every`. Replaces any earlier request for it.
    fn schedule(&self, job: BackgroundJob, every: Duration) -> Result<(), PlatformError>;
}

/// Wall time, injected so ceremonies and the 72-hour PLC window are testable (and because
/// `SystemTime::now` panics on `wasm32-unknown-unknown`).
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}
