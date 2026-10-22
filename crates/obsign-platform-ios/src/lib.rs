//! The iOS implementations of `obsign-core`'s platform traits (ADR-0039): the Keychain
//! [`KeyStore`](obsign_core::keystore::KeyStore), the Secure Enclave
//! [`Signer`](obsign_core::signer::Signer), the iCloud
//! [`BackupStore`](obsign_core::backup_store::BackupStore), and the `BGTaskScheduler`
//! [`Scheduler`](obsign_core::scheduler::Scheduler). The shell constructs and installs them.
//!
//! Apple-only, so the whole crate is empty elsewhere. Account names, the Keychain service, and
//! `BGTaskScheduler` identifiers are the app's, passed in: nothing here names an app.
#![cfg(target_vendor = "apple")]

pub mod enclave_signer;
pub mod icloud;
pub mod keychain;
#[cfg(target_os = "ios")]
pub mod scheduler;
