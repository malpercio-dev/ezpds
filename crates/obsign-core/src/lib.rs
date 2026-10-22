//! The Obsign wallet's platform-free core (ADR-0039).
//!
//! The core reaches the platform only through five traits, which a shell implements:
//! [`KeyStore`](keystore::KeyStore) here, and [`Signer`](platform::Signer),
//! [`EventSink`](platform::EventSink), [`Scheduler`](platform::Scheduler) and
//! [`Clock`](platform::Clock) in [`platform`]. Nothing in this crate names Tauri, carries a
//! `cfg(target_os)`, or depends on an Apple crate.
//!
//! The wallet's logic moves in from `apps/identity-wallet/src-tauri` one step at a time; the
//! order is `docs/implementation-plans/2026-10-21-obsign-core-extraction.md`.

pub mod diagnostics;
pub mod http;
pub mod keystore;
pub mod oauth_client;
pub mod pds_capabilities;
pub mod pds_client;
pub mod platform;
pub mod share_ceremony;
pub mod source_login;
