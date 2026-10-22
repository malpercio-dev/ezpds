//! The Obsign wallet's platform-free core (ADR-0039).
//!
//! The core reaches the platform only through traits a shell implements:
//! [`KeyStore`](keystore::KeyStore), [`Signer`](signer::Signer),
//! [`EventSink`](events::EventSink), [`BackupStore`](backup_store::BackupStore),
//! [`Scheduler`](scheduler::Scheduler) and [`Clock`](platform::Clock). Nothing in this crate names Tauri, carries a
//! `cfg(target_os)`, or depends on an Apple crate.
//!
//! The wallet's logic moves in from `apps/identity-wallet/src-tauri` one step at a time; the
//! order is `docs/implementation-plans/2026-10-21-obsign-core-extraction.md`.

pub mod agents;
pub mod app_passwords;
pub mod backup_policy;
pub mod backup_store;
pub mod blob_backup;
pub mod claim;
pub mod create_flow;
pub mod device_key;
pub mod diagnostics;
pub mod disaster_recovery;
pub mod endpoint_repair;
pub mod events;
pub mod handle_change;
pub mod http;
pub mod identity_removal;
pub mod identity_store;
pub mod import_did_web;
pub mod keystore;
pub mod migrate;
pub mod migration_orchestrator;
pub mod notification_routes;
pub mod notifications;
pub mod oauth;
pub mod oauth_client;
pub mod oauth_consent;
pub mod password_unlock;
pub mod pds_capabilities;
pub mod pds_client;
pub mod pds_config;
pub mod platform;
pub mod plc_monitor;
pub mod preferences;
pub mod recovery;
pub mod rekey;
pub mod repo_backup;
pub mod rotate_repo_key;
pub mod scheduler;
pub mod self_held_kit;
pub mod session_provider;
pub mod share_ceremony;
pub mod share_recovery;
pub mod signer;
pub mod source_login;
pub mod sovereign_session;
pub mod startup_reconcile;
