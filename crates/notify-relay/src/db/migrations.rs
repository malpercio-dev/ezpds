//! The forward-only schema migration manifest.
//!
//! Same shape as the pds crate's manifest, deliberately copied rather than shared: the
//! runner is a few dozen lines and the two crates' migration histories are independent.
//! A schema change touches only this file plus its new `migrations/VNNN__*.sql`.
//!
//! Invariants: versions are sequential positive integers starting at 1, and an applied
//! migration's SQL is never modified — only new higher-numbered entries are appended.

/// One schema migration: its version number and the SQL that applies it.
pub(super) struct Migration {
    pub(super) version: u32,
    pub(super) sql: &'static str,
}

/// Every schema migration in application order.
pub(super) static MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    sql: include_str!("migrations/V001__init.sql"),
}];
