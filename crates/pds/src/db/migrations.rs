//! The forward-only schema migration manifest.
//!
//! `MIGRATIONS` is the ordered list of every schema version, each pairing a
//! version number with its `include_str!`-embedded SQL file under `migrations/`.
//! Kept in its own module so a schema change touches only this file plus the new
//! `migrations/VNNN__*.sql` file, leaving the pool setup and migration runner in
//! `mod.rs` untouched. The runner (`db::run_migrations`) applies every entry whose
//! version is absent from `schema_migrations`, in order, inside one transaction.
//!
//! Invariants (see `db/AGENTS.md`): versions are sequential positive integers
//! starting at 1, and an applied migration's SQL is never modified — only new
//! higher-numbered entries are appended.

/// One schema migration: its version number and the SQL that applies it.
pub(super) struct Migration {
    pub(super) version: u32,
    pub(super) sql: &'static str,
}

/// Every schema migration in application order.
///
/// `include_str!` paths are relative to this file's directory (`db/`), so they
/// point at `db/migrations/VNNN__*.sql`.
pub(super) static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: include_str!("migrations/V001__init.sql"),
    },
    Migration {
        version: 2,
        sql: include_str!("migrations/V002__auth_identity.sql"),
    },
    Migration {
        version: 3,
        sql: include_str!("migrations/V003__relay_signing_keys.sql"),
    },
    Migration {
        version: 4,
        sql: include_str!("migrations/V004__claim_codes_invite.sql"),
    },
    Migration {
        version: 5,
        sql: include_str!("migrations/V005__pending_accounts.sql"),
    },
    Migration {
        version: 6,
        sql: include_str!("migrations/V006__devices_v2.sql"),
    },
    Migration {
        version: 7,
        sql: include_str!("migrations/V007__pending_sessions.sql"),
    },
    Migration {
        version: 8,
        sql: include_str!("migrations/V008__did_promotion.sql"),
    },
    Migration {
        version: 9,
        sql: include_str!("migrations/V009__sessions_v2.sql"),
    },
    Migration {
        version: 10,
        sql: include_str!("migrations/V010__recovery_shares.sql"),
    },
    Migration {
        version: 11,
        sql: include_str!("migrations/V011__pending_shares.sql"),
    },
    Migration {
        version: 12,
        sql: include_str!("migrations/V012__oauth_token_endpoint.sql"),
    },
    Migration {
        version: 13,
        sql: include_str!("migrations/V013__identity_wallet_oauth_client.sql"),
    },
    Migration {
        version: 14,
        sql: include_str!("migrations/V014__password_reset_tokens.sql"),
    },
    Migration {
        version: 15,
        sql: include_str!("migrations/V015__jwt_signing_secret.sql"),
    },
    Migration {
        version: 16,
        sql: include_str!("migrations/V016__blobs.sql"),
    },
    Migration {
        version: 17,
        sql: include_str!("migrations/V017__repo_blocks.sql"),
    },
    Migration {
        version: 18,
        sql: include_str!("migrations/V018__accounts_repo_root.sql"),
    },
    Migration {
        version: 19,
        sql: include_str!("migrations/V019__per_account_repo_signing_key.sql"),
    },
    Migration {
        version: 20,
        sql: include_str!("migrations/V020__accounts_repo_rev.sql"),
    },
    Migration {
        version: 21,
        sql: include_str!("migrations/V021__blocks_rev.sql"),
    },
    Migration {
        version: 22,
        sql: include_str!("migrations/V022__iroh_identity.sql"),
    },
    Migration {
        version: 23,
        sql: include_str!("migrations/V023__account_preferences.sql"),
    },
    Migration {
        version: 24,
        sql: include_str!("migrations/V024__account_delete_after.sql"),
    },
    Migration {
        version: 25,
        sql: include_str!("migrations/V025__admin_devices.sql"),
    },
    Migration {
        version: 26,
        sql: include_str!("migrations/V026__account_lifecycle_status.sql"),
    },
    Migration {
        version: 27,
        sql: include_str!("migrations/V027__transfers.sql"),
    },
    Migration {
        version: 28,
        sql: include_str!("migrations/V028__repo_seq.sql"),
    },
    Migration {
        version: 29,
        sql: include_str!("migrations/V029__transfer_accept_devices.sql"),
    },
    Migration {
        version: 30,
        sql: include_str!("migrations/V030__transfer_complete_audit.sql"),
    },
    Migration {
        version: 31,
        sql: include_str!("migrations/V031__app_passwords.sql"),
    },
    Migration {
        version: 32,
        sql: include_str!("migrations/V032__reserved_signing_keys.sql"),
    },
    Migration {
        version: 33,
        sql: include_str!("migrations/V033__plc_operation_tokens.sql"),
    },
    Migration {
        version: 34,
        sql: include_str!("migrations/V034__account_deletion_tokens.sql"),
    },
    Migration {
        version: 35,
        sql: include_str!("migrations/V035__block_owners.sql"),
    },
    Migration {
        version: 36,
        sql: include_str!("migrations/V036__email_tokens.sql"),
    },
    Migration {
        version: 37,
        sql: include_str!("migrations/V037__agent_auth.sql"),
    },
    Migration {
        version: 38,
        sql: include_str!("migrations/V038__agent_identities_nullable_did.sql"),
    },
    Migration {
        version: 39,
        sql: include_str!("migrations/V039__blob_owners.sql"),
    },
    Migration {
        version: 40,
        sql: include_str!("migrations/V040__agent_audit_events.sql"),
    },
    Migration {
        version: 41,
        sql: include_str!("migrations/V041__claim_codes_revoked.sql"),
    },
    Migration {
        version: 42,
        sql: include_str!("migrations/V042__canonical_wallet_oauth_client.sql"),
    },
    Migration {
        version: 43,
        sql: include_str!("migrations/V043__sovereign_session_nonces.sql"),
    },
    Migration {
        version: 44,
        sql: include_str!("migrations/V044__did_web_hosting.sql"),
    },
    Migration {
        version: 45,
        sql: include_str!("migrations/V045__normalize_account_emails.sql"),
    },
];
