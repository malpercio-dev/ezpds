//! Query modules only `pds` reads. The pool, the migration log and runner, and the
//! cross-feature query modules live in `custos-db` (see its `AGENTS.md`); they are re-exported
//! below so `crate::db::…` paths keep resolving.

pub mod account_deletion_tokens;
pub mod account_labels;
pub mod agent_audit;
pub mod agent_auth;
pub mod agent_child_deletions;
pub mod app_passwords;
pub mod claim_codes;
pub mod email_tokens;
pub mod firehose_seq;
pub mod notifications;
pub mod password_reset;
pub mod pending_oauth_authorizations;
pub mod plc_operation_tokens;
pub mod preferences;
pub mod recovery_audit;
pub mod recovery_escrow;
pub mod recovery_otps;
pub mod relay_signing_keys;
pub mod sovereign_session_nonces;
pub mod waitlist;

#[cfg(test)]
pub(crate) use custos_db::test_pool;
pub use custos_db::{
    accounts, admin_audit, admin_devices, blobs, blocks, dids, handles, insert_with_retry_if,
    insert_with_retry_on_collision, is_unique_violation, kek, oauth, open_pool, refresh_tokens,
    repo_keys, run_migrations, server_stats, sessions, transfers,
};
