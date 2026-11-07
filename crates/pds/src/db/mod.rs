//! Query modules only `pds` reads. The pool, the migration log and runner, and the
//! cross-feature query modules live in `custos-db` (see its `AGENTS.md`); reach them as
//! `custos_db::…`, never through here.

pub mod account_deletion_tokens;
pub mod account_labels;
pub mod app_passwords;
pub mod claim_codes;
pub mod email_tokens;
pub mod notifications;
pub mod password_reset;
pub mod plc_operation_tokens;
pub mod preferences;
pub mod recovery_audit;
pub mod recovery_escrow;
pub mod recovery_otps;
pub mod relay_signing_keys;
pub mod sovereign_session_nonces;
pub mod waitlist;
