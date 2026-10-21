//! The Spaces query modules: SQL only, no business logic. The pool, migrations, and the
//! cross-feature tables are `custos_db`'s, re-exported crate-wide so `crate::db::accounts::…`
//! resolves as it does in `pds`.

#[cfg(test)]
pub(crate) use custos_db::{dids, test_pool};
pub(crate) use custos_db::{accounts, admin_audit, blobs, oauth};

pub mod space_jti;
pub mod space_notify;
pub mod space_repos;
pub mod spaces;
