//! The OAuth server's own query module. The pool, migrations, and the cross-feature tables are
//! `custos_db`'s, re-exported crate-wide so `crate::db::oauth::…` resolves as it does in `pds`.

pub(crate) use custos_db::{accounts, agent_audit, agent_auth, handles, oauth};

pub(crate) mod pending_oauth_authorizations;
