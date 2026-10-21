//! The agents' own query module. The pool, migrations, and the cross-feature tables are
//! `custos_db`'s, re-exported crate-wide so `crate::db::agent_auth::…` resolves as it does in `pds`.

pub(crate) use custos_db::*;

pub mod agent_child_deletions;
