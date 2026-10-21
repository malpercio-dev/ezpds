//! The blobs feature's own query module. The pool, migrations, and the cross-feature tables
//! (`blobs`, `blocks`, `accounts`, …) are `custos_db`'s, re-exported crate-wide so
//! `crate::db::blobs::…` resolves as it does in `pds`.

pub(crate) use custos_db::*;

pub(crate) mod space_record_blocks;
