//! The blobs feature's own query module. The pool, migrations, and the cross-feature tables
//! (`blobs`, `blocks`, `accounts`, …) are `custos_db`'s and are named there.

pub(crate) mod space_record_blocks;
