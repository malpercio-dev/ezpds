// pattern: Imperative Shell

//! The account-purge tripwire, shared by every crate that owns account-keyed tables.
//!
//! The schema has no account-keyed FK cascades, so a purge must delete every row referencing
//! `accounts(did)` explicitly. Each owner (a feature crate, or `pds` for the core rows) walks the
//! live schema with [`account_foreign_keys`] and asserts its own purge statements reach every
//! FK column on the tables it owns, so a migration that adds a table without a purge step fails
//! in the owning crate's tests instead of FK-failing the reaper in production.

use sqlx::{Row, SqlitePool};

/// Every `(table, column)` in the live schema that foreign-keys `accounts(did)`.
#[allow(clippy::unwrap_used)] // fixture: a failed schema read panics the test
pub async fn account_foreign_keys(pool: &SqlitePool) -> Vec<(String, String)> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut out = Vec::new();
    for table in tables {
        let fks = sqlx::query(&format!("PRAGMA foreign_key_list({table})"))
            .fetch_all(pool)
            .await
            .unwrap();
        for fk in fks {
            if fk.get::<String, _>("table") == "accounts" {
                out.push((table.clone(), fk.get("from")));
            }
        }
    }
    out
}

/// Whether one purge statement deletes (or unlinks) rows of `table` scoped by `column`.
pub fn statement_scopes(sql: &str, table: &str, column: &str) -> bool {
    (sql.contains(&format!("FROM {table} ")) || sql.contains(&format!("UPDATE {table} ")))
        && (sql.contains(&format!("{column} = ?")) || sql.contains(&format!("{column} IN (")))
}

/// Assert `statements` scope every account FK column on the tables `owns` claims, and return how
/// many columns were checked (callers assert it is non-zero, so a renamed prefix can't pass
/// vacuously).
pub async fn assert_purge_covers(
    pool: &SqlitePool,
    owns: impl Fn(&str) -> bool,
    statements: &[&str],
) -> usize {
    let mut checked = 0;
    for (table, column) in account_foreign_keys(pool).await {
        if !owns(&table) {
            continue;
        }
        checked += 1;
        assert!(
            statements
                .iter()
                .any(|sql| statement_scopes(sql, &table, &column)),
            "{table}.{column} FK-references accounts(did) but no purge statement scopes it — \
             purging an account with a row here fails the FK check. Add it to the owning \
             crate's PURGE_ACCOUNT_SQL."
        );
    }
    checked
}
