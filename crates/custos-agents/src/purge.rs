// pattern: Imperative Shell

//! This crate's step of `pds`'s account purge: the agent tables' rows for one DID, deleted inside
//! the caller's purge transaction. `pds` owns the ordering and the sovereign-child cascade (it
//! deactivates each child before calling [`purge_account_rows`]); this module owns which rows go.

use sqlx::SqliteConnection;

/// The statements [`purge_account_rows`] runs, in FK order: audit events and claim attempts
/// reference the identity row, so they go first.
///
/// Scoping the SQL alone can't show:
///
/// * `agent_audit_events` rows carrying this DID on a *foreign* account's registration are
///   unlinked (`did = NULL`), not deleted — they belong to that account's audit trail.
/// * The sovereign-child tables (V047/V049) are scoped by *both* DID columns: a purged parent
///   takes its children's registration/provisioning rows with it (the child *accounts* are
///   cascade-scheduled onto the reaper, ADR-0023), and a purged child's own provisioning row must
///   go before its `accounts` row. `agent_child_deletions` is deleted `WHERE parent_did = ?` only,
///   never by `child_did` (the table's key, see V049) — the tombstone must survive its child's
///   purge to keep the parent's audit view alive.
pub const PURGE_ACCOUNT_SQL: &[&str] = &[
    "DELETE FROM agent_audit_events WHERE registration_id IN (SELECT id FROM agent_identities WHERE did = ?)",
    "DELETE FROM agent_audit_events WHERE registration_id IN (SELECT id FROM agent_identities WHERE parent_did = ?)",
    "DELETE FROM agent_claim_attempts WHERE identity_id IN (SELECT id FROM agent_identities WHERE did = ?)",
    "DELETE FROM agent_claim_attempts WHERE identity_id IN (SELECT id FROM agent_identities WHERE parent_did = ?)",
    "DELETE FROM agent_identities WHERE did = ?",
    "DELETE FROM agent_identities WHERE parent_did = ?",
    "UPDATE agent_audit_events SET did = NULL WHERE did = ?",
    "DELETE FROM agent_child_provisionings WHERE child_did = ?",
    "DELETE FROM agent_child_provisionings WHERE parent_did = ?",
    "DELETE FROM agent_child_deletions WHERE parent_did = ?",
];

/// Delete every agent-owned row of `did` inside the caller's account-purge transaction.
pub async fn purge_account_rows(tx: &mut SqliteConnection, did: &str) -> Result<(), sqlx::Error> {
    for sql in PURGE_ACCOUNT_SQL {
        sqlx::query(sql).bind(did).execute(&mut *tx).await?;
    }
    Ok(())
}

/// The sovereign children of `parent`, read from both child tables so a mid-provisioning child
/// (a row in only one) is still caught. Call before [`purge_account_rows`], which deletes the
/// rows this reads.
pub async fn child_dids(
    tx: &mut SqliteConnection,
    parent: &str,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT did FROM agent_identities WHERE parent_did = ? AND did IS NOT NULL \
         UNION \
         SELECT child_did FROM agent_child_provisionings WHERE parent_did = ?",
    )
    .bind(parent)
    .bind(parent)
    .fetch_all(&mut *tx)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every account FK on an agent table is scoped by a statement above, so an `agent_*` table
    /// added without extending the purge fails here rather than FK-failing the reaper.
    #[tokio::test]
    async fn purge_covers_every_agent_account_foreign_key() {
        let pool = custos_db::test_pool().await;
        let checked = custos_db::purge_coverage::assert_purge_covers(
            &pool,
            |t| t.starts_with("agent_"),
            PURGE_ACCOUNT_SQL,
        )
        .await;
        assert!(checked >= 6, "sanity: found {checked} agent account FKs");
    }
}
