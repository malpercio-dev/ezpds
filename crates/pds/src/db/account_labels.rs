// pattern: Imperative Shell

//! Query functions for `account_labels` (V051): account-level labels observed on hosted
//! accounts from watched labelers.
//!
//! The table is a reconciled cache of external labeler state, written by the periodic
//! `labeler_watch` pass and read by the operator account listing/health readouts. Rows
//! represent labels *currently in force* — the watcher deletes a row when the labeler
//! negates or expires the label — so "flagged" is simply "has any row".

use std::collections::HashMap;

/// One label currently in force on an account, as surfaced to the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccountLabel {
    /// The labeler that applied the label.
    pub(crate) labeler_did: String,
    /// The label value (e.g. `spam`, `!hide`).
    pub(crate) val: String,
    /// The labeler's label-creation timestamp.
    pub(crate) cts: String,
}

/// A stored `(did, val, cts)` triple for one labeler, as the reconcile pass reads it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredLabel {
    pub(crate) did: String,
    pub(crate) val: String,
    pub(crate) cts: String,
}

/// Fetch every label in force for each of `dids`, newest first per account.
///
/// One query for the whole page (the listing calls this with at most a page of DIDs);
/// accounts with no labels are simply absent from the returned map.
pub(crate) async fn labels_for_dids(
    db: &sqlx::SqlitePool,
    dids: &[String],
) -> Result<HashMap<String, Vec<AccountLabel>>, sqlx::Error> {
    if dids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = vec!["?"; dids.len()].join(", ");
    let sql = format!(
        "SELECT did, labeler_did, val, cts FROM account_labels \
         WHERE did IN ({placeholders}) ORDER BY cts DESC, labeler_did ASC, val ASC"
    );
    let mut query = sqlx::query_as::<_, (String, String, String, String)>(&sql);
    for did in dids {
        query = query.bind(did);
    }
    let rows = query.fetch_all(db).await?;

    let mut by_did: HashMap<String, Vec<AccountLabel>> = HashMap::new();
    for (did, labeler_did, val, cts) in rows {
        by_did.entry(did).or_default().push(AccountLabel {
            labeler_did,
            val,
            cts,
        });
    }
    Ok(by_did)
}

/// Every stored label attributed to `labeler_did`, for the reconcile diff.
pub(crate) async fn labels_for_labeler(
    db: &sqlx::SqlitePool,
    labeler_did: &str,
) -> Result<Vec<StoredLabel>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String, String, String)>(
        "SELECT did, val, cts FROM account_labels WHERE labeler_did = ?",
    )
    .bind(labeler_did)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(did, val, cts)| StoredLabel { did, val, cts })
        .collect())
}

/// Insert or refresh one in-force label. Generic over the executor so the reconcile pass
/// applies its whole diff in one transaction.
///
/// Guarded on the account still existing (the DID list is read before the labeler fetch,
/// so an account deleted in between must not fail the whole reconcile on its FK); a repeat
/// observation updates `cts` in place and leaves `first_seen_at` untouched — that column
/// records first observation, the future notifier's new-vs-backfill seam.
pub(crate) async fn upsert_label<'e, E>(
    exec: E,
    did: &str,
    labeler_did: &str,
    val: &str,
    cts: &str,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(
        "INSERT INTO account_labels (did, labeler_did, val, cts) \
         SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM accounts a WHERE a.did = ?1) \
         ON CONFLICT (did, labeler_did, val) DO UPDATE SET cts = excluded.cts",
    )
    .bind(did)
    .bind(labeler_did)
    .bind(val)
    .bind(cts)
    .execute(exec)
    .await?;
    Ok(())
}

/// Delete one no-longer-in-force label. Generic over the executor for the reconcile
/// transaction; deleting an already-absent row is a no-op.
pub(crate) async fn delete_label<'e, E>(
    exec: E,
    did: &str,
    labeler_did: &str,
    val: &str,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query("DELETE FROM account_labels WHERE did = ? AND labeler_did = ? AND val = ?")
        .bind(did)
        .bind(labeler_did)
        .bind(val)
        .execute(exec)
        .await?;
    Ok(())
}

/// Delete every label attributed to a labeler that is no longer watched, returning how many
/// rows were removed.
///
/// With an empty `watched` list this clears the table entirely — flagged state must never
/// outlive the configuration that produced it (startup calls this when watching is
/// disabled, so stale flags don't linger in the operator listing forever).
pub(crate) async fn delete_labels_for_unwatched(
    db: &sqlx::SqlitePool,
    watched: &[String],
) -> Result<u64, sqlx::Error> {
    let result = if watched.is_empty() {
        sqlx::query("DELETE FROM account_labels")
            .execute(db)
            .await?
    } else {
        let placeholders = vec!["?"; watched.len()].join(", ");
        let sql = format!("DELETE FROM account_labels WHERE labeler_did NOT IN ({placeholders})");
        let mut query = sqlx::query(&sql);
        for did in watched {
            query = query.bind(did);
        }
        query.execute(db).await?
    };
    Ok(result.rows_affected())
}

/// Count of hosted accounts carrying at least one in-force label, for the operator health
/// readout's badge count.
pub(crate) async fn count_flagged_accounts(db: &sqlx::SqlitePool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(DISTINCT did) FROM account_labels")
        .fetch_one(db)
        .await
}
