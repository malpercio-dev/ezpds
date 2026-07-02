// pattern: Imperative Shell

use sqlx::Sqlite;

use common::{ApiError, ErrorCode};

/// Fetch the locally-stored preferences blob for an account.
///
/// Returns `Some(json)` when the account has stored preferences and `None` when no row
/// exists yet (a brand-new account). The stored value is the JSON-encoded `preferences`
/// array exactly as written by `putPreferences`; callers parse it themselves so the DB
/// layer stays free of business logic. Generic over the executor so `putPreferences` can
/// read the prior blob and write the merged one inside the same transaction.
pub async fn get_preferences<'e, E>(executor: E, did: &str) -> Result<Option<String>, ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let row: Option<(String,)> =
        sqlx::query_as("SELECT preferences FROM account_preferences WHERE did = ?")
            .bind(did)
            .fetch_optional(executor)
            .await
            .map_err(|e| {
                tracing::error!(did = %did, error = %e, "failed to load account preferences");
                ApiError::new(ErrorCode::InternalError, "failed to load preferences")
            })?;

    Ok(row.map(|(prefs,)| prefs))
}

/// Store the preferences blob for an account, overwriting any previous value.
///
/// `putPreferences` replaces the stored array in its entirety, so this upserts the single
/// row keyed by `did`: a brand-new account gets an INSERT, an existing one has its blob and
/// `updated_at` replaced. The `blob` is the already-serialized `preferences` array; the
/// handler does the parsing, scope filtering, and merging with any preserved entries,
/// keeping the DB layer free of business logic. Generic over the executor so the handler can
/// run the read-merge-write sequence inside one transaction.
pub async fn put_preferences<'e, E>(executor: E, did: &str, blob: &str) -> Result<(), ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO account_preferences (did, preferences, updated_at) \
         VALUES (?, ?, datetime('now')) \
         ON CONFLICT(did) DO UPDATE SET \
             preferences = excluded.preferences, \
             updated_at = excluded.updated_at",
    )
    .bind(did)
    .bind(blob)
    .execute(executor)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to store account preferences");
        ApiError::new(ErrorCode::InternalError, "failed to store preferences")
    })?;

    Ok(())
}
