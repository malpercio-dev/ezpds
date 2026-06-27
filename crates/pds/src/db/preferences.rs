// pattern: Imperative Shell

use common::{ApiError, ErrorCode};

/// Fetch the locally-stored preferences blob for an account.
///
/// Returns `Some(json)` when the account has stored preferences and `None` when no row
/// exists yet (a brand-new account). The stored value is the JSON-encoded `preferences`
/// array exactly as written by `putPreferences`; callers parse it themselves so the DB
/// layer stays free of business logic.
pub async fn get_preferences(db: &sqlx::SqlitePool, did: &str) -> Result<Option<String>, ApiError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT preferences FROM account_preferences WHERE did = ?")
            .bind(did)
            .fetch_optional(db)
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
/// handler does the parsing and validation, keeping the DB layer free of business logic.
pub async fn put_preferences(db: &sqlx::SqlitePool, did: &str, blob: &str) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO account_preferences (did, preferences, updated_at) \
         VALUES (?, ?, datetime('now')) \
         ON CONFLICT(did) DO UPDATE SET \
             preferences = excluded.preferences, \
             updated_at = excluded.updated_at",
    )
    .bind(did)
    .bind(blob)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to store account preferences");
        ApiError::new(ErrorCode::InternalError, "failed to store preferences")
    })?;

    Ok(())
}
