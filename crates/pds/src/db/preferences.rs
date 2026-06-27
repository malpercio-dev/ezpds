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
