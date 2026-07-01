// pattern: Imperative Shell
//
// App-password queries. Reads and writes the `app_passwords` table (V031); returns plain
// data structs. No business logic — callers decide what to do with the result. Revocation
// (which also deletes the app password's refresh tokens/sessions) is a multi-table
// transaction and lives in the route handler, not here.

use common::{ApiError, ErrorCode};

use super::is_unique_violation;

/// One app password's public metadata (everything except the secret hash). Returned by
/// `list_app_passwords`.
pub(crate) struct AppPasswordRow {
    pub(crate) name: String,
    /// RFC 3339 creation instant, stored verbatim at insert time.
    pub(crate) created_at: String,
    /// `true` for a privileged (DM-capable) app password.
    pub(crate) privileged: bool,
}

/// One app password's verification material. Returned by `list_verify_candidates` so
/// `createSession` can try a supplied password against each stored hash.
pub(crate) struct AppPasswordCandidate {
    pub(crate) name: String,
    /// argon2id PHC string of the generated secret.
    pub(crate) password_hash: String,
    pub(crate) privileged: bool,
}

/// Outcome of `insert_app_password`.
pub(crate) enum InsertOutcome {
    Created,
    /// An app password with this name already exists for the account (PK collision).
    DuplicateName,
}

/// Insert a new app password for `did`. `created_at` is the RFC 3339 instant to store.
///
/// A name already used by this account trips the `(did, name)` primary key and is reported
/// as [`InsertOutcome::DuplicateName`] (the 409 path) rather than an error.
pub(crate) async fn insert_app_password(
    db: &sqlx::SqlitePool,
    did: &str,
    name: &str,
    password_hash: &str,
    privileged: bool,
    created_at: &str,
) -> Result<InsertOutcome, ApiError> {
    let result = sqlx::query(
        "INSERT INTO app_passwords (did, name, password_hash, privileged, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(did)
    .bind(name)
    .bind(password_hash)
    .bind(i64::from(privileged))
    .bind(created_at)
    .execute(db)
    .await;

    match result {
        Ok(_) => Ok(InsertOutcome::Created),
        Err(e) if is_unique_violation(&e) => Ok(InsertOutcome::DuplicateName),
        Err(e) => {
            tracing::error!(did = %did, error = %e, "DB error inserting app password");
            Err(ApiError::new(
                ErrorCode::InternalError,
                "failed to create app password",
            ))
        }
    }
}

/// List an account's app passwords (public metadata only), oldest first.
pub(crate) async fn list_app_passwords(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Vec<AppPasswordRow>, ApiError> {
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT name, created_at, privileged FROM app_passwords \
         WHERE did = ? ORDER BY created_at ASC, name ASC",
    )
    .bind(did)
    .fetch_all(db)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "DB error listing app passwords");
        ApiError::new(ErrorCode::InternalError, "failed to list app passwords")
    })?;

    Ok(rows
        .into_iter()
        .map(|(name, created_at, privileged)| AppPasswordRow {
            name,
            created_at,
            privileged: privileged != 0,
        })
        .collect())
}

/// Fetch every app password's hash + privileged flag for `did`, for `createSession` to try a
/// supplied password against. Excludes the plaintext (never stored) — only the argon2id hash.
pub(crate) async fn list_verify_candidates(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Vec<AppPasswordCandidate>, ApiError> {
    let rows: Vec<(String, String, i64)> =
        sqlx::query_as("SELECT name, password_hash, privileged FROM app_passwords WHERE did = ?")
            .bind(did)
            .fetch_all(db)
            .await
            .map_err(|e| {
                tracing::error!(did = %did, error = %e, "DB error loading app password candidates");
                ApiError::new(ErrorCode::InternalError, "failed to verify credentials")
            })?;

    Ok(rows
        .into_iter()
        .map(|(name, password_hash, privileged)| AppPasswordCandidate {
            name,
            password_hash,
            privileged: privileged != 0,
        })
        .collect())
}

/// Look up whether the named app password is privileged. `None` when no such app password
/// exists (e.g. it was revoked). Used by `refreshSession` to re-derive the app-pass scope
/// when rotating a session's tokens.
pub(crate) async fn app_password_privileged(
    db: &sqlx::SqlitePool,
    did: &str,
    name: &str,
) -> Result<Option<bool>, ApiError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT privileged FROM app_passwords WHERE did = ? AND name = ?")
            .bind(did)
            .bind(name)
            .fetch_optional(db)
            .await
            .map_err(|e| {
                tracing::error!(did = %did, error = %e, "DB error reading app password privilege");
                ApiError::new(ErrorCode::InternalError, "failed to load app password")
            })?;

    Ok(row.map(|(privileged,)| privileged != 0))
}
