// pattern: Imperative Shell

//! App-password queries over the `app_passwords` table (V031, grants extended V063). Plain
//! data out; no business logic.
//!
//! `insert_app_password` reports a `(did, name)` PK collision as
//! `InsertOutcome::DuplicateName` (the 409 path). `list_app_passwords` returns public
//! metadata only — never the hash. `list_verify_candidates` returns hash + grants for
//! `createSession` to try a supplied password against, and `app_password_grants`
//! re-derives an app-pass session's grants on `refreshSession`. Revocation — deleting the
//! row plus the app password's refresh tokens and sessions — is a multi-table transaction
//! owned by `routes/revoke_app_password.rs`, not here.

use common::{ApiError, ErrorCode};

use super::is_unique_violation;

/// The mint-time grants carried by an app password beyond its base scope: `privileged`
/// (DM/chat access, mirroring the reference scopes) and `personal_details` (read/write the
/// full-access-only preference types — the ADR-0033 divergence). Immutable after mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AppPasswordGrants {
    pub(crate) privileged: bool,
    pub(crate) personal_details: bool,
}

/// One app password's public metadata (everything except the secret hash). Returned by
/// `list_app_passwords`.
pub(crate) struct AppPasswordRow {
    pub(crate) name: String,
    /// RFC 3339 creation instant, stored verbatim at insert time.
    pub(crate) created_at: String,
    pub(crate) grants: AppPasswordGrants,
}

/// One app password's verification material. Returned by `list_verify_candidates` so
/// `createSession` can try a supplied password against each stored hash.
pub(crate) struct AppPasswordCandidate {
    pub(crate) name: String,
    /// argon2id PHC string of the generated secret.
    pub(crate) password_hash: String,
    pub(crate) grants: AppPasswordGrants,
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
    grants: AppPasswordGrants,
    created_at: &str,
) -> Result<InsertOutcome, ApiError> {
    let result = sqlx::query(
        "INSERT INTO app_passwords (did, name, password_hash, privileged, personal_details, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(did)
    .bind(name)
    .bind(password_hash)
    .bind(i64::from(grants.privileged))
    .bind(i64::from(grants.personal_details))
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
    let rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT name, created_at, privileged, personal_details FROM app_passwords \
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
        .map(
            |(name, created_at, privileged, personal_details)| AppPasswordRow {
                name,
                created_at,
                grants: AppPasswordGrants {
                    privileged: privileged != 0,
                    personal_details: personal_details != 0,
                },
            },
        )
        .collect())
}

/// Fetch every app password's hash + grants for `did`, for `createSession` to try a
/// supplied password against. Excludes the plaintext (never stored) — only the argon2id hash.
pub(crate) async fn list_verify_candidates(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Vec<AppPasswordCandidate>, ApiError> {
    let rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT name, password_hash, privileged, personal_details FROM app_passwords WHERE did = ?",
    )
    .bind(did)
    .fetch_all(db)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "DB error loading app password candidates");
        ApiError::new(ErrorCode::InternalError, "failed to verify credentials")
    })?;

    Ok(rows
        .into_iter()
        .map(
            |(name, password_hash, privileged, personal_details)| AppPasswordCandidate {
                name,
                password_hash,
                grants: AppPasswordGrants {
                    privileged: privileged != 0,
                    personal_details: personal_details != 0,
                },
            },
        )
        .collect())
}

/// Look up the named app password's grants. `None` when no such app password exists (e.g.
/// it was revoked). Generic over the executor so session issuance can re-check the stored
/// authority inside its transaction while `refreshSession` can query through the pool.
pub(crate) async fn app_password_grants<'e, E>(
    executor: E,
    did: &str,
    name: &str,
) -> Result<Option<AppPasswordGrants>, ApiError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT privileged, personal_details FROM app_passwords WHERE did = ? AND name = ?",
    )
    .bind(did)
    .bind(name)
    .fetch_optional(executor)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "DB error reading app password grants");
        ApiError::new(ErrorCode::InternalError, "failed to load app password")
    })?;

    Ok(row.map(|(privileged, personal_details)| AppPasswordGrants {
        privileged: privileged != 0,
        personal_details: personal_details != 0,
    }))
}
