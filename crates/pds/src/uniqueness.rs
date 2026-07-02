// pattern: Imperative Shell

use sqlx::SqlitePool;

/// Returns `true` if the email already exists in `accounts` or `pending_accounts`.
pub async fn email_taken(db: &SqlitePool, email: &str) -> Result<bool, sqlx::Error> {
    let taken: i64 = sqlx::query_scalar(
        "SELECT CAST(
             (EXISTS(SELECT 1 FROM accounts WHERE email = ?)
              OR EXISTS(SELECT 1 FROM pending_accounts WHERE email = ?))
         AS INTEGER)",
    )
    .bind(email)
    .bind(email)
    .fetch_one(db)
    .await?;
    Ok(taken != 0)
}

/// Returns `true` if the handle already exists in `handles` or `pending_accounts`.
pub async fn handle_taken(db: &SqlitePool, handle: &str) -> Result<bool, sqlx::Error> {
    let taken: i64 = sqlx::query_scalar(
        "SELECT CAST(
             (EXISTS(SELECT 1 FROM handles WHERE handle = ?)
              OR EXISTS(SELECT 1 FROM pending_accounts WHERE handle = ?))
         AS INTEGER)",
    )
    .bind(handle)
    .bind(handle)
    .fetch_one(db)
    .await?;
    Ok(taken != 0)
}
