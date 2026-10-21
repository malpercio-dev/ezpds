// pattern: Imperative Shell

use sqlx::SqlitePool;

pub use common::{is_plausible_email, normalize_email};

/// Returns `true` if the email already exists in `accounts` or `pending_accounts`.
///
/// `email` is normalized first (see [`normalize_email`]) since stored addresses are normalized —
/// a caller does not need to normalize before calling.
pub async fn email_taken(db: &SqlitePool, email: &str) -> Result<bool, sqlx::Error> {
    let email = normalize_email(email);
    let taken: i64 = sqlx::query_scalar(
        "SELECT CAST(
             (EXISTS(SELECT 1 FROM accounts WHERE email = ?)
              OR EXISTS(SELECT 1 FROM pending_accounts WHERE email = ?))
         AS INTEGER)",
    )
    .bind(&email)
    .bind(&email)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn email_taken_matches_regardless_of_case() {
        let db = crate::db::open_pool("sqlite::memory:").await.unwrap();
        crate::db::run_migrations(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:a', 'alice@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .execute(&db)
        .await
        .unwrap();

        assert!(email_taken(&db, "Alice@Example.com").await.unwrap());
        assert!(email_taken(&db, "  ALICE@EXAMPLE.COM  ").await.unwrap());
        assert!(!email_taken(&db, "bob@example.com").await.unwrap());
    }
}
