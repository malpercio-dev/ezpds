// pattern: Imperative Shell

use sqlx::SqlitePool;

/// Normalize an email address for storage, lookup, and uniqueness comparison.
///
/// Trims surrounding whitespace and lowercases, matching the reference PDS's case-insensitive
/// email handling. Applied on every write (account creation, `updateEmail`) and read
/// (`resolve_by_email`, uniqueness checks, `confirmEmail`'s account-email match) so a
/// differently-cased or accidentally-padded address never causes a silent lookup miss (e.g. a
/// `requestPasswordReset` that silently no-ops because the stored and submitted addresses differ
/// only by case).
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

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

/// A minimal email plausibility check: exactly one `@` with a non-empty local part and a
/// dotted domain. Not full RFC 5322 validation — just enough to reject obvious garbage before
/// a DB write. Homed here beside `normalize_email` so the account-creation, `updateEmail`, and
/// admin-repair routes share one validator without importing across route modules.
pub fn is_plausible_email(email: &str) -> bool {
    let mut parts = email.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
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

    #[test]
    fn normalize_email_trims_and_lowercases() {
        assert_eq!(normalize_email("  Alice@Example.COM "), "alice@example.com");
        assert_eq!(normalize_email("bob@example.com"), "bob@example.com");
    }

    #[test]
    fn normalize_email_is_idempotent() {
        let once = normalize_email("Alice@Example.COM");
        assert_eq!(normalize_email(&once), once);
    }

    #[test]
    fn is_plausible_email_accepts_and_rejects() {
        assert!(is_plausible_email("alice@example.com"));
        assert!(is_plausible_email("a.b+c@sub.example.co.uk"));
        assert!(!is_plausible_email("no-at-sign"));
        assert!(!is_plausible_email("@example.com"));
        assert!(!is_plausible_email("alice@nodot"));
        assert!(!is_plausible_email("alice@.com"));
        assert!(!is_plausible_email("alice@example."));
        assert!(!is_plausible_email("two@at@example.com"));
    }

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
