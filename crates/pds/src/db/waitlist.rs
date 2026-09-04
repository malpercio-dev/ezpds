// pattern: Imperative Shell

//! Waitlist signup queries (V057, the `waitlist` capability).
//!
//! One row per interested person, keyed by normalized email so a repeat signup is an
//! idempotent no-op (`InsertSignupOutcome::AlreadySignedUp`) rather than a duplicate row
//! or an enumeration oracle. `list_signups` is a rowid-cursor page, newest first, for the
//! operator readout (`GET /v1/admin/waitlist`), with `count_signups` for the total. The
//! table has no foreign keys — signups predate accounts — so it stays off the
//! account-purge path.

use common::ApiError;
use sqlx::{Row, SqlitePool};

use super::is_unique_violation;

/// Outcome of a signup insert. Both arms are a 200 to the caller — the distinction
/// exists so the route can log/count without leaking "this email was already here".
pub(crate) enum InsertSignupOutcome {
    Created,
    AlreadySignedUp,
}

/// Insert a signup row. `email` must already be normalized (`uniqueness::normalize_email`);
/// `handle` must already be syntactically validated.
pub(crate) async fn insert_signup(
    db: &SqlitePool,
    email: &str,
    handle: Option<&str>,
) -> Result<InsertSignupOutcome, ApiError> {
    let result = sqlx::query(
        "INSERT INTO waitlist_signups (email, handle, created_at) VALUES (?, ?, datetime('now'))",
    )
    .bind(email)
    .bind(handle)
    .execute(db)
    .await;

    match result {
        Ok(_) => Ok(InsertSignupOutcome::Created),
        Err(e) if is_unique_violation(&e) => Ok(InsertSignupOutcome::AlreadySignedUp),
        Err(e) => Err(ApiError::internal_as(
            e,
            "DB error inserting waitlist signup",
            "failed to record signup",
        )),
    }
}

/// One listed signup row, plus the rowid the pagination cursor is built from.
pub(crate) struct WaitlistSignupRow {
    pub rowid: i64,
    pub email: String,
    pub handle: Option<String>,
    pub created_at: String,
}

/// Newest-first rowid-cursor page: rows with `rowid < before` (all when `before` is `None`),
/// at most `limit`.
pub(crate) async fn list_signups(
    db: &SqlitePool,
    before: Option<i64>,
    limit: i64,
) -> Result<Vec<WaitlistSignupRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT rowid, email, handle, created_at FROM waitlist_signups \
         WHERE (? IS NULL OR rowid < ?) ORDER BY rowid DESC LIMIT ?",
    )
    .bind(before)
    .bind(before)
    .bind(limit)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| WaitlistSignupRow {
            rowid: row.get("rowid"),
            email: row.get("email"),
            handle: row.get("handle"),
            created_at: row.get("created_at"),
        })
        .collect())
}

/// Total signup count, for the listing's summary field.
pub(crate) async fn count_signups(db: &SqlitePool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM waitlist_signups")
        .fetch_one(db)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> SqlitePool {
        let db = crate::db::open_pool("sqlite::memory:").await.unwrap();
        crate::db::run_migrations(&db).await.unwrap();
        db
    }

    #[tokio::test]
    async fn insert_is_idempotent_per_email() {
        let db = test_pool().await;
        assert!(matches!(
            insert_signup(&db, "alice@example.com", Some("alice.bsky.social"))
                .await
                .unwrap(),
            InsertSignupOutcome::Created
        ));
        assert!(matches!(
            insert_signup(&db, "alice@example.com", None).await.unwrap(),
            InsertSignupOutcome::AlreadySignedUp
        ));
        assert_eq!(count_signups(&db).await.unwrap(), 1);
        // The original row (and its handle) survives the repeat.
        let rows = list_signups(&db, None, 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].handle.as_deref(), Some("alice.bsky.social"));
    }

    #[tokio::test]
    async fn listing_pages_newest_first() {
        let db = test_pool().await;
        for i in 0..5 {
            insert_signup(&db, &format!("user{i}@example.com"), None)
                .await
                .unwrap();
        }
        let first = list_signups(&db, None, 2).await.unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].email, "user4@example.com");
        assert_eq!(first[1].email, "user3@example.com");

        let second = list_signups(&db, Some(first[1].rowid), 2).await.unwrap();
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].email, "user2@example.com");
        assert_eq!(second[1].email, "user1@example.com");
        assert_eq!(count_signups(&db).await.unwrap(), 5);
    }
}
