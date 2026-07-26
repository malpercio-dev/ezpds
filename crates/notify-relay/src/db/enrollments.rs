// pattern: Imperative Shell
//
// Which nodes may talk to this relay. Enrollment is the relay's only authorization
// decision: every RPC except `enroll` itself is refused for a node with no row here.

use sqlx::{Sqlite, SqlitePool};

/// Whether `node_id` is enrolled.
pub async fn is_enrolled(db: &SqlitePool, node_id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM enrollments WHERE node_id = ?)")
        .bind(node_id)
        .fetch_one(db)
        .await
}

/// Record an enrollment, ignoring a repeat (enrollment is idempotent — a node that
/// re-enrolls after a restart must not be told "no" or charged a second code).
///
/// Generic over the executor so it can join the code-redemption transaction.
pub async fn insert_enrollment<'e, E>(
    executor: E,
    node_id: &str,
    code_used: Option<&str>,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO enrollments (node_id, enrolled_at, code_used) \
         VALUES (?, datetime('now'), ?) \
         ON CONFLICT(node_id) DO NOTHING",
    )
    .bind(node_id)
    .bind(code_used)
    .execute(executor)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_pool;

    #[tokio::test]
    async fn enrollment_is_idempotent_and_scoped_to_the_node() {
        let pool = test_pool().await;
        assert!(!is_enrolled(&pool, "node-a").await.expect("probe"));

        insert_enrollment(&pool, "node-a", Some("GRANT-1"))
            .await
            .expect("enroll");
        insert_enrollment(&pool, "node-a", None)
            .await
            .expect("re-enroll");

        assert!(is_enrolled(&pool, "node-a").await.expect("probe"));
        assert!(
            !is_enrolled(&pool, "node-b").await.expect("probe"),
            "enrolling one node must not enroll another"
        );

        let code: Option<String> =
            sqlx::query_scalar("SELECT code_used FROM enrollments WHERE node_id = ?")
                .bind("node-a")
                .fetch_one(&pool)
                .await
                .expect("read");
        assert_eq!(
            code.as_deref(),
            Some("GRANT-1"),
            "a re-enroll must not overwrite the original grant record"
        );
    }
}
