// pattern: Imperative Shell
//
// The handle store. A handle is 128 bits of randomness standing in for one device's APNs
// token; the instance sends the handle, never the token, so a compromised relay database
// still cannot be correlated with anything an instance said before enrolling.
//
// Every query here takes the caller's node id and binds it into the WHERE clause. That is
// the whole cross-tenant boundary: a handle belonging to node B is, for node A, exactly as
// resolvable as one that never existed.

use sqlx::SqlitePool;

/// A handle row as its owner may see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleRow {
    pub handle: String,
    pub apns_token: String,
    pub apns_topic: String,
}

/// Register (or re-register) a device for `node_id`, returning the live handle.
///
/// Re-registering the same `(node_id, apns_token)` **rotates** the handle: the old one
/// stops resolving in the same transaction the new one starts. Rotation is the point —
/// a handle that outlived its registration would be a stale capability.
pub async fn register_handle(
    db: &SqlitePool,
    node_id: &str,
    apns_token: &str,
    apns_topic: &str,
    handle: &str,
) -> Result<String, sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM handles WHERE node_id = ? AND apns_token = ?")
        .bind(node_id)
        .bind(apns_token)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO handles (handle, node_id, apns_token, apns_topic, created_at) \
         VALUES (?, ?, ?, ?, datetime('now'))",
    )
    .bind(handle)
    .bind(node_id)
    .bind(apns_token)
    .bind(apns_topic)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(handle.to_owned())
}

/// Resolve a handle **owned by** `node_id`. `None` covers both "no such handle" and
/// "someone else's handle" — the caller must not distinguish them.
pub async fn resolve_handle(
    db: &SqlitePool,
    node_id: &str,
    handle: &str,
) -> Result<Option<HandleRow>, sqlx::Error> {
    let row = sqlx::query_as::<_, (String, String, String)>(
        "SELECT handle, apns_token, apns_topic FROM handles WHERE handle = ? AND node_id = ?",
    )
    .bind(handle)
    .bind(node_id)
    .fetch_optional(db)
    .await?;

    Ok(row.map(|(handle, apns_token, apns_topic)| HandleRow {
        handle,
        apns_token,
        apns_topic,
    }))
}

/// Record that Apple accepted a notification for this handle.
///
/// Scoped by node id like every other query here, so it cannot be used to probe for
/// another node's handles by observing a write. Called only on a successful delivery:
/// `last_push_at` is the operator's "is this registration still live?" signal, and
/// stamping it on a refusal would make a dead device look healthy.
pub async fn touch_last_push(
    db: &SqlitePool,
    node_id: &str,
    handle: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE handles SET last_push_at = datetime('now') WHERE handle = ? AND node_id = ?",
    )
    .bind(handle)
    .bind(node_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Drop a handle owned by `node_id`. Idempotent; reports whether a row was removed so the
/// relay can log real deletions without telling the caller anything either way.
pub async fn drop_handle(
    db: &SqlitePool,
    node_id: &str,
    handle: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM handles WHERE handle = ? AND node_id = ?")
        .bind(handle)
        .bind(node_id)
        .execute(db)
        .await?;
    Ok(result.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{enrollments, test_pool};

    async fn enrolled_pool() -> SqlitePool {
        let pool = test_pool().await;
        for node in ["node-a", "node-b"] {
            enrollments::insert_enrollment(&pool, node, None)
                .await
                .expect("enroll");
        }
        pool
    }

    #[tokio::test]
    async fn re_registering_the_same_token_rotates_the_handle() {
        let pool = enrolled_pool().await;
        register_handle(&pool, "node-a", "tok", "org.obsign.app", "h1")
            .await
            .expect("register");
        register_handle(&pool, "node-a", "tok", "org.obsign.app", "h2")
            .await
            .expect("re-register");

        assert!(resolve_handle(&pool, "node-a", "h1")
            .await
            .expect("resolve")
            .is_none());
        assert_eq!(
            resolve_handle(&pool, "node-a", "h2")
                .await
                .expect("resolve")
                .map(|r| r.apns_token),
            Some("tok".to_owned())
        );
    }

    #[tokio::test]
    async fn a_handle_is_invisible_to_every_other_node() {
        let pool = enrolled_pool().await;
        register_handle(&pool, "node-a", "tok", "org.obsign.app", "h1")
            .await
            .expect("register");

        assert!(
            resolve_handle(&pool, "node-b", "h1")
                .await
                .expect("resolve")
                .is_none(),
            "node B must not resolve node A's handle"
        );
        assert!(
            !drop_handle(&pool, "node-b", "h1").await.expect("drop"),
            "node B must not drop node A's handle"
        );
        assert!(
            resolve_handle(&pool, "node-a", "h1")
                .await
                .expect("resolve")
                .is_some(),
            "the owner's handle must survive a foreign drop attempt"
        );
    }

    #[tokio::test]
    async fn a_delivery_stamp_is_scoped_to_the_owning_node() {
        let pool = enrolled_pool().await;
        register_handle(&pool, "node-a", "tok", "org.obsign.app", "h1")
            .await
            .expect("register");

        let stamp = |pool: SqlitePool| async move {
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT last_push_at FROM handles WHERE handle = 'h1'",
            )
            .fetch_one(&pool)
            .await
            .expect("read stamp")
        };
        assert!(stamp(pool.clone()).await.is_none(), "unpushed to start");

        touch_last_push(&pool, "node-b", "h1")
            .await
            .expect("a foreign touch is not an error");
        assert!(
            stamp(pool.clone()).await.is_none(),
            "node B must not be able to stamp node A's handle"
        );

        touch_last_push(&pool, "node-a", "h1")
            .await
            .expect("owner touch");
        assert!(stamp(pool).await.is_some(), "the owner's delivery stamps");
    }

    #[tokio::test]
    async fn dropping_is_idempotent() {
        let pool = enrolled_pool().await;
        register_handle(&pool, "node-a", "tok", "org.obsign.app", "h1")
            .await
            .expect("register");
        assert!(drop_handle(&pool, "node-a", "h1").await.expect("drop"));
        assert!(!drop_handle(&pool, "node-a", "h1").await.expect("re-drop"));
    }
}
