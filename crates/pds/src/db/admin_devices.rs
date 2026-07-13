// pattern: Imperative Shell

//! Admin-device data model: pairing codes, devices, and anti-replay nonces.
//!
//! Backs the operator companion app's per-device signed-request authentication.
//! Each device holds a non-extractable P-256 key (Secure Enclave on iOS) and the
//! relay stores only its public key as a `did:key`; there is no replayable secret
//! at rest. A new device enrolls by claiming a single-use pairing code minted with
//! the master admin token.
//!
//! Status is derived from timestamp columns at query time (never stored), matching
//! `claim_codes` (V004): a pairing code is *pending* while unconsumed and unexpired;
//! a device is *active* while `revoked_at IS NULL`.
//!
//! These functions own queries, not business-logic transactions. The ones the
//! pairing/auth routes run inside a transaction (`consume_pairing_code`,
//! `insert_device`, `insert_nonce_if_absent`) are generic over the executor so a
//! caller can pass either the pool or an open `&mut Transaction`.

#![allow(dead_code)]

use sqlx::{Sqlite, SqlitePool};

/// A registered admin device with its derived active/revoked status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminDeviceRow {
    pub id: String,
    pub label: String,
    pub public_key: String,
    pub platform: String,
    pub scopes: String,
    pub created_at: String,
    pub last_seen_at: Option<String>,
    pub revoked_at: Option<String>,
    /// Derived: `revoked_at IS NULL` at query time.
    pub is_active: bool,
}

/// The fields needed to register a new admin device. `scopes` defaults to `full`
/// at the schema level and `last_seen_at`/`revoked_at` start NULL.
#[derive(Debug, Clone)]
pub struct NewAdminDevice<'a> {
    pub id: &'a str,
    pub label: &'a str,
    pub public_key: &'a str,
    pub platform: &'a str,
}

/// A pairing code's consume/expiry state, for deriving pending/consumed/expired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCodeRow {
    pub code: String,
    pub consumed_at: Option<String>,
    /// Derived: `expires_at <= datetime('now')` at query time.
    pub is_expired: bool,
}

impl PairingCodeRow {
    /// A code is claimable only while unconsumed and unexpired.
    pub fn is_pending(&self) -> bool {
        self.consumed_at.is_none() && !self.is_expired
    }
}

// ── Pairing codes ──────────────────────────────────────────────────────────

/// Insert a single-use pairing code expiring `ttl_minutes` from now.
///
/// Returns the computed `expires_at` timestamp so the minting route can echo it
/// back to the operator. Duplicate codes surface as a UNIQUE violation on the PK.
pub async fn insert_pairing_code(
    pool: &SqlitePool,
    code: &str,
    ttl_minutes: i64,
) -> Result<String, sqlx::Error> {
    if ttl_minutes < 0 {
        return Err(sqlx::Error::Protocol(
            "ttl_minutes must be non-negative".to_string(),
        ));
    }
    let modifier = format!("+{ttl_minutes} minutes");
    sqlx::query(
        "INSERT INTO admin_pairing_codes (code, expires_at, created_at) \
         VALUES (?, datetime('now', ?), datetime('now'))",
    )
    .bind(code)
    .bind(&modifier)
    .execute(pool)
    .await?;

    let (expires_at,): (String,) =
        sqlx::query_as("SELECT expires_at FROM admin_pairing_codes WHERE code = ?")
            .bind(code)
            .fetch_one(pool)
            .await?;
    Ok(expires_at)
}

/// Look up a pairing code with its derived expiry state. `None` if no such code.
pub async fn get_pairing_code(
    pool: &SqlitePool,
    code: &str,
) -> Result<Option<PairingCodeRow>, sqlx::Error> {
    let row: Option<(String, Option<String>, bool)> = sqlx::query_as(
        "SELECT code, consumed_at, expires_at <= datetime('now') AS is_expired \
         FROM admin_pairing_codes WHERE code = ?",
    )
    .bind(code)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(code, consumed_at, is_expired)| PairingCodeRow {
        code,
        consumed_at,
        is_expired,
    }))
}

/// Atomically consume a pairing code, enforcing single-use semantics.
///
/// The conditional UPDATE only touches a row that is still pending (unconsumed and
/// unexpired), so a second claim — or a claim of an expired code — affects no rows.
/// Returns `true` iff this call consumed the code. Generic over the executor so the
/// register-device route can run it in the same transaction as `insert_device`.
pub async fn consume_pairing_code<'e, E>(executor: E, code: &str) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "UPDATE admin_pairing_codes SET consumed_at = datetime('now') \
         WHERE code = ? AND consumed_at IS NULL AND expires_at > datetime('now')",
    )
    .bind(code)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

// ── Devices ────────────────────────────────────────────────────────────────

/// Insert a new admin device. Generic over the executor so it can run in the same
/// transaction that consumes the pairing code.
pub async fn insert_device<'e, E>(
    executor: E,
    device: &NewAdminDevice<'_>,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO admin_devices (id, label, public_key, platform, created_at) \
         VALUES (?, ?, ?, ?, datetime('now'))",
    )
    .bind(device.id)
    .bind(device.label)
    .bind(device.public_key)
    .bind(device.platform)
    .execute(executor)
    .await?;
    Ok(())
}

/// Fetch a single device by id, with derived active status. `None` if absent.
pub async fn get_device(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<AdminDeviceRow>, sqlx::Error> {
    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            bool,
        ),
    >(
        "SELECT id, label, public_key, platform, scopes, created_at, last_seen_at, revoked_at, \
                revoked_at IS NULL AS is_active \
         FROM admin_devices WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(into_device_row))
}

/// List all devices (active and revoked) newest first, with derived status.
///
/// `created_at` is only second-granularity, so the `rowid` tie-breaker decides order
/// among devices registered in the same second. `rowid` tracks insertion order on this
/// (rowid) table, so it is a true recency tie-breaker — unlike the random-UUID `id`.
pub async fn list_devices(pool: &SqlitePool) -> Result<Vec<AdminDeviceRow>, sqlx::Error> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            bool,
        ),
    >(
        "SELECT id, label, public_key, platform, scopes, created_at, last_seen_at, revoked_at, \
                revoked_at IS NULL AS is_active \
         FROM admin_devices ORDER BY created_at DESC, rowid DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(into_device_row).collect())
}

/// Revoke a device by stamping `revoked_at`. The conditional UPDATE is idempotent:
/// it only affects a row that is still active, so revoking twice returns `false` the
/// second time. Returns `true` iff this call revoked an active device.
pub async fn revoke_device(pool: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE admin_devices SET revoked_at = datetime('now') \
         WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Bump a device's `last_seen_at` to now — liveness bookkeeping run after a device
/// signed request authenticates. Touches the row by id unconditionally; a missing
/// device simply affects no rows (the caller has already verified the device exists).
pub async fn touch_last_seen(pool: &SqlitePool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE admin_devices SET last_seen_at = datetime('now') WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

fn into_device_row(
    row: (
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        bool,
    ),
) -> AdminDeviceRow {
    let (id, label, public_key, platform, scopes, created_at, last_seen_at, revoked_at, is_active) =
        row;
    AdminDeviceRow {
        id,
        label,
        public_key,
        platform,
        scopes,
        created_at,
        last_seen_at,
        revoked_at,
        is_active,
    }
}

// ── Nonces (anti-replay) ───────────────────────────────────────────────────

/// Record a request nonce, rejecting replays. Returns `true` iff the nonce was new
/// (inserted now); `false` means it had already been seen — a replay. `INSERT OR
/// IGNORE` makes the seen-once check atomic on the PRIMARY KEY. Generic over the
/// executor so it can run inside the request-verification transaction.
pub async fn insert_nonce_if_absent<'e, E>(
    executor: E,
    nonce: &str,
    device_id: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "INSERT OR IGNORE INTO admin_nonces (nonce, device_id, seen_at) \
         VALUES (?, ?, datetime('now'))",
    )
    .bind(nonce)
    .bind(device_id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Delete nonces older than `max_age_seconds`, keeping the table bounded to roughly
/// the timestamp window. Returns the number of rows swept.
pub async fn sweep_stale_nonces(
    pool: &SqlitePool,
    max_age_seconds: i64,
) -> Result<u64, sqlx::Error> {
    if max_age_seconds < 0 {
        return Err(sqlx::Error::Protocol(
            "max_age_seconds must be non-negative".to_string(),
        ));
    }
    let modifier = format!("-{max_age_seconds} seconds");
    let result = sqlx::query("DELETE FROM admin_nonces WHERE seen_at <= datetime('now', ?)")
        .bind(&modifier)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_pool, run_migrations};

    async fn test_pool() -> SqlitePool {
        let pool = open_pool("sqlite::memory:").await.unwrap();
        run_migrations(&pool).await.unwrap();
        pool
    }

    fn sample_device(id: &str) -> NewAdminDevice<'_> {
        NewAdminDevice {
            id,
            label: "Operator iPhone",
            public_key: "did:key:zSampleDeviceKey",
            platform: "ios",
        }
    }

    // ── Pairing codes ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn insert_then_get_pairing_code_is_pending() {
        let pool = test_pool().await;
        let expires_at = insert_pairing_code(&pool, "PAIR-1", 5).await.unwrap();
        assert_eq!(
            expires_at.len(),
            19,
            "expires_at is a 19-char ISO-8601 datetime"
        );

        let row = get_pairing_code(&pool, "PAIR-1").await.unwrap().unwrap();
        assert_eq!(row.code, "PAIR-1");
        assert!(row.consumed_at.is_none());
        assert!(!row.is_expired);
        assert!(row.is_pending(), "a fresh, unconsumed code is pending");
    }

    #[tokio::test]
    async fn get_pairing_code_none_when_absent() {
        let pool = test_pool().await;
        assert_eq!(get_pairing_code(&pool, "nope").await.unwrap(), None);
    }

    #[tokio::test]
    async fn consume_pairing_code_is_single_use() {
        let pool = test_pool().await;
        insert_pairing_code(&pool, "PAIR-2", 5).await.unwrap();

        assert!(
            consume_pairing_code(&pool, "PAIR-2").await.unwrap(),
            "first claim consumes"
        );
        assert!(
            !consume_pairing_code(&pool, "PAIR-2").await.unwrap(),
            "second claim of the same code must fail (single-use)"
        );

        let row = get_pairing_code(&pool, "PAIR-2").await.unwrap().unwrap();
        assert!(row.consumed_at.is_some(), "consumed_at is stamped");
        assert!(!row.is_pending());
    }

    #[tokio::test]
    async fn consume_missing_pairing_code_returns_false() {
        let pool = test_pool().await;
        assert!(!consume_pairing_code(&pool, "ghost").await.unwrap());
    }

    #[tokio::test]
    async fn expired_pairing_code_is_not_pending_and_cannot_be_consumed() {
        let pool = test_pool().await;
        // Insert an already-expired code directly (expires in the past).
        sqlx::query(
            "INSERT INTO admin_pairing_codes (code, expires_at, created_at) \
             VALUES ('PAIR-OLD', datetime('now', '-1 minute'), datetime('now', '-6 minutes'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        let row = get_pairing_code(&pool, "PAIR-OLD").await.unwrap().unwrap();
        assert!(row.is_expired);
        assert!(!row.is_pending(), "an expired code is not pending");
        assert!(
            !consume_pairing_code(&pool, "PAIR-OLD").await.unwrap(),
            "an expired code cannot be consumed"
        );
    }

    #[tokio::test]
    async fn duplicate_pairing_code_rejected() {
        let pool = test_pool().await;
        insert_pairing_code(&pool, "DUP", 5).await.unwrap();
        let err = insert_pairing_code(&pool, "DUP", 5).await.unwrap_err();
        assert!(
            crate::db::is_unique_violation(&err),
            "duplicate pairing code must hit the PRIMARY KEY constraint"
        );
    }

    #[tokio::test]
    async fn consume_inside_transaction_with_device_insert() {
        // Mirrors the register-device flow: consume the code and insert the
        // device atomically in one transaction.
        let pool = test_pool().await;
        insert_pairing_code(&pool, "PAIR-TX", 5).await.unwrap();

        let mut tx = pool.begin().await.unwrap();
        assert!(consume_pairing_code(&mut *tx, "PAIR-TX").await.unwrap());
        insert_device(&mut *tx, &sample_device("dev-tx"))
            .await
            .unwrap();
        tx.commit().await.unwrap();

        assert!(get_device(&pool, "dev-tx").await.unwrap().is_some());
        let row = get_pairing_code(&pool, "PAIR-TX").await.unwrap().unwrap();
        assert!(row.consumed_at.is_some());
    }

    // ── Devices ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn insert_then_get_device_is_active() {
        let pool = test_pool().await;
        insert_device(&pool, &sample_device("dev-1")).await.unwrap();

        let row = get_device(&pool, "dev-1").await.unwrap().unwrap();
        assert_eq!(row.id, "dev-1");
        assert_eq!(row.label, "Operator iPhone");
        assert_eq!(row.public_key, "did:key:zSampleDeviceKey");
        assert_eq!(row.platform, "ios");
        assert_eq!(row.scopes, "full", "scopes defaults to full");
        assert!(row.last_seen_at.is_none());
        assert!(row.revoked_at.is_none());
        assert!(row.is_active);
    }

    #[tokio::test]
    async fn get_device_none_when_absent() {
        let pool = test_pool().await;
        assert_eq!(get_device(&pool, "nobody").await.unwrap(), None);
    }

    #[tokio::test]
    async fn duplicate_device_id_rejected() {
        let pool = test_pool().await;
        insert_device(&pool, &sample_device("dev-dup"))
            .await
            .unwrap();
        let err = insert_device(&pool, &sample_device("dev-dup"))
            .await
            .unwrap_err();
        assert!(
            crate::db::is_unique_violation(&err),
            "duplicate device id must hit the PRIMARY KEY constraint"
        );
    }

    #[tokio::test]
    async fn list_devices_returns_all_with_status() {
        let pool = test_pool().await;
        insert_device(&pool, &sample_device("dev-a")).await.unwrap();
        insert_device(&pool, &sample_device("dev-b")).await.unwrap();
        revoke_device(&pool, "dev-a").await.unwrap();

        let devices = list_devices(&pool).await.unwrap();
        assert_eq!(devices.len(), 2);

        let a = devices.iter().find(|d| d.id == "dev-a").unwrap();
        let b = devices.iter().find(|d| d.id == "dev-b").unwrap();
        assert!(!a.is_active, "revoked device reports inactive");
        assert!(a.revoked_at.is_some());
        assert!(b.is_active, "untouched device reports active");
    }

    #[tokio::test]
    async fn list_devices_breaks_same_second_ties_by_insertion_order() {
        // Two devices sharing a created_at must still list newest-insertion-first. The
        // random-UUID id is no recency signal, so the order rides on rowid (insertion
        // order). `zzz` < `aaa` lexically, proving the tie-break is not id-based.
        let pool = test_pool().await;
        for id in ["zzz-first", "aaa-second"] {
            sqlx::query(
                "INSERT INTO admin_devices (id, label, public_key, platform, created_at) \
                 VALUES (?, 'L', 'did:key:z', 'ios', '2026-06-28 12:00:00')",
            )
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        }

        let devices = list_devices(&pool).await.unwrap();
        assert_eq!(
            devices.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
            ["aaa-second", "zzz-first"],
            "the later insertion lists first despite an alphabetically smaller id"
        );
    }

    #[tokio::test]
    async fn revoke_device_is_idempotent() {
        let pool = test_pool().await;
        insert_device(&pool, &sample_device("dev-rev"))
            .await
            .unwrap();

        assert!(
            revoke_device(&pool, "dev-rev").await.unwrap(),
            "first revoke succeeds"
        );
        assert!(
            !revoke_device(&pool, "dev-rev").await.unwrap(),
            "revoking an already-revoked device affects no rows"
        );
        let row = get_device(&pool, "dev-rev").await.unwrap().unwrap();
        assert!(!row.is_active);
    }

    #[tokio::test]
    async fn revoke_missing_device_returns_false() {
        let pool = test_pool().await;
        assert!(!revoke_device(&pool, "ghost").await.unwrap());
    }

    #[tokio::test]
    async fn touch_last_seen_stamps_timestamp() {
        let pool = test_pool().await;
        insert_device(&pool, &sample_device("dev-seen"))
            .await
            .unwrap();
        assert!(
            get_device(&pool, "dev-seen")
                .await
                .unwrap()
                .unwrap()
                .last_seen_at
                .is_none(),
            "a fresh device has no last_seen_at"
        );

        touch_last_seen(&pool, "dev-seen").await.unwrap();

        assert!(
            get_device(&pool, "dev-seen")
                .await
                .unwrap()
                .unwrap()
                .last_seen_at
                .is_some(),
            "last_seen_at is stamped after touch"
        );
    }

    // ── Nonces ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn insert_nonce_rejects_replay() {
        let pool = test_pool().await;
        insert_device(&pool, &sample_device("dev-n")).await.unwrap();

        assert!(
            insert_nonce_if_absent(&pool, "nonce-1", "dev-n")
                .await
                .unwrap(),
            "a fresh nonce within the window is accepted exactly once"
        );
        assert!(
            !insert_nonce_if_absent(&pool, "nonce-1", "dev-n")
                .await
                .unwrap(),
            "reusing a previously-seen nonce is rejected"
        );
    }

    #[tokio::test]
    async fn distinct_nonces_both_accepted() {
        let pool = test_pool().await;
        insert_device(&pool, &sample_device("dev-n2"))
            .await
            .unwrap();

        assert!(insert_nonce_if_absent(&pool, "n-a", "dev-n2")
            .await
            .unwrap());
        assert!(insert_nonce_if_absent(&pool, "n-b", "dev-n2")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn same_nonce_accepted_once_per_device() {
        // Nonce uniqueness is scoped per device: the same value may be used once by
        // each device without colliding (replay detection asks "has THIS device seen
        // this nonce?"). A 128-bit random nonce makes cross-device collisions
        // negligible anyway, but the schema must not falsely reject them.
        let pool = test_pool().await;
        insert_device(&pool, &sample_device("dev-x")).await.unwrap();
        insert_device(&pool, &sample_device("dev-y")).await.unwrap();

        assert!(
            insert_nonce_if_absent(&pool, "shared", "dev-x")
                .await
                .unwrap(),
            "device x records the nonce"
        );
        assert!(
            insert_nonce_if_absent(&pool, "shared", "dev-y")
                .await
                .unwrap(),
            "device y may use the same nonce value independently"
        );
        assert!(
            !insert_nonce_if_absent(&pool, "shared", "dev-x")
                .await
                .unwrap(),
            "device x reusing its own nonce is still a replay"
        );
    }

    #[tokio::test]
    async fn nonce_requires_existing_device() {
        let pool = test_pool().await;
        // FK violations are reported regardless of OR IGNORE.
        let result = insert_nonce_if_absent(&pool, "orphan", "no-such-device").await;
        assert!(
            result.is_err(),
            "a nonce for an unknown device must be rejected by the FK"
        );
    }

    #[tokio::test]
    async fn sweep_removes_stale_keeps_fresh() {
        let pool = test_pool().await;
        insert_device(&pool, &sample_device("dev-sweep"))
            .await
            .unwrap();

        // One stale nonce (seen 5 minutes ago) and one fresh.
        sqlx::query(
            "INSERT INTO admin_nonces (nonce, device_id, seen_at) \
             VALUES ('stale', 'dev-sweep', datetime('now', '-5 minutes'))",
        )
        .execute(&pool)
        .await
        .unwrap();
        insert_nonce_if_absent(&pool, "fresh", "dev-sweep")
            .await
            .unwrap();

        let swept = sweep_stale_nonces(&pool, 120).await.unwrap();
        assert_eq!(swept, 1, "only the stale nonce is swept");

        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM admin_nonces")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "the fresh nonce survives");
    }

    #[tokio::test]
    async fn negative_durations_rejected() {
        // A negative interval would format into an invalid SQLite modifier
        // ("+-5 minutes" / "--5 seconds"); reject it up front instead of letting it
        // become a NULL datetime (NOT NULL error) or a silent no-op sweep.
        let pool = test_pool().await;
        assert!(insert_pairing_code(&pool, "NEG", -5).await.is_err());
        assert!(sweep_stale_nonces(&pool, -1).await.is_err());

        // The rejected insert wrote nothing.
        assert_eq!(get_pairing_code(&pool, "NEG").await.unwrap(), None);
    }
}
