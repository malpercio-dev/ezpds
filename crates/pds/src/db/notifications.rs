// pattern: Imperative Shell

//! Queries over the three notification tables (V058): the instance's versioned sender keys,
//! and the per-device registrations for each app surface.
//!
//! Sender-key status is derived from timestamps rather than stored as a column, following the
//! `claim_codes` doctrine — there is no state machine to drift out of sync with reality:
//!
//! * **active** — `retired_at IS NULL AND revoked_at IS NULL`. Published, and the newest one
//!   seals every outgoing payload.
//! * **retired** — `retired_at` set. Still published, so a device can still verify a payload
//!   sealed before the rotation, but never used to seal anything new.
//! * **revoked** — `revoked_at` set. Gone from the published set on the next fetch. The row
//!   survives as a tombstone so its `kid` is never reissued by the AUTOINCREMENT counter.
//!
//! Like every `db/` module this file moves opaque ciphertext only: wrapping and unwrapping the
//! sender secret happens in the caller (`crate::notifications`).

use sqlx::SqlitePool;

/// A sender key as stored: the wrapped secret plus its derived status flags.
#[derive(Debug, Clone)]
pub struct SenderKeyRow {
    /// The versioned key id devices see in the envelope. INTEGER PK, monotonically
    /// increasing, never reused.
    pub kid: i64,
    /// The AES-256-GCM-wrapped 32-byte P-256 scalar (`crypto::encrypt_secret_bytes`).
    pub secret_key_encrypted: String,
    /// `true` once the key has been rotated out of sealing duty but is still published.
    pub retired: bool,
}

/// Every sender key a device may still verify against: active and retired, never revoked.
///
/// This is exactly the set the `sender-keys` routes publish. Revocation takes effect the
/// moment the row is stamped — there is no overlap window for a compromised key, which is
/// the whole point of distinguishing revoke from retire.
///
/// Newest first, so a caller wanting "the key to seal with" reads the head.
pub async fn list_publishable_sender_keys(
    pool: &SqlitePool,
) -> Result<Vec<SenderKeyRow>, sqlx::Error> {
    let rows: Vec<(i64, String, Option<String>)> = sqlx::query_as(
        "SELECT kid, secret_key_encrypted, retired_at FROM notification_sender_keys \
         WHERE revoked_at IS NULL ORDER BY kid DESC",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(kid, secret_key_encrypted, retired_at)| SenderKeyRow {
            kid,
            secret_key_encrypted,
            retired: retired_at.is_some(),
        })
        .collect())
}

/// The key new payloads are sealed with: the newest key that is neither retired nor revoked.
///
/// `None` means the instance has never generated one (or every key has been retired or
/// revoked without a replacement) — the caller generates one rather than sending unsealed.
pub async fn get_active_sender_key(pool: &SqlitePool) -> Result<Option<SenderKeyRow>, sqlx::Error> {
    let row: Option<(i64, String)> = sqlx::query_as(
        "SELECT kid, secret_key_encrypted FROM notification_sender_keys \
         WHERE retired_at IS NULL AND revoked_at IS NULL ORDER BY kid DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(kid, secret_key_encrypted)| SenderKeyRow {
        kid,
        secret_key_encrypted,
        retired: false,
    }))
}

/// Store a freshly generated wrapped sender secret, returning its assigned `kid`.
pub async fn insert_sender_key(
    pool: &SqlitePool,
    secret_key_encrypted: &str,
) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "INSERT INTO notification_sender_keys (secret_key_encrypted, created_at) \
         VALUES (?, datetime('now')) RETURNING kid",
    )
    .bind(secret_key_encrypted)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Retire a key: stop sealing with it, keep publishing it so already-delivered payloads still
/// verify. Idempotent — the guard keeps the original retirement timestamp.
///
/// Reports whether this call actually transitioned a row, so a caller can tell a real
/// retirement from a no-op on an unknown or already-retired `kid`. The operator CLI prints the
/// difference: without it, a mistyped `kid` reads as success.
pub async fn retire_sender_key(pool: &SqlitePool, kid: i64) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE notification_sender_keys SET retired_at = datetime('now') \
         WHERE kid = ? AND retired_at IS NULL",
    )
    .bind(kid)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Revoke a key: remove it from the published set immediately. Idempotent.
///
/// Reports whether this call transitioned a row, for the same reason [`retire_sender_key`]
/// does — and it matters more here, since an operator revoking a key believes they have just
/// closed a compromise.
pub async fn revoke_sender_key(pool: &SqlitePool, kid: i64) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE notification_sender_keys SET revoked_at = datetime('now') \
         WHERE kid = ? AND revoked_at IS NULL",
    )
    .bind(kid)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

// ── Registrations ─────────────────────────────────────────────────────────────

/// One device's registration — the account surface and the admin surface share this shape,
/// differing only in what identifies the device.
#[derive(Debug, Clone)]
pub struct RegistrationRow {
    /// `device_uuid` for an account registration, `admin_device_id` for an admin one.
    pub device_id: String,
    /// The device's notification `did:key` — what payloads are sealed to.
    pub notification_public_key: String,
    /// The relay's opaque handle; `None` until the relay round trip has succeeded.
    pub push_handle: Option<String>,
    /// Metadata-minimizing ping mode: the device asked for content-free background pushes
    /// instead of sealed payloads. Default `false` — sealed stays the default.
    pub ping: bool,
}

// `apns_token`/`apns_topic` are deliberately absent: they are written from the request body
// and read only by the relay, which knows them by handle. Selecting them here would invite a
// caller to make a delivery decision from a stale copy of Apple's routing state.

/// Create or replace an account device's registration.
///
/// An upsert rather than an insert because the app re-registers on every APNs token change
/// and on every reinstall — a device that rotates its token must not accumulate rows, and
/// the primary key is what enforces that. `push_handle` is deliberately reset to NULL: the
/// old handle points at the previous token, and re-registering with the relay mints a new one.
pub async fn upsert_registration(
    pool: &SqlitePool,
    did: &str,
    device_uuid: &str,
    notification_public_key: &str,
    apns_token: &str,
    apns_topic: &str,
    ping: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO notification_registrations \
             (did, device_uuid, notification_public_key, apns_token, apns_topic, ping, \
              push_handle, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, NULL, datetime('now'), datetime('now')) \
         ON CONFLICT(did, device_uuid) DO UPDATE SET \
             notification_public_key = excluded.notification_public_key, \
             apns_token = excluded.apns_token, \
             apns_topic = excluded.apns_topic, \
             ping = excluded.ping, \
             push_handle = NULL, \
             updated_at = datetime('now')",
    )
    .bind(did)
    .bind(device_uuid)
    .bind(notification_public_key)
    .bind(apns_token)
    .bind(apns_topic)
    .bind(ping)
    .execute(pool)
    .await?;
    Ok(())
}

/// Every registration for an account — the fan-out set for `notify_device`.
pub async fn list_registrations(
    pool: &SqlitePool,
    did: &str,
) -> Result<Vec<RegistrationRow>, sqlx::Error> {
    let rows: Vec<(String, String, Option<String>, bool)> = sqlx::query_as(
        "SELECT device_uuid, notification_public_key, push_handle, ping \
         FROM notification_registrations WHERE did = ? ORDER BY device_uuid",
    )
    .bind(did)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(into_registration).collect())
}

/// Record the relay handle that every registration naming this APNs token now resolves through.
///
/// Scoped to the **token**, not to the `(did, device_uuid)` whose request minted the handle,
/// because the token is the relay's own rotation key: registering it there drops the previous
/// handle for it, so one token has exactly one live handle at any instant. A device holding
/// several identities on this instance re-registers all of them on every app open, and a
/// per-DID write-back left every identity but the last naming a handle the relay had already
/// rotated away. Those pushes come back `unknownHandle`, which is correctly not a prune
/// signal — so the rows survive to fail again on the next open, silently.
///
/// Keying on the token rather than on `device_uuid` is what keeps a token change honest: a row
/// whose token has already moved on matches nothing here, and the job for its new token stamps
/// it instead.
///
/// Deliberately **unconditional** — no `push_handle IS NULL` guard. The send worker is a
/// single task draining a FIFO queue and awaiting each job to completion, so handle writes
/// land in registration order and the last one is by construction the newest. That ordering
/// is load-bearing: a guarded write would reject the *second* of two re-registrations
/// (the first job's handle is already stored by then), stranding the handle for the
/// superseded APNs token — the exact staleness a guard looks like it would prevent.
///
/// Reports how many rows were stamped, so a caller can tell a normal write from a handle no
/// registration claims.
pub async fn set_registration_handles_for_token(
    pool: &SqlitePool,
    apns_token: &str,
    push_handle: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE notification_registrations SET push_handle = ?, updated_at = datetime('now') \
         WHERE apns_token = ?",
    )
    .bind(push_handle)
    .bind(apns_token)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Delete a registration, returning whether a row existed.
///
/// Called both by the explicit DELETE route and by the send path when the relay reports the
/// device token dead (APNs 410) — pruning at the moment of proof, rather than accumulating
/// tombstones for devices that will never receive again.
pub async fn delete_registration(
    pool: &SqlitePool,
    did: &str,
    device_uuid: &str,
) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("DELETE FROM notification_registrations WHERE did = ? AND device_uuid = ?")
            .bind(did)
            .bind(device_uuid)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() > 0)
}

// ── Admin registrations ───────────────────────────────────────────────────────

/// Create or replace an admin device's registration. Same upsert reasoning as the account
/// surface, keyed by the authenticated admin device instead.
pub async fn upsert_admin_registration(
    pool: &SqlitePool,
    admin_device_id: &str,
    notification_public_key: &str,
    apns_token: &str,
    apns_topic: &str,
    ping: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin_notification_registrations \
             (admin_device_id, notification_public_key, apns_token, apns_topic, ping, \
              push_handle, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, NULL, datetime('now'), datetime('now')) \
         ON CONFLICT(admin_device_id) DO UPDATE SET \
             notification_public_key = excluded.notification_public_key, \
             apns_token = excluded.apns_token, \
             apns_topic = excluded.apns_topic, \
             ping = excluded.ping, \
             push_handle = NULL, \
             updated_at = datetime('now')",
    )
    .bind(admin_device_id)
    .bind(notification_public_key)
    .bind(apns_token)
    .bind(apns_topic)
    .bind(ping)
    .execute(pool)
    .await?;
    Ok(())
}

/// Every *active* admin device's registration.
///
/// The join against `admin_devices` is what would make revocation authoritative for pushes
/// too: a revoked device stops receiving operational alerts the instant its tombstone is
/// stamped, without waiting for the cleanup delete to run. No route sends an operator alert
/// yet, so the only current caller is `admin_notifications.rs`'s own registration tests.
#[cfg(test)]
pub(crate) async fn list_active_admin_registrations(
    pool: &SqlitePool,
) -> Result<Vec<RegistrationRow>, sqlx::Error> {
    let rows: Vec<(String, String, Option<String>, bool)> = sqlx::query_as(
        "SELECT r.admin_device_id, r.notification_public_key, r.push_handle, r.ping \
         FROM admin_notification_registrations r \
         JOIN admin_devices d ON d.id = r.admin_device_id \
         WHERE d.revoked_at IS NULL ORDER BY r.admin_device_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(into_registration).collect())
}

/// The relay handle for one admin device, regardless of the device's revocation status.
///
/// Deliberately *not* the active-only query: the caller that needs this most is the revoke
/// cleanup, which runs after the tombstone is stamped. Reusing the fan-out query there would
/// silently find nothing and leave the relay holding a live route to a cut-off device.
pub async fn admin_registration_handle(
    pool: &SqlitePool,
    admin_device_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT push_handle FROM admin_notification_registrations WHERE admin_device_id = ?",
    )
    .bind(admin_device_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(handle,)| handle))
}

/// The operator analog: stamp the handle onto every admin registration naming this APNs token.
///
/// Token-scoped and unconditional for the same reasons as
/// [`set_registration_handles_for_token`]. The two tables fan out separately rather than
/// through one query because Apple issues a device token per *app*: the wallet and the console
/// can never present the same one, so a row here and a row there are never two claims on a
/// single relay handle.
pub async fn set_admin_registration_handles_for_token(
    pool: &SqlitePool,
    apns_token: &str,
    push_handle: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE admin_notification_registrations \
         SET push_handle = ?, updated_at = datetime('now') WHERE apns_token = ?",
    )
    .bind(push_handle)
    .bind(apns_token)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Delete an admin device's registration. Idempotent; called on revoke and on 410 pruning.
pub async fn delete_admin_registration(
    pool: &SqlitePool,
    admin_device_id: &str,
) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("DELETE FROM admin_notification_registrations WHERE admin_device_id = ?")
            .bind(admin_device_id)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() > 0)
}

fn into_registration(
    (device_id, notification_public_key, push_handle, ping): (String, String, Option<String>, bool),
) -> RegistrationRow {
    RegistrationRow {
        device_id,
        notification_public_key,
        push_handle,
        ping,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_pool, run_migrations};

    async fn pool() -> SqlitePool {
        let pool = open_pool("sqlite::memory:").await.expect("pool");
        run_migrations(&pool).await.expect("migrations");
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:notif', 'n@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .expect("seed account");
        pool
    }

    #[tokio::test]
    async fn sender_keys_are_versioned_and_the_newest_is_the_active_one() {
        let pool = pool().await;
        let first = insert_sender_key(&pool, "wrapped-1").await.unwrap();
        let second = insert_sender_key(&pool, "wrapped-2").await.unwrap();
        assert!(second > first, "kids must increase, never be reused");

        assert_eq!(
            get_active_sender_key(&pool).await.unwrap().unwrap().kid,
            second
        );
    }

    /// The rotation contract, in one test: retiring the old key keeps it verifiable while
    /// moving sealing duty to the new one.
    #[tokio::test]
    async fn a_retired_key_still_verifies_but_no_longer_seals() {
        let pool = pool().await;
        let old = insert_sender_key(&pool, "wrapped-old").await.unwrap();
        let new = insert_sender_key(&pool, "wrapped-new").await.unwrap();
        retire_sender_key(&pool, old).await.unwrap();

        let published = list_publishable_sender_keys(&pool).await.unwrap();
        assert_eq!(
            published.iter().map(|k| k.kid).collect::<Vec<_>>(),
            vec![new, old],
            "a retired key stays published so in-flight payloads still verify"
        );
        assert!(published.iter().find(|k| k.kid == old).unwrap().retired);
        assert_eq!(
            get_active_sender_key(&pool).await.unwrap().unwrap().kid,
            new
        );
    }

    /// Revocation is the compromise path, so it must be immediate — not a retirement with a
    /// grace period.
    #[tokio::test]
    async fn a_revoked_key_vanishes_from_the_published_set_at_once() {
        let pool = pool().await;
        let compromised = insert_sender_key(&pool, "wrapped-bad").await.unwrap();
        let good = insert_sender_key(&pool, "wrapped-good").await.unwrap();
        revoke_sender_key(&pool, compromised).await.unwrap();

        let published = list_publishable_sender_keys(&pool).await.unwrap();
        assert_eq!(
            published.iter().map(|k| k.kid).collect::<Vec<_>>(),
            vec![good]
        );
        assert_eq!(
            get_active_sender_key(&pool).await.unwrap().unwrap().kid,
            good
        );

        // The tombstone stays, so the kid is never handed out a second time.
        let next = insert_sender_key(&pool, "wrapped-next").await.unwrap();
        assert!(next > good && next > compromised);
    }

    #[tokio::test]
    async fn retire_and_revoke_are_idempotent() {
        let pool = pool().await;
        let kid = insert_sender_key(&pool, "wrapped").await.unwrap();
        assert!(retire_sender_key(&pool, kid).await.unwrap());
        let first: Option<String> =
            sqlx::query_scalar("SELECT retired_at FROM notification_sender_keys WHERE kid = ?")
                .bind(kid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            !retire_sender_key(&pool, kid).await.unwrap(),
            "a repeat retire transitions nothing"
        );

        assert!(revoke_sender_key(&pool, kid).await.unwrap());
        let revoked_first: Option<String> =
            sqlx::query_scalar("SELECT revoked_at FROM notification_sender_keys WHERE kid = ?")
                .bind(kid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            !revoke_sender_key(&pool, kid).await.unwrap(),
            "a repeat revoke transitions nothing"
        );

        let (again, revoked_again): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT retired_at, revoked_at FROM notification_sender_keys WHERE kid = ?",
        )
        .bind(kid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(first, again, "a repeat retire must not move the timestamp");
        assert_eq!(
            revoked_first, revoked_again,
            "a repeat revoke must not move the timestamp"
        );
    }

    /// An unknown kid must report that it changed nothing — the operator CLI turns this into a
    /// loud failure, so a mistyped kid cannot read as a successful revocation.
    #[tokio::test]
    async fn retiring_or_revoking_an_unknown_key_reports_no_transition() {
        let pool = pool().await;
        assert!(!retire_sender_key(&pool, 9999).await.unwrap());
        assert!(!revoke_sender_key(&pool, 9999).await.unwrap());
    }

    /// The revoke cleanup runs *after* the device tombstone is stamped, so this lookup must
    /// stay status-independent — scoping it to active devices would silently find nothing and
    /// leave the relay holding a route to a cut-off device.
    #[tokio::test]
    async fn an_admin_handle_is_still_readable_after_the_device_is_revoked() {
        let pool = pool().await;
        seed_admin_device(&pool, "adm-1").await;
        upsert_admin_registration(&pool, "adm-1", "pk", "tok", "org.obsign.admin", false)
            .await
            .unwrap();
        set_admin_registration_handles_for_token(&pool, "tok", "handle-1")
            .await
            .unwrap();
        sqlx::query("UPDATE admin_devices SET revoked_at = datetime('now') WHERE id = 'adm-1'")
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(
            admin_registration_handle(&pool, "adm-1").await.unwrap(),
            Some("handle-1".to_owned()),
            "the cleanup must still find the handle to drop at the relay"
        );
    }

    #[tokio::test]
    async fn with_no_keys_at_all_there_is_nothing_to_publish_or_seal_with() {
        let pool = pool().await;
        assert!(list_publishable_sender_keys(&pool)
            .await
            .unwrap()
            .is_empty());
        assert!(get_active_sender_key(&pool).await.unwrap().is_none());
    }

    /// Re-registering the same device replaces its row rather than adding one — and drops the
    /// stale handle, which pointed at the previous APNs token.
    #[tokio::test]
    async fn re_registering_a_device_replaces_its_row_and_clears_the_handle() {
        let pool = pool().await;
        upsert_registration(
            &pool,
            "did:plc:notif",
            "dev-1",
            "pk1",
            "tok1",
            "org.obsign.app",
            false,
        )
        .await
        .unwrap();
        set_registration_handles_for_token(&pool, "tok1", "handle-1")
            .await
            .unwrap();
        upsert_registration(
            &pool,
            "did:plc:notif",
            "dev-1",
            "pk2",
            "tok2",
            "org.obsign.app",
            false,
        )
        .await
        .unwrap();

        let rows = list_registrations(&pool, "did:plc:notif").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].notification_public_key, "pk2");
        let token: String = sqlx::query_scalar(
            "SELECT apns_token FROM notification_registrations WHERE device_uuid = 'dev-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(token, "tok2");
        assert_eq!(
            rows[0].push_handle, None,
            "the old handle names the old token; it must not survive re-registration"
        );
    }

    /// The ping preference round-trips through the upsert, and — like every other field — a
    /// re-registration overwrites it, so turning the toggle back off actually lands.
    #[tokio::test]
    async fn the_ping_preference_round_trips_and_defaults_to_sealed() {
        let pool = pool().await;
        upsert_registration(
            &pool,
            "did:plc:notif",
            "dev-1",
            "pk",
            "tok",
            "org.obsign.app",
            false,
        )
        .await
        .unwrap();
        assert!(
            !list_registrations(&pool, "did:plc:notif").await.unwrap()[0].ping,
            "sealed is the default"
        );

        for ping in [true, false] {
            upsert_registration(
                &pool,
                "did:plc:notif",
                "dev-1",
                "pk",
                "tok",
                "org.obsign.app",
                ping,
            )
            .await
            .unwrap();
            assert_eq!(
                list_registrations(&pool, "did:plc:notif").await.unwrap()[0].ping,
                ping,
                "a re-registration must carry the toggle in both directions"
            );
        }
    }

    async fn seed_second_account(pool: &SqlitePool) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:notif2', 'n2@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .execute(pool)
        .await
        .expect("seed second account");
    }

    /// Two identities on one device share one APNs token, and the relay keeps one live handle
    /// per token — so a mint made on either identity's behalf is the handle *both* must use.
    /// Stamping only the requesting row left the other naming a rotated-away handle, whose
    /// pushes the relay refuses as `unknownHandle` with nothing surfacing to the user.
    #[tokio::test]
    async fn one_mint_carries_every_identity_sharing_the_device_token() {
        let pool = pool().await;
        seed_second_account(&pool).await;
        for did in ["did:plc:notif", "did:plc:notif2"] {
            upsert_registration(
                &pool,
                did,
                "dev-1",
                "pk",
                "shared-tok",
                "org.obsign.app",
                false,
            )
            .await
            .unwrap();
        }

        // One registration's round trip completes. It speaks for the token, not for its row.
        let stamped = set_registration_handles_for_token(&pool, "shared-tok", "handle-live")
            .await
            .unwrap();
        assert_eq!(stamped, 2, "both identities name this token");

        for did in ["did:plc:notif", "did:plc:notif2"] {
            let rows = list_registrations(&pool, did).await.unwrap();
            assert_eq!(
                rows[0].push_handle.as_deref(),
                Some("handle-live"),
                "{did} must resolve through the relay's one live handle"
            );
        }
    }

    /// The reason the fan-out keys on the token and not on `device_uuid`: a row whose token has
    /// already moved on must not be handed a handle minted for the token it left behind.
    #[tokio::test]
    async fn a_registration_that_changed_token_is_left_to_its_own_mint() {
        let pool = pool().await;
        seed_second_account(&pool).await;
        upsert_registration(
            &pool,
            "did:plc:notif",
            "dev-1",
            "pk",
            "old-tok",
            "org.obsign.app",
            false,
        )
        .await
        .unwrap();
        upsert_registration(
            &pool,
            "did:plc:notif2",
            "dev-1",
            "pk",
            "new-tok",
            "org.obsign.app",
            false,
        )
        .await
        .unwrap();

        let stamped = set_registration_handles_for_token(&pool, "old-tok", "handle-old")
            .await
            .unwrap();
        assert_eq!(stamped, 1);
        assert_eq!(
            list_registrations(&pool, "did:plc:notif2").await.unwrap()[0].push_handle,
            None,
            "a handle for the old token says nothing about the new one"
        );
    }

    /// Nothing claiming the handle is a distinguishable outcome, not a silent no-op: the caller
    /// gives the orphaned handle back to the relay rather than leaving a live route to a device
    /// this instance can no longer address.
    #[tokio::test]
    async fn a_handle_no_registration_claims_reports_zero() {
        let pool = pool().await;
        assert_eq!(
            set_registration_handles_for_token(&pool, "vanished-tok", "handle-orphan")
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn deleting_a_registration_reports_whether_one_existed() {
        let pool = pool().await;
        upsert_registration(
            &pool,
            "did:plc:notif",
            "dev-1",
            "pk",
            "tok",
            "org.obsign.app",
            false,
        )
        .await
        .unwrap();
        assert!(delete_registration(&pool, "did:plc:notif", "dev-1")
            .await
            .unwrap());
        assert!(!delete_registration(&pool, "did:plc:notif", "dev-1")
            .await
            .unwrap());
        assert!(list_registrations(&pool, "did:plc:notif")
            .await
            .unwrap()
            .is_empty());
    }

    async fn seed_admin_device(pool: &SqlitePool, id: &str) {
        sqlx::query(
            "INSERT INTO admin_devices (id, label, public_key, platform, scopes, created_at) \
             VALUES (?, 'console', 'zPub', 'ios', 'admin', datetime('now'))",
        )
        .bind(id)
        .execute(pool)
        .await
        .expect("seed admin device");
    }

    /// The operator surface composes the same way: an operator who re-pairs gets a second
    /// `admin_devices` row for one physical console, and both registrations present that
    /// console's single APNs token. The relay keeps one handle for it, so both rows must
    /// follow it.
    #[tokio::test]
    async fn one_mint_carries_every_admin_device_sharing_the_console_token() {
        let pool = pool().await;
        for id in ["adm-1", "adm-2"] {
            seed_admin_device(&pool, id).await;
            upsert_admin_registration(&pool, id, "pk", "console-tok", "org.obsign.admin", false)
                .await
                .unwrap();
        }

        let stamped = set_admin_registration_handles_for_token(&pool, "console-tok", "handle-live")
            .await
            .unwrap();
        assert_eq!(stamped, 2);
        for id in ["adm-1", "adm-2"] {
            assert_eq!(
                admin_registration_handle(&pool, id)
                    .await
                    .unwrap()
                    .as_deref(),
                Some("handle-live"),
                "{id} must resolve through the relay's one live handle"
            );
        }
    }

    /// Revoking the device is enough to stop its pushes — the fan-out query joins on the
    /// tombstone, so it never depends on the cleanup delete having run.
    #[tokio::test]
    async fn a_revoked_admin_device_drops_out_of_the_fan_out_immediately() {
        let pool = pool().await;
        seed_admin_device(&pool, "adm-1").await;
        seed_admin_device(&pool, "adm-2").await;
        upsert_admin_registration(&pool, "adm-1", "pk1", "tok1", "org.obsign.admin", false)
            .await
            .unwrap();
        upsert_admin_registration(&pool, "adm-2", "pk2", "tok2", "org.obsign.admin", false)
            .await
            .unwrap();

        sqlx::query("UPDATE admin_devices SET revoked_at = datetime('now') WHERE id = 'adm-1'")
            .execute(&pool)
            .await
            .unwrap();

        let active = list_active_admin_registrations(&pool).await.unwrap();
        assert_eq!(
            active
                .iter()
                .map(|r| r.device_id.as_str())
                .collect::<Vec<_>>(),
            vec!["adm-2"]
        );

        assert!(delete_admin_registration(&pool, "adm-1").await.unwrap());
        assert!(!delete_admin_registration(&pool, "adm-1").await.unwrap());
    }
}
