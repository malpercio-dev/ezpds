// pattern: Imperative Shell
//
// Shared permanent account-deletion machinery, used by both the standard XRPC surface
// (`routes/delete_account.rs`, POST /xrpc/com.atproto.server.deleteAccount) and the scheduled
// deletion reaper (`account_reaper.rs`, which acts on `deleteAfter`). Deletion is a multi-table
// atomic transaction plus a firehose `#account` (deleted) frame, so it lives here as a dedicated
// helper rather than in a `db/` submodule (those own single-table queries, not business
// transactions) and rather than in a route (routes must not import from one another).
//
// **What deletion does NOT do.** ezpds is wallet-native: the PDS never holds the DID's top
// rotation key (ADR-0001), so it cannot sign a PLC tombstone the way a key-custodying PDS would.
// Deletion therefore removes all *local* account data and announces the removal on the firehose;
// the did:plc identity itself remains on plc.directory under the wallet's control (the wallet can
// tombstone or migrate it independently). This mirrors the reference PDS's `deleteAccount`, which
// likewise deletes local data and sequences an account event rather than tombstoning the identity.

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::db::accounts::{deactivate_account, AccountStateChange};

/// The firehose `#account` status reported for a permanent deletion.
const STATUS_DELETED: &str = "deleted";

/// The firehose `#account` status reported for a cascade-scheduled child's deactivation.
const STATUS_DEACTIVATED: &str = "deactivated";

/// Outcome of [`purge_account`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeOutcome {
    /// The account existed and was fully deleted; a `#account` (deleted) frame was emitted.
    Deleted,
    /// No account row matched the DID (already gone / never existed). Idempotent no-op: no data
    /// was changed and no firehose frame was emitted.
    NotFound,
}

/// Child tables that hold a row per account keyed by a `did` column, listed in an order that
/// respects the inter-child foreign keys (**no account-keyed FK cascades**: the schema's only
/// `ON DELETE CASCADE`s hang content-addressed ownership rows off their physical tables
/// (`block_owners.cid` → `blocks`, `blob_owners.cid` → `blobs`), never off `accounts`, so every
/// child must be deleted explicitly and in dependency order before the `accounts` row):
///
/// * `refresh_tokens` before `sessions` (`refresh_tokens.session_id → sessions.id`)
/// * `transfer_audit_events` before `transfers` before `transfer_devices`
///   (`transfer_audit_events.transfer_id → transfers.id`, `transfers.accepted_device_id →
///   transfer_devices.id`)
/// * `agent_audit_events` and `agent_claim_attempts` before `agent_identities`
///   (`agent_audit_events.registration_id → agent_identities.id`,
///   `agent_claim_attempts.identity_id → agent_identities.id`); audit events are keyed through
///   the identity rather than their own `did` column because pre-claim events on an anonymous
///   registration carry a NULL `did` but still pin the identity row via the FK. Any audit event
///   left carrying this DID on a *foreign* account's registration is part of that account's
///   trail, so it is unlinked (`did = NULL` — the column is nullable) rather than deleted.
/// * `sovereign_session_nonces` before `accounts` (each replay row is FK-owned by its DID)
/// * `email_tokens` before `accounts` (FK-owned by the DID; consumption only stamps `used_at`,
///   so confirm/update rows persist for the account's lifetime and must be purged here)
/// * `recovery_otps`, `recovery_audit_events`, and `recovery_escrow` before `accounts` (all
///   FK-owned by the DID; no FK links them, so their relative order is free)
///
/// The sovereign-child-agent tables (V047/V049) are scoped by *both* of their DID columns:
///
/// * `agent_identities` / `agent_child_provisionings` are additionally keyed
///   `WHERE parent_did = ?`: a purged parent's children lose the account their custody chains to
///   (ADR-0023), so their registration/provisioning rows go with the parent — the child
///   *accounts* are cascade-scheduled for the reaper by `purge_account` itself (see below).
/// * `agent_child_provisionings` is keyed `WHERE child_did = ?`: a minted child's provisioning row
///   FK-references `accounts(did)` on `child_did`, so deleting a child account without first
///   removing this row is a foreign-key violation. A no-op for a non-child account (only children
///   have a provisioning row).
/// * `agent_child_deletions` is keyed `WHERE parent_did = ?` — never `child_did`. It is the durable
///   child-deletion tombstone that must *survive* a child's purge to keep the parent's audit view
///   alive, so it carries no FK on `child_did`; it is anchored to `parent_did` and reclaimed only
///   when the *parent* is deleted. A no-op for a child (a child authors no deletions).
///
/// The `purge_covers_every_account_foreign_key_in_the_schema` test walks the live schema's
/// FK graph and fails if a migration adds an account-keyed table this list doesn't reach.
///
/// `did_documents` and `reserved_signing_keys` carry the DID with no FK to `accounts`, but are
/// scoped by `did` so removing this account's rows is correct. `repo_seq` (the durable firehose
/// log) is deliberately **excluded**: it is a shared, densely-sequenced log and punching per-DID
/// holes in it would break cursor-replay's density invariant for every other account. The
/// account's history there ages out via the normal retention sweep; the `#account` (deleted) frame
/// we emit is how subscribers learn the account is gone.
const DELETE_BY_DID: &[&str] = &[
    "DELETE FROM account_labels WHERE did = ?",
    "DELETE FROM operator_account_audit_events WHERE did = ?",
    "DELETE FROM refresh_tokens WHERE did = ?",
    "DELETE FROM sessions WHERE did = ?",
    "DELETE FROM oauth_tokens WHERE did = ?",
    "DELETE FROM oauth_authorization_codes WHERE did = ?",
    "DELETE FROM handles WHERE did = ?",
    "DELETE FROM signing_keys WHERE did = ?",
    "DELETE FROM account_preferences WHERE did = ?",
    "DELETE FROM app_passwords WHERE did = ?",
    "DELETE FROM password_reset_tokens WHERE did = ?",
    "DELETE FROM plc_operation_tokens WHERE did = ?",
    "DELETE FROM account_deletion_tokens WHERE did = ?",
    "DELETE FROM sovereign_session_nonces WHERE did = ?",
    "DELETE FROM email_tokens WHERE did = ?",
    "DELETE FROM recovery_otps WHERE did = ?",
    "DELETE FROM recovery_audit_events WHERE did = ?",
    "DELETE FROM recovery_escrow WHERE did = ?",
    "DELETE FROM agent_audit_events WHERE registration_id IN (SELECT id FROM agent_identities WHERE did = ?)",
    "DELETE FROM agent_audit_events WHERE registration_id IN (SELECT id FROM agent_identities WHERE parent_did = ?)",
    "DELETE FROM agent_claim_attempts WHERE identity_id IN (SELECT id FROM agent_identities WHERE did = ?)",
    "DELETE FROM agent_claim_attempts WHERE identity_id IN (SELECT id FROM agent_identities WHERE parent_did = ?)",
    "DELETE FROM agent_identities WHERE did = ?",
    "DELETE FROM agent_identities WHERE parent_did = ?",
    "UPDATE agent_audit_events SET did = NULL WHERE did = ?",
    "DELETE FROM agent_child_provisionings WHERE child_did = ?",
    "DELETE FROM agent_child_provisionings WHERE parent_did = ?",
    "DELETE FROM agent_child_deletions WHERE parent_did = ?",
    "DELETE FROM transfer_audit_events WHERE did = ?",
    "DELETE FROM transfers WHERE did = ?",
    "DELETE FROM transfer_devices WHERE did = ?",
    "DELETE FROM did_documents WHERE did = ?",
    "DELETE FROM reserved_signing_keys WHERE did = ?",
];

/// The account's ownership rows in the content-addressed repo block store.
///
/// `blocks` is keyed by `cid` globally and stores the physical bytes once. `block_owners` is the
/// authoritative account-scoped metadata, so deletion removes this account's references and then
/// reclaims only unowned, non-legacy physical bytes.
const DELETE_BLOCKS: &str = "DELETE FROM block_owners WHERE account_did = ?";

/// Permanently delete an account and everything it owns, atomically, and announce the removal on
/// the firehose.
///
/// Steps, in order:
/// 1. Under the firehose sequencer lock (acquired before the transaction, per `lock_emit`'s
///    ordering contract), open a transaction and delete every child table in FK order — including
///    the account's `blob_owners` rows, reclaiming (with `RETURNING cid, storage_path`) only the
///    physical blobs left with no owner, so the list of files to remove is captured atomically
///    with the rows actually deleted and a blob another account still owns keeps its file —
///    then delete the `accounts` row.
/// 2. If the `accounts` row did not exist, roll back and report [`PurgeOutcome::NotFound`] —
///    idempotent, no frame emitted, and the rolled-back blob deletes leave the files on disk.
/// 3. Otherwise stage an `#account` (`active=false`, `status="deleted"`) frame in the same
///    transaction, commit, and broadcast it.
/// 4. Best-effort: delete the reclaimed blob files from disk (a failure here leaks a file for the
///    blob GC / operator to reclaim later, but the account is already gone from the DB and
///    firehose, so it is logged, not propagated).
pub async fn purge_account(state: &AppState, did: &str) -> Result<PurgeOutcome, ApiError> {
    let map_err = |e: sqlx::Error| {
        tracing::error!(did = %did, error = %e, "DB error deleting account");
        ApiError::new(ErrorCode::InternalError, "failed to delete account")
    };

    // Step 1: acquire the sequencer lock *before* the transaction (see `Firehose::lock_emit`),
    // then delete every child row and the account row atomically.
    let emit_guard = state.firehose.lock_emit().await;
    let mut tx = state.db.begin().await.map_err(map_err)?;

    // Cascade: a purged parent's sovereign children lose the account their recovery authority
    // chains to (ADR-0023), so each child is scheduled for the same deactivate → `delete_after`
    // → reaper pipeline a parent-driven `POST /agent/child/delete` uses. The children's
    // registration/provisioning rows are removed by the parent-keyed `DELETE_BY_DID` entries;
    // the child *accounts* stay behind, deactivated, until the reaper purges them. Collected
    // from both child tables so a mid-provisioning child (row in only one) is still caught.
    let child_dids: Vec<String> = sqlx::query_scalar(
        "SELECT did FROM agent_identities WHERE parent_did = ? AND did IS NOT NULL \
         UNION \
         SELECT child_did FROM agent_child_provisionings WHERE parent_did = ?",
    )
    .bind(did)
    .bind(did)
    .fetch_all(&mut *tx)
    .await
    .map_err(map_err)?;
    let mut deactivated_children = Vec::new();
    if !child_dids.is_empty() {
        let grace = i64::try_from(state.config.accounts.child_deletion_grace_secs)
            .unwrap_or(i64::MAX);
        let delete_after = (chrono::Utc::now() + chrono::Duration::seconds(grace))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        for child in &child_dids {
            // A real active → deactivated transition gets an `#account` frame after commit; a
            // child already deactivated (e.g. deletion already scheduled) only has its
            // `delete_after` refreshed, exactly like a repeated `POST /agent/child/delete`.
            if matches!(
                deactivate_account(&mut tx, child, Some(&delete_after)).await?,
                AccountStateChange::Changed
            ) {
                deactivated_children.push(child.clone());
            }
        }
    }

    for sql in DELETE_BY_DID {
        sqlx::query(sql)
            .bind(did)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
    }
    let block_cids: Vec<String> =
        sqlx::query_scalar("SELECT cid FROM block_owners WHERE account_did = ?")
            .bind(did)
            .fetch_all(&mut *tx)
            .await
            .map_err(map_err)?;
    sqlx::query(DELETE_BLOCKS)
        .bind(did)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
    crate::db::blocks::delete_unowned_unprotected_blocks_in_tx(&mut tx, &block_cids)
        .await
        .map_err(map_err)?;

    // Blobs follow the same ownership model as repo blocks (V039): delete this account's
    // `blob_owners` rows, then reclaim only the physical rows left with no owner — a CID
    // another account still references keeps its row and its on-disk file. The reclaim list is
    // captured by the same transaction that removes the rows, so a racing upload can't slip a
    // blob past it. Files are removed after the transaction commits (below).
    let blob_files = crate::db::blobs::delete_owners_and_unowned_blobs_in_tx(&mut tx, did)
        .await
        .map_err(map_err)?;

    let deleted = sqlx::query("DELETE FROM accounts WHERE did = ?")
        .bind(did)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;

    // Step 2: the account didn't exist — idempotent no-op, emit nothing. The rollback also undoes
    // the blob-row deletes above, so their files are correctly left in place.
    if deleted.rows_affected() == 0 {
        tx.rollback().await.ok();
        tracing::debug!(did = %did, "deleteAccount: account not found; no-op");
        return Ok(PurgeOutcome::NotFound);
    }

    // Step 4: tell subscribers the account is gone (active=false, status="deleted"), atomically
    // with the deletion — a durable removal must never end up without its firehose frame.
    let pending = emit_guard
        .stage_account(
            &mut tx,
            did.to_string(),
            false,
            Some(STATUS_DELETED.to_string()),
        )
        .await
        .map_err(|e| {
            tracing::error!(did = %did, error = %e, "failed to stage #account deletion event");
            ApiError::new(ErrorCode::InternalError, "failed to delete account")
        })?;
    tx.commit().await.map_err(map_err)?;
    pending.finish();

    // Announce each cascade-scheduled child's deactivation so relays stop serving its repo
    // now rather than at its reap. Best-effort AFTER the deletion transaction (the staged
    // frame chain carries one account event; these ride the bare primitive): a failed emit
    // leaves the deactivation discoverable via the lifecycle endpoints and the child's own
    // deleted frame still fires when the reaper purges it.
    for child in &deactivated_children {
        if let Err(e) = state
            .firehose
            .emit_account(child.clone(), false, Some(STATUS_DEACTIVATED.to_string()))
            .await
        {
            tracing::warn!(
                parent = %did,
                child = %child,
                error = %e,
                "failed to emit #account deactivated for cascade-scheduled child"
            );
        }
    }

    // Step 4: reclaim the on-disk blob files (best-effort; the DB row and firehose frame are the
    // source of truth for "deleted", so a stray file is a leak to clean up, not a failure).
    for (cid, storage_path) in &blob_files {
        match crate::blob_store::delete_blob_file(&state.config.data_dir, storage_path).await {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                did = %did,
                cid = %cid,
                path = %storage_path,
                "deleteAccount: blob file already absent on disk"
            ),
            Err(e) => tracing::warn!(
                did = %did,
                cid = %cid,
                path = %storage_path,
                error = %e,
                "deleteAccount: failed to delete blob file; leaving it for blob GC"
            ),
        }
    }

    tracing::info!(did = %did, blobs = blob_files.len(), "account permanently deleted");
    Ok(PurgeOutcome::Deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use crate::firehose::FirehoseEvent;
    use crate::routes::test_utils::{seed_account_with_repo, test_master_key};
    use std::sync::Arc;

    /// Test state with a real on-disk `data_dir` (so blob-file deletes are observable) and the
    /// signing-key master key configured (so seeded accounts have a usable repo).
    async fn purge_state() -> (AppState, tempfile::TempDir) {
        let base = test_state().await;
        let dir = tempfile::tempdir().unwrap();
        let mut config = (*base.config).clone();
        config.data_dir = dir.path().to_path_buf();
        config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(
            test_master_key(),
        )));
        let state = AppState {
            config: Arc::new(config),
            ..base
        };
        (state, dir)
    }

    async fn row_count(db: &sqlx::SqlitePool, table: &str, column: &str, did: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?"))
            .bind(did)
            .fetch_one(db)
            .await
            .unwrap()
    }

    async fn block_exists(db: &sqlx::SqlitePool, cid: &str) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM blocks WHERE cid = ?)")
            .bind(cid)
            .fetch_one(db)
            .await
            .unwrap()
    }

    async fn insert_owned_block(
        db: &sqlx::SqlitePool,
        did: &str,
        cid: &str,
        bytes: &[u8],
        legacy_protected: bool,
    ) {
        sqlx::query(
            "INSERT INTO blocks (cid, account_did, bytes, legacy_protected) VALUES (?, ?, ?, ?)",
        )
        .bind(cid)
        .bind(did)
        .bind(bytes)
        .bind(legacy_protected)
        .execute(db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO block_owners (cid, account_did) VALUES (?, ?)")
            .bind(cid)
            .bind(did)
            .execute(db)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn purge_removes_all_account_data_and_emits_deleted_frame() {
        let (state, _dir) = purge_state().await;
        let did = "did:plc:purgeme";
        seed_account_with_repo(&state.db, did).await;
        // Give the account a handle, a preference blob, and an agent-auth registration so the
        // multi-table delete has something to remove in several child-table shapes.
        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("purge.example.com")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO account_preferences (did, preferences, updated_at) \
             VALUES (?, '[]', datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, scopes, assertion_expires_at, status, created_at, updated_at) \
             VALUES ('reg_purge', ?, 'anonymous', '[\"com.atproto.access\"]', \
                     '2099-01-01T00:00:00Z', 'active', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agent_claim_attempts \
             (id, identity_id, user_code, user_code_expires_at, status, created_at) \
             VALUES ('cla_purge', 'reg_purge', '123456', '2099-01-01T00:00:00Z', \
                     'pending', datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();
        // A NULL-did audit event still pins the identity via its registration_id FK, so the
        // purge must remove it by identity, not by the event's own did column.
        sqlx::query(
            "INSERT INTO agent_audit_events \
             (id, registration_id, did, event_type, detail, created_at) \
             VALUES ('evt_purge', 'reg_purge', NULL, 'registered', NULL, datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();
        crate::db::sovereign_session_nonces::insert_nonce_if_absent(
            &state.db,
            did,
            "consumed-proof",
        )
        .await
        .unwrap();
        crate::db::recovery_escrow::insert_escrow_share(&state.db, did, "escrow-ciphertext")
            .await
            .unwrap();
        crate::db::recovery_audit::insert_recovery_audit_event(
            &state.db,
            "evt_purge_escrow",
            did,
            crate::db::recovery_audit::RecoveryAuditEventType::Deposited,
            None,
        )
        .await
        .unwrap();

        let other_did = "did:plc:purge-other";
        seed_account_with_repo(&state.db, other_did).await;
        insert_owned_block(&state.db, did, "bafpurgeowned", b"owned", false).await;
        insert_owned_block(&state.db, did, "bafpurgeshared", b"shared", false).await;
        insert_owned_block(&state.db, did, "bafpurgelegacy", b"legacy", true).await;
        sqlx::query("INSERT INTO block_owners (cid, account_did) VALUES (?, ?)")
            .bind("bafpurgeshared")
            .bind(other_did)
            .execute(&state.db)
            .await
            .unwrap();

        let mut rx = state.firehose.subscribe();
        let outcome = purge_account(&state, did).await.unwrap();
        assert_eq!(outcome, PurgeOutcome::Deleted);

        // The account and all its child rows are gone.
        assert_eq!(row_count(&state.db, "accounts", "did", did).await, 0);
        assert_eq!(row_count(&state.db, "handles", "did", did).await, 0);
        assert_eq!(row_count(&state.db, "signing_keys", "did", did).await, 0);
        assert_eq!(row_count(&state.db, "did_documents", "did", did).await, 0);
        assert_eq!(
            row_count(&state.db, "account_preferences", "did", did).await,
            0
        );
        assert_eq!(
            row_count(&state.db, "agent_identities", "did", did).await,
            0
        );
        assert_eq!(
            row_count(&state.db, "sovereign_session_nonces", "did", did).await,
            0
        );
        assert_eq!(row_count(&state.db, "recovery_escrow", "did", did).await, 0);
        assert_eq!(
            row_count(&state.db, "recovery_audit_events", "did", did).await,
            0
        );
        let claim_attempts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_claim_attempts WHERE identity_id = 'reg_purge'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(claim_attempts, 0);
        let audit_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_audit_events WHERE registration_id = 'reg_purge'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(audit_events, 0);
        assert_eq!(
            row_count(&state.db, "block_owners", "account_did", did).await,
            0
        );
        assert!(
            !block_exists(&state.db, "bafpurgeowned").await,
            "unshared, non-legacy physical bytes should be reclaimed"
        );
        assert!(
            block_exists(&state.db, "bafpurgeshared").await,
            "physical bytes still owned by another account must remain"
        );
        assert!(
            block_exists(&state.db, "bafpurgelegacy").await,
            "legacy-protected physical bytes must remain"
        );

        // The firehose announced the deletion.
        let FirehoseEvent::Account(event) = rx.try_recv().unwrap() else {
            panic!("expected an #account firehose event");
        };
        assert_eq!(event.did, did);
        assert!(!event.active);
        assert_eq!(event.status.as_deref(), Some("deleted"));
    }

    #[tokio::test]
    async fn purge_reclaims_blob_files_from_disk() {
        let (state, _dir) = purge_state().await;
        let did = "did:plc:purgeblobs";
        seed_account_with_repo(&state.db, did).await;

        // Store a blob on disk + its metadata row.
        let stored = crate::blob_store::store_blob(
            &state.config.data_dir,
            b"blob to reclaim",
            "application/octet-stream",
        )
        .await
        .unwrap();
        crate::db::blobs::insert_blob(
            &state.db,
            &stored.cid,
            did,
            &stored.mime_type,
            stored.size_bytes as i64,
            &stored.storage_path,
            "2020-01-01T00:00:00Z",
        )
        .await
        .unwrap();
        let file = state.config.data_dir.join(&stored.storage_path);
        assert!(file.exists(), "blob file must exist before deletion");

        purge_account(&state, did).await.unwrap();

        assert_eq!(
            row_count(&state.db, "blob_owners", "account_did", did).await,
            0
        );
        assert_eq!(row_count(&state.db, "blobs", "cid", &stored.cid).await, 0);
        assert!(!file.exists(), "blob file must be reclaimed from disk");
    }

    /// Purging one owner of a shared blob must not destroy the file (or physical row)
    /// another account still owns.
    #[tokio::test]
    async fn purge_keeps_blob_still_owned_by_another_account() {
        let (state, _dir) = purge_state().await;
        let did = "did:plc:purgeshareblob";
        let other = "did:plc:keepshareblob";
        seed_account_with_repo(&state.db, did).await;
        seed_account_with_repo(&state.db, other).await;

        // Both accounts upload the same bytes → one file, one physical row, two owner rows.
        let stored = crate::blob_store::store_blob(
            &state.config.data_dir,
            b"shared blob bytes",
            "application/octet-stream",
        )
        .await
        .unwrap();
        for owner in [did, other] {
            crate::db::blobs::insert_blob(
                &state.db,
                &stored.cid,
                owner,
                &stored.mime_type,
                stored.size_bytes as i64,
                &stored.storage_path,
                "2030-01-01 00:00:00",
            )
            .await
            .unwrap();
        }
        let file = state.config.data_dir.join(&stored.storage_path);
        assert!(file.exists());

        purge_account(&state, did).await.unwrap();

        assert_eq!(
            row_count(&state.db, "blob_owners", "account_did", did).await,
            0
        );
        assert_eq!(
            row_count(&state.db, "blob_owners", "account_did", other).await,
            1,
            "the surviving account's ownership row must remain"
        );
        assert_eq!(
            row_count(&state.db, "blobs", "cid", &stored.cid).await,
            1,
            "the shared physical row must remain"
        );
        assert!(file.exists(), "the shared blob file must remain on disk");
    }

    /// Purging a sovereign child must remove its `agent_child_provisionings` row (FK-ordered ahead
    /// of the `accounts` delete, or the constraint fails) while its `agent_child_deletions`
    /// tombstone — keyed to the parent — survives, so the parent's deletion audit outlives the
    /// child.
    #[tokio::test]
    async fn purge_child_removes_provisioning_and_keeps_parent_tombstone() {
        let (state, _dir) = purge_state().await;
        let parent = "did:plc:tombstoneparent";
        let child = "did:plc:tombstonechild";
        seed_account_with_repo(&state.db, parent).await;
        seed_account_with_repo(&state.db, child).await;

        // The child's durable provisioning row (FK to accounts on both child_did and parent_did).
        sqlx::query(
            "INSERT INTO agent_child_provisionings \
             (child_did, parent_did, handle, registration_id, signed_op, scopes, \
              identity_assertion, assertion_expires_at, genesis_car, sync_car, created_at, updated_at) \
             VALUES (?, ?, 'child.example.com', 'reg_tomb', 'op', '[]', 'jwt', \
                     '2099-01-01T00:00:00Z', ?, ?, datetime('now'), datetime('now'))",
        )
        .bind(child)
        .bind(parent)
        .bind(Vec::<u8>::new())
        .bind(Vec::<u8>::new())
        .execute(&state.db)
        .await
        .unwrap();
        // The parent's deletion tombstone for this child.
        sqlx::query(
            "INSERT INTO agent_child_deletions \
             (child_did, parent_did, handle, registration_id, scheduled_at, delete_after) \
             VALUES (?, ?, 'child.example.com', 'reg_tomb', datetime('now'), '2099-01-01T00:00:00Z')",
        )
        .bind(child)
        .bind(parent)
        .execute(&state.db)
        .await
        .unwrap();

        assert_eq!(
            purge_account(&state, child).await.unwrap(),
            PurgeOutcome::Deleted
        );
        assert_eq!(row_count(&state.db, "accounts", "did", child).await, 0);
        assert_eq!(
            row_count(&state.db, "agent_child_provisionings", "child_did", child).await,
            0,
            "the child's provisioning row must be purged (FK-ordered before the account row)"
        );
        assert_eq!(
            row_count(&state.db, "agent_child_deletions", "parent_did", parent).await,
            1,
            "the parent's deletion tombstone must survive the child's purge"
        );
    }

    /// `email_tokens` rows FK-reference the account and are never consumed-by-delete
    /// (`consume_email_token` only stamps `used_at`), so the purge must remove them or the
    /// `accounts` delete fails the FK check.
    #[tokio::test]
    async fn purge_removes_email_tokens() {
        let (state, _dir) = purge_state().await;
        let did = "did:plc:purgemailtok";
        seed_account_with_repo(&state.db, did).await;
        sqlx::query(
            "INSERT INTO email_tokens (token_hash, did, purpose, expires_at, used_at, created_at) \
             VALUES ('hash_purge_used', ?, 'confirm', '2020-01-01T00:00:00Z', datetime('now'), datetime('now')), \
                    ('hash_purge_live', ?, 'update', '2099-01-01T00:00:00Z', NULL, datetime('now'))",
        )
        .bind(did)
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        assert_eq!(
            purge_account(&state, did).await.unwrap(),
            PurgeOutcome::Deleted
        );
        assert_eq!(row_count(&state.db, "email_tokens", "did", did).await, 0);
    }

    /// Purging a parent with living sovereign children must not FK-fail on the children's
    /// `parent_did` rows: the children are cascade-scheduled for deletion (deactivated with a
    /// `delete_after`, announced as deactivated), and their registration/provisioning rows —
    /// whose custody chain dies with the parent — are removed with the parent.
    #[tokio::test]
    async fn purge_parent_cascade_schedules_children() {
        let (state, _dir) = purge_state().await;
        let parent = "did:plc:cascadeparent";
        let child = "did:plc:cascadechild";
        seed_account_with_repo(&state.db, parent).await;
        seed_account_with_repo(&state.db, child).await;

        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, parent_did, registration_type, scopes, assertion_expires_at, status, \
              created_at, updated_at) \
             VALUES ('reg_casc', ?, ?, 'child', '[]', '2099-01-01T00:00:00Z', 'active', \
                     datetime('now'), datetime('now'))",
        )
        .bind(child)
        .bind(parent)
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agent_audit_events \
             (id, registration_id, did, event_type, detail, created_at) \
             VALUES ('evt_casc', 'reg_casc', ?, 'registered', NULL, datetime('now'))",
        )
        .bind(child)
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agent_child_provisionings \
             (child_did, parent_did, handle, registration_id, signed_op, scopes, \
              identity_assertion, assertion_expires_at, genesis_car, sync_car, created_at, updated_at) \
             VALUES (?, ?, 'cascade-child.example.com', 'reg_casc', 'op', '[]', 'jwt', \
                     '2099-01-01T00:00:00Z', ?, ?, datetime('now'), datetime('now'))",
        )
        .bind(child)
        .bind(parent)
        .bind(Vec::<u8>::new())
        .bind(Vec::<u8>::new())
        .execute(&state.db)
        .await
        .unwrap();

        let mut rx = state.firehose.subscribe();
        assert_eq!(
            purge_account(&state, parent).await.unwrap(),
            PurgeOutcome::Deleted
        );

        // The parent and its child-agent rows are gone; the child ACCOUNT survives, but is
        // deactivated with a scheduled deletion instant for the reaper.
        assert_eq!(row_count(&state.db, "accounts", "did", parent).await, 0);
        assert_eq!(
            row_count(&state.db, "agent_identities", "parent_did", parent).await,
            0
        );
        assert_eq!(
            row_count(&state.db, "agent_child_provisionings", "parent_did", parent).await,
            0
        );
        let (deactivated_at, delete_after): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT deactivated_at, delete_after FROM accounts WHERE did = ?")
                .bind(child)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert!(
            deactivated_at.is_some(),
            "the child must be deactivated by the cascade"
        );
        assert!(
            delete_after.is_some(),
            "the child must carry a scheduled deletion instant for the reaper"
        );

        // Frames: the parent's deleted frame (staged in the transaction), then the child's
        // best-effort deactivated frame.
        let FirehoseEvent::Account(deleted) = rx.try_recv().unwrap() else {
            panic!("expected the parent's #account deleted frame first");
        };
        assert_eq!(deleted.did, parent);
        assert_eq!(deleted.status.as_deref(), Some("deleted"));
        let FirehoseEvent::Account(deactivated) = rx.try_recv().unwrap() else {
            panic!("expected the child's #account deactivated frame");
        };
        assert_eq!(deactivated.did, child);
        assert!(!deactivated.active);
        assert_eq!(deactivated.status.as_deref(), Some("deactivated"));
    }

    /// A cascade-scheduled child is purgeable by the reaper afterwards: its registration and
    /// provisioning rows went with the parent, so the later child purge is a plain account purge.
    #[tokio::test]
    async fn cascade_scheduled_child_purges_cleanly_afterwards() {
        let (state, _dir) = purge_state().await;
        let parent = "did:plc:cascade2parent";
        let child = "did:plc:cascade2child";
        seed_account_with_repo(&state.db, parent).await;
        seed_account_with_repo(&state.db, child).await;
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, parent_did, registration_type, scopes, assertion_expires_at, status, \
              created_at, updated_at) \
             VALUES ('reg_casc2', ?, ?, 'child', '[]', '2099-01-01T00:00:00Z', 'active', \
                     datetime('now'), datetime('now'))",
        )
        .bind(child)
        .bind(parent)
        .execute(&state.db)
        .await
        .unwrap();

        purge_account(&state, parent).await.unwrap();
        assert_eq!(
            purge_account(&state, child).await.unwrap(),
            PurgeOutcome::Deleted
        );
        assert_eq!(row_count(&state.db, "accounts", "did", child).await, 0);
    }

    /// An audit event carrying the purged DID on ANOTHER account's registration is part of that
    /// other account's trail: it must survive the purge, unlinked (did = NULL) so the FK holds.
    #[tokio::test]
    async fn purge_unlinks_audit_events_on_foreign_registrations() {
        let (state, _dir) = purge_state().await;
        let did = "did:plc:purgestray";
        let other = "did:plc:keepstray";
        seed_account_with_repo(&state.db, did).await;
        seed_account_with_repo(&state.db, other).await;
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, scopes, assertion_expires_at, status, created_at, updated_at) \
             VALUES ('reg_stray', ?, 'anonymous', '[]', '2099-01-01T00:00:00Z', 'claimed', \
                     datetime('now'), datetime('now'))",
        )
        .bind(other)
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agent_audit_events \
             (id, registration_id, did, event_type, detail, created_at) \
             VALUES ('evt_stray', 'reg_stray', ?, 'activity', NULL, datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        assert_eq!(
            purge_account(&state, did).await.unwrap(),
            PurgeOutcome::Deleted
        );

        let (count, linked): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COUNT(did) FROM agent_audit_events WHERE registration_id = 'reg_stray'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(count, 1, "the other account's audit trail must survive");
        assert_eq!(linked, 0, "the surviving event must be unlinked from the purged DID");
    }

    /// Tripwire: every foreign key referencing `accounts(did)` in the LIVE schema must be
    /// covered by the purge — by a `DELETE_BY_DID`/`DELETE_BLOCKS` statement scoping that
    /// exact column, or by one of the named non-list mechanisms. A new migration that adds
    /// an account-keyed table without extending the purge fails here instead of FK-failing
    /// the reaper in production.
    #[tokio::test]
    async fn purge_covers_every_account_foreign_key_in_the_schema() {
        use sqlx::Row;

        // Covered outside DELETE_BY_DID; each entry names its mechanism.
        const COVERED_ELSEWHERE: &[(&str, &str, &str)] = &[
            ("block_owners", "account_did", "DELETE_BLOCKS + delete_unowned_unprotected_blocks_in_tx"),
            ("blob_owners", "account_did", "db::blobs::delete_owners_and_unowned_blobs_in_tx"),
        ];

        let state = crate::app::test_state().await;
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )
        .fetch_all(&state.db)
        .await
        .unwrap();

        let mut checked = 0;
        for table in &tables {
            let fks = sqlx::query(&format!("PRAGMA foreign_key_list({table})"))
                .fetch_all(&state.db)
                .await
                .unwrap();
            for fk in fks {
                let target: String = fk.get("table");
                if target != "accounts" {
                    continue;
                }
                let column: String = fk.get("from");
                checked += 1;
                if COVERED_ELSEWHERE
                    .iter()
                    .any(|(t, c, _)| t == table && *c == column)
                {
                    continue;
                }
                let covered = DELETE_BY_DID.iter().chain([&DELETE_BLOCKS]).any(|sql| {
                    (sql.contains(&format!("FROM {table} "))
                        || sql.contains(&format!("UPDATE {table} ")))
                        && (sql.contains(&format!("{column} = ?"))
                            || sql.contains(&format!("{column} IN (")))
                });
                assert!(
                    covered,
                    "{table}.{column} FK-references accounts(did) but no purge statement \
                     scopes it — a purge of an account with a row here fails the FK check. \
                     Add a DELETE_BY_DID entry (or register a mechanism in COVERED_ELSEWHERE)."
                );
            }
        }
        assert!(
            checked >= 25,
            "sanity: expected to find the schema's account FKs, found {checked}"
        );
    }

    #[tokio::test]
    async fn purge_missing_account_is_a_noop() {
        let (state, _dir) = purge_state().await;
        let mut rx = state.firehose.subscribe();

        let outcome = purge_account(&state, "did:plc:ghostpurge").await.unwrap();
        assert_eq!(outcome, PurgeOutcome::NotFound);
        assert!(
            rx.try_recv().is_err(),
            "purging a missing account must emit no firehose frame"
        );
    }
}
