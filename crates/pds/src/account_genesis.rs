// pattern: Imperative Shell

//! The steps the two account-genesis transactions share: the `accounts` row, the genesis repo's
//! blocks plus the firehose events that describe them, and the post-commit announcement.
//!
//! Two routes promote a DID into a live account with a genesis repo —
//! `routes/create_did.rs` (the mobile ceremony finishing a pending account) and
//! `routes/create_account_xrpc.rs` (`com.atproto.server.createAccount`). Routes must not import
//! from one another, so what they share lives here.
//!
//! They are deliberately *not* one function. Around this shared middle the two differ in more
//! than a flag each: one redeems an invite code, the other lands a recovery-escrow deposit; one
//! writes a handle row, the other deletes the pending account's sessions, devices, and row; one
//! inserts a session from a token hash the ceremony already issued, the other issues a fresh
//! session at a different point in the sequence. Merging them would trade two readable
//! straight-line transactions for one branching transaction whose statement order — the part that
//! actually has to be right — would be conditional.

use common::{ApiError, ErrorCode};
use repo_engine::Cid;
use sqlx::{Sqlite, Transaction};

use crate::app::AppState;
use crate::db::is_unique_violation;
use crate::firehose::{CommitInput, EmitGuard, PendingWithSync, SyncInput};

/// The `accounts` row a promotion inserts. `recovery_share` (the legacy server-held Share 2
/// column, V010) is never written on a new promotion — the client-share path escrows into
/// `recovery_escrow` and did:web escrows nothing — so it stays NULL by omission.
pub(crate) struct NewAccountRow<'a> {
    pub(crate) did: &'a str,
    pub(crate) email: &'a str,
    /// `None` for a passwordless account (the `optionalPassword` capability) — stores NULL, the
    /// same column state migration-mode `createAccount` has always written for OAuth-only accounts.
    pub(crate) password_hash: Option<&'a str>,
    pub(crate) repo_root_cid: &'a str,
    pub(crate) repo_rev: &'a str,
}

/// Insert the account row, reporting a DID collision as `already_exists` in the caller's own
/// wording (the two flows describe the same collision differently: a pending account that was
/// already promoted, versus a DID that already has an account here).
pub(crate) async fn insert_account_row(
    tx: &mut Transaction<'_, Sqlite>,
    account: &NewAccountRow<'_>,
    already_exists: &'static str,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO accounts \
         (did, email, password_hash, repo_root_cid, repo_rev, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
    )
    .bind(account.did)
    .bind(account.email)
    .bind(account.password_hash)
    .bind(account.repo_root_cid)
    .bind(account.repo_rev)
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert account");
        if is_unique_violation(&e) {
            ApiError::new(ErrorCode::DidAlreadyExists, already_exists)
        } else {
            ApiError::new(ErrorCode::InternalError, "failed to create account")
        }
    })?;
    Ok(())
}

/// The in-memory genesis repo, built before the PLC call and persisted with the account.
pub(crate) struct GenesisRepo<'a> {
    pub(crate) did: &'a str,
    pub(crate) root: &'a str,
    pub(crate) rev: &'a str,
    pub(crate) blocks: &'a [(Cid, Vec<u8>)],
    /// CAR of the genesis blocks, carried in the `#commit` frame.
    pub(crate) car: Vec<u8>,
    /// CAR of just the signed commit block, carried in the `#sync` frame.
    pub(crate) sync_car: Vec<u8>,
}

/// Persist the genesis repo blocks and stage its `#commit` + `#sync` firehose events, all in the
/// caller's open transaction.
///
/// The blocks land in the same transaction as the account and its signing key, so account +
/// signing key + a complete repo all commit together. The events are staged into that same
/// transaction rather than emitted after it: a repo root recorded on `accounts` with no
/// corresponding firehose row would be the "durable write, silently dropped event" hazard
/// `record_write::commit_repo_write` avoids for ordinary record writes.
///
/// The `#sync` is chained after the `#commit`, under the same sequencer lock. The reference PDS
/// emits `#sync` on account activation; for a fresh account, genesis *is* that activation, so a
/// relay learns this host's authoritative head atomically with the repo it describes. `prev_data`
/// is `None` — the genesis commit has no predecessor.
///
/// `emit_guard` must have been acquired *before* the caller opened `tx` — see `Firehose::lock_emit`
/// and the lock/connection ordering rule in `firehose/mod.rs`'s module doc for why that order
/// matters on this crate's single-connection pool. The returned handle does nothing until the
/// caller commits `tx` and hands it to [`announce_active_account`].
pub(crate) async fn stage_genesis_repo<'f>(
    tx: &mut Transaction<'_, Sqlite>,
    emit_guard: EmitGuard<'f>,
    repo: GenesisRepo<'_>,
) -> Result<PendingWithSync<'f>, ApiError> {
    for (cid, bytes) in repo.blocks {
        let cid = cid.to_string();
        crate::db::blocks::put_block_with_rev(tx, &cid, repo.did, bytes.as_slice(), Some(repo.rev))
            .await
            .inspect_err(|e| tracing::error!(error = %e, "failed to insert genesis block"))
            .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store genesis repo"))?;
    }

    emit_guard
        .stage_commit(
            tx,
            CommitInput {
                repo: repo.did.to_string(),
                commit: repo.root.to_string(),
                rev: repo.rev.to_string(),
                since: None,
                prev_data: None,
                ops: Vec::new(),
                blocks: repo.car,
            },
        )
        .await
        .inspect_err(|e| tracing::error!(error = %e, did = %repo.did, "failed to stage genesis firehose commit event"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to sequence genesis repo"))?
        .stage_sync(
            tx,
            SyncInput {
                did: repo.did.to_string(),
                rev: repo.rev.to_string(),
                blocks: repo.sync_car,
            },
        )
        .await
        .inspect_err(|e| tracing::error!(error = %e, did = %repo.did, "failed to stage genesis firehose sync event"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to sequence genesis repo"))
}

/// Announce a just-committed account: broadcast its staged genesis events, emit `#account`
/// (active), and invite the crawlers.
///
/// Call this **only** after the transaction carrying `pending`'s `repo_seq` rows has committed —
/// `finish` advances the sequence counter past both events and broadcasts them.
///
/// The `#account` frame is emitted separately and best-effort, mirroring `create_handle.rs`'s
/// post-write `#identity` emission: a sequencer write failure here is logged and dropped rather
/// than failing an otherwise-successful account creation. A relay that misses it still learns the
/// account is active from the genesis commit above or a later one. The crawl request matters for
/// the same reason in the other direction — a fresh account may be the first thing this host has
/// ever announced, so a relay that has never seen this PDS discovers it now rather than waiting on
/// some future commit.
pub(crate) async fn announce_active_account(
    state: &AppState,
    pending: PendingWithSync<'_>,
    did: &str,
) {
    pending.finish();

    if let Err(e) = state
        .firehose
        .emit_account(did.to_string(), true, None)
        .await
    {
        tracing::warn!(
            error = %e,
            did = %did,
            "failed to sequence #account firehose event after account creation (non-fatal)"
        );
    }

    state.crawlers.notify();
}
