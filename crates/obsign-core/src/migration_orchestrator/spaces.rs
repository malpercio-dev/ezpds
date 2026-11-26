// pattern: Mixed (pure cores + Imperative Shell commands — see the parent module doc)

//! Space transfer: carrying the account's spaces from the source host to the destination.
//!
//! `transfer_spaces` runs between the blob drain and the preferences leg:
//!
//! 1. Page the source's `listSpaces`. A source that doesn't implement it holds no spaces, so
//!    there is nothing to carry and the step advances.
//! 2. Probe the destination's `listSpaces`. A destination that doesn't implement it can't hold
//!    spaces: the step answers `SpacesUnsupported { spaces }` before importing anything. The
//!    user stops there, or re-invokes with `accept_loss` to leave the spaces behind, and
//!    `verify_import` then skips those spaces' digests. Spaces never drop out silently.
//! 3. **Meta pass:** for every space whose space-ref names this account as authority,
//!    `exportSpaceMeta` on the source → `importSpaceMeta` on the destination. It runs over all
//!    of them first, because a destination refuses an authority's `importRepo` until the space
//!    exists there.
//! 4. **Repo pass:** for every space the account holds a repo in (`listSpaces` gave it a
//!    `data` digest), `getRepo` → `importRepo`, then `listBlobs` → `getBlob` → `uploadBlob`.
//!    A blob that fails after the per-blob retries joins the existing `BlobLoss` manifest,
//!    carrying its space-ref, and surfaces as `BlobDrainIncomplete` for the user to accept.
//!
//! There's no per-space journal. Both imports replace what the destination holds, so a resume
//! simply reruns the whole step.
//!
//! **What `verify_import` checks for spaces** ([`space_verification`]), all of it read from the
//! two hosts at verify time, so nothing about it depends on this session's history:
//!
//! * every source space's `listSpaces` `data` digest matches the destination's;
//! * every blob the source's `listBlobs` names for the account in a space answers a body-less
//!   `HEAD` on the destination's space `getBlob`, unless the user accepted losing it. The
//!   destination's own `listBlobs` can't stand in here: on both Custos and the reference it
//!   lists the blobs the records reference, stored or not.

use super::*;
use crate::pds_client::{MissingBlob, PdsClientError};
use custos_client::spaces::{self as wire, SpaceView};

/// What the space transfer keeps between commands.
#[derive(Debug, Clone, Default)]
pub struct SpaceTransferState {
    /// Spaces the user accepted leaving behind because the destination can't hold spaces.
    /// `verify_import` doesn't compare their digests.
    pub accepted_loss: Vec<String>,
}

// ── pure cores ─────────────────────────────────────────────────────

/// Whether `space` (a space-ref, `at://{authority}/space/{type}/{skey}`) names `did` as its
/// authority.
pub fn is_space_authority(space: &str, did: &str) -> bool {
    space
        .strip_prefix("at://")
        .and_then(|rest| rest.split('/').next())
        == Some(did)
}

/// The source spaces whose `data` digest the destination doesn't match, or doesn't list at
/// all, leaving out the spaces in `accepted_loss`.
pub fn digest_mismatches(
    source: &[SpaceView],
    dest: &[SpaceView],
    accepted_loss: &[String],
) -> Vec<String> {
    source
        .iter()
        .filter(|s| !accepted_loss.contains(&s.space))
        .filter(|s| !dest.iter().any(|d| d.space == s.space && d.data == s.data))
        .map(|s| s.space.clone())
        .collect()
}

// ── wire helpers ───────────────────────────────────────────────────

/// Every space `client`'s host lists for the account, or `None` when the host doesn't
/// implement `listSpaces`.
pub(super) async fn list_all_spaces(
    client: &OAuthClient,
) -> Result<Option<Vec<SpaceView>>, PdsClientError> {
    let mut spaces = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = match wire::list_spaces(client, cursor.as_deref()).await {
            Ok(page) => page,
            Err(e) if cursor.is_none() && wire::is_method_unsupported(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let exhausted = page.spaces.is_empty();
        spaces.extend(page.spaces);
        match page.cursor {
            Some(next) if !exhausted && cursor.as_deref() != Some(next.as_str()) => {
                cursor = Some(next)
            }
            _ => return Ok(Some(spaces)),
        }
    }
}

fn space_failure(space: &str, what: &str, e: impl std::fmt::Display) -> MigrationError {
    tracing::error!(space = %space, error = %e, "space transfer: {what} failed");
    MigrationError::SpaceTransferFailed {
        message: format!("{space}: {what} failed: {e}"),
    }
}

/// Fetch one space blob from the source and upload it to the destination, each half with the
/// drain's per-blob retries. A blob still failing becomes a [`BlobLoss`] naming its space.
async fn transfer_space_blob(
    source: &OAuthClient,
    dest: &OAuthClient,
    space: &str,
    did: &str,
    cid: &str,
) -> Result<(), BlobLoss> {
    let blob = MissingBlob {
        cid: cid.to_string(),
        record_uri: space.to_string(),
    };
    let mut attempt = 0;
    let bytes = loop {
        attempt += 1;
        match wire::get_space_blob(source, space, did, cid).await {
            Ok(bytes) => break bytes,
            Err(e) if attempt >= BLOB_TRANSFER_ATTEMPTS => {
                tracing::error!(did = %did, space = %space, cid = %cid, attempts = attempt, error = %e, "space getBlob exhausted retries; recording blob loss");
                return Err(BlobLoss {
                    cid: blob.cid,
                    record_uri: blob.record_uri,
                    direction: BlobTransferDirection::Source,
                    reason: e.to_string(),
                    space: Some(space.to_string()),
                });
            }
            Err(e) => {
                tracing::warn!(did = %did, space = %space, cid = %cid, attempt, error = %e, "space getBlob failed; retrying");
                tokio::time::sleep(blob_backoff(attempt)).await;
            }
        }
    };
    upload_blob_with_retries(dest, did, &blob, bytes, BlobOrigin::SourcePds)
        .await
        .map(|_| ())
        .map_err(|loss| BlobLoss {
            space: Some(space.to_string()),
            ..loss
        })
}

/// The meta pass: every space this account is authority of, exported and imported.
pub(super) async fn transfer_space_meta(
    source: &OAuthClient,
    dest: &OAuthClient,
    did: &str,
    spaces: &[SpaceView],
) -> Result<(), MigrationError> {
    for view in spaces.iter().filter(|v| is_space_authority(&v.space, did)) {
        let archive = wire::export_space_meta(source, &view.space)
            .await
            .map_err(|e| space_failure(&view.space, "exportSpaceMeta", e))?;
        wire::import_space_meta(dest, archive)
            .await
            .map_err(|e| space_failure(&view.space, "importSpaceMeta", e))?;
        tracing::debug!(did = %did, space = %view.space, "space meta transferred");
    }
    Ok(())
}

/// The repo pass: every space the account holds a repo in, exported and imported, then its
/// blobs. Returns the blobs that couldn't be transferred.
pub(super) async fn transfer_space_repos(
    source: &OAuthClient,
    dest: &OAuthClient,
    did: &str,
    spaces: &[SpaceView],
) -> Result<Vec<BlobLoss>, MigrationError> {
    let mut losses = Vec::new();
    for view in spaces.iter().filter(|v| v.data.is_some()) {
        let space = view.space.as_str();
        let archive = wire::get_space_repo(source, space, did)
            .await
            .map_err(|e| space_failure(space, "getRepo", e))?;
        wire::import_space_repo(dest, archive)
            .await
            .map_err(|e| space_failure(space, "importRepo", e))?;

        let mut cursor: Option<String> = None;
        loop {
            let page = wire::list_space_blobs(source, space, did, cursor.as_deref())
                .await
                .map_err(|e| space_failure(space, "listBlobs", e))?;
            let exhausted = page.cids.is_empty();
            for cid in &page.cids {
                if let Err(loss) = transfer_space_blob(source, dest, space, did, cid).await {
                    losses.push(loss);
                }
            }
            match page.cursor {
                Some(next) if !exhausted && cursor.as_deref() != Some(next.as_str()) => {
                    cursor = Some(next)
                }
                _ => break,
            }
        }
        tracing::debug!(did = %did, space = %space, "space repo transferred");
    }
    Ok(losses)
}

/// `verify_import`'s space check: the source spaces the destination doesn't match, either by
/// `data` digest or by a blob it doesn't hold (see the module doc). `accepted_blob_loss` excuses
/// the space blobs the user accepted losing; `spaces.accepted_loss` excuses whole spaces.
pub(super) async fn space_verification(
    source: &OAuthClient,
    dest: &OAuthClient,
    did: &str,
    spaces: &SpaceTransferState,
    accepted_blob_loss: &[BlobLoss],
) -> Result<Vec<String>, MigrationError> {
    let net = |what: &'static str| {
        move |e: PdsClientError| MigrationError::NetworkError {
            message: format!("{what}: {e}"),
        }
    };
    let source_spaces = list_all_spaces(source)
        .await
        .map_err(net("failed to list spaces on the source"))?
        .unwrap_or_default();
    if source_spaces.is_empty() {
        return Ok(Vec::new());
    }
    let dest_spaces = list_all_spaces(dest)
        .await
        .map_err(net("failed to list spaces on the destination"))?
        .unwrap_or_default();
    let mut failed = digest_mismatches(&source_spaces, &dest_spaces, &spaces.accepted_loss);

    for view in source_spaces.iter().filter(|v| v.data.is_some()) {
        let space = view.space.as_str();
        if spaces.accepted_loss.iter().any(|s| s == space) || failed.iter().any(|s| s == space) {
            continue;
        }
        let excused = |cid: &str| {
            accepted_blob_loss
                .iter()
                .any(|l| l.space.as_deref() == Some(space) && l.cid == cid)
        };
        let mut cursor: Option<String> = None;
        'pages: loop {
            let page = wire::list_space_blobs(source, space, did, cursor.as_deref())
                .await
                .map_err(net("failed to list a space's blobs on the source"))?;
            for cid in page.cids.iter().filter(|c| !excused(c)) {
                let present = wire::space_blob_present(dest, space, did, cid)
                    .await
                    .map_err(net("failed to check a space blob on the destination"))?;
                if !present {
                    tracing::warn!(did = %did, space = %space, cid = %cid, "space blob missing on the destination");
                    failed.push(view.space.clone());
                    break 'pages;
                }
            }
            match page.cursor {
                Some(next) if !page.cids.is_empty() && cursor.as_deref() != Some(next.as_str()) => {
                    cursor = Some(next)
                }
                _ => break,
            }
        }
    }
    Ok(failed)
}

// ── transfer_spaces ────────────────────────────────────────────────

/// Tauri command: carry the account's spaces to the destination (see the module doc).
///
/// Gate: ensure_phase_did(..., BlobsTransferred). Advances to SpacesTransferred on success, an
/// accepted `SpacesUnsupported`, or an accepted blob-loss manifest. A recovery session has no
/// source to list, so it advances with nothing transferred.
pub async fn transfer_spaces(
    state: &crate::oauth::Core,
    did: String,
    accept_loss: bool,
) -> Result<(), MigrationError> {
    transfer_spaces_core(&state.orchestration_state, &did, accept_loss).await
}

/// [`transfer_spaces`] over the orchestration slot, so it is drivable against mock servers.
pub(super) async fn transfer_spaces_core(
    orchestration_state: &tokio::sync::Mutex<Option<OutboundMigrationState>>,
    did: &str,
    accept_loss: bool,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, accept_loss, "transfer_spaces: carrying spaces to the destination");
    let journal = MigrationJournal::new(orchestration_state, did);

    let (source_client, dest_client, recovery) = {
        let orchestration = orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, did, MigrationPhase::BlobsTransferred).map_err(
            |e| {
                tracing::warn!("transfer_spaces: phase gate failed: {}", e);
                e
            },
        )?;
        (
            mig.source_client.clone(),
            mig.dest_client.clone(),
            mig.recovery,
        )
    }; // lock released

    if recovery {
        tracing::info!(did = %did, "transfer_spaces: recovery session has no source to list spaces from; skipping");
        return journal
            .commit(MigrationPhase::SpacesTransferred, |mig| {
                mig.spaces.accepted_loss.clear()
            })
            .await;
    }
    let Some(source_client) = source_client else {
        return Err(MigrationError::SourceAuthFailed {
            message: "source client not authenticated".into(),
        });
    };
    let Some(dest_client) = dest_client else {
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    let source_spaces = list_all_spaces(&source_client)
        .await
        .map_err(|e| MigrationError::SpaceTransferFailed {
            message: format!("failed to list spaces on the source: {e}"),
        })?
        .unwrap_or_default();
    if source_spaces.is_empty() {
        tracing::info!(did = %did, "transfer_spaces: the source holds no spaces");
        return journal
            .commit(MigrationPhase::SpacesTransferred, |mig| {
                mig.spaces.accepted_loss.clear()
            })
            .await;
    }
    let refs: Vec<String> = source_spaces.iter().map(|s| s.space.clone()).collect();

    // The destination must be able to hold spaces before anything is imported.
    let dest_listing =
        list_all_spaces(&dest_client)
            .await
            .map_err(|e| MigrationError::SpaceTransferFailed {
                message: format!("failed to list spaces on the destination: {e}"),
            })?;
    if dest_listing.is_none() {
        if !accept_loss {
            tracing::warn!(did = %did, spaces = refs.len(), "transfer_spaces: destination can't hold spaces; awaiting user decision");
            return Err(MigrationError::SpacesUnsupported { spaces: refs });
        }
        tracing::warn!(did = %did, spaces = refs.len(), "transfer_spaces: leaving spaces behind as an accepted loss");
        return journal
            .commit(MigrationPhase::SpacesTransferred, |mig| {
                mig.spaces.accepted_loss = refs
            })
            .await;
    }

    transfer_space_meta(&source_client, &dest_client, did, &source_spaces).await?;
    let losses = transfer_space_repos(&source_client, &dest_client, did, &source_spaces).await?;

    if !losses.is_empty() && !accept_loss {
        tracing::warn!(did = %did, lost = losses.len(), "transfer_spaces: some space blobs couldn't be transferred; awaiting user decision");
        return Err(MigrationError::BlobDrainIncomplete { losses });
    }
    journal
        .commit(MigrationPhase::SpacesTransferred, |mig| {
            mig.accepted_blob_loss.retain(|loss| loss.space.is_none());
            mig.accepted_blob_loss.extend(losses);
            mig.spaces.accepted_loss.clear();
        })
        .await?;
    tracing::info!(did = %did, spaces = refs.len(), "spaces transferred successfully");
    Ok(())
}
