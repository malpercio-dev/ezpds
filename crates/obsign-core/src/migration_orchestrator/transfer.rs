// pattern: Mixed (pure cores + Imperative Shell commands — see the parent module doc)

//! Data transfer steps: repo, blobs, preferences, and the `verify_import` completeness gate.

use super::*;

// ── transfer_repo ──────────────────────────────────────────────────

/// Pure core: fetch the source repo CAR (auth:none) and import it into the destination
/// (Bearer). Extracted for unit testability with mocked servers.
///
/// `mirror_root`, when present, is the wallet's local iCloud repo mirror. If the source PDS can't
/// serve `getRepo` (the repo twin of the observed blob-drain fault), the transfer falls back to the
/// mirror's snapshot before giving up — content addressing makes that substitution trustless
/// (`repo_backup::mirror_repo_car` re-validates the CAR against the DID and returns `None` on any
/// doubt), so a backed-up user's dead source repo becomes a non-event. When the mirror can't supply
/// a valid snapshot the original source failure is surfaced unchanged, exactly as before the mirror
/// existed. The fallback is consulted only for the source `getRepo` half; a destination `importRepo`
/// refusal is a genuinely different failure the mirror can't fix. A source `429` never falls back:
/// the source is alive and pacing repeat full exports, and the mirror may be older than it.
pub(super) async fn transfer_repo_impl(
    pds_client: &crate::pds_client::PdsClient,
    dest_client: &OAuthClient,
    source_pds_url: &str,
    did: &str,
    mirror_root: Option<&Path>,
) -> Result<(), MigrationError> {
    // 1. Fetch repository CAR from source; on a source getRepo failure, fall back to the local
    //    iCloud mirror before giving up.
    tracing::debug!(did = %did, source_url = %source_pds_url, "fetching repository from source");
    let car = match pds_client.fetch_repo_car(source_pds_url, did).await {
        Ok(car) => car,
        // A 429 means the source can serve the repo and is only pacing us; the mirror may be older
        // than the live repo, so importing it would silently roll the account back. Wait instead.
        Err(crate::pds_client::PdsClientError::RateLimited { retry_after, .. }) => {
            tracing::warn!(did = %did, ?retry_after, "source getRepo rate-limited; not falling back to the mirror");
            return Err(MigrationError::RateLimited { retry_after });
        }
        Err(source_err) => {
            tracing::error!(did = %did, error = %source_err, "failed to fetch repository CAR from source");
            // The source PDS can't serve getRepo. Try the local mirror: a CID/commit-valid backup
            // copy stands in for the bytes the source can't serve. `mirror_repo_car` is fail-closed
            // (revalidates, returns None on a missing/undownloaded/rotten snapshot), so the original
            // source failure is preserved unchanged whenever no trustworthy snapshot exists.
            match mirror_root {
                Some(root) => match crate::repo_backup::mirror_repo_car(root, did).await {
                    Some(car) => {
                        tracing::info!(did = %did, "transfer_repo: recovered the repo snapshot from the local mirror after a source getRepo failure");
                        car
                    }
                    None => {
                        return Err(MigrationError::RepoTransferFailed {
                            message: format!("failed to fetch repository: {}", source_err),
                        });
                    }
                },
                None => {
                    return Err(MigrationError::RepoTransferFailed {
                        message: format!("failed to fetch repository: {}", source_err),
                    });
                }
            }
        }
    };

    // 2. Import repository into destination
    tracing::debug!(did = %did, car_len = %car.len(), "importing repository to destination");
    crate::pds_client::import_repo(dest_client, car)
        .await
        .map_err(|e| {
            tracing::error!(did = %did, error = %e, "failed to import repository");
            MigrationError::RepoTransferFailed {
                message: format!("failed to import repository: {}", e),
            }
        })?;

    Ok(())
}

/// Tauri command: fetch repository from source PDS and import into destination.
///
/// Gate: ensure_phase_did(..., DestCreated) → clone dest_client, read source_pds_url; drop lock
/// Then: fetch_repo_car(source) → import_repo(dest); re-lock + advance to RepoTransferred.
/// A source `getRepo` failure falls back to the local iCloud repo mirror when this device has a
/// CID/commit-valid snapshot for the DID (`repo_backup::mirror_repo_car`), turning a dead source
/// repo into a non-event for backed-up users; when no valid snapshot exists the original source
/// failure is surfaced unchanged.
pub async fn transfer_repo(state: &crate::oauth::Core, did: String) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "transfer_repo: fetching and importing repository");

    // Gate + extract dependencies
    let (dest_client, source_pds_url) = {
        let orchestration = state.orchestration_state.lock().await;
        let mig =
            ensure_phase_did(&orchestration, &did, MigrationPhase::DestCreated).map_err(|e| {
                tracing::warn!("transfer_repo: phase gate failed: {}", e);
                e
            })?;

        (mig.dest_client.clone(), mig.source_pds_url.clone())
    }; // lock released

    let Some(dest_client) = dest_client else {
        tracing::error!(did = %did, "transfer_repo: dest_client not found");
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    let pds_client = state.pds_client();

    // Resolve the local repo mirror, if this device has one. When present the transfer falls back to
    // it for a source PDS that can't serve getRepo (the repo twin of the blob drain's fallback);
    // when absent the transfer behaves as before.
    let mirror_root = crate::blob_backup::resolve_backup_root(state).map(|(root, _location)| root);

    // Fetch source CAR + import into destination (pure core, unit-tested).
    transfer_repo_impl(
        pds_client,
        &dest_client,
        &source_pds_url,
        &did,
        mirror_root.as_deref(),
    )
    .await?;

    MigrationJournal::new(&state.orchestration_state, &did)
        .save(MigrationPhase::RepoTransferred)
        .await?;

    tracing::info!(did = %did, "repository transferred successfully");
    Ok(())
}

// ── transfer_blobs ─────────────────────────────────────────────────

/// Per-blob transfer attempts before the drain gives up on a blob and records it in the loss
/// manifest. A source PDS that permanently 500s every `getBlob` (the observed source-PDS fault) is
/// declared lost after this many tries; transient blips get absorbed by the retry.
pub(super) const BLOB_TRANSFER_ATTEMPTS: u32 = 3;

/// Short exponential backoff between per-blob retries: 250ms after the 1st failure, 500ms after the
/// 2nd. Keeps a doomed drain from hammering the source while still spacing out transient retries.
pub(super) fn blob_backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_millis(250u64 * 2u64.pow(attempt.saturating_sub(1)))
}

/// Where a successfully-transferred blob's bytes came from. Tracked so a drain that leaned on the
/// local mirror to route around a source-PDS `getBlob` fault is visible in the logs (and countable),
/// never a silent substitution — the observability the resilience design asks of any degraded path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BlobOrigin {
    /// Fetched from the source PDS, the normal path.
    SourcePds,
    /// Recovered from the wallet's local blob mirror after the source PDS failed `getBlob`.
    LocalMirror,
}

/// Transfer one blob: fetch it from the source, then upload it to the destination, retrying each
/// half up to `BLOB_TRANSFER_ATTEMPTS` times with a short backoff. On success `Ok(BlobOrigin)`
/// naming where the bytes came from; once retries are exhausted, `Err(BlobLoss)` naming which half
/// failed (and the last server error) so the caller can fold it into the loss manifest instead of
/// aborting the whole drain.
///
/// `mirror_root`, when present, is the local blob-backup mirror. If the source PDS can't serve the
/// blob (the observed real-migration fault: metadata present, `getBlob` 500s), the drain falls back
/// to the mirror before recording a loss — content addressing makes that substitution trustless, so
/// a backed-up user's dead source blob becomes a non-event. The mirror is consulted only for the
/// fetch half; a destination `uploadBlob` refusal is a genuinely different failure it can't fix.
pub(super) async fn transfer_one_blob(
    pds_client: &crate::pds_client::PdsClient,
    dest_client: &OAuthClient,
    source_pds_url: Option<&str>,
    did: &str,
    blob: &crate::pds_client::MissingBlob,
    mirror_root: Option<&Path>,
) -> Result<BlobOrigin, BlobLoss> {
    // No source at all (disaster recovery): the mirror IS the source. Skip the doomed
    // fetch retries and read the CID-verified backup copy directly.
    let Some(source_pds_url) = source_pds_url else {
        return match mirror_root {
            Some(root) => {
                match crate::blob_backup::mirror_fallback_blob(root, did, &blob.cid).await {
                    Some(bytes) => {
                        upload_blob_with_retries(
                            dest_client,
                            did,
                            blob,
                            bytes,
                            BlobOrigin::LocalMirror,
                        )
                        .await
                    }
                    None => Err(BlobLoss {
                        cid: blob.cid.clone(),
                        record_uri: blob.record_uri.clone(),
                        direction: BlobTransferDirection::Source,
                        reason: "source PDS unavailable and the backup mirror has no usable copy"
                            .to_string(),
                    }),
                }
            }
            None => Err(BlobLoss {
                cid: blob.cid.clone(),
                record_uri: blob.record_uri.clone(),
                direction: BlobTransferDirection::Source,
                reason: "source PDS unavailable and no backup mirror on this device".to_string(),
            }),
        };
    };

    // Fetch-from-source half.
    let mut attempt = 0;
    let (bytes, origin) = loop {
        attempt += 1;
        match pds_client.fetch_blob(source_pds_url, did, &blob.cid).await {
            Ok(bytes) => break (bytes, BlobOrigin::SourcePds),
            Err(e) if attempt >= BLOB_TRANSFER_ATTEMPTS => {
                // Source PDS is out of retries. Before declaring the blob lost, try the local
                // mirror: content addressing lets a verified backup copy stand in for the bytes the
                // source can't serve.
                match mirror_root {
                    Some(root) => {
                        match crate::blob_backup::mirror_fallback_blob(root, did, &blob.cid).await {
                            Some(bytes) => break (bytes, BlobOrigin::LocalMirror),
                            None => {
                                tracing::error!(did = %did, cid = %blob.cid, attempts = attempt, error = %e, "fetch_blob exhausted retries and the local mirror has no usable copy; recording blob loss");
                                return Err(BlobLoss {
                                    cid: blob.cid.clone(),
                                    record_uri: blob.record_uri.clone(),
                                    direction: BlobTransferDirection::Source,
                                    reason: e.to_string(),
                                });
                            }
                        }
                    }
                    None => {
                        tracing::error!(did = %did, cid = %blob.cid, attempts = attempt, error = %e, "fetch_blob exhausted retries; recording blob loss");
                        return Err(BlobLoss {
                            cid: blob.cid.clone(),
                            record_uri: blob.record_uri.clone(),
                            direction: BlobTransferDirection::Source,
                            reason: e.to_string(),
                        });
                    }
                }
            }
            Err(e) => {
                tracing::warn!(did = %did, cid = %blob.cid, attempt, error = %e, "fetch_blob failed; retrying");
                tokio::time::sleep(blob_backoff(attempt)).await;
            }
        }
    };

    // Upload-to-destination half.
    upload_blob_with_retries(dest_client, did, blob, bytes, origin).await
}

/// Upload one blob's bytes to the destination with per-blob retries — the shared
/// upload half of `transfer_one_blob` for both the source-fetched and mirror-read
/// paths. Returns the given `origin` on success.
pub(super) async fn upload_blob_with_retries(
    dest_client: &OAuthClient,
    did: &str,
    blob: &crate::pds_client::MissingBlob,
    bytes: Vec<u8>,
    origin: BlobOrigin,
) -> Result<BlobOrigin, BlobLoss> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        match crate::pds_client::upload_blob(dest_client, "application/octet-stream", bytes.clone())
            .await
        {
            Ok(_) => return Ok(origin),
            Err(e) if attempt >= BLOB_TRANSFER_ATTEMPTS => {
                tracing::error!(did = %did, cid = %blob.cid, attempts = attempt, error = %e, "upload_blob exhausted retries; recording blob loss");
                return Err(BlobLoss {
                    cid: blob.cid.clone(),
                    record_uri: blob.record_uri.clone(),
                    direction: BlobTransferDirection::Destination,
                    reason: e.to_string(),
                });
            }
            Err(e) => {
                tracing::warn!(did = %did, cid = %blob.cid, attempt, error = %e, "upload_blob failed; retrying");
                tokio::time::sleep(blob_backoff(attempt)).await;
            }
        }
    }
}

/// Pure core: drain the destination's missing-blob set via cursor pagination, degrading per-blob.
///
/// Loops `list_missing_blobs(cursor)`; each blob is transferred via `transfer_one_blob` (which
/// retries per-blob). A blob that still fails is added to a give-up set and recorded in the returned
/// loss manifest — one dead blob no longer parks the whole migration. The give-up set also
/// drives termination: `listMissingBlobs` keeps re-reporting a skipped blob, so the loop stops once
/// a full pass (cursor exhausted) surfaces no *new* transferable blob. A clean drain returns an
/// empty `Vec`. Only `list_missing_blobs` itself failing — we can't even enumerate, so no manifest
/// is possible — aborts hard with `BlobTransferFailed`, still WITHOUT advancing the phase.
///
/// `mirror_root`, when present, is the wallet's local blob mirror: a blob the source PDS can't serve
/// is recovered from it before being recorded as lost (see `transfer_one_blob`), shrinking the loss
/// manifest — ideally to empty — for backed-up users.
pub(super) async fn drain_missing_blobs(
    pds_client: &crate::pds_client::PdsClient,
    dest_client: &OAuthClient,
    source_pds_url: Option<&str>,
    did: &str,
    mirror_root: Option<&Path>,
) -> Result<Vec<BlobLoss>, MigrationError> {
    let mut cursor: Option<String> = None;
    let mut losses: Vec<BlobLoss> = Vec::new();
    let mut recovered_from_mirror: u64 = 0;
    let mut given_up: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    loop {
        let page = crate::pds_client::list_missing_blobs(dest_client, cursor.as_deref())
            .await
            .map_err(|e| {
                tracing::error!(did = %did, error = %e, "list_missing_blobs failed");
                MigrationError::BlobTransferFailed {
                    message: format!("failed to list missing blobs: {}", e),
                }
            })?;

        // Blobs on this page we haven't already given up on.
        let pending: Vec<&crate::pds_client::MissingBlob> = page
            .blobs
            .iter()
            .filter(|b| !given_up.contains(&b.cid))
            .collect();

        if pending.is_empty() {
            // Nothing transferable on this page: either the set is fully drained (empty page → a
            // clean drain) or only already-given-up blobs remain. Keep scanning while pages remain;
            // once a full pass (cursor exhausted) yields no transferable blob, return the manifest.
            match page.cursor {
                Some(next) => {
                    cursor = Some(next);
                    continue;
                }
                None => {
                    if recovered_from_mirror > 0 {
                        tracing::info!(did = %did, recovered = recovered_from_mirror, "blob drain: recovered blob(s) from the local mirror after source getBlob failures");
                    }
                    if losses.is_empty() {
                        tracing::debug!(did = %did, "blob drain complete: missing set is empty");
                    } else {
                        tracing::warn!(did = %did, lost = losses.len(), "blob drain incomplete: some blobs could not be transferred");
                    }
                    return Ok(losses);
                }
            }
        }

        for blob in pending {
            tracing::debug!(did = %did, cid = %blob.cid, "transferring blob");
            match transfer_one_blob(
                pds_client,
                dest_client,
                source_pds_url,
                did,
                blob,
                mirror_root,
            )
            .await
            {
                Ok(BlobOrigin::LocalMirror) => recovered_from_mirror += 1,
                Ok(BlobOrigin::SourcePds) => {}
                Err(loss) => {
                    given_up.insert(blob.cid.clone());
                    losses.push(loss);
                }
            }
        }

        // Advance: Some → next page; None → re-list from the start. On the re-list the transferred
        // blobs are gone from the missing set, so only given-up blobs remain and the `pending`
        // filter above converges the loop.
        cursor = page.cursor;
    }
}

/// Tauri command: drain missing blobs from destination via cursor-paginated loop.
///
/// Gate: ensure_phase_did(..., RepoTransferred) → clone dest_client, read source_pds_url; drop lock.
/// Then `drain_missing_blobs` degrades per-blob:
/// - clean drain → advance to BlobsTransferred.
/// - some blobs lost and `accept_loss = false` → return `BlobDrainIncomplete { losses }` WITHOUT
///   advancing, so the UI can show the manifest and let the user decide.
/// - `accept_loss = true` → record the (re-drained) losses on the state, advance anyway, and
///   `verify_import` later subtracts them so the migration still reconciles.
pub async fn transfer_blobs(
    state: &crate::oauth::Core,
    did: String,
    accept_loss: bool,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, accept_loss, "transfer_blobs: draining missing blobs");

    // Gate + extract dependencies. A recovery session has no usable source: the drain
    // reads the iCloud mirror directly instead of burning retries on a dead host.
    let (dest_client, source_pds_url) = {
        let orchestration = state.orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, &did, MigrationPhase::RepoTransferred).map_err(
            |e| {
                tracing::warn!("transfer_blobs: phase gate failed: {}", e);
                e
            },
        )?;

        let source = if mig.recovery {
            None
        } else {
            Some(mig.source_pds_url.clone())
        };
        (mig.dest_client.clone(), source)
    }; // lock released

    let Some(dest_client) = dest_client else {
        tracing::error!(did = %did, "transfer_blobs: dest_client not found");
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    let pds_client = state.pds_client();

    // Resolve the local blob mirror, if this device has one. When present the drain falls back to it
    // for any blob the source PDS can't serve (the observed real-migration fault), turning a dead
    // source blob into a non-event for backed-up users; when absent the drain behaves as before.
    let mirror_root = crate::blob_backup::resolve_backup_root(state).map(|(root, _location)| root);

    // Drain the missing-blob set. A hard enumerate failure propagates as BlobTransferFailed.
    let losses = drain_missing_blobs(
        pds_client,
        &dest_client,
        source_pds_url.as_deref(),
        &did,
        mirror_root.as_deref(),
    )
    .await?;

    // Some blobs couldn't be transferred. Unless the user has already accepted the loss, surface the
    // manifest and DON'T advance — the step stays retry-safe (the transferable blobs are already on
    // the destination; a Retry re-drains and may recover blobs that failed transiently).
    if !losses.is_empty() && !accept_loss {
        tracing::warn!(did = %did, lost = losses.len(), "transfer_blobs: drain incomplete; awaiting user decision");
        return Err(MigrationError::BlobDrainIncomplete { losses });
    }

    // Update orchestration state: record any accepted losses and advance to BlobsTransferred.
    if !losses.is_empty() {
        tracing::warn!(did = %did, accepted = losses.len(), "transfer_blobs: proceeding with an accepted blob-loss manifest");
    }
    MigrationJournal::new(&state.orchestration_state, &did)
        .commit(MigrationPhase::BlobsTransferred, |mig| {
            mig.accepted_blob_loss = losses
        })
        .await?;

    tracing::info!(did = %did, "blobs transferred successfully");
    Ok(())
}

// ── transfer_preferences ───────────────────────────────────────────

/// Pure core: get preferences from source and put them to destination.
/// Extracted for unit testability with mocked servers.
pub(super) async fn transfer_preferences_impl(
    source_client: &OAuthClient,
    dest_client: &OAuthClient,
) -> Result<(), MigrationError> {
    // 1. Get preferences from source (old PDS, authenticated)
    tracing::debug!("fetching preferences from source");
    let prefs = crate::pds_client::get_preferences(source_client)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to get preferences from source");
            MigrationError::PreferencesTransferFailed {
                message: format!("failed to get preferences: {}", e),
            }
        })?;

    // 2. Put preferences to destination (new PDS, Bearer-authenticated)
    tracing::debug!("uploading preferences to destination");
    crate::pds_client::put_preferences(dest_client, &prefs)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to put preferences to destination");
            MigrationError::PreferencesTransferFailed {
                message: format!("failed to put preferences: {}", e),
            }
        })?;

    Ok(())
}

/// Tauri command: get preferences from source PDS and put to destination.
///
/// Gate: ensure_phase_did(..., BlobsTransferred) → clone source_client AND dest_client; drop lock
/// Then: transfer_preferences_impl; re-lock + advance to PreferencesTransferred
pub async fn transfer_preferences(
    state: &crate::oauth::Core,
    did: String,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "transfer_preferences: getting and putting preferences");

    // Gate + extract dependencies
    let (source_client, dest_client, recovery) = {
        let orchestration = state.orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, &did, MigrationPhase::BlobsTransferred)
            .map_err(|e| {
                tracing::warn!("transfer_preferences: phase gate failed: {}", e);
                e
            })?;

        (
            mig.source_client.clone(),
            mig.dest_client.clone(),
            mig.recovery,
        )
    }; // lock released

    // Disaster recovery: there is no source to read preferences from and no
    // preferences backup exists — skip honestly and advance the phase so the rest of
    // the flow proceeds.
    if recovery {
        tracing::info!(did = %did, "transfer_preferences: recovery session has no preferences source; skipping");
        return MigrationJournal::new(&state.orchestration_state, &did)
            .save(MigrationPhase::PreferencesTransferred)
            .await;
    }

    let Some(source_client) = source_client else {
        tracing::error!(did = %did, "transfer_preferences: source_client not found");
        return Err(MigrationError::SourceAuthFailed {
            message: "source client not authenticated".into(),
        });
    };

    let Some(dest_client) = dest_client else {
        tracing::error!(did = %did, "transfer_preferences: dest_client not found");
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    // Transfer preferences (pure core, unit-tested).
    transfer_preferences_impl(&source_client, &dest_client).await?;

    MigrationJournal::new(&state.orchestration_state, &did)
        .save(MigrationPhase::PreferencesTransferred)
        .await?;

    tracing::info!(did = %did, "preferences transferred successfully");
    Ok(())
}

// ── verify_import ──────────────────────────────────────────────────

/// Pure completeness check: the import reconciles when every expected blob is accounted
/// for — either imported or on the user-accepted loss manifest — AND the repo is present. Does NOT
/// require valid_did (the DID doc still points at the old PDS pre-identity-op). `accepted_loss` is
/// the count of blobs the user explicitly chose to skip via the drain's manifest; on a clean
/// migration it is 0 and this reduces to the exact `imported == expected` check.
pub fn import_reconciles_with_loss(
    status: &crate::pds_client::AccountStatus,
    accepted_loss: u64,
) -> bool {
    status.imported_blobs.saturating_add(accepted_loss) == status.expected_blobs
        && status.repo_commit.is_some()
}

/// Tauri command: check destination account completeness, advance to Verified if reconciled.
///
/// Gate: ensure_phase_did(..., PreferencesTransferred) → clone dest_client; drop lock
/// Then: check_account_status(dest_client); if import_reconciles → advance to Verified & return status;
///       else → VerificationIncomplete with counts, phase unchanged
pub async fn verify_import(
    state: &crate::oauth::Core,
    did: String,
) -> Result<crate::pds_client::AccountStatus, MigrationError> {
    tracing::info!(did = %did, "verify_import: checking account completeness");

    // Gate + extract dependencies. Capture the accepted blob-loss count so the reconcile check can
    // tolerate blobs the user explicitly chose to skip via the drain's manifest.
    let (dest_client, accepted_loss) = {
        let orchestration = state.orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, &did, MigrationPhase::PreferencesTransferred)
            .map_err(|e| {
                tracing::warn!("verify_import: phase gate failed: {}", e);
                e
            })?;

        (mig.dest_client.clone(), mig.accepted_blob_loss.len() as u64)
    }; // lock released

    let Some(dest_client) = dest_client else {
        tracing::error!(did = %did, "verify_import: dest_client not found");
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    // Check account status on destination
    let status = crate::pds_client::check_account_status(&dest_client)
        .await
        .map_err(|e| {
            tracing::error!(did = %did, error = %e, "check_account_status failed");
            MigrationError::NetworkError {
                message: format!("failed to check account status: {}", e),
            }
        })?;

    // Gate: verify import is complete (blobs — imported or accepted-as-lost — plus repo)
    if import_reconciles_with_loss(&status, accepted_loss) {
        MigrationJournal::new(&state.orchestration_state, &did)
            .save(MigrationPhase::Verified)
            .await?;

        tracing::info!(did = %did, "import verified successfully");
        Ok(status)
    } else {
        // Import incomplete — return counts, phase unchanged
        tracing::warn!(
            did = %did,
            imported_blobs = status.imported_blobs,
            expected_blobs = status.expected_blobs,
            repo_commit = ?status.repo_commit,
            "import incomplete"
        );
        Err(MigrationError::VerificationIncomplete {
            imported: status.imported_blobs,
            expected: status.expected_blobs,
        })
    }
}
