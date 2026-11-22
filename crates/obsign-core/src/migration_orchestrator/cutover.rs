// pattern: Mixed (pure cores + Imperative Shell commands — see the parent module doc)

//! Cutover steps: `arm_identity_leg` and `finalize_migration`.

use super::*;

// ── arm_identity_leg ───────────────────────────────────────────────

/// Tauri command: populate the migration identity-leg state with the destination Bearer client,
/// then advance to IdentityArmed.
///
/// Gate: ensure_phase_did(..., Verified) → clone dest_client; drop lock
/// Build fresh MigrationState { did, dest_oauth_client, signed_op: None, op_cid: None }; store in Core
/// Advance phase → IdentityArmed
pub async fn arm_identity_leg(
    state: &crate::oauth::Core,
    did: String,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "arm_identity_leg: populating migration identity-leg state");
    arm_identity_leg_core(&state.orchestration_state, &state.migration_state, &did).await
}

/// Core of `arm_identity_leg`, parameterized over the two mutexes so it is unit-testable without a
/// Tauri `State`. Gate at Verified → build `migrate::MigrationState` with the dest Bearer client →
/// park it in `migration_state` → advance the orchestration phase to `IdentityArmed`. No network.
pub(super) async fn arm_identity_leg_core(
    orchestration_state: &tokio::sync::Mutex<Option<OutboundMigrationState>>,
    migration_state: &tokio::sync::Mutex<Option<crate::migrate::MigrationState>>,
    did: &str,
) -> Result<(), MigrationError> {
    // Gate: ensure phase + DID, extract dest_client
    let dest_client = {
        let orchestration = orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, did, MigrationPhase::Verified).map_err(|e| {
            tracing::warn!("arm_identity_leg: phase gate failed: {}", e);
            e
        })?;
        mig.dest_client.clone()
    }; // lock released

    let Some(dest_client) = dest_client else {
        tracing::error!(did = %did, "arm_identity_leg: dest_client not found");
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    // Build + park the identity-leg state (dest_oauth_client is Arc<OAuthClient>, NOT Option).
    *migration_state.lock().await = Some(crate::migrate::MigrationState {
        did: did.to_string(),
        dest_oauth_client: dest_client,
        signed_op: None,
        op_cid: None,
    });

    MigrationJournal::new(orchestration_state, did)
        .save(MigrationPhase::IdentityArmed)
        .await?;

    tracing::info!(did = %did, "identity leg armed successfully");
    Ok(())
}

// ── finalize_migration ─────────────────────────────────────────────

/// Activate the destination account. First cutover step — retry-tolerant and
/// server-idempotent, so a resumed finalize can safely call it again.
pub(super) async fn activate_destination_account(
    dest_client: &OAuthClient,
) -> Result<(), MigrationError> {
    tracing::debug!("finalizing migration: activating destination account");
    crate::pds_client::activate_account(dest_client)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "activate_account failed");
            MigrationError::ActivationFailed {
                message: format!("failed to activate destination account: {}", e),
            }
        })
}

/// Deactivate the source account (no `deleteAfter`). Last cutover step — runs only
/// after the destination is active AND its sovereign session is durably persisted,
/// so a wallet crash can never strand the account credential-less.
pub(super) async fn deactivate_source_account(
    source_client: &OAuthClient,
) -> Result<(), MigrationError> {
    tracing::debug!("finalizing migration: deactivating source account");
    crate::pds_client::deactivate_account(source_client, None)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "deactivate_account failed");
            MigrationError::DeactivationFailed {
                message: format!("failed to deactivate source account: {}", e),
            }
        })
}

/// Map a sovereign-login failure onto the retryable pre-cutover migration errors.
/// A Keychain write failure is a *persistence* failure (the mint succeeded but could
/// not be saved); everything else is a *login* failure. Both keep the source active.
pub(super) fn map_sovereign_error(
    error: crate::sovereign_session::SovereignLoginError,
) -> MigrationError {
    use crate::sovereign_session::SovereignLoginError as E;
    match error {
        E::Shared(crate::failure::SharedFailure::KeychainError { message }) => {
            MigrationError::SessionPersistFailed { message }
        }
        other => MigrationError::SovereignLoginFailed {
            message: other.to_string(),
        },
    }
}

/// Ensure the migrated DID has a durably persisted destination sovereign session,
/// minting one with the DID's current rotation key if needed.
///
/// Idempotency (the resume seam): if a persisted record whose *refresh* token is
/// still unexpired already exists, this returns `Ok` without signing anything — a
/// resumed finalize must not re-mint (and thus must not require a fresh device-key
/// signature) when a durable credential already exists. Only a missing or
/// refresh-expired record triggers a new device-signed mint via
/// `sovereign_login`, which discovers plc.directory's current rotation set and
/// the hosted account, proves control, and atomically replaces the token record.
pub(super) async fn ensure_sovereign_session_persisted(
    core: &crate::oauth::Core,
    did: &str,
) -> Result<(), MigrationError> {
    let now = core.unix_timestamp();
    if let Some(record) = core.identities().load_oauth_tokens(did).map_err(|e| {
        MigrationError::SessionPersistFailed {
            message: e.to_string(),
        }
    })? {
        if record
            .refresh_expires_at
            .is_some_and(|exp| (exp as i64) > now)
        {
            tracing::info!(did = %did, "sovereign session already persisted; skipping re-mint");
            return Ok(());
        }
    }

    crate::sovereign_session::sovereign_login(core, did.to_string())
        .await
        .map(|_| ())
        .map_err(map_sovereign_error)
}

/// Ensure a migrated identity has a durably persisted destination session, built from the
/// Bearer pair the destination already issued during the migration `createAccount`.
///
/// This is the finalize path for every destination that cannot mint a sovereign session,
/// for either of two reasons:
///
/// * **The identity has no rotation keys.** A did:web account has no PLC rotation set, so
///   the rotation-key-signed mint is impossible regardless of who hosts it.
/// * **The host does not serve one.** `/v1/sessions/sovereign` is a Custos route; a
///   reference PDS, bsky.social, or any other spec-compliant host has no such endpoint.
///
/// In both cases the Bearer pair from `createAccount` is the account's only credential.
/// Persisting it into the same versioned `{did}:oauth-tokens` record `sovereign_login`
/// writes is what makes it survive the app process — and from that write on, the session
/// provider restores, refreshes, and host-change-discards it identically no matter which
/// path minted it. Post-cutover re-unlock then rides the password `createSession` route
/// (`password_unlock`), which is exactly what a non-Custos host serves.
///
/// It must succeed *before* the source is deactivated, so a failure here aborts the
/// cutover with the source still active.
///
/// Idempotency mirrors `ensure_sovereign_session_persisted`: an existing record
/// whose refresh token is still unexpired is left untouched, so a resumed
/// finalize never clobbers a durable credential with a possibly-staler one.
pub(super) async fn ensure_bearer_session_persisted(
    core: &crate::oauth::Core,
    did: &str,
    dest_client: &OAuthClient,
    dest_pds_url: &str,
    dest_server_did: &str,
) -> Result<(), MigrationError> {
    let store = core.identities();
    let now = core.unix_timestamp();
    if let Some(record) =
        store
            .load_oauth_tokens(did)
            .map_err(|e| MigrationError::SessionPersistFailed {
                message: e.to_string(),
            })?
    {
        if record
            .refresh_expires_at
            .is_some_and(|exp| (exp as i64) > now)
        {
            tracing::info!(did = %did, "destination bearer session already persisted; skipping");
            return Ok(());
        }
    }

    let (access_jwt, refresh_jwt) = dest_client.session_tokens();
    let access_claims = crate::sovereign_session::bearer_jwt_claims(&access_jwt).ok_or(
        MigrationError::SessionPersistFailed {
            message: "destination access token is not a readable JWT".into(),
        },
    )?;
    let refresh_claims = crate::sovereign_session::bearer_jwt_claims(&refresh_jwt).ok_or(
        MigrationError::SessionPersistFailed {
            message: "destination refresh token is not a readable JWT".into(),
        },
    )?;
    for claims in [&access_claims, &refresh_claims] {
        if claims.sub != did {
            return Err(MigrationError::SessionPersistFailed {
                message: "destination session subject does not match the migrated DID".into(),
            });
        }
        if !crate::sovereign_session::audience_matches_server(
            &claims.aud,
            dest_server_did,
            dest_pds_url,
        ) {
            return Err(MigrationError::SessionPersistFailed {
                message: "destination session audience does not match the destination PDS".into(),
            });
        }
    }

    let record = crate::identity_store::SovereignTokenRecord {
        version: crate::identity_store::SovereignTokenRecord::VERSION,
        access_jwt,
        refresh_jwt,
        pds_url: dest_pds_url.trim_end_matches('/').to_string(),
        server_did: dest_server_did.to_string(),
        access_expires_at: Some(access_claims.exp),
        refresh_expires_at: Some(refresh_claims.exp),
        stored_at: u64::try_from(now).map_err(|_| MigrationError::SessionPersistFailed {
            message: "system clock is before the Unix epoch".into(),
        })?,
    };
    store
        .store_oauth_tokens(did, &record)
        .map_err(|e| MigrationError::SessionPersistFailed {
            message: e.to_string(),
        })
}

/// Which durable destination credential this finalize should persist.
///
/// The sovereign mint (`/v1/sessions/sovereign`) needs two things that are not always
/// present: PLC rotation keys to sign the proof with, and a host that serves the route.
/// This is the pure decision over both, so the reasoning is testable without a PDS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DestinationCredential {
    /// Mint a fresh rotation-key-signed session against the destination.
    Sovereign,
    /// Persist the Bearer pair the destination already issued at `createAccount`.
    Bearer,
}

/// Decide which credential the cutover should durably persist.
///
/// * A **did:web** identity has no PLC rotation set, so nothing can sign the sovereign
///   proof — Bearer regardless of host.
/// * A host that **answered** describeServer and does not advertise `sovereignSessions`
///   has no such route; attempting the mint would 404 *after* the identity op already
///   landed, which is the whole failure this branch removes.
/// * A host that could **not be asked** keeps today's sovereign behavior. Step 1 of the
///   cutover (`activateAccount`) has already succeeded against this host by the time this
///   is read, so `reached: false` here means a describeServer hiccup, not a dead server —
///   and inferring "no sovereign sessions" from a blink would silently downgrade a Custos
///   destination's credential on the strength of a fact never established.
pub(super) fn destination_credential(
    did: &str,
    destination: &ServerCapabilities,
) -> DestinationCredential {
    if did.starts_with("did:web:") {
        return DestinationCredential::Bearer;
    }
    if destination.reached && !destination.sovereign_sessions() {
        return DestinationCredential::Bearer;
    }
    DestinationCredential::Sovereign
}

/// Tauri command: run the safe cutover — activate the destination, durably persist its
/// session, deactivate the source, then advance to Finalized.
///
/// Gate: ensure_phase_did(..., IdentityArmed) → defense-in-depth: migration_state
/// must be cleared (None) to prove the identity op was submitted; if Some → MIGRATION_NOT_READY.
///
/// Which credential gets persisted is [`destination_credential`]'s call. On the sovereign
/// branch the mint runs against the DID's *current* PLC rotation set (the identity op has
/// already landed) using a fresh device-key proof; the frontend re-gates biometric before
/// every finalize invocation, so a resumed attempt obtains fresh authorization before that
/// signature (and the idempotent skip means an already-persisted session signs nothing at all).
///
/// Both branches run through the same [`finalize_migration_core`], so the strict activate →
/// durable credential → deactivate ordering and the phase advance are identical no matter which
/// credential is persisted.
pub async fn finalize_migration(
    core: &crate::oauth::Core,
    did: String,
) -> Result<(), MigrationError> {
    let did = did.as_str();
    let orchestration_state = &core.orchestration_state;
    let migration_state = &core.migration_state;
    let pds_client = core.pds_client();
    tracing::info!(did = %did, "finalize_migration: activate → destination session → deactivate");

    // Snapshot the destination coordinates up front — the closure runs after
    // `finalize_migration_core`'s own phase/client gates, so a missing client here surfaces
    // through those gates, never through the closure.
    let (dest_client, dest_pds_url, dest_server_did) = {
        let orchestration = orchestration_state.lock().await;
        match orchestration.as_ref() {
            Some(mig) => (
                mig.dest_client.clone(),
                mig.dest_pds_url.clone(),
                mig.dest_did.clone(),
            ),
            None => (None, String::new(), String::new()),
        }
    };

    // Reads the per-host cache `prepare_migration`'s describeServer already warmed, so this
    // is normally a lock and a map lookup rather than a request.
    let destination_capabilities = if dest_pds_url.is_empty() {
        ServerCapabilities::none()
    } else {
        crate::pds_capabilities::probe(pds_client, &dest_pds_url).await
    };

    if destination_credential(did, &destination_capabilities) == DestinationCredential::Bearer {
        tracing::info!(
            did = %did,
            dest_pds_url = %dest_pds_url,
            "destination cannot mint a sovereign session; persisting the createAccount bearer pair"
        );
        return finalize_migration_core(orchestration_state, migration_state, did, || async move {
            let dest_client = dest_client.ok_or_else(|| MigrationError::AccountCreationFailed {
                message: "destination client not authenticated".into(),
            })?;
            ensure_bearer_session_persisted(
                core,
                did,
                &dest_client,
                &dest_pds_url,
                &dest_server_did,
            )
            .await
        })
        .await;
    }

    finalize_migration_core(orchestration_state, migration_state, did, || async move {
        ensure_sovereign_session_persisted(core, did).await
    })
    .await
}

/// Core of `finalize_migration`, parameterized over the two mutexes and an injected
/// `ensure_session` step so its gating, ordering, and phase advance are unit-testable without a
/// Tauri `State`, a Keychain, or a live PDS. Gate at IdentityArmed; require the migrate
/// `migration_state` cleared (== None, proving `submit_migration_op_cmd` ran); then run the cutover
/// in strict order — **activate destination → ensure sovereign session persisted → deactivate
/// source** — and advance to `Finalized`.
///
/// The ordering is the whole point: `ensure_session` (mint + Keychain persist) runs *after*
/// activation and *before* deactivation, so a sovereign-login or persistence failure aborts the
/// cutover with the source still active and no phase advance — retryable, never `Finalized`.
pub(super) async fn finalize_migration_core<Fut>(
    orchestration_state: &tokio::sync::Mutex<Option<OutboundMigrationState>>,
    migration_state: &tokio::sync::Mutex<Option<crate::migrate::MigrationState>>,
    did: &str,
    ensure_session: impl FnOnce() -> Fut,
) -> Result<(), MigrationError>
where
    Fut: std::future::Future<Output = Result<(), MigrationError>>,
{
    // Gate: ensure phase + DID, extract clients
    let (dest_client, source_client, recovery) = {
        let orchestration = orchestration_state.lock().await;
        let mig =
            ensure_phase_did(&orchestration, did, MigrationPhase::IdentityArmed).map_err(|e| {
                tracing::warn!("finalize_migration: phase gate failed: {}", e);
                e
            })?;
        (
            mig.dest_client.clone(),
            mig.source_client.clone(),
            mig.recovery,
        )
    }; // lock released

    let Some(dest_client) = dest_client else {
        tracing::error!(did = %did, "finalize_migration: dest_client not found");
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    // A disaster recovery has no source to deactivate — the source PDS is presumed
    // dead. A normal migration requires the authenticated source client for step 3.
    let source_client = if recovery {
        None
    } else {
        match source_client {
            Some(client) => Some(client),
            None => {
                tracing::error!(did = %did, "finalize_migration: source_client not found");
                return Err(MigrationError::SourceAuthFailed {
                    message: "source client not authenticated".into(),
                });
            }
        }
    };

    // Defense-in-depth: the identity op must have been submitted (migration_state cleared).
    if migration_state.lock().await.is_some() {
        tracing::error!(did = %did, "finalize_migration: migration identity op not yet submitted");
        return Err(MigrationError::MigrationNotReady {
            message: "identity op not yet submitted".into(),
        });
    }

    // 1. Activate destination (idempotent, server-side).
    activate_destination_account(&dest_client).await?;

    // 2. Mint + persist the destination sovereign session BEFORE touching the source. A failure
    //    here (login rejected/rate-limited/5xx/transport, or Keychain write) leaves the source
    //    active and is retryable; the migration never reaches `Finalized`.
    ensure_session().await?;

    // 3. Deactivate source (no deleteAfter) — the destination credential is now durable.
    //    Skipped entirely in a disaster recovery: the source is gone, and there is
    //    nothing to deactivate.
    if let Some(source_client) = &source_client {
        deactivate_source_account(source_client).await?;
    }

    MigrationJournal::new(orchestration_state, did)
        .save(MigrationPhase::Finalized)
        .await?;

    tracing::info!(did = %did, "migration finalized successfully");
    Ok(())
}
