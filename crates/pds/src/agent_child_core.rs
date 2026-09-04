// pattern: Imperative Shell
//
// The verify → provision → publish → finalize core behind sovereign child accounts. Route modules
// may not import one another, so the mint lives here and its two callers — the parent-owned
// `POST /agent/child` and the cooperative arm of `POST /agent/identity/claim/confirm` — share it;
// every caller owns its own authentication and response shape. They differ only in how the child's
// registration row comes into being, which `ChildRegistration` names.
//
// The sequence is resumable rather than atomic, because publishing the genesis operation to
// plc.directory is a network call that cannot join a SQLite transaction: `prepare_child` commits
// the child deactivated with a provisioning row, the op is published, and `finalize_child` activates
// it and sequences the repo. A crash or a plc outage between the two leaves a deactivated child that
// the next identical mint resumes from its provisioning row.

use uuid::Uuid;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::agent_assertion::{mint_identity_assertion, scopes_to_json};
use crate::auth::password::hash_password;
use crate::db::agent_auth::{
    complete_agent_claim_attempt, convert_identity_to_child, insert_agent_identity,
    AgentIdentityStatus, InsertAgentIdentityOutcome, NewAgentIdentity, RegistrationType,
};
use crate::db::is_unique_violation;
use crate::db::repo_keys::{get_reserved_repo_key_by_id, insert_did_signing_key, RepoSigningKey};

/// How the child's agent-registration row comes into being — the one thing that differs between
/// this core's callers.
///
/// `POST /agent/child` opens a fresh registration. The cooperative claim arm instead *converts* the
/// anonymous registration the agent is already polling, so the agent collects a child-subject
/// credential through the claim-grant poll it was already running. The claim attempt is consumed in
/// the same transaction as that conversion: everything that can reject a mint (handle validation,
/// genesis verification, the reserved-key check, plc publication) happens strictly before it, so a
/// rejected mint leaves the registration claimable.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ChildRegistration<'a> {
    New,
    FromClaim {
        registration_id: &'a str,
        claim_attempt_id: &'a str,
        /// The account owner who confirmed — attributed on the claim-confirmed audit event.
        confirmed_by: &'a str,
    },
}

impl ChildRegistration<'_> {
    fn registration_id(&self) -> String {
        match self {
            ChildRegistration::New => format!("reg_{}", Uuid::new_v4().simple()),
            ChildRegistration::FromClaim {
                registration_id, ..
            } => (*registration_id).to_string(),
        }
    }
}

/// A provisioned sovereign child: its identity, and the capability its parent hands the agent.
pub(crate) struct MintedChild {
    pub(crate) registration_id: String,
    pub(crate) did: String,
    pub(crate) did_document: serde_json::Value,
    pub(crate) identity_assertion: String,
    /// SQLite datetime, as stored on the identity row; callers format their own wire value.
    pub(crate) assertion_expires: String,
    pub(crate) scopes: Vec<String>,
}

/// Verify a wallet-signed genesis operation and provision the child it describes under `parent_did`.
///
/// The caller has already established that `parent_did` is an authenticated local account owner —
/// this performs no authorization of its own beyond refusing a child DID equal to its parent.
/// Re-running it with the same handle and operation resumes an interrupted mint instead of
/// conflicting; a different parent or handle for an in-flight child DID is a conflict.
pub(crate) async fn mint_child_account(
    state: &AppState,
    parent_did: &str,
    handle: &str,
    plc_op: &serde_json::Value,
    registration: ChildRegistration<'_>,
) -> Result<MintedChild, ApiError> {
    crate::identity::handle::validate_handle(
        handle,
        &state.config.available_user_domains,
        &state.config.reserved_handles,
    )
    .map_err(|message| ApiError::new(ErrorCode::InvalidHandle, message))?;

    let rotation_key = plc_op
        .get("rotationKeys")
        .and_then(serde_json::Value::as_array)
        .and_then(|keys| keys.first())
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ApiError::new(ErrorCode::InvalidClaim, "plcOp.rotationKeys[0] is required")
        })?;
    let (verified, signed_op) = crate::identity::genesis::verify_and_validate_genesis_op(
        rotation_key,
        plc_op,
        handle,
        &state.config.public_url,
    )?;
    let child_did = verified.did.clone();
    if child_did == parent_did {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "child DID must differ from parent",
        ));
    }
    let repo_key_id = verified
        .verification_methods
        .get("atproto")
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidClaim, "plcOp atproto key is required"))?;
    let repo_key = get_reserved_repo_key_by_id(&state.db, repo_key_id)
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to load signing key"))?
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidClaim,
                "plcOp atproto key is not reserved on this server",
            )
        })?;
    let master_key: &[u8; 32] = state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|key| &*key.0)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::ServiceUnavailable,
                "signing key service unavailable",
            )
        })?;
    let private = crypto::decrypt_private_key(&repo_key.private_key_encrypted, master_key)
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to prepare child repo"))?;
    let signer = repo_engine::CommitSigner::from_bytes(&private)
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to prepare child repo"))?;
    let (root, rev, blocks) = repo_engine::build_genesis_repo(&child_did, &signer)
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to build child repo"))?;
    let root_string = root.to_string();
    let genesis_car = crate::identity::genesis::build_genesis_car(root, &blocks);
    let sync_car = crate::identity::genesis::build_commit_block_car(root, &blocks)
        .ok_or_else(|| ApiError::new(ErrorCode::InternalError, "failed to build child repo"))?;
    let did_document = crate::identity::genesis::build_did_document(&verified)?;

    let registration_id = registration.registration_id();
    let scopes = state.config.agent_auth.granted_scopes.clone();
    let scopes_json = scopes_to_json(&scopes);
    let assertion = mint_identity_assertion(
        &state.oauth_signing_keypair,
        &state.config.public_url,
        state.config.agent_auth.claimed_assertion_ttl_secs,
        &child_did,
        &registration_id,
        RegistrationType::Child.as_str(),
        &scopes,
    )
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to mint child capability"))?;

    let prepared = prepare_child(
        state,
        parent_did,
        handle,
        &child_did,
        &did_document,
        &repo_key,
        &registration_id,
        &scopes_json,
        &assertion.jwt,
        &assertion.expires_sqlite,
        &root_string,
        &rev,
        &blocks,
        &signed_op,
        &genesis_car,
        &sync_car,
    )
    .await?;

    if !prepared.plc_published {
        publish_child_genesis(state, &prepared, &did_document).await?;
        sqlx::query(
            "UPDATE agent_child_provisionings SET plc_published_at = datetime('now'), \
             updated_at = datetime('now') WHERE child_did = ?",
        )
        .bind(&child_did)
        .execute(&state.db)
        .await
        .map_err(|_| {
            ApiError::new(
                ErrorCode::InternalError,
                "child published; retry to finish local activation",
            )
        })?;
    }
    finalize_child(state, &prepared, registration).await?;

    Ok(MintedChild {
        registration_id: prepared.registration_id,
        did: child_did,
        did_document,
        identity_assertion: prepared.assertion,
        assertion_expires: prepared.assertion_expires,
        scopes: serde_json::from_str(&prepared.scopes).unwrap_or(scopes),
    })
}

struct PreparedChild {
    child_did: String,
    child_handle: String,
    parent_did: String,
    registration_id: String,
    scopes: String,
    assertion: String,
    assertion_expires: String,
    signed_op: String,
    root: String,
    rev: String,
    genesis_car: Vec<u8>,
    sync_car: Vec<u8>,
    plc_published: bool,
    finalized: bool,
}

#[allow(clippy::too_many_arguments)]
async fn prepare_child(
    state: &AppState,
    parent_did: &str,
    handle: &str,
    child_did: &str,
    did_document: &serde_json::Value,
    repo_key: &RepoSigningKey,
    registration_id: &str,
    scopes: &str,
    assertion: &str,
    assertion_expires_at: &str,
    root: &str,
    rev: &str,
    blocks: &[(repo_engine::Cid, Vec<u8>)],
    signed_op: &str,
    genesis_car: &[u8],
    sync_car: &[u8],
) -> Result<PreparedChild, ApiError> {
    type PendingRow = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        bool,
        bool,
    );
    let existing = sqlx::query_as::<_, PendingRow>(
        "SELECT p.parent_did, p.handle, p.registration_id, p.scopes, p.identity_assertion, \
                p.assertion_expires_at, p.signed_op, p.genesis_car, p.sync_car, \
                p.plc_published_at IS NOT NULL, p.finalized_at IS NOT NULL \
         FROM agent_child_provisionings p WHERE p.child_did = ?",
    )
    .bind(child_did)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        ApiError::new(
            ErrorCode::InternalError,
            "failed to resume child provisioning",
        )
    })?;
    if let Some((
        stored_parent,
        stored_handle,
        stored_registration,
        stored_scopes,
        stored_assertion,
        stored_expiry,
        stored_signed_op,
        stored_genesis_car,
        stored_sync_car,
        plc_published,
        finalized,
    )) = existing
    {
        if stored_parent != parent_did || stored_handle != handle {
            return Err(ApiError::new(
                ErrorCode::DidAlreadyExists,
                "child DID is already being provisioned",
            ));
        }
        let (stored_root, stored_rev): (String, String) =
            sqlx::query_as("SELECT repo_root_cid, repo_rev FROM accounts WHERE did = ?")
                .bind(child_did)
                .fetch_one(&state.db)
                .await
                .map_err(|_| {
                    ApiError::new(
                        ErrorCode::InternalError,
                        "failed to resume child provisioning",
                    )
                })?;
        return Ok(PreparedChild {
            child_did: child_did.to_string(),
            child_handle: stored_handle,
            parent_did: stored_parent,
            registration_id: stored_registration,
            scopes: stored_scopes,
            assertion: stored_assertion,
            assertion_expires: stored_expiry,
            signed_op: stored_signed_op,
            root: stored_root,
            rev: stored_rev,
            genesis_car: stored_genesis_car,
            sync_car: stored_sync_car,
            plc_published,
            finalized,
        });
    }

    let document = serde_json::to_string(did_document)
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store child DID"))?;
    let disabled_password = hash_password(&Uuid::new_v4().to_string())?;
    let mut tx = state.db.begin().await.map_err(|_| {
        ApiError::new(
            ErrorCode::InternalError,
            "failed to begin child transaction",
        )
    })?;
    let account_result = sqlx::query(
        "INSERT INTO accounts (did, email, password_hash, repo_root_cid, repo_rev, deactivated_at, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'), datetime('now'))",
    )
    .bind(child_did)
    .bind(format!("{registration_id}@agents.invalid"))
    .bind(disabled_password)
    .bind(root)
    .bind(rev)
    .execute(&mut *tx)
    .await;
    if let Err(error) = account_result {
        return Err(if is_unique_violation(&error) {
            ApiError::new(ErrorCode::DidAlreadyExists, "child DID already exists")
        } else {
            ApiError::new(ErrorCode::InternalError, "failed to create child account")
        });
    }
    sqlx::query("INSERT INTO did_documents (did, document, created_at, updated_at) VALUES (?, ?, datetime('now'), datetime('now'))")
        .bind(child_did).bind(document).execute(&mut *tx).await
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store child DID"))?;
    sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
        .bind(handle)
        .bind(child_did)
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                ApiError::new(ErrorCode::HandleTaken, "handle is already taken")
            } else {
                ApiError::new(ErrorCode::InternalError, "failed to store child handle")
            }
        })?;
    insert_did_signing_key(&mut *tx, child_did, repo_key)
        .await
        .map_err(|_| {
            ApiError::new(
                ErrorCode::InternalError,
                "failed to store child signing key",
            )
        })?;
    for (cid, bytes) in blocks {
        crate::db::blocks::put_block_with_rev(
            &mut tx,
            &cid.to_string(),
            child_did,
            bytes,
            Some(rev),
        )
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store child repo"))?;
    }
    sqlx::query(
        "INSERT INTO agent_child_provisionings \
         (child_did, parent_did, handle, registration_id, signed_op, scopes, identity_assertion, \
          assertion_expires_at, genesis_car, sync_car, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
    )
    .bind(child_did)
    .bind(parent_did)
    .bind(handle)
    .bind(registration_id)
    .bind(signed_op)
    .bind(scopes)
    .bind(assertion)
    .bind(assertion_expires_at)
    .bind(genesis_car)
    .bind(sync_car)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        ApiError::new(
            ErrorCode::InternalError,
            "failed to reserve child provisioning",
        )
    })?;
    tx.commit().await.map_err(|_| {
        ApiError::new(
            ErrorCode::InternalError,
            "failed to reserve child provisioning",
        )
    })?;
    Ok(PreparedChild {
        child_did: child_did.to_string(),
        child_handle: handle.to_string(),
        parent_did: parent_did.to_string(),
        registration_id: registration_id.to_string(),
        scopes: scopes.to_string(),
        assertion: assertion.to_string(),
        assertion_expires: assertion_expires_at.to_string(),
        signed_op: signed_op.to_string(),
        root: root.to_string(),
        rev: rev.to_string(),
        genesis_car: genesis_car.to_vec(),
        sync_car: sync_car.to_vec(),
        plc_published: false,
        finalized: false,
    })
}

async fn publish_child_genesis(
    state: &AppState,
    prepared: &PreparedChild,
    expected_document: &serde_json::Value,
) -> Result<(), ApiError> {
    let plc_url = format!("{}/{}", state.config.plc_directory_url, prepared.child_did);
    let already_published = match state.http_client.get(&plc_url).send().await {
        Ok(response) if response.status().is_success() => response
            .json::<serde_json::Value>()
            .await
            .is_ok_and(|document| document == *expected_document),
        _ => false,
    };
    if !already_published {
        crate::identity::genesis::post_to_plc_directory(
            &state.http_client,
            &state.config.plc_directory_url,
            &prepared.child_did,
            &prepared.signed_op,
        )
        .await?;
    }
    Ok(())
}

async fn finalize_child(
    state: &AppState,
    prepared: &PreparedChild,
    registration: ChildRegistration<'_>,
) -> Result<(), ApiError> {
    if prepared.finalized {
        return Ok(());
    }
    let emit_guard = state.firehose.lock_emit().await;
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to finalize child"))?;
    match registration {
        ChildRegistration::New => {
            let inserted = insert_agent_identity(
                &mut *tx,
                &NewAgentIdentity {
                    id: &prepared.registration_id,
                    did: Some(&prepared.child_did),
                    parent_did: Some(&prepared.parent_did),
                    registration_type: RegistrationType::Child,
                    issuer: None,
                    subject: Some(&prepared.child_did),
                    email: None,
                    scopes: &prepared.scopes,
                    identity_assertion: Some(&prepared.assertion),
                    assertion_expires_at: &prepared.assertion_expires,
                    pre_claim_scopes: None,
                    claim_token: None,
                    claim_token_expires_at: None,
                    handle_hint: None,
                },
            )
            .await?;
            if inserted != InsertAgentIdentityOutcome::Created {
                return Err(ApiError::new(
                    ErrorCode::InternalError,
                    "failed to create child capability",
                ));
            }
            // A child is provisioned and authorized in one parent-approved operation.
            crate::db::agent_auth::set_agent_identity_status(
                &mut *tx,
                &prepared.registration_id,
                AgentIdentityStatus::Claimed,
            )
            .await?;
        }
        ChildRegistration::FromClaim {
            claim_attempt_id,
            confirmed_by,
            ..
        } => {
            // This is the claim-consuming write. Each half carries its own guard, so a lost race
            // against a concurrent confirm rolls the whole mint back rather than double-claiming.
            if !complete_agent_claim_attempt(&mut *tx, claim_attempt_id).await? {
                return Err(ApiError::new(
                    ErrorCode::InvalidClaim,
                    "this claim attempt is no longer pending",
                ));
            }
            if !convert_identity_to_child(
                &mut *tx,
                &prepared.registration_id,
                &prepared.child_did,
                &prepared.parent_did,
                &prepared.scopes,
                &prepared.assertion,
                &prepared.assertion_expires,
            )
            .await?
            {
                return Err(ApiError::new(
                    ErrorCode::InvalidClaim,
                    "this registration is no longer active",
                ));
            }
            // The human gate anchors the audit trail, so it commits with the claim itself.
            crate::db::agent_audit::insert_agent_audit_event(
                &mut *tx,
                &Uuid::new_v4().to_string(),
                &prepared.registration_id,
                Some(confirmed_by),
                crate::db::agent_audit::AgentAuditEventType::ClaimConfirmed,
                Some(
                    &serde_json::json!({
                        "claim_attempt_id": claim_attempt_id,
                        "child_did": prepared.child_did,
                        "scopes": serde_json::from_str::<serde_json::Value>(&prepared.scopes)
                            .unwrap_or(serde_json::Value::Null),
                    })
                    .to_string(),
                ),
            )
            .await?;
        }
    }
    let pending = emit_guard
        .stage_commit(
            &mut tx,
            crate::firehose::CommitInput {
                repo: prepared.child_did.clone(),
                commit: prepared.root.clone(),
                rev: prepared.rev.clone(),
                since: None,
                prev_data: None,
                ops: Vec::new(),
                blocks: prepared.genesis_car.clone(),
            },
        )
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to sequence child repo"))?
        .stage_sync(
            &mut tx,
            crate::firehose::SyncInput {
                did: prepared.child_did.clone(),
                rev: prepared.rev.clone(),
                blocks: prepared.sync_car.clone(),
            },
        )
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to sequence child repo"))?;
    sqlx::query(
        "UPDATE accounts SET deactivated_at = NULL, updated_at = datetime('now') WHERE did = ?",
    )
    .bind(&prepared.child_did)
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to activate child"))?;
    sqlx::query(
        "UPDATE agent_child_provisionings SET finalized_at = datetime('now'), \
         updated_at = datetime('now') WHERE child_did = ? AND plc_published_at IS NOT NULL",
    )
    .bind(&prepared.child_did)
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to finalize child"))?;
    tx.commit()
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to commit child"))?;
    pending.finish();
    if let Err(error) = state
        .firehose
        .emit_account(prepared.child_did.clone(), true, None)
        .await
    {
        tracing::warn!(%error, did = %prepared.child_did, "failed to emit child account event");
    }
    // Announce the child's handle binding the same way createHandle does. Without this frame a
    // relay never learns the new DID's handle: the PLC genesis op lands, but nothing upstream
    // re-resolves a DID it has no reason to look at, so every app shows the child as an invalid
    // handle until some unrelated event forces a resolution.
    if let Err(error) = state
        .firehose
        .emit_identity(
            prepared.child_did.clone(),
            Some(prepared.child_handle.clone()),
        )
        .await
    {
        tracing::warn!(%error, did = %prepared.child_did, "failed to emit child identity event");
    }
    state.crawlers.notify();
    Ok(())
}
