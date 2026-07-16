// pattern: Imperative Shell
//
// Parent-owned provisioning for sovereign child agents. Recovery authority enters only as a
// wallet-signed PLC genesis operation; the server stores the public DID document and its separate
// repo-signing key, then issues a revocable, scope-clamped agent assertion.

use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::agent_assertion::{mint_identity_assertion, scopes_to_json};
use crate::auth::guards::{authenticate_account_owner, OwnerAuthError};
use crate::auth::password::hash_password;
use crate::db::agent_auth::{
    get_child_of_parent, insert_agent_identity, list_children_of_parent, revoke_agent_identity,
    AgentIdentityStatus, InsertAgentIdentityOutcome, NewAgentIdentity, RegistrationType,
};
use crate::db::is_unique_violation;
use crate::db::repo_keys::{get_reserved_repo_key_by_id, insert_did_signing_key, RepoSigningKey};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintChildRequest {
    handle: String,
    plc_op: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MintChildResponse {
    registration_id: String,
    did: String,
    handle: String,
    did_document: serde_json::Value,
    identity_assertion: String,
    assertion_expires: String,
    scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildView {
    registration_id: String,
    did: String,
    handle: String,
    status: &'static str,
    created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ChildListResponse {
    children: Vec<ChildView>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeChildRequest {
    did: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeChildResponse {
    did: String,
    status: &'static str,
}

fn owner_error(error: OwnerAuthError) -> ApiError {
    match error {
        OwnerAuthError::Unauthenticated(error) => error,
        OwnerAuthError::AgentDerived | OwnerAuthError::NotFullAccess => ApiError::new(
            ErrorCode::Forbidden,
            "full account-owner authority is required",
        ),
    }
}

pub async fn mint_child(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MintChildRequest>,
) -> Result<Json<MintChildResponse>, ApiError> {
    let parent_did = authenticate_account_owner(&headers, &state)
        .await
        .map_err(owner_error)?;
    if !crate::db::accounts::account_exists(&state.db, &parent_did).await? {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "parent account is not local",
        ));
    }
    crate::identity::handle::validate_handle(
        &request.handle,
        &state.config.available_user_domains,
        &state.config.reserved_handles,
    )
    .map_err(|message| ApiError::new(ErrorCode::InvalidHandle, message))?;

    let rotation_key = request
        .plc_op
        .get("rotationKeys")
        .and_then(serde_json::Value::as_array)
        .and_then(|keys| keys.first())
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ApiError::new(ErrorCode::InvalidClaim, "plcOp.rotationKeys[0] is required")
        })?;
    let (verified, signed_op) = crate::identity::genesis::verify_and_validate_genesis_op(
        rotation_key,
        &request.plc_op,
        &request.handle,
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

    let registration_id = format!("reg_{}", Uuid::new_v4().simple());
    let scopes = state.config.agent_auth.granted_scopes.clone();
    let scopes_json = scopes_to_json(&scopes);
    let assertion = mint_identity_assertion(
        &state.oauth_signing_keypair,
        &state.config.public_url,
        state.config.agent_auth.assertion_ttl_secs,
        &child_did,
        &registration_id,
        RegistrationType::Child.as_str(),
        &scopes,
    )
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to mint child capability"))?;

    let prepared = prepare_child(
        &state,
        &parent_did,
        &request.handle,
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
        publish_child_genesis(&state, &prepared, &did_document).await?;
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
    finalize_child(&state, &prepared).await?;

    Ok(Json(MintChildResponse {
        registration_id: prepared.registration_id,
        did: child_did,
        handle: request.handle,
        did_document,
        identity_assertion: prepared.assertion,
        assertion_expires: crate::auth::agent_assertion::parse_sqlite_datetime(
            &prepared.assertion_expires,
        )
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        scopes: serde_json::from_str(&prepared.scopes).unwrap_or(scopes),
    }))
}

struct PreparedChild {
    child_did: String,
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

async fn finalize_child(state: &AppState, prepared: &PreparedChild) -> Result<(), ApiError> {
    if prepared.finalized {
        return Ok(());
    }
    let emit_guard = state.firehose.lock_emit().await;
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to finalize child"))?;
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
    state.crawlers.notify();
    Ok(())
}

pub async fn list_children(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ChildListResponse>, ApiError> {
    let parent = authenticate_account_owner(&headers, &state)
        .await
        .map_err(owner_error)?;
    let rows = list_children_of_parent(&state.db, &parent).await?;
    let mut children = Vec::with_capacity(rows.len());
    for row in rows {
        let did = row.did.unwrap_or_default();
        let handle = crate::db::handles::get_handle_by_did(&state.db, &did)
            .await?
            .unwrap_or_default();
        children.push(ChildView {
            registration_id: row.id,
            did,
            handle,
            status: row.status.as_str(),
            created_at: row.created_at,
        });
    }
    Ok(Json(ChildListResponse { children }))
}

pub async fn revoke_child(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RevokeChildRequest>,
) -> Result<Json<RevokeChildResponse>, ApiError> {
    let parent = authenticate_account_owner(&headers, &state)
        .await
        .map_err(owner_error)?;
    let child = get_child_of_parent(&state.db, &request.did, &parent)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "child agent not found"))?;
    revoke_agent_identity(&state.db, &child.id).await?;
    Ok(Json(RevokeChildResponse {
        did: request.did,
        status: "revoked",
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use wiremock::{
        matchers::{method, path_regex},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;
    use crate::app::app;
    use crate::routes::test_utils::{access_jwt, seed_account_with_repo, test_master_key};

    async fn state_with_plc() -> (AppState, MockServer) {
        let plc = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:[a-z2-7]+$"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&plc)
            .await;
        let base = crate::app::test_state_with_plc_url(plc.uri()).await;
        let mut config = (*base.config).clone();
        config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(
            test_master_key(),
        )));
        config.available_user_domains = vec!["example.com".to_string()];
        (
            AppState {
                config: Arc::new(config),
                ..base
            },
            plc,
        )
    }

    async fn state() -> AppState {
        state_with_plc().await.0
    }

    fn request(uri: &str, token: Option<&str>, body: serde_json::Value) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    fn get_request(uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    async fn reserve(db: &sqlx::SqlitePool) -> crypto::P256Keypair {
        let key = crypto::generate_p256_keypair().unwrap();
        let encrypted =
            crypto::encrypt_private_key(&key.private_key_bytes, &test_master_key()).unwrap();
        crate::db::repo_keys::insert_reserved_repo_key(
            db,
            None,
            &RepoSigningKey {
                key_id: key.key_id.to_string(),
                public_key: key.public_key.clone(),
                private_key_encrypted: encrypted,
            },
        )
        .await
        .unwrap();
        key
    }

    fn genesis(handle: &str, pds: &str, signing_key: &str) -> serde_json::Value {
        let rotation = crypto::generate_p256_keypair().unwrap();
        let op = crypto::build_did_plc_genesis_op(
            &rotation.key_id,
            &crypto::DidKeyUri(signing_key.to_string()),
            &rotation.private_key_bytes,
            handle,
            pds,
        )
        .unwrap();
        serde_json::from_str(&op.signed_op_json).unwrap()
    }

    #[tokio::test]
    async fn local_parent_mints_lists_and_revokes_sovereign_child() {
        let state = state().await;
        let parent = "did:plc:parentchildowner111111";
        seed_account_with_repo(&state.db, parent).await;
        let repo_key = reserve(&state.db).await;
        let handle = "alice-writer.example.com";
        let op = genesis(handle, &state.config.public_url, &repo_key.key_id.0);
        let token = access_jwt(&[0x42; 32], parent);

        let response = app(state.clone())
            .oneshot(request(
                "/agent/child",
                Some(&token),
                serde_json::json!({"handle": handle, "plcOp": op}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let minted: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let child = minted["did"].as_str().unwrap();
        assert_ne!(child, parent);
        assert!(crate::db::accounts::account_exists(&state.db, child)
            .await
            .unwrap());
        assert_eq!(
            crate::db::handles::resolve_handle(&state.db, handle)
                .await
                .unwrap()
                .as_deref(),
            Some(child)
        );
        let row = get_child_of_parent(&state.db, child, parent)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, AgentIdentityStatus::Claimed);

        let response = app(state.clone())
            .oneshot(get_request("/agent/child", &token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let listed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(listed["children"][0]["did"], child);
        assert_eq!(listed["children"][0]["handle"], handle);
        assert_eq!(listed["children"][0]["status"], "claimed");
        assert_eq!(
            listed["children"][0]["registrationId"],
            minted["registrationId"]
        );

        let response = app(state.clone())
            .oneshot(request(
                "/agent/child/revoke",
                Some(&token),
                serde_json::json!({"did": child}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let row = get_child_of_parent(&state.db, child, parent)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, AgentIdentityStatus::Revoked);
        assert!(
            crate::db::accounts::account_exists(&state.db, child)
                .await
                .unwrap(),
            "revocation preserves the sovereign identity and recovery path"
        );
    }

    #[tokio::test]
    async fn parent_reads_child_audit_trail_foreign_account_cannot() {
        let state = state().await;
        let parent = "did:plc:parentchildaudit111111";
        seed_account_with_repo(&state.db, parent).await;
        let repo_key = reserve(&state.db).await;
        let handle = "audited-writer.example.com";
        let op = genesis(handle, &state.config.public_url, &repo_key.key_id.0);
        let token = access_jwt(&[0x42; 32], parent);

        let response = app(state.clone())
            .oneshot(request(
                "/agent/child",
                Some(&token),
                serde_json::json!({"handle": handle, "plcOp": op}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let minted: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let registration_id = minted["registrationId"].as_str().unwrap().to_string();

        // The child's own tokens are agent-derived and never pass the owner guard, so the
        // parent is the only party that can read the child's audit trail.
        let response = app(state.clone())
            .oneshot(get_request(
                &format!("/v1/agents/{registration_id}/audit"),
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // A foreign account still sees the uniform 404 (no existence oracle).
        let foreign = access_jwt(&[0x42; 32], "did:plc:someoneelse1111111");
        let response = app(state.clone())
            .oneshot(get_request(
                &format!("/v1/agents/{registration_id}/audit"),
                &foreign,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn caller_without_local_parent_cannot_mint() {
        let state = state().await;
        let repo_key = reserve(&state.db).await;
        let op = genesis(
            "outsider-bot.example.com",
            &state.config.public_url,
            &repo_key.key_id.0,
        );
        let token = access_jwt(&[0x42; 32], "did:plc:not-local-parent1111");
        let response = app(state.clone())
            .oneshot(request(
                "/agent/child",
                Some(&token),
                serde_json::json!({"handle": "outsider-bot.example.com", "plcOp": op}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_identities WHERE registration_type = 'child'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn plc_failure_leaves_a_deactivated_provisioning_that_retry_finishes() {
        let (state, plc) = state_with_plc().await;
        plc.reset().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:[a-z2-7]+$"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&plc)
            .await;
        let parent = "did:plc:parentchildretry111111";
        seed_account_with_repo(&state.db, parent).await;
        let repo_key = reserve(&state.db).await;
        let handle = "alice-retry.example.com";
        let op = genesis(handle, &state.config.public_url, &repo_key.key_id.0);
        let rotation_key = op["rotationKeys"][0].as_str().unwrap();
        let child = crate::identity::genesis::verify_and_validate_genesis_op(
            rotation_key,
            &op,
            handle,
            &state.config.public_url,
        )
        .unwrap()
        .0
        .did;
        let token = access_jwt(&[0x42; 32], parent);

        let response = app(state.clone())
            .oneshot(request(
                "/agent/child",
                Some(&token),
                serde_json::json!({"handle": handle, "plcOp": op.clone()}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let deactivated: Option<String> =
            sqlx::query_scalar("SELECT deactivated_at FROM accounts WHERE did = ?")
                .bind(&child)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert!(deactivated.is_some());
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_child_provisionings WHERE child_did = ? AND plc_published_at IS NULL",
        )
        .bind(&child)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(pending, 1);

        plc.reset().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:[a-z2-7]+$"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&plc)
            .await;
        let response = app(state.clone())
            .oneshot(request(
                "/agent/child",
                Some(&token),
                serde_json::json!({"handle": handle, "plcOp": op}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let deactivated: Option<String> =
            sqlx::query_scalar("SELECT deactivated_at FROM accounts WHERE did = ?")
                .bind(&child)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert!(deactivated.is_none());
        assert!(get_child_of_parent(&state.db, &child, parent)
            .await
            .unwrap()
            .is_some());
    }
}
