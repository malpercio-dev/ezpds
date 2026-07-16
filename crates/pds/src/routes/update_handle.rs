// pattern: Imperative Shell
//
// POST /xrpc/com.atproto.identity.updateHandle — change the authenticated account's handle
//
// Inputs:
//   - Authorization: Bearer <access_jwt>
//   - JSON body: { "handle": "new-handle.example.com" }
//
// Processing steps:
//   1. AuthenticatedUser extractor → JWT-scoped DID; reject non-access tokens
//   2. Validate new handle structure (validate_handle_structure)
//   3. Check local ownership: if caller already owns the handle → idempotent;
//      if a different DID owns it → 409 HANDLE_TAKEN
//   4. For handles on external domains (not in available_user_domains), verify
//      resolution via the resolveHandle chain (local DB → DNS TXT → HTTP well-known);
//      PDS-served handles skip this — the PDS is authoritative
//   5. For a PDS-custodied did:plc (the PDS key is rotationKeys[0]), build and sign
//      an alsoKnownAs-only PLC operation. Wallet-sovereign identities are left for
//      the device-key-signed wallet flow.
//   6. For the custodied path, submit the operation to plc.directory *before* opening any
//      transaction (the single-connection pool must never be held across a network call), then
//      atomically swap handles and cache the updated DID document in one short transaction.
//   7. Emit #identity firehose frame with the new handle
//   8. Return 200 (empty JSON object)
//
// Outputs (success):  200 { }
// Outputs (error):    400 INVALID_HANDLE, 401 UNAUTHORIZED, 409 HANDLE_TAKEN,
//                     400 HANDLE_RESOLUTION_FAILED, 500 INTERNAL_ERROR

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::auth::oauth_scopes;
use crate::db::dids::{fetch_also_known_as, update_also_known_as};
use crate::db::repo_keys::get_signing_key_by_did;
use crate::identity::plc::{build_did_document_from_op, fetch_current_plc_state};
use crate::lexicon::LexiconInput;
use common::{ApiError, ErrorCode};

struct CustodiedPlcUpdate {
    signed_operation: String,
    did_document: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateHandleRequest {
    pub handle: String,
}

#[derive(Serialize)]
pub struct UpdateHandleResponse {}

pub async fn update_handle_handler(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    LexiconInput(payload): LexiconInput<UpdateHandleRequest>,
) -> Result<Json<UpdateHandleResponse>, ApiError> {
    let did = &user.did;

    // Require full access scope (reject refresh / app-password tokens).
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }
    oauth_scopes::require_identity(&user.scope_claim, "handle")?;

    crate::identity::handle::validate_handle_structure(&payload.handle)
        .map_err(|msg| ApiError::new(ErrorCode::InvalidHandle, msg))?;

    // Checked before external resolution, so a caller updating to a handle they already
    // own never pays for an external resolver round trip.
    let existing_owner = crate::db::handles::resolve_handle(&state.db, &payload.handle).await?;

    if let Some(owner_did) = existing_owner {
        if owner_did != *did {
            return Err(ApiError::new(
                ErrorCode::HandleTaken,
                "handle is already taken",
            ));
        }
        // Caller already owns this handle — idempotent no-op.
        // Still proceed to emit #identity (idempotent).
    }

    let is_served_domain = {
        // Structural validation guarantees at least one dot.
        let dot = payload
            .handle
            .find('.')
            .expect("structure guarantees a dot");
        let domain = &payload.handle[dot + 1..];
        state
            .config
            .available_user_domains
            .iter()
            .any(|d| d == domain)
    };

    if is_served_domain {
        // PDS-served handle: the PDS is authoritative. The handle will resolve
        // once we insert it — skip external resolution. Because this branch skips
        // the resolution proof, the infrastructure-name reservation must gate here
        // (registration paths get it via validate_handle).
        let dot = payload
            .handle
            .find('.')
            .expect("structure guarantees a dot");
        if crate::identity::handle::is_reserved_name(
            &payload.handle[..dot],
            &state.config.reserved_handles,
        ) {
            return Err(ApiError::new(
                ErrorCode::InvalidHandle,
                "this handle name is reserved",
            ));
        }
    } else {
        // User-controlled domain: verify the handle already resolves to the
        // caller's DID via the resolveHandle chain (local DB → DNS TXT → HTTP
        // well-known).
        let resolved_did = resolve_handle_for_update(&state, &payload.handle).await?;
        if resolved_did.as_deref() != Some(did.as_str()) {
            return Err(ApiError::new(
                ErrorCode::HandleResolutionFailed,
                "new handle does not resolve to your DID",
            ));
        }
    }

    let plc_update = prepare_custodied_plc_update(&state, did, &payload.handle).await?;

    // On the PDS-custodied path, submit the authoritative change to plc.directory *before* opening
    // the handle-swap transaction. This crate's pool is single-connection, so awaiting the remote
    // POST (up to the `http_client` timeout) while a transaction held the connection would stall
    // every other request in the process on the connection acquire — the same head-of-line reason
    // the firehose/activateAccount paths build their CARs before opening their tx. Publishing before
    // the local swap deliberately accepts a brief window where plc.directory is ahead of local
    // resolution: for a did:plc account plc.directory is authoritative, so a re-resolve reconciles
    // local to it. The reverse ordering (local committed, PLC not yet) is the unsafe one — a
    // re-resolve would then silently revert the user's handle change. A failed POST returns here
    // before any local mutation, leaving the old handle intact.
    if let Some(plc_update) = &plc_update {
        crate::identity::genesis::post_to_plc_directory(
            &state.http_client,
            &state.config.plc_directory_url,
            did,
            &plc_update.signed_operation,
        )
        .await?;
    }

    // DELETE old + INSERT new (+ cache the submitted PLC doc) share one short transaction so the
    // swap commits or rolls back together while the connection is held only for local writes. The
    // INSERT's UNIQUE constraint still rejects a concurrent claimant (→ HANDLE_TAKEN), so two DIDs
    // can never both resolve the handle locally — the concurrent-claimant safety property is
    // preserved without holding the connection across the network POST above.
    {
        let mut tx = state.db.begin().await.map_err(|e| {
            tracing::error!(error = %e, "failed to begin transaction for handle swap");
            ApiError::new(ErrorCode::InternalError, "failed to update handles")
        })?;

        let rows_deleted = sqlx::query("DELETE FROM handles WHERE did = ?")
            .bind(did)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to remove old handles");
                ApiError::new(ErrorCode::InternalError, "failed to update handles")
            })?
            .rows_affected();
        tracing::debug!(did = %did, rows_deleted, new_handle = %payload.handle, "removed old handles");

        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind(&payload.handle)
            .bind(did)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                if crate::db::is_unique_violation(&e) {
                    // Race: another request inserted this handle between our check and insert.
                    return ApiError::new(ErrorCode::HandleTaken, "handle was taken concurrently");
                }
                tracing::error!(
                    error = %e,
                    handle = %payload.handle,
                    did = %did,
                    "failed to insert handle"
                );
                ApiError::new(ErrorCode::InternalError, "failed to update handles")
            })?;

        if let Some(plc_update) = &plc_update {
            sqlx::query(
                "INSERT INTO did_documents (did, document, created_at, updated_at) \
                 VALUES (?, ?, datetime('now'), datetime('now')) \
                 ON CONFLICT(did) DO UPDATE SET \
                    document = excluded.document, updated_at = datetime('now')",
            )
            .bind(did)
            .bind(plc_update.did_document.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to cache submitted handle PLC operation");
                ApiError::new(ErrorCode::InternalError, "failed to update DID document")
            })?;
        }

        tx.commit().await.map_err(|e| {
            tracing::error!(error = %e, "failed to commit handle swap transaction");
            ApiError::new(ErrorCode::InternalError, "failed to update handles")
        })?;
    }

    if plc_update.is_none() {
        // Wallet-sovereign and did:web accounts keep the existing local behavior. For did:plc,
        // the wallet follows this allocation call with a device-key-signed alsoKnownAs operation;
        // the PDS must not sign with its lower-priority key and manufacture an authorization alert.
        let also_known_as = fetch_also_known_as(&state.db, did).await?;

        if let Err(e) = update_also_known_as(&state.db, did, &also_known_as).await {
            tracing::error!(
                error = %e,
                did = %did,
                handle = %payload.handle,
                "failed to update DID document alsoKnownAs after handle change"
            );
        }
    }

    if let Err(e) = state
        .firehose
        .emit_identity(did.clone(), Some(payload.handle.clone()))
        .await
    {
        tracing::warn!(
            error = %e,
            did = %did,
            handle = %payload.handle,
            "failed to sequence #identity firehose event after handle update (non-fatal)"
        );
    }

    Ok(Json(UpdateHandleResponse {}))
}

/// Build an alsoKnownAs-only PLC update when Custos owns the DID's root rotation key.
///
/// A Custos-held key lower in the rotation list is deliberately insufficient: `rotationKeys[0]`
/// is the custody signal used by the wallet. Signing such an identity from the PDS would bypass the
/// device-key approval boundary even though plc.directory would accept the signature.
async fn prepare_custodied_plc_update(
    state: &AppState,
    did: &str,
    handle: &str,
) -> Result<Option<CustodiedPlcUpdate>, ApiError> {
    if !did.starts_with("did:plc:") {
        return Ok(None);
    }

    let signing_key = get_signing_key_by_did(&state.db, did).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to load account signing key");
        ApiError::new(ErrorCode::InternalError, "failed to load account keys")
    })?;
    let Some(signing_key) = signing_key else {
        return Ok(None);
    };

    // Custody cannot be classified from did_documents: that table stores the rendered W3C DID
    // document, which intentionally omits PLC rotationKeys. Fetch the authoritative audit-log head
    // before deciding whether the locally-held key is the root key or a lower-priority key retained
    // by a wallet-sovereign identity.
    let current =
        fetch_current_plc_state(&state.http_client, &state.config.plc_directory_url, did).await?;

    if current.rotation_keys.first() != Some(&signing_key.key_id) {
        return Ok(None);
    }

    let master_key: &[u8; 32] = state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|key| &*key.0)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::ServiceUnavailable,
                "signing key master key not configured",
            )
        })?;
    let private_key = crypto::decrypt_private_key(&signing_key.private_key_encrypted, master_key)
        .map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to decrypt account signing key");
        ApiError::new(ErrorCode::InternalError, "failed to prepare signing key")
    })?;
    let signer = repo_engine::CommitSigner::from_bytes(&private_key).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid account signing key bytes");
        ApiError::new(ErrorCode::InternalError, "failed to prepare signing key")
    })?;

    let also_known_as = vec![format!("at://{handle}")];
    if current.also_known_as == also_known_as {
        return Ok(None);
    }

    let signed = crypto::build_did_plc_rotation_op(
        &current.cid,
        current.rotation_keys,
        current.verification_methods.clone(),
        also_known_as.clone(),
        current.services.clone(),
        |bytes| Ok(signer.sign(bytes)),
    )
    .map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to build handle PLC operation");
        ApiError::new(ErrorCode::InternalError, "failed to sign PLC operation")
    })?;
    let did_document = build_did_document_from_op(
        did,
        &current.verification_methods,
        &also_known_as,
        &current.services,
    )?;

    Ok(Some(CustodiedPlcUpdate {
        signed_operation: signed.signed_op_json,
        did_document,
    }))
}

/// Resolve a handle to a DID using the same three-step chain as `resolveHandle`:
/// local handles table → DNS TXT `_atproto.<handle>` → HTTP `/.well-known/atproto-did`.
///
/// Returns `Ok(Some(did))` when resolution succeeds, `Ok(None)` when the handle
/// does not resolve anywhere, and `Err` only on infrastructure failures.
async fn resolve_handle_for_update(
    state: &AppState,
    handle: &str,
) -> Result<Option<String>, ApiError> {
    // 1. Check local handles table.
    let row = crate::db::handles::resolve_handle(&state.db, handle).await?;

    if let Some(did) = row {
        return Ok(Some(did));
    }

    // 2. DNS TXT fallback: look for `did=<did>` in `_atproto.<handle>` records.
    if let Some(resolver) = &state.txt_resolver {
        let name = format!("_atproto.{}", handle);
        match resolver.txt_lookup(&name).await {
            Ok(records) => {
                for record in records {
                    if let Some(did) = record.strip_prefix("did=") {
                        return Ok(Some(did.to_string()));
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    handle = %handle,
                    "DNS TXT lookup failed during handle verification; falling through to well-known"
                );
            }
        }
    }

    // 3. HTTP well-known fallback: GET https://<handle>/.well-known/atproto-did
    if let Some(resolver) = &state.well_known_resolver {
        match resolver.resolve(handle).await {
            Ok(Some(did)) => return Ok(Some(did)),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    handle = %handle,
                    "HTTP well-known lookup failed during handle verification"
                );
            }
        }
    }

    Ok(None)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin, sync::Arc};

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use uuid::Uuid;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::app::{app, test_state, AppState};
    use crate::identity::dns::{DnsError, TxtResolver};
    use crate::identity::well_known::{WellKnownError, WellKnownResolver};
    use crate::routes::test_utils::{seed_account_with_signing_key, state_with_master_key};

    // ── Test doubles ──────────────────────────────────────────────────────────

    struct FixedTxtResolver {
        records: Vec<String>,
    }

    impl TxtResolver for FixedTxtResolver {
        fn txt_lookup<'a>(
            &'a self,
            _name: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsError>> + Send + 'a>> {
            let records = self.records.clone();
            Box::pin(async move { Ok(records) })
        }
    }

    fn state_with_txt(state: AppState, records: Vec<String>) -> AppState {
        AppState {
            txt_resolver: Some(Arc::new(FixedTxtResolver { records })),
            ..state
        }
    }

    struct FixedWellKnownResolver {
        did: Option<String>,
    }

    impl WellKnownResolver for FixedWellKnownResolver {
        fn resolve<'a>(
            &'a self,
            _handle: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<String>, WellKnownError>> + Send + 'a>>
        {
            let did = self.did.clone();
            Box::pin(async move { Ok(did) })
        }
    }

    fn state_with_well_known(state: AppState, did: Option<String>) -> AppState {
        AppState {
            well_known_resolver: Some(Arc::new(FixedWellKnownResolver { did })),
            ..state
        }
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    struct TestSession {
        did: String,
        access_jwt: String,
    }

    async fn insert_session(db: &sqlx::SqlitePool, did: &str) -> String {
        use crate::auth::token::generate_token;

        let token = generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(did)
        .bind(&token.hash)
        .execute(db)
        .await
        .expect("insert session");

        super::super::test_utils::access_jwt(&[0x42u8; 32], did)
    }

    /// Insert a promoted account and session, returns the DID + access JWT.
    async fn insert_account_and_session(db: &sqlx::SqlitePool, handle: &str) -> TestSession {
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind(format!("{}@test.example.com", &did[8..16]))
        .execute(db)
        .await
        .expect("insert account");

        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind(handle)
            .bind(&did)
            .execute(db)
            .await
            .expect("insert handle");

        let access_jwt = insert_session(db, &did).await;

        TestSession { did, access_jwt }
    }

    async fn state_with_plc(plc_url: String) -> AppState {
        let base = state_with_master_key().await;
        let mut config = (*base.config).clone();
        config.plc_directory_url = plc_url;
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    async fn mount_audit_log(
        plc: &MockServer,
        did: &str,
        old_handle: &str,
        rotation_keys: Vec<String>,
        signing_key: &str,
        endpoint: &str,
    ) {
        Mock::given(method("GET"))
            .and(path(format!("/{did}/log/audit")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "did": did,
                    "cid": "bafyHandleHead",
                    "createdAt": "2026-07-15T00:00:00Z",
                    "nullified": false,
                    "operation": {
                        "type": "plc_operation",
                        "prev": null,
                        "rotationKeys": rotation_keys,
                        "verificationMethods": { "atproto": signing_key },
                        "alsoKnownAs": [format!("at://{old_handle}")],
                        "services": {
                            "atproto_pds": {
                                "type": "AtprotoPersonalDataServer",
                                "endpoint": endpoint
                            }
                        }
                    }
                }])),
            )
            .mount(plc)
            .await;
    }

    async fn seed_cached_did(db: &sqlx::SqlitePool, did: &str, handle: &str) {
        sqlx::query(
            "INSERT INTO did_documents (did, document, created_at, updated_at) \
             VALUES (?, ?, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(serde_json::json!({"id": did, "alsoKnownAs": [format!("at://{handle}")]}).to_string())
        .execute(db)
        .await
        .unwrap();
    }

    fn update_handle_request(jwt: &str, handle: &str) -> Request<Body> {
        let body = serde_json::json!({
            "handle": handle,
        });
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.identity.updateHandle")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// A reserved infrastructure name on a served domain is rejected: the served-domain
    /// branch skips external resolution, so the reservation must gate here.
    #[tokio::test]
    async fn served_domain_reserved_name_is_rejected() {
        let state = test_state().await;
        let db = state.db.clone();
        let old_handle = format!("alice.{}", state.config.available_user_domains[0]);
        let reserved = format!("identitywallet.{}", state.config.available_user_domains[0]);
        let ts = insert_account_and_session(&db, &old_handle).await;

        let app = app(state);
        let response = app
            .oneshot(update_handle_request(&ts.access_jwt, &reserved))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let reserved_row: Option<(String,)> =
            sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
                .bind(&reserved)
                .fetch_optional(&db)
                .await
                .unwrap();
        assert!(
            reserved_row.is_none(),
            "the reserved handle must not be inserted"
        );
    }

    // ── Happy path ─────────────────────────────────────────────────────────────

    /// Changing to a new handle on the same PDS-served domain succeeds: old handle is removed,
    /// new handle is inserted, DID document alsoKnownAs is updated, and #identity is emitted.
    #[tokio::test]
    async fn happy_path_changes_handle() {
        let state = test_state().await;
        let db = state.db.clone();
        let old_handle = format!("alice.{}", state.config.available_user_domains[0]);
        let new_handle = format!("bob.{}", state.config.available_user_domains[0]);
        let ts = insert_account_and_session(&db, &old_handle).await;

        // Hold a clone so the channel stays open.
        let firehose = state.firehose.clone();
        let mut rx = firehose.subscribe();
        let frontier = firehose.current_seq();

        let app = app(state);
        let response = app
            .oneshot(update_handle_request(&ts.access_jwt, &new_handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Old handle is gone.
        let old_row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&old_handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(old_row.is_none(), "old handle should be removed");

        // New handle is inserted.
        let new_row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&new_handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(new_row.is_some(), "new handle should be inserted");
        assert_eq!(new_row.unwrap().0, ts.did);

        // #identity frame was emitted with the new handle.
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("identity frame was emitted")
            .expect("receiver not closed");
        let crate::firehose::FirehoseEvent::Identity(identity) = event else {
            panic!("expected an #identity frame, got {event:?}");
        };
        assert_eq!(identity.did, ts.did);
        assert_eq!(identity.handle.as_deref(), Some(new_handle.as_str()));
        assert_eq!(identity.seq, frontier + 1);
        drop(firehose);
    }

    #[tokio::test]
    async fn pds_custodied_account_submits_plc_op_and_updates_cache() {
        let plc = MockServer::start().await;
        let state = state_with_plc(plc.uri()).await;
        let db = state.db.clone();
        let did = "did:plc:updatehandlecustodied111";
        let old_handle = format!("alice.{}", state.config.available_user_domains[0]);
        let new_handle = format!("bob.{}", state.config.available_user_domains[0]);
        let key_id = seed_account_with_signing_key(&db, did, &old_handle).await;
        // Deliberately leave did_documents empty: the accepted operation must populate a missing
        // cache row as well as update an existing one.
        let jwt = insert_session(&db, did).await;
        mount_audit_log(
            &plc,
            did,
            &old_handle,
            vec![key_id.clone()],
            &key_id,
            &state.config.public_url,
        )
        .await;
        Mock::given(method("POST"))
            .and(path(format!("/{did}")))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&plc)
            .await;

        let response = app(state)
            .oneshot(update_handle_request(&jwt, &new_handle))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let requests = plc.received_requests().await.unwrap();
        let post = requests
            .iter()
            .find(|request| request.method.as_str() == "POST")
            .expect("PLC operation submitted");
        let operation: serde_json::Value = serde_json::from_slice(&post.body).unwrap();
        assert_eq!(
            operation["alsoKnownAs"],
            serde_json::json!([format!("at://{new_handle}")])
        );
        crypto::verify_plc_operation(&operation.to_string(), &[crypto::DidKeyUri(key_id)])
            .expect("PLC operation is signed by the custodied root key");

        let cached: String = sqlx::query_scalar("SELECT document FROM did_documents WHERE did = ?")
            .bind(did)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&cached).unwrap()["alsoKnownAs"],
            serde_json::json!([format!("at://{new_handle}")])
        );
    }

    #[tokio::test]
    async fn wallet_sovereign_account_is_not_signed_by_pds_key() {
        let plc = MockServer::start().await;
        let state = state_with_plc(plc.uri()).await;
        let db = state.db.clone();
        let did = "did:plc:updatehandlesovereign111";
        let old_handle = format!("alice.{}", state.config.available_user_domains[0]);
        let new_handle = format!("bob.{}", state.config.available_user_domains[0]);
        let key_id = seed_account_with_signing_key(&db, did, &old_handle).await;
        seed_cached_did(&db, did, &old_handle).await;
        let jwt = insert_session(&db, did).await;
        mount_audit_log(
            &plc,
            did,
            &old_handle,
            vec!["did:key:zWalletRoot".to_string(), key_id.clone()],
            &key_id,
            &state.config.public_url,
        )
        .await;
        Mock::given(method("POST"))
            .and(path(format!("/{did}")))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&plc)
            .await;

        let response = app(state)
            .oneshot(update_handle_request(&jwt, &new_handle))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            crate::db::handles::resolve_handle(&db, &new_handle)
                .await
                .unwrap()
                .as_deref(),
            Some(did)
        );
    }

    #[tokio::test]
    async fn custodied_account_skips_plc_op_when_authoritative_handle_matches() {
        let plc = MockServer::start().await;
        let state = state_with_plc(plc.uri()).await;
        let db = state.db.clone();
        let did = "did:plc:updatehandlecurrent111111";
        let handle = format!("alice.{}", state.config.available_user_domains[0]);
        let key_id = seed_account_with_signing_key(&db, did, &handle).await;
        seed_cached_did(&db, did, &handle).await;
        let jwt = insert_session(&db, did).await;
        mount_audit_log(
            &plc,
            did,
            &handle,
            vec![key_id.clone()],
            &key_id,
            &state.config.public_url,
        )
        .await;
        Mock::given(method("POST"))
            .and(path(format!("/{did}")))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&plc)
            .await;

        let response = app(state)
            .oneshot(update_handle_request(&jwt, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            crate::db::handles::resolve_handle(&db, &handle)
                .await
                .unwrap()
                .as_deref(),
            Some(did)
        );
    }

    #[tokio::test]
    async fn plc_failure_rolls_back_custodied_handle_swap() {
        let plc = MockServer::start().await;
        let state = state_with_plc(plc.uri()).await;
        let db = state.db.clone();
        let did = "did:plc:updatehandlefailure11111";
        let old_handle = format!("alice.{}", state.config.available_user_domains[0]);
        let new_handle = format!("bob.{}", state.config.available_user_domains[0]);
        let key_id = seed_account_with_signing_key(&db, did, &old_handle).await;
        seed_cached_did(&db, did, &old_handle).await;
        let jwt = insert_session(&db, did).await;
        mount_audit_log(
            &plc,
            did,
            &old_handle,
            vec![key_id.clone()],
            &key_id,
            &state.config.public_url,
        )
        .await;
        Mock::given(method("POST"))
            .and(path(format!("/{did}")))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&plc)
            .await;

        let response = app(state)
            .oneshot(update_handle_request(&jwt, &new_handle))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            crate::db::handles::resolve_handle(&db, &old_handle)
                .await
                .unwrap()
                .as_deref(),
            Some(did)
        );
        assert!(crate::db::handles::resolve_handle(&db, &new_handle)
            .await
            .unwrap()
            .is_none());
    }

    /// Changing to the same handle (no-op) returns 200 and still emits #identity.
    #[tokio::test]
    async fn same_handle_is_idempotent() {
        let state = test_state().await;
        let db = state.db.clone();
        let handle = format!("alice.{}", state.config.available_user_domains[0]);
        let ts = insert_account_and_session(&db, &handle).await;

        let app = app(state);
        let response = app
            .oneshot(update_handle_request(&ts.access_jwt, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // The handle row still exists with the same DID.
        let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(row.is_some());
        assert_eq!(row.unwrap().0, ts.did);
    }

    // ── Resolution: DNS TXT fallback ──────────────────────────────────────────

    /// When the new handle resolves via DNS TXT rather than the local DB, it still succeeds.
    #[tokio::test]
    async fn handle_resolves_via_dns_txt() {
        let state = test_state().await;
        let db = state.db.clone();
        let old_handle = format!("alice.{}", state.config.available_user_domains[0]);
        let new_handle = "charlie.external.example".to_string();
        let ts = insert_account_and_session(&db, &old_handle).await;

        let state = state_with_txt(state, vec![format!("did={}", ts.did)]);

        let app = app(state);
        let response = app
            .oneshot(update_handle_request(&ts.access_jwt, &new_handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let new_row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&new_handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(new_row.is_some());
    }

    // ── Resolution: HTTP well-known fallback ───────────────────────────────────

    /// When the new handle resolves via HTTP well-known, it still succeeds.
    #[tokio::test]
    async fn handle_resolves_via_well_known() {
        let state = test_state().await;
        let db = state.db.clone();
        let old_handle = format!("alice.{}", state.config.available_user_domains[0]);
        let new_handle = "diana.bsky.social".to_string();
        let ts = insert_account_and_session(&db, &old_handle).await;

        let state = state_with_well_known(state, Some(ts.did.clone()));

        let app = app(state);
        let response = app
            .oneshot(update_handle_request(&ts.access_jwt, &new_handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // ── Resolution failure ─────────────────────────────────────────────────────

    /// When the new handle is on an external domain and does not resolve to the caller's DID,
    /// return 400. Uses `external.test` as the domain — not in `available_user_domains`.
    #[tokio::test]
    async fn handle_not_resolving_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let old_handle = format!("alice.{}", state.config.available_user_domains[0]);
        let new_handle = "ghost.external.test".to_string();
        let ts = insert_account_and_session(&db, &old_handle).await;

        // Neither txt_resolver nor well_known_resolver are configured, and
        // "ghost.external.test" is not in the local handles table.

        let app = app(state);
        let response = app
            .oneshot(update_handle_request(&ts.access_jwt, &new_handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "HANDLE_RESOLUTION_FAILED");
    }

    /// When the new handle is on an external domain and resolves to a different DID, return 400.
    #[tokio::test]
    async fn handle_resolves_to_wrong_did_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let old_handle = format!("alice.{}", state.config.available_user_domains[0]);
        let new_handle = "someone-else.external.test".to_string();
        let ts = insert_account_and_session(&db, &old_handle).await;

        let state = state_with_txt(state, vec!["did=did:plc:someotheruser".to_string()]);

        let app = app(state);
        let response = app
            .oneshot(update_handle_request(&ts.access_jwt, &new_handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "HANDLE_RESOLUTION_FAILED");
    }

    // ── Handle already taken ──────────────────────────────────────────────────

    /// When the new handle is already owned by a different DID, return 409.
    #[tokio::test]
    async fn handle_already_taken_by_other_returns_409() {
        let state = test_state().await;
        let db = state.db.clone();
        let old_handle = format!("alice.{}", state.config.available_user_domains[0]);
        let new_handle = format!("bob.{}", state.config.available_user_domains[0]);
        let ts = insert_account_and_session(&db, &old_handle).await;

        // Pre-insert the new handle owned by a different DID.
        let other_did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&other_did)
        .bind(format!("{}@other.example.com", &other_did[..8]))
        .execute(&db)
        .await
        .unwrap();
        // seed_handle would also insert an accounts row — just insert the handle directly.
        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind(&new_handle)
            .bind(&other_did)
            .execute(&db)
            .await
            .unwrap();

        let app = app(state);
        let response = app
            .oneshot(update_handle_request(&ts.access_jwt, &new_handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "HANDLE_TAKEN");
    }

    // ── Invalid handle format ─────────────────────────────────────────────────

    /// Bare label (no dot) returns 400.
    #[tokio::test]
    async fn bare_label_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let old_handle = format!("alice.{}", state.config.available_user_domains[0]);
        let ts = insert_account_and_session(&db, &old_handle).await;

        let app = app(state);
        let response = app
            .oneshot(update_handle_request(&ts.access_jwt, "badhandle"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        // A structurally invalid handle is now caught by the lexicon input layer (before the
        // handler's own domain-policy checks), with the reference PDS's message shape.
        assert_eq!(body["error"]["code"], "InvalidRequest");
        assert_eq!(
            body["error"]["message"],
            "Input/handle must be a valid handle"
        );
    }

    // ── Auth failures ──────────────────────────────────────────────────────────

    /// Missing Authorization header returns 401.
    #[tokio::test]
    async fn missing_auth_returns_401() {
        let state = test_state().await;
        let new_handle = format!("alice.{}", state.config.available_user_domains[0]);

        let body = serde_json::json!({ "handle": new_handle });
        let request = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.identity.updateHandle")
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let app = app(state);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Wrong-scope token (refresh instead of access) returns 401.
    #[tokio::test]
    async fn wrong_scope_token_returns_401() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};

        let state = test_state().await;
        let db = state.db.clone();
        let old_handle = format!("alice.{}", state.config.available_user_domains[0]);
        let new_handle = format!("bob.{}", state.config.available_user_domains[0]);
        let ts = insert_account_and_session(&db, &old_handle).await;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let refresh_jwt = encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "scope": "com.atproto.refresh",
                "sub": ts.did,
                "iat": now,
                "exp": now + 7200_u64,
            }),
            &EncodingKey::from_secret(&[0x42u8; 32]),
        )
        .unwrap();

        let app = app(state);
        let response = app
            .oneshot(update_handle_request(&refresh_jwt, &new_handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
