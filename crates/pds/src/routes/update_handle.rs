// pattern: Imperative Shell
//
// POST /xrpc/com.atproto.identity.updateHandle — change the authenticated account's handle
//
// Inputs:
//   - Authorization: Bearer <access_jwt>
//   - JSON body: { "handle": "new-handle.example.com" }
//
// Processing steps:
//   1. AuthenticatedUser extractor → JWT-scoped DID
//   2. Validate new handle structure (validate_handle_structure)
//   3. Verify the new handle resolves to the caller's DID
//      (local DB → DNS TXT → HTTP well-known, same chain as resolveHandle)
//   4. Check the new handle is not already owned by a different DID (handles table)
//   5. Fetch the current handle(s) for the caller's DID
//   6. Swap handles: DELETE old handle(s) for this DID, INSERT new handle
//   7. Update DID document alsoKnownAs to reflect the new handle set
//   8. Emit #identity firehose frame with the new handle
//   9. Return 200 (empty JSON object)
//
// Outputs (success):  200 { }
// Outputs (error):    400 INVALID_HANDLE, 401 UNAUTHORIZED, 409 HANDLE_TAKEN,
//                     400 HANDLE_RESOLUTION_FAILED, 500 INTERNAL_ERROR

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::db::dids::{fetch_also_known_as, update_also_known_as};
use common::{ApiError, ErrorCode};

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
    Json(payload): Json<UpdateHandleRequest>,
) -> Result<Json<UpdateHandleResponse>, ApiError> {
    let did = &user.did;

    // Require full access scope (reject refresh / app-password tokens).
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }

    // Step 1: Validate handle structure.
    crate::handle::validate_handle_structure(&payload.handle)
        .map_err(|msg| ApiError::new(ErrorCode::InvalidHandle, msg))?;

    // Step 2: Determine whether the new handle is on a PDS-served domain or an external
    // domain, and verify it resolves (or will resolve) to the caller's DID.
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
        // PDS-served handle: the PDS is authoritative. The only check needed is that
        // the handle is not already taken by a different DID (performed in Step 3).
        // External resolution is skipped because the handle will resolve once we insert it.
    } else {
        // User-controlled domain: verify the handle already resolves to the caller's DID
        // via the resolveHandle chain (local DB → DNS TXT → HTTP well-known).
        let resolved_did = resolve_handle_for_update(&state, &payload.handle).await?;
        if resolved_did.as_deref() != Some(did.as_str()) {
            return Err(ApiError::new(
                ErrorCode::HandleResolutionFailed,
                "new handle does not resolve to your DID",
            ));
        }
    }

    // Step 3: Check the new handle is not already owned by a different DID.
    let existing_owner: Option<(String,)> =
        sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&payload.handle)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, handle = %payload.handle, "failed to query handle");
                ApiError::new(ErrorCode::InternalError, "handle lookup failed")
            })?;

    if let Some((owner_did,)) = existing_owner {
        if owner_did != *did {
            return Err(ApiError::new(
                ErrorCode::HandleTaken,
                "handle is already taken",
            ));
        }
        // If the owner IS the caller, this is a no-op — same handle.
        // Still proceed to emit #identity (idempotent).
    }

    // Step 4: Remove all old handles for this DID, insert the new one.
    // Atomic via DB-level serialisation (SQLite single writer) — no explicit transaction needed
    // since the two statements are safe independently: if the DELETE succeeds but INSERT fails,
    // the caller has no handle (retryable). If INSERT succeeds but DELETE fails (impossible with
    // no error on INSERT), they'd have two handles (also recoverable).
    let rows_deleted = sqlx::query("DELETE FROM handles WHERE did = ?")
        .bind(did)
        .execute(&state.db)
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
        .execute(&state.db)
        .await
        .map_err(|e| {
            if crate::db::is_unique_violation(&e) {
                // Race: another request inserted this handle between our check and insert.
                return ApiError::new(ErrorCode::HandleTaken, "handle was taken concurrently");
            }
            tracing::error!(error = %e, handle = %payload.handle, did = %did, "failed to insert handle");
            ApiError::new(ErrorCode::InternalError, "failed to update handles")
        })?;

    // Step 5: Update DID document alsoKnownAs to reflect the new handle set.
    let also_known_as = fetch_also_known_as(&state.db, did).await?;

    if let Err(e) = update_also_known_as(&state.db, did, &also_known_as).await {
        tracing::error!(
            error = %e,
            did = %did,
            handle = %payload.handle,
            "failed to update DID document alsoKnownAs after handle change"
        );
    }

    // Step 6: Emit #identity firehose frame with the new handle.
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
    let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
        .bind(handle)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, handle = %handle, "failed to query handle");
            ApiError::new(ErrorCode::InternalError, "handle lookup failed")
        })?;

    if let Some((did,)) = row {
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

    use crate::app::{app, test_state, AppState};
    use crate::dns::{DnsError, TxtResolver};
    use crate::well_known::{WellKnownError, WellKnownResolver};

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

    /// Insert a promoted account and session, returns the DID + access JWT.
    async fn insert_account_and_session(db: &sqlx::SqlitePool, handle: &str) -> TestSession {
        use crate::token::generate_token;

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

        // Create a session and mint an access JWT.
        let token = generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&did)
        .bind(&token.hash)
        .execute(db)
        .await
        .expect("insert session");

        let access_jwt = super::super::test_utils::access_jwt(&[0x42u8; 32], &did);

        TestSession { did, access_jwt }
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
        assert_eq!(body["error"]["code"], "INVALID_HANDLE");
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
