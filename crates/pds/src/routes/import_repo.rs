// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (JWT extractor), the raw CAR request body, DB pool via AppState
// Processes: scope check → deactivated-account precondition → parse/validate the CAR
//            (repo_engine::import_repo_car) → persist the reachable blocks and set the repo
//            root/rev, atomically, only while the account is still deactivated
// Returns: 200 OK (empty) on success; ApiError on failure
//
// Implements: POST /xrpc/com.atproto.repo.importRepo

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;

/// Maximum accepted repo CAR size. A repository CAR bundles every MST node and record block, so
/// it is larger than a single blob; 100 MiB comfortably covers a substantial repo while bounding
/// memory (the body is buffered whole before parsing).
const MAX_IMPORT_CAR_BYTES: usize = 100 * 1024 * 1024;

/// POST /xrpc/com.atproto.repo.importRepo
///
/// Ingests a full repository CAR (as exported by `com.atproto.sync.getRepo`) into the
/// authenticated account. The account must be **deactivated** — this is the data-transfer leg of
/// account migration, run after `createAccount` (which leaves a migration account deactivated and
/// repo-less) and before `activateAccount`. The imported commit is stored verbatim; its blocks
/// become serveable via `getRepo` once the account is activated.
///
/// Only full access-scope tokens are accepted. The CAR's commit `did` must match the caller.
pub async fn import_repo(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    request: Request<Body>,
) -> Result<StatusCode, ApiError> {
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }
    let did = user.did.clone();

    // Fast-path rejection: check Content-Length before reading the body (the lexicon requires it).
    if let Some(content_length) = request
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
    {
        if content_length > MAX_IMPORT_CAR_BYTES {
            return Err(ApiError::new(
                ErrorCode::PayloadTooLarge,
                format!("repo CAR exceeds maximum size of {MAX_IMPORT_CAR_BYTES} bytes"),
            ));
        }
    }

    // Precondition: the account exists and is deactivated. Read this before buffering the (large)
    // body so an active or missing account is rejected cheaply. The set-root guard below re-checks
    // the deactivated state at commit time, closing the gap against a concurrent activation.
    let write_state = crate::db::accounts::get_repo_write_state(&state.db, &did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to query account state");
            ApiError::new(ErrorCode::InternalError, "failed to import repo")
        })?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;
    if write_state.active {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "account must be deactivated to import a repo",
        ));
    }

    // Read the full CAR body, enforcing the size cap.
    let car_bytes = axum::body::to_bytes(request.into_body(), MAX_IMPORT_CAR_BYTES)
        .await
        .map(|b| b.to_vec())
        .map_err(|_| {
            ApiError::new(
                ErrorCode::PayloadTooLarge,
                format!("repo CAR exceeds maximum size of {MAX_IMPORT_CAR_BYTES} bytes"),
            )
        })?;

    // Parse + validate the CAR (block hashes, single root, MST integrity, commit DID/version).
    let imported = repo_engine::import_repo_car(&car_bytes, &did)
        .await
        .map_err(|e| {
            use repo_engine::CarImportError::*;
            match e {
                DidMismatch { .. } => {
                    tracing::warn!(did = %did, error = %e, "importRepo rejected: DID mismatch");
                    ApiError::new(
                        ErrorCode::Forbidden,
                        "repo commit does not belong to this account",
                    )
                }
                other => {
                    tracing::warn!(did = %did, error = %other, "importRepo rejected: invalid CAR");
                    ApiError::new(ErrorCode::InvalidRequest, "invalid repo CAR")
                }
            }
        })?;

    // Persist the reachable blocks and set the repo root/rev in one transaction. Every block is
    // tagged with the imported head rev (mirroring genesis persistence) so `getRepo?since` deltas
    // and block stats see a revisioned repo.
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to begin import transaction");
        ApiError::new(ErrorCode::InternalError, "failed to import repo")
    })?;

    for (cid, bytes) in &imported.blocks {
        sqlx::query(
            "INSERT INTO blocks (cid, account_did, bytes, rev) VALUES (?, ?, ?, ?) \
             ON CONFLICT(cid) DO NOTHING",
        )
        .bind(cid.to_string())
        .bind(&did)
        .bind(bytes.as_slice())
        .bind(&imported.rev)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to persist imported block");
            ApiError::new(ErrorCode::InternalError, "failed to import repo")
        })?;
    }

    let root_str = imported.root.to_string();
    let updated = crate::db::accounts::set_repo_root_for_deactivated(
        &mut *tx,
        &did,
        &root_str,
        &imported.rev,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to set imported repo root");
        ApiError::new(ErrorCode::InternalError, "failed to import repo")
    })?;
    if !updated {
        // The account left the deactivated state between the precondition check and here.
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "account is no longer deactivated",
        ));
    }

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to commit import transaction");
        ApiError::new(ErrorCode::InternalError, "failed to import repo")
    })?;

    tracing::info!(
        did = %did,
        root = %root_str,
        rev = %imported.rev,
        blocks = imported.blocks.len(),
        "repo imported"
    );

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use tower::ServiceExt;

    use crate::routes::test_utils::{access_jwt, seed_account_with_repo, state_with_master_key};

    /// Export the seeded account's repo as a CAR, then wipe the account's repo state so it looks
    /// like a fresh, deactivated migration target (repo-less) ready to import that CAR.
    async fn export_then_reset(state: &AppState, did: &str) -> Vec<u8> {
        let root: String = sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(&state.db)
            .await
            .unwrap();
        let root_cid = repo_engine::Cid::try_from(root.as_str()).unwrap();
        let mut store = crate::db::blocks::SqliteBlockStore::new(state.db.clone(), did.to_string());
        let car = repo_engine::export_repo_car(&mut store, root_cid)
            .await
            .unwrap();

        // Reset to a deactivated, repo-less account.
        sqlx::query(
            "UPDATE accounts SET repo_root_cid = NULL, repo_rev = NULL, \
             deactivated_at = datetime('now') WHERE did = ?",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
        crate::db::blocks::delete_blocks_for_account(&state.db, did)
            .await
            .unwrap();
        car
    }

    fn import_req(car: Vec<u8>, token: Option<&str>) -> Request<Body> {
        let mut b = Request::builder()
            .method(http::Method::POST)
            .uri("/xrpc/com.atproto.repo.importRepo")
            .header("Content-Type", "application/vnd.ipld.car");
        if let Some(t) = token {
            b = b.header("Authorization", format!("Bearer {t}"));
        }
        b.body(Body::from(car)).unwrap()
    }

    #[tokio::test]
    async fn import_without_auth_returns_401() {
        let state = state_with_master_key().await;
        let app = crate::app::app(state);
        let resp = app
            .oneshot(import_req(b"anything".to_vec(), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn import_into_active_account_returns_403() {
        let state = state_with_master_key().await;
        let did = "did:plc:importactive";
        seed_account_with_repo(&state.db, did).await; // active, has a repo
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state);
        let resp = app
            .oneshot(import_req(b"anything".to_vec(), Some(&token)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn import_nonexistent_account_returns_404() {
        let state = state_with_master_key().await;
        let token = access_jwt(&state.jwt_secret, "did:plc:importghost");
        let app = crate::app::app(state);
        let resp = app
            .oneshot(import_req(b"anything".to_vec(), Some(&token)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn import_garbage_car_returns_400() {
        let state = state_with_master_key().await;
        let did = "did:plc:importgarbage";
        seed_account_with_repo(&state.db, did).await;
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state);
        let resp = app
            .oneshot(import_req(b"not a car".to_vec(), Some(&token)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn import_round_trip_makes_repo_serveable() {
        let state = state_with_master_key().await;
        let did = "did:plc:importroundtrip";
        seed_account_with_repo(&state.db, did).await;

        // Add a record so the exported repo has content, then export + reset.
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state.clone());
        let put = crate::routes::test_utils::put_record_request(
            did,
            "app.bsky.feed.post",
            "hello",
            serde_json::json!({ "record": { "text": "migrated" } }),
            Some(&token),
        );
        assert_eq!(
            app.clone().oneshot(put).await.unwrap().status(),
            StatusCode::OK
        );

        let car = export_then_reset(&state, did).await;

        // Import the CAR into the now-deactivated, repo-less account.
        let resp = app
            .clone()
            .oneshot(import_req(car, Some(&token)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "import must succeed");

        // Reactivate, then the record must be serveable via getRecord.
        sqlx::query("UPDATE accounts SET deactivated_at = NULL WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let get = Request::builder()
            .method(http::Method::GET)
            .uri(format!(
                "/xrpc/com.atproto.repo.getRecord?did={did}&collection=app.bsky.feed.post&rkey=hello"
            ))
            .body(Body::empty())
            .unwrap();
        let r = app.oneshot(get).await.unwrap();
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "imported record must be serveable"
        );
        let body = crate::routes::test_utils::body_json(r).await;
        assert_eq!(body["value"]["text"], "migrated");
    }
}
