// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (JWT extractor), the raw CAR request body, DB pool via AppState
// Processes: scope check → deactivated-account precondition → parse/validate the CAR
//            (repo_engine::import_repo_car) → idempotent same-root no-op, else persist the
//            reachable blocks and compare-and-swap the repo root/rev against the root observed at
//            precondition time, atomically, only while the account is still deactivated
// Returns: 200 OK (empty) on success (import performed, or an already-present no-op); ApiError on
//          failure
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
/// account migration, run after `createAccount` (which leaves a migration account deactivated) and
/// before `activateAccount`. The imported commit is stored verbatim; its blocks become serveable
/// via `getRepo` once the account is activated.
///
/// Import is idempotent and supports return migration into a prior residency: if the account
/// already carries exactly the CAR's root, the call is a no-op success; if it carries a *different*
/// root — a completed prior residency, resumed via `createAccount`'s resumable migration mode — that
/// root is replaced under an optimistic compare-and-swap against the root observed at precondition
/// time, so a concurrent import with a different base loses loudly instead of silently clobbering
/// the winner.
///
/// Only full access-scope tokens are accepted. The CAR's commit `did` must match the caller.
pub async fn import_repo(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    request: Request<Body>,
) -> Result<StatusCode, ApiError> {
    let metrics = state.metrics.clone();
    let result = import_repo_inner(state, user, request).await;
    metrics.migration_imports.add(
        1,
        &[crate::metrics::label(
            crate::metrics::names::LABEL_OUTCOME,
            if result.is_ok() { "ok" } else { "error" },
        )],
    );
    result
}

async fn import_repo_inner(
    state: AppState,
    user: AuthenticatedUser,
    request: Request<Body>,
) -> Result<StatusCode, ApiError> {
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }
    // Repo import is an account-migration operation, never something an agent should perform.
    user.require_not_agent()?;
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
    // body so an active or missing account is rejected cheaply. The swap CAS below re-checks the
    // deactivated state — and the observed root — atomically at commit time, closing the gap
    // against a concurrent activation or a concurrent import.
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
    // The repo root observed at precondition time. `None` for a fresh migration target; `Some` when
    // a completed prior residency's repo is still present — a migrate-away-and-return round trip
    // resumes a still-deactivated account (see `createAccount`'s resumable migration mode) that
    // still carries its previous root. Import is no longer strictly first-write-wins: an existing
    // root is either reimported idempotently (same root, below) or replaced under a compare-and-swap
    // (different root, at commit), so a return migration is not blocked while the CAS preserves the
    // anti-race guarantee.
    let observed_root = write_state.repo_root_cid;

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

    let root_str = imported.root.to_string();

    // Tier 1 — idempotent same-root import. The account already carries exactly this repo root, so a
    // prior import (atomic, all-or-nothing) already persisted every block reachable from it. Return
    // success without rewriting: a retried import — and the common return-migration case where
    // nothing was written at the other residency, so the incoming CAR is byte-identical (same rev) —
    // is a no-op. This is what replaces the old first-write-wins 409 that deterministically blocked
    // a migrate-away-and-return round trip.
    if observed_root.as_deref() == Some(root_str.as_str()) {
        tracing::info!(
            did = %did,
            root = %root_str,
            rev = %imported.rev,
            "importRepo no-op: account already at this repo root"
        );
        return Ok(StatusCode::OK);
    }

    // Tier 2 — persist the reachable blocks and compare-and-swap the repo root/rev in one
    // transaction. Every block is tagged with the imported head rev (mirroring genesis persistence)
    // so `getRepo?since` deltas and block stats see a revisioned repo. When this replaces a prior
    // residency's root, the old root's blocks that the new root no longer references become
    // unreferenced ownership rows; they are reclaimed by the account's next write-path GC (the diff
    // walk's keep-set is `reachable(new head)`, which excludes them) — there is no separate block GC
    // to run here. Blobs are transferred separately, so importRepo never touches `blob_owners`; the
    // periodic blob GC reconciles per owner and releases (with grace) any blob the new root no longer
    // references.
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to begin import transaction");
        ApiError::new(ErrorCode::InternalError, "failed to import repo")
    })?;

    for (cid, bytes) in &imported.blocks {
        let cid = cid.to_string();
        crate::db::blocks::put_block_with_rev(
            &mut tx,
            &cid,
            &did,
            bytes.as_slice(),
            Some(&imported.rev),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to persist imported block");
            ApiError::new(ErrorCode::InternalError, "failed to import repo")
        })?;
    }

    // Compare-and-swap against the root observed at precondition time (`None` for a fresh target,
    // `Some(old_root)` for a replacement). The swap lands only if the persisted root is still that
    // value and the account is still deactivated — so a concurrent import with a different base, or a
    // concurrent activation, makes this lose loudly rather than clobber the winner.
    let updated = crate::db::accounts::swap_repo_root_for_deactivated(
        &mut *tx,
        &did,
        &root_str,
        &imported.rev,
        observed_root.as_deref(),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to set imported repo root");
        ApiError::new(ErrorCode::InternalError, "failed to import repo")
    })?;
    if !updated {
        // Between the precondition read and this atomic CAS, the account was activated (or
        // suspended/taken down), or a concurrent import moved the root off the observed value.
        // Nothing is clobbered — the winner's root stands and this import loses loudly.
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "repo root changed since import began; retry against the current state",
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

    /// Export the account's repo at its *current* persisted root as a CAR, without touching any
    /// account state — the source side of an import round-trip.
    async fn export_current_repo(state: &AppState, did: &str) -> Vec<u8> {
        let root: String = sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(&state.db)
            .await
            .unwrap();
        let root_cid = repo_engine::Cid::try_from(root.as_str()).unwrap();
        let mut store = crate::db::blocks::SqliteBlockStore::new(state.db.clone(), did.to_string());
        repo_engine::export_repo_car(&mut store, root_cid)
            .await
            .unwrap()
    }

    /// Wipe the account's repo state so it looks like a fresh, deactivated migration target
    /// (repo-less), dropping its owned blocks.
    async fn reset_to_deactivated_repoless(state: &AppState, did: &str) {
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
    }

    /// Export the seeded account's repo as a CAR, then reset it to a fresh, deactivated migration
    /// target ready to import that CAR back.
    async fn export_then_reset(state: &AppState, did: &str) -> Vec<u8> {
        let car = export_current_repo(state, did).await;
        reset_to_deactivated_repoless(state, did).await;
        car
    }

    /// Read an account's stored repo root CID.
    async fn stored_root(state: &AppState, did: &str) -> String {
        sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(&state.db)
            .await
            .unwrap()
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
        // A real migration target is deactivated AND repo-less; clear the seeded repo so the CAR
        // parse (not the repo-exists guard) is what rejects the request.
        sqlx::query(
            "UPDATE accounts SET deactivated_at = datetime('now'), repo_root_cid = NULL, \
             repo_rev = NULL WHERE did = ?",
        )
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
    async fn import_hostile_frame_returns_400() {
        let state = state_with_master_key().await;
        let did = "did:plc:importhostile";
        seed_account_with_repo(&state.db, did).await;

        // A valid CAR with a trailing hostile frame: declared length (2) shorter than its CID
        // (36 bytes). Unvalidated, this underflows inside the CAR parser and panics the request
        // task; the validated front-end must reject it as a plain 400.
        let mut car = export_then_reset(&state, did).await;
        car.push(0x02);
        car.extend_from_slice(&[0x01, 0x71, 0x12, 0x20]);
        car.extend_from_slice(&[0u8; 32]);

        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state);
        let resp = app.oneshot(import_req(car, Some(&token))).await.unwrap();
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

    #[tokio::test]
    async fn reimport_same_root_is_idempotent_noop() {
        let state = state_with_master_key().await;
        let did = "did:plc:importtwice";
        seed_account_with_repo(&state.db, did).await;
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state.clone());

        let car = export_then_reset(&state, did).await;

        // First import into the deactivated, repo-less account succeeds.
        let r1 = app
            .clone()
            .oneshot(import_req(car.clone(), Some(&token)))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        let root_after_first = stored_root(&state, did).await;

        // A second import of the SAME CAR (same root) is now an idempotent no-op success — the
        // return-migration path where nothing was written at the other residency, so the incoming
        // repo is byte-identical. This replaces the old first-write-wins 409 that deterministically
        // blocked a migrate-away-and-return round trip.
        let r2 = app.oneshot(import_req(car, Some(&token))).await.unwrap();
        assert_eq!(
            r2.status(),
            StatusCode::OK,
            "a same-root reimport must be a 200 no-op, not a 409"
        );
        assert_eq!(
            stored_root(&state, did).await,
            root_after_first,
            "the repo root must be unchanged by the no-op reimport"
        );
    }

    #[tokio::test]
    async fn reimport_different_root_replaces_while_deactivated() {
        let state = state_with_master_key().await;
        let did = "did:plc:importreplace";
        seed_account_with_repo(&state.db, did).await;
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state.clone());

        // Commit a record → repo at root A; capture CAR_A.
        let put_a = crate::routes::test_utils::put_record_request(
            did,
            "app.bsky.feed.post",
            "first",
            serde_json::json!({ "record": { "text": "first residency" } }),
            Some(&token),
        );
        assert_eq!(
            app.clone().oneshot(put_a).await.unwrap().status(),
            StatusCode::OK
        );
        let car_a = export_current_repo(&state, did).await;

        // Commit a second record → repo at a different root B (superset of A); capture CAR_B.
        let put_b = crate::routes::test_utils::put_record_request(
            did,
            "app.bsky.feed.post",
            "second",
            serde_json::json!({ "record": { "text": "second residency" } }),
            Some(&token),
        );
        assert_eq!(
            app.clone().oneshot(put_b).await.unwrap().status(),
            StatusCode::OK
        );
        let car_b = export_current_repo(&state, did).await;

        // Reset to a fresh, deactivated, repo-less migration target, then import root A.
        reset_to_deactivated_repoless(&state, did).await;
        let r1 = app
            .clone()
            .oneshot(import_req(car_a, Some(&token)))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        let root_after_a = stored_root(&state, did).await;

        // A *different* root (B) replaces A while still deactivated — the return-migration case
        // where the repo changed at the other residency. This is what the old first-write-wins
        // guard forbade.
        let r2 = app
            .clone()
            .oneshot(import_req(car_b, Some(&token)))
            .await
            .unwrap();
        assert_eq!(
            r2.status(),
            StatusCode::OK,
            "a different root must replace the prior one while deactivated"
        );
        let root_after_b = stored_root(&state, did).await;
        assert_ne!(
            root_after_b, root_after_a,
            "the stored root must advance to the replacement repo"
        );

        // Reactivate; both records (CAR_B is a superset of A) must serve from the replacement repo.
        sqlx::query("UPDATE accounts SET deactivated_at = NULL WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        for rkey in ["first", "second"] {
            let get = Request::builder()
                .method(http::Method::GET)
                .uri(format!(
                    "/xrpc/com.atproto.repo.getRecord?did={did}&collection=app.bsky.feed.post&rkey={rkey}"
                ))
                .body(Body::empty())
                .unwrap();
            let r = app.clone().oneshot(get).await.unwrap();
            assert_eq!(
                r.status(),
                StatusCode::OK,
                "record {rkey} must serve from the replacement repo after reactivation"
            );
        }
    }
}
