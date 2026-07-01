// pattern: Imperative Shell

//! com.atproto.server.checkAccountStatus - Report import/migration progress for an account.

use std::collections::HashSet;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use futures_util::StreamExt;
use ipld_core::ipld::Ipld;
use serde::Serialize;

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::db::blocks::SqliteBlockStore;
use common::{ApiError, ErrorCode};
use repo_engine::Repository;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckAccountStatusResponse {
    /// `true` when the account is active (not deactivated).
    pub activated: bool,
    /// `true` when the account has a DID document in the PLC directory (i.e. a row exists
    /// in `did_documents`).
    pub valid_did: bool,
    /// The repo's root commit CID, or `null` when the account has no repo yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_commit: Option<String>,
    /// The repo's commit revision (TID), or `null` when there is no repo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_rev: Option<String>,
    /// Total blocks stored for this DID in the block store — includes MST nodes, records,
    /// commits, and any orphaned blocks from incomplete writes not yet cleaned up.
    pub stored_blocks: i64,
    /// Number of records indexed in the repo (total record count across all collections).
    pub indexed_records: usize,
    /// Number of private state values (ezpds does not use private state — always 0).
    pub private_state_values: usize,
    /// Number of distinct blob CIDs referenced by repo records.
    pub expected_blobs: usize,
    /// Number of blobs actually imported into the blob store.
    pub imported_blobs: i64,
}

/// GET /xrpc/com.atproto.server.checkAccountStatus
///
/// Authenticated endpoint that reports the account's current state — activation, DID validity,
/// repo block/record counts, and blob reference-vs-imported diff — for migration tooling to
/// confirm import completeness before calling `activateAccount`.
pub async fn check_account_status(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    let did = &user.did;

    // ── 1. Account lifecycle ──────────────────────────────────────────────

    let (activated, repo_commit, repo_rev) = {
        let row = crate::db::accounts::get_repo_status(&state.db, did)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to fetch repo status");
                ApiError::new(ErrorCode::InternalError, "failed to get account status")
            })?
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "account not found"))?;
        (row.lifecycle.is_active(), row.head, row.rev)
    };

    // ── 2. DID document existence ─────────────────────────────────────────

    let valid_did: bool =
        sqlx::query_scalar::<_, i64>("SELECT 1 FROM did_documents WHERE did = ? LIMIT 1")
            .bind(did)
            .fetch_optional(&state.db)
            .await
            .map(|row| row.is_some())
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to check DID document");
                ApiError::new(ErrorCode::InternalError, "failed to check DID document")
            })?;

    // ── 3. Repo block count ───────────────────────────────────────────────

    let stored_blocks = crate::db::blocks::account_block_stats(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to fetch block stats");
            ApiError::new(ErrorCode::InternalError, "failed to get block stats")
        })?
        .block_count;

    // ── 4. Repo-walking counts (records + expected blobs) ─────────────────

    let (indexed_records, expected_blobs) = match &repo_commit {
        Some(head) => {
            let (records, blobs) = count_records_and_blob_refs(&state, did, head).await?;
            (records, blobs)
        }
        None => (0, 0),
    };

    // ── 5. Imported blob count ────────────────────────────────────────────

    let (imported_blobs, _) = crate::db::blobs::account_blob_metrics(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to fetch blob metrics");
            ApiError::new(ErrorCode::InternalError, "failed to get blob metrics")
        })?;

    Ok((
        StatusCode::OK,
        Json(CheckAccountStatusResponse {
            activated,
            valid_did,
            repo_commit,
            repo_rev,
            stored_blocks,
            indexed_records,
            private_state_values: 0,
            expected_blobs,
            imported_blobs,
        }),
    )
        .into_response())
}

/// Open the repo at `head`, walk every MST key, count records, and extract distinct blob
/// CIDs from record values.
///
/// Returns `(record_count, blob_cid_count)`.
///
/// # Performance
///
/// We walk the MST once to collect all `(key, cid)` entries, then read each record block
/// directly from the block store via [`crate::db::blocks::get_block`]. Each record read is a
/// single-row `SELECT BY cid` — O(1) per record — instead of calling `Repository::get_raw_cid`
/// which re-walks the entire MST for every record (O(N²) total).
async fn count_records_and_blob_refs(
    state: &AppState,
    did: &str,
    head: &str,
) -> Result<(usize, usize), ApiError> {
    let root_cid = repo_engine::Cid::try_from(head).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID");
        ApiError::new(ErrorCode::InternalError, "invalid repo root CID")
    })?;

    // Open the repo just to walk the MST and collect (key, cid) entries.
    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to open repo")
    })?;

    let entries: Vec<(String, String)> = {
        let mut tree = repo.tree();
        let mut stream = Box::pin(tree.entries_prefixed(""));
        let mut entries = Vec::new();
        while let Some(res) = stream.next().await {
            let (key, cid) = res.map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to iterate MST");
                ApiError::new(ErrorCode::InternalError, "failed to iterate MST")
            })?;
            entries.push((key, cid.to_string()));
        }
        entries
    };
    // Drop tree/repo — we only need the block store from here on.

    let mut record_count = 0usize;
    let mut blob_cids: HashSet<String> = HashSet::new();

    for (key, cid_str) in entries {
        // Count records: MST keys are `<collection>/<rkey>`.
        if !key.contains('/') {
            continue;
        }
        record_count += 1;

        // Read the record block directly from the DB (O(1) SELECT BY cid) instead of
        // calling `Repository::get_raw_cid` which does an O(N) MST walk per record.
        let row = crate::db::blocks::get_block(&state.db, &cid_str)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, cid = %cid_str, "failed to read block");
                ApiError::new(ErrorCode::InternalError, "failed to read record block")
            })?
            .ok_or_else(|| {
                // Tree referenced a CID that doesn't exist — repo corruption.
                tracing::error!(did = %did, cid = %cid_str, key = %key, "MST entry references missing block");
                ApiError::new(ErrorCode::InternalError, "repo integrity error")
            })?;

        let ipld: Ipld = serde_ipld_dagcbor::from_slice(&row.bytes).map_err(|e| {
            tracing::error!(error = %e, did = %did, cid = %cid_str, "failed to decode DAG-CBOR");
            ApiError::new(ErrorCode::InternalError, "failed to decode record")
        })?;

        collect_blob_cids(&ipld, &mut blob_cids);
    }

    Ok((record_count, blob_cids.len()))
}

/// Recursively walk an [`Ipld`] value and collect all blob-reference CIDs into `out`.
///
/// A blob reference in an ATProto record is a map with `"$type": "blob"` whose `ref` key
/// carries the CID. After `json_to_record_value`, `ref` is an `Ipld::Link` (not a nested
/// map — `{"$link": "..."}` is canonicalized). We also handle the raw-map form for
/// completeness. CID links and byte strings terminate recursion.
fn collect_blob_cids(ipld: &Ipld, out: &mut HashSet<String>) {
    match ipld {
        Ipld::Map(map) => {
            // Check for a blob reference: `{"$type": "blob", "ref": <cid-link>, ...}`.
            if let Some(Ipld::String(typ)) = map.get("$type") {
                if typ == "blob" {
                    if let Some(link) = map.get("ref") {
                        match link {
                            // Canonical: `json_to_record_value` converts `{"$link": "..."}` to `Ipld::Link`.
                            Ipld::Link(cid) => {
                                out.insert(cid.to_string());
                            }
                            // Raw-JSON fallback: `ref` is still a map with a `$link` key.
                            Ipld::Map(ref_map) => {
                                if let Some(Ipld::Link(cid)) = ref_map.get("$link") {
                                    out.insert(cid.to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            // Recurse into all map values — a blob could be nested inside an embed.
            for v in map.values() {
                collect_blob_cids(v, out);
            }
        }
        Ipld::List(items) => {
            for v in items {
                collect_blob_cids(v, out);
            }
        }
        // Scalars and links are leafs — no further recursion.
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use tower::ServiceExt;

    use crate::routes::test_utils::{
        access_jwt, body_json, seed_account_with_repo, state_with_master_key,
    };

    async fn check(app: &axum::Router, token: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/xrpc/com.atproto.server.checkAccountStatus")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(request).await.unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    #[tokio::test]
    async fn active_account_with_repo_reports_correct_counts() {
        let state = state_with_master_key().await;
        let did = "did:plc:checkactive";
        seed_account_with_repo(&state.db, did).await;
        // Insert a minimal DID document so validDid is true.
        sqlx::query(
            "INSERT INTO did_documents (did, document, created_at, updated_at) VALUES (?, '{}', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state);

        let (status, body) = check(&app, &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["activated"], true);
        assert_eq!(body["validDid"], true);
        // A genesis repo has 0 records and 0 blocks initially (the commit itself is a
        // block, but it belongs to the MST, not the records).
        assert_eq!(body["indexedRecords"], 0);
        assert_eq!(body["expectedBlobs"], 0);
        assert_eq!(body["importedBlobs"], 0);
        assert!(body["repoCommit"].is_string());
        assert!(body["repoRev"].is_string());
    }

    #[tokio::test]
    async fn deactivated_account_reports_activated_false() {
        let state = state_with_master_key().await;
        let did = "did:plc:checkdeact";
        seed_account_with_repo(&state.db, did).await;
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state);

        let (status, body) = check(&app, &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["activated"], false);
    }

    #[tokio::test]
    async fn unauthenticated_returns_401() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/xrpc/com.atproto.server.checkAccountStatus")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn nonexistent_account_returns_404() {
        let state = state_with_master_key().await;
        let token = access_jwt(&state.jwt_secret, "did:plc:checkghost");
        let app = crate::app::app(state);

        let (status, body) = check(&app, &token).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn account_without_did_document_reports_invalid_did() {
        let state = state_with_master_key().await;
        let did = "did:plc:checknodid";
        seed_account_with_repo(&state.db, did).await;
        // Delete the DID document (the seed creates one).
        sqlx::query("DELETE FROM did_documents WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state);

        let (status, body) = check(&app, &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["validDid"], false);
    }

    #[tokio::test]
    async fn account_with_records_counts_correctly() {
        let state = state_with_master_key().await;
        let did = "did:plc:checkrecords";
        seed_account_with_repo(&state.db, did).await;
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state.clone());

        // Put a couple of records.
        for (rkey, text) in [("a", "hello"), ("b", "world")] {
            let request = crate::routes::test_utils::put_record_request(
                did,
                "app.bsky.feed.post",
                rkey,
                serde_json::json!({ "record": { "text": text } }),
                Some(&token),
            );
            let resp = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "putRecord {rkey} should succeed"
            );
        }

        let (status, body) = check(&app, &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["indexedRecords"], 2);
    }

    #[tokio::test]
    async fn account_with_blob_refs_counts_expected_blobs() {
        let state = state_with_master_key().await;
        let did = "did:plc:checkblobs";
        seed_account_with_repo(&state.db, did).await;
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state.clone());

        // A record referencing a blob via a valid CID.
        let blob_cid = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";
        let record = serde_json::json!({
            "record": {
                "text": "with image",
                "embed": {
                    "images": [{
                        "image": {
                            "$type": "blob",
                            "ref": { "$link": blob_cid },
                            "mimeType": "image/png",
                            "size": 100
                        },
                        "alt": "test"
                    }]
                }
            }
        });
        let request = crate::routes::test_utils::put_record_request(
            did,
            "app.bsky.feed.post",
            "post1",
            record,
            Some(&token),
        );
        let resp = app.clone().oneshot(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let (status, body) = check(&app, &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["indexedRecords"], 1);
        assert_eq!(body["expectedBlobs"], 1);
        // Blob not actually imported.
        assert_eq!(body["importedBlobs"], 0);
    }
}
