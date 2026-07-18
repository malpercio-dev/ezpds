// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (JWT extractor), query params (limit, cursor), DB pool via AppState
// Processes: walk the account's repo MST → collect blob references from records → diff against
//            the blobs the account has uploaded → paginate the missing set by CID
// Returns: JSON { blobs: [{ cid, recordUri }], cursor? }
//
// Implements: GET /xrpc/com.atproto.repo.listMissingBlobs

use std::collections::HashSet;

use axum::{extract::State, response::Json};
use futures_util::StreamExt;
use ipld_core::ipld::Ipld;
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::db::blocks::SqliteBlockStore;
use crate::lexicon::LexiconParams;
use repo_engine::Repository;

// ── Query parameters ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListMissingBlobsParams {
    #[serde(default = "default_limit")]
    pub limit: i64,
    pub cursor: Option<String>,
}

fn default_limit() -> i64 {
    500
}

// ── Response types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissingBlob {
    pub cid: String,
    pub record_uri: String,
}

#[derive(Debug, Serialize)]
pub struct ListMissingBlobsResponse {
    pub blobs: Vec<MissingBlob>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

// ── Handler ────────────────────────────────────────────────────────────────────

/// GET /xrpc/com.atproto.repo.listMissingBlobs?limit=500&cursor=<cid>
///
/// Authenticated endpoint for the account-migration flow: lists blob CIDs referenced by the
/// account's imported records that have not yet been uploaded, so the client can drive blob
/// transfer (`getBlob` old → `uploadBlob` new) to completion. Missing blobs are returned ordered
/// by CID with cursor pagination; each carries one referencing record's AT-URI.
pub async fn list_missing_blobs(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    LexiconParams(params): LexiconParams<ListMissingBlobsParams>,
) -> Result<Json<ListMissingBlobsResponse>, ApiError> {
    let did = &user.did;
    // Already bounded to [1, 1000] by the lexicon; the cast just changes the integer type.
    let limit = params.limit as usize;

    // No repo yet → nothing referenced, nothing missing.
    let Some(head) = crate::db::accounts::get_repo_root_cid(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to fetch repo root");
            ApiError::new(ErrorCode::InternalError, "failed to list missing blobs")
        })?
    else {
        return Ok(Json(ListMissingBlobsResponse {
            blobs: Vec::new(),
            cursor: None,
        }));
    };

    // Walk the MST once, collecting each record's referenced blob CIDs paired with the record's
    // AT-URI. The first record (in MST order) to reference a given blob wins the pairing, so the
    // reported `recordUri` is deterministic across pages.
    let refs = collect_repo_blob_refs(&state, did, &head).await?;

    // Diff against the blobs this account has actually uploaded.
    let referenced_cids: Vec<String> = refs.iter().map(|(cid, _)| cid.clone()).collect();
    let present = crate::db::blobs::present_cids(&state.db, did, &referenced_cids)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to check uploaded blobs");
            ApiError::new(ErrorCode::InternalError, "failed to list missing blobs")
        })?;

    // Missing = referenced but not present, ordered by CID for stable cursor pagination.
    let mut missing: Vec<(String, String)> = refs
        .into_iter()
        .filter(|(cid, _)| !present.contains(cid))
        .collect();
    missing.sort_by(|a, b| a.0.cmp(&b.0));

    // Apply the cursor (exclusive lower bound on CID), then take `limit`, fetching one extra to
    // decide whether a next cursor is needed.
    let start = match &params.cursor {
        Some(c) => missing.partition_point(|(cid, _)| cid.as_str() <= c.as_str()),
        None => 0,
    };
    let page: Vec<(String, String)> = missing.into_iter().skip(start).take(limit + 1).collect();

    let has_more = page.len() > limit;
    let blobs: Vec<MissingBlob> = page
        .into_iter()
        .take(limit)
        .map(|(cid, record_uri)| MissingBlob { cid, record_uri })
        .collect();
    let cursor = if has_more {
        blobs.last().map(|b| b.cid.clone())
    } else {
        None
    };

    Ok(Json(ListMissingBlobsResponse { blobs, cursor }))
}

/// Open the repo at `head` and collect `(blob_cid, record_uri)` pairs for every blob referenced by
/// a record, deduplicated by blob CID (first referencing record wins).
///
/// Mirrors `check_account_status`'s walk: iterate the MST once to gather `(key, cid)` entries, then
/// read each record block directly from the block store (O(1) `SELECT BY cid`) rather than through
/// `Repository::get_raw_cid` (which re-walks the whole MST per record).
async fn collect_repo_blob_refs(
    state: &AppState,
    did: &str,
    head: &str,
) -> Result<Vec<(String, String)>, ApiError> {
    let root_cid = repo_engine::Cid::try_from(head).map_err(|e| {
        tracing::error!(error = %e, did = %did, "invalid repo root CID");
        ApiError::new(ErrorCode::InternalError, "failed to list missing blobs")
    })?;

    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(block_store, root_cid).await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to open repo");
        ApiError::new(ErrorCode::InternalError, "failed to list missing blobs")
    })?;

    let entries: Vec<(String, String)> = {
        let mut tree = repo.tree();
        let mut stream = Box::pin(tree.entries_prefixed(""));
        let mut entries = Vec::new();
        while let Some(res) = stream.next().await {
            let (key, cid) = res.map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to iterate MST");
                ApiError::new(ErrorCode::InternalError, "failed to list missing blobs")
            })?;
            entries.push((key, cid.to_string()));
        }
        entries
    };

    let mut seen: HashSet<String> = HashSet::new();
    let mut refs: Vec<(String, String)> = Vec::new();
    for (key, cid_str) in entries {
        // MST keys are `<collection>/<rkey>`; keys without a slash are not records.
        if !key.contains('/') {
            continue;
        }
        let record_uri = format!("at://{did}/{key}");

        let row = crate::db::blocks::get_block(&state.db, &cid_str)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, cid = %cid_str, "failed to read block");
                ApiError::new(ErrorCode::InternalError, "failed to list missing blobs")
            })?
            .ok_or_else(|| {
                tracing::error!(did = %did, cid = %cid_str, key = %key, "MST entry references missing block");
                ApiError::new(ErrorCode::InternalError, "repo integrity error")
            })?;

        let ipld: Ipld = serde_ipld_dagcbor::from_slice(&row.bytes).map_err(|e| {
            tracing::error!(error = %e, did = %did, cid = %cid_str, "failed to decode DAG-CBOR");
            ApiError::new(ErrorCode::InternalError, "failed to decode record")
        })?;

        for blob_cid in repo_engine::record_blob_cids(&ipld) {
            let blob_cid = blob_cid.to_string();
            if seen.insert(blob_cid.clone()) {
                refs.push((blob_cid, record_uri.clone()));
            }
        }
    }

    Ok(refs)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
    use tower::ServiceExt;

    use crate::routes::test_utils::{
        access_jwt, body_json, put_record_request, seed_account_with_repo, state_with_master_key,
    };

    const BLOB_CID_A: &str = "bafkreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";
    const BLOB_CID_B: &str = "bafkreib3cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";

    async fn get(app: &axum::Router, uri: &str, token: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(request).await.unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    /// Put a record that references a blob via a CID link.
    async fn put_blob_post(app: &axum::Router, did: &str, token: &str, rkey: &str, blob_cid: &str) {
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
        let req = put_record_request(did, "app.bsky.feed.post", rkey, record, Some(token));
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn unauthenticated_returns_401() {
        let state = crate::app::test_state().await;
        let app = crate::app::app(state);
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/xrpc/com.atproto.repo.listMissingBlobs")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn empty_repo_returns_no_missing_blobs() {
        let state = state_with_master_key().await;
        let did = "did:plc:missingempty";
        seed_account_with_repo(&state.db, did).await;
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state);

        let (status, body) = get(&app, "/xrpc/com.atproto.repo.listMissingBlobs", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["blobs"].as_array().unwrap().len(), 0);
        assert!(body["cursor"].is_null());
    }

    #[tokio::test]
    async fn reports_referenced_but_not_uploaded_blob() {
        let state = state_with_master_key().await;
        let did = "did:plc:missingone";
        seed_account_with_repo(&state.db, did).await;
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state);

        put_blob_post(&app, did, &token, "post1", BLOB_CID_A).await;

        let (status, body) = get(&app, "/xrpc/com.atproto.repo.listMissingBlobs", &token).await;
        assert_eq!(status, StatusCode::OK);
        let blobs = body["blobs"].as_array().unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0]["cid"], BLOB_CID_A);
        assert_eq!(
            blobs[0]["recordUri"],
            format!("at://{did}/app.bsky.feed.post/post1")
        );
    }

    #[tokio::test]
    async fn uploaded_blob_is_not_reported_missing() {
        let state = state_with_master_key().await;
        let did = "did:plc:missingnone";
        seed_account_with_repo(&state.db, did).await;
        let token = access_jwt(&state.jwt_secret, did);

        // Mark the blob as already uploaded for this account.
        crate::db::blobs::insert_blob(
            &state.db,
            BLOB_CID_A,
            did,
            "image/png",
            100,
            "blobs/xx/blob",
            "2999-01-01 00:00:00",
        )
        .await
        .unwrap();

        let app = crate::app::app(state);
        put_blob_post(&app, did, &token, "post1", BLOB_CID_A).await;

        let (status, body) = get(&app, "/xrpc/com.atproto.repo.listMissingBlobs", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["blobs"].as_array().unwrap().len(),
            0,
            "an uploaded blob must not be reported missing"
        );
    }

    #[tokio::test]
    async fn paginates_by_cid_with_cursor() {
        let state = state_with_master_key().await;
        let did = "did:plc:missingpage";
        seed_account_with_repo(&state.db, did).await;
        let token = access_jwt(&state.jwt_secret, did);
        let app = crate::app::app(state);

        // Two distinct missing blobs across two records.
        put_blob_post(&app, did, &token, "post1", BLOB_CID_A).await;
        put_blob_post(&app, did, &token, "post2", BLOB_CID_B).await;

        // Page 1: limit 1 → one blob + a cursor.
        let (status, body) = get(
            &app,
            "/xrpc/com.atproto.repo.listMissingBlobs?limit=1",
            &token,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page1 = body["blobs"].as_array().unwrap();
        assert_eq!(page1.len(), 1);
        assert!(
            body["cursor"].is_string(),
            "cursor present when more remain"
        );
        let cursor = body["cursor"].as_str().unwrap().to_string();
        let first_cid = page1[0]["cid"].as_str().unwrap().to_string();

        // Page 2: the remaining blob, no further cursor, no overlap.
        let (status, body2) = get(
            &app,
            &format!("/xrpc/com.atproto.repo.listMissingBlobs?limit=1&cursor={cursor}"),
            &token,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page2 = body2["blobs"].as_array().unwrap();
        assert_eq!(page2.len(), 1);
        assert!(body2["cursor"].is_null(), "no cursor after the last page");
        let second_cid = page2[0]["cid"].as_str().unwrap();
        assert!(
            second_cid > first_cid.as_str(),
            "pages are ordered and disjoint"
        );
    }
}
