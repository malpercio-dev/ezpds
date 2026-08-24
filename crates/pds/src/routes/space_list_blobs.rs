// pattern: Imperative Shell

//! com.atproto.space.listBlobs — enumerate the blob CIDs an account's records in one space
//! reference.
//!
//! Scoped to one space and behind the space read seam on purpose: blobs behind permissioned
//! records are never enumerated by the unauthenticated `com.atproto.sync.listBlobs`. This is
//! how a syncer discovers what to fetch via `space.getBlob`, and how migration enumerates the
//! blobs a permissioned repo must carry.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::lexicon::LexiconParams;
use common::ApiError;

const DEFAULT_LIMIT: usize = 500;
const MAX_LIMIT: usize = 1000;

#[derive(Deserialize)]
pub struct SpaceListBlobsParams {
    space: String,
    repo: String,
    /// Only blobs referenced by records written after this repo rev (V066's per-record rev).
    since: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}

/// GET /xrpc/com.atproto.space.listBlobs
///
/// CIDs ascending, deduplicated; the cursor is the last CID of a full page (a short page is
/// the last one and carries none) — the reference's exact paging shape.
pub async fn space_list_blobs(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceListBlobsParams>,
) -> Result<impl IntoResponse, ApiError> {
    let space = super::space_views::parse_space(&params.space)?;
    crate::auth::space::authenticate_space_read(
        &state,
        &headers,
        &method,
        &uri,
        &space,
        &params.repo,
    )
    .await?;
    super::space_views::load_repo(&state, &space.uri, &params.repo).await?;

    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    // Derived per request by decoding the repo's records (blob linkage is deliberately not a
    // table); `space_blob_cids` carries the scale ceiling note.
    let cids = super::space_views::space_blob_cids(
        &state,
        &space.uri,
        &params.repo,
        params.since.as_deref(),
    )
    .await?;

    let page: Vec<String> = cids
        .into_iter()
        .filter(|cid| {
            params
                .cursor
                .as_deref()
                .is_none_or(|cursor| cid.as_str() > cursor)
        })
        .take(limit)
        .collect();

    let mut body = serde_json::json!({ "cids": page });
    if page.len() == limit {
        if let Some(last) = page.last() {
            body["cursor"] = serde_json::Value::String(last.clone());
        }
    }
    Ok((StatusCode::OK, axum::Json(body)))
}
