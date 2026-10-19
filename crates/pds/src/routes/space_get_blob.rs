// pattern: Imperative Shell

//! com.atproto.space.getBlob — space-authed blob serving.
//!
//! Blobs upload once via `com.atproto.repo.uploadBlob` and are associated on reference, so
//! this route serves the same stored bytes as the public `sync.getBlob` — but only to a caller
//! the space read seam admits, and only for a blob some record in this `(space, repo)` still
//! references. An unreferenced-but-stored blob, an unknown CID, and a CID owned by another
//! account all read as the same `BlobNotFound`: whether an unreferenced blob exists is not a
//! fact a space reader is entitled to learn (the reference's `isBlobInSpace` posture).

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::app::AppState;
use crate::lexicon::LexiconParams;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
pub struct SpaceGetBlobParams {
    space: String,
    repo: String,
    cid: String,
}

/// GET /xrpc/com.atproto.space.getBlob
pub async fn space_get_blob(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceGetBlobParams>,
) -> Result<Response, ApiError> {
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

    // Referenced-in-this-space gate, before any lookup that could leak existence.
    let referenced =
        super::space_views::space_blob_cids(&state, &space.uri, &params.repo, None).await?;
    if !referenced.contains(&params.cid) {
        return Err(blob_not_found());
    }

    let blob = crate::db::blobs::get_owned_blob(&state.db, &params.repo, &params.cid)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, cid = %params.cid, "failed to query blob metadata");
            ApiError::new(ErrorCode::InternalError, "failed to query blob metadata")
        })?
        .ok_or_else(blob_not_found)?;

    let content = crate::blob_store::read_blob(&state.config.data_dir, &blob.storage_path)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, cid = %params.cid, path = %blob.storage_path, "failed to read blob from filesystem");
            ApiError::new(ErrorCode::InternalError, "failed to read blob")
        })?;

    // Same integrity gate as the public route: content-addressed bytes are re-hashed before
    // serving, and corrupt bytes read as absent rather than ever going out.
    let computed = crate::blob_store::compute_cid(&content);
    if computed != blob.cid {
        tracing::error!(
            cid = %blob.cid,
            computed = %computed,
            path = %blob.storage_path,
            "blob file failed integrity check on serve; refusing to serve corrupt bytes"
        );
        state.metrics.blob_scrub_flagged.add(1, &[]);
        return Err(blob_not_found());
    }

    let content_type = if blob.mime_type.is_empty() {
        "application/octet-stream".to_string()
    } else {
        blob.mime_type
    };

    // Unlike the public route's immutable-public caching, this response required a space
    // credential or OAuth grant — `private` keeps shared caches out of the access perimeter.
    // The CSP/nosniff/attachment trio is the reference's stored-XSS hardening for
    // client-declared MIME types.
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "private".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", blob.cid),
            ),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; sandbox".to_string(),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        ],
        Body::from(content),
    )
        .into_response())
}

fn blob_not_found() -> ApiError {
    ApiError::new(ErrorCode::BlobNotFound, "blob not found")
}
