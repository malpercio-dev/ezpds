// pattern: Imperative Shell

//! com.atproto.space.getRecord — read one record from a permissioned space repo.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::lexicon::LexiconParams;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
pub struct SpaceGetRecordParams {
    space: String,
    repo: String,
    collection: String,
    rkey: String,
}

/// GET /xrpc/com.atproto.space.getRecord
pub async fn space_get_record(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceGetRecordParams>,
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

    let record = crate::db::space_repos::get_record(
        &state.db,
        &space.uri,
        &params.repo,
        &params.collection,
        &params.rkey,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, space = %space.uri, "failed to read space record");
        ApiError::new(ErrorCode::InternalError, "failed to read space record")
    })?
    .ok_or_else(|| ApiError::new(ErrorCode::RecordNotFound, "could not locate record"))?;

    Ok((
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "uri": space.record_uri(&params.repo, &params.collection, &params.rkey),
            "cid": record.cid,
            "value": super::space_views::decode_value(&record.value)?,
        })),
    ))
}
