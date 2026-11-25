// pattern: Imperative Shell

//! com.atproto.space.getRecord — read one record from a permissioned space repo.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use custos_core::CoreState;
use serde::Deserialize;

use common::{ApiError, Did, ErrorCode};
use crypto::http_signature::MacProfile;
use custos_core::lexicon::LexiconParams;

#[derive(Deserialize)]
pub struct SpaceGetRecordParams {
    space: String,
    repo: Did,
    collection: String,
    rkey: String,
}

/// GET /xrpc/com.atproto.space.getRecord
///
/// A requested MAC covers the record's uri and cid (`space_mac`).
pub async fn space_get_record(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceGetRecordParams>,
) -> Result<Response, ApiError> {
    let space = crate::views::parse_space(&params.space)?;
    let reader = crate::auth::space::authenticate_space_read(
        &state,
        &headers,
        &method,
        &uri,
        &space,
        &params.repo,
    )
    .await?;
    let mac =
        crate::space_mac::mac_grant(&state, &headers, &reader, &params.repo, MacProfile::Record)
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

    let record_uri = space.record_uri(&params.repo, &params.collection, &params.rkey);
    let response = (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "uri": record_uri,
            "cid": record.cid,
            "value": crate::views::decode_value(&record.value)?,
        })),
    )
        .into_response();
    crate::space_mac::with_record_mac(response, &record_uri, &record.cid, mac.as_ref())
}
