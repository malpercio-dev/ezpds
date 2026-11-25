// pattern: Imperative Shell

//! com.atproto.space.exportSpaceMeta — the authority's `atproto-space-meta` archive of a space,
//! for migrating its account (`crate::space_migration`).

use axum::extract::State;
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use custos_core::CoreState;
use serde::Deserialize;

use common::ApiError;
use custos_core::auth::oauth_scopes::SpaceOp;
use custos_core::lexicon::LexiconParams;

#[derive(Deserialize)]
pub struct ExportSpaceMetaParams {
    space: String,
}

/// GET /xrpc/com.atproto.space.exportSpaceMeta
///
/// OAuth only, as for `getSpace`: the archive is the authority's own state. A space the operator
/// took down answers `SpaceNotFound` here as everywhere else.
pub async fn space_export_space_meta(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<ExportSpaceMetaParams>,
) -> Result<impl IntoResponse, ApiError> {
    let space = crate::views::parse_space(&params.space)?;
    crate::auth::space::authenticate_space_authority(
        &state,
        &headers,
        &method,
        &uri,
        &space,
        SpaceOp::ReadSelf,
    )
    .await?;
    let archive = crate::space_migration::export_space_meta(&state, &space).await?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/vnd.dasl.star"),
            (header::CACHE_CONTROL, "private"),
        ],
        archive,
    ))
}
