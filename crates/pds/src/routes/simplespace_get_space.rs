// pattern: Imperative Shell

//! com.atproto.simplespace.getSpace — a space's simplespace configuration.

use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::response::Json;
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::space::authenticate_space_access;
use crate::lexicon::LexiconParams;
use common::ApiError;

#[derive(Deserialize)]
pub struct GetSpaceParams {
    space: String,
}

/// GET /xrpc/com.atproto.simplespace.getSpace
///
/// Served by the space host: an OAuth caller must be the authority with a `read_self` grant,
/// a member hosted anywhere (including here) presents the DPoP-bound space credential the
/// authority issued it — which is itself the proof it is authorized for the space.
pub async fn simplespace_get_space(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<GetSpaceParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let space = super::space_views::parse_space(&params.space)?;
    authenticate_space_access(&state, &headers, &method, &uri, &space).await?;
    let row = super::space_views::load_active_simplespace(&state.db, &space).await?;
    Ok(Json(super::space_views::simplespace_view(&row)))
}
