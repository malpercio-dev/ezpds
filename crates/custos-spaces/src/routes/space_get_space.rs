// pattern: Imperative Shell

//! com.atproto.space.getSpace — a space and its policy.

use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::response::Json;
use custos_core::CoreState;
use serde::Deserialize;

use crate::auth::space::authenticate_space_authority;
use common::ApiError;
use custos_core::auth::oauth_scopes::SpaceOp;
use custos_core::lexicon::LexiconParams;

#[derive(Deserialize)]
pub struct GetSpaceParams {
    space: String,
}

/// GET /xrpc/com.atproto.space.getSpace
///
/// OAuth only, and authority only, under a `read_self` grant: the policy is the authority's own
/// state, so a space credential does not reach it. A policy can publish itself to readers
/// instead (`publishPolicy`).
pub async fn space_get_space(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<GetSpaceParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let space = crate::views::parse_space(&params.space)?;
    authenticate_space_authority(&state, &headers, &method, &uri, &space, SpaceOp::ReadSelf)
        .await?;
    let (_, policy) = crate::views::load_active_space(&state.db, &space).await?;
    Ok(Json(serde_json::json!({
        "space": space.uri,
        "policy": policy.to_json(),
    })))
}
