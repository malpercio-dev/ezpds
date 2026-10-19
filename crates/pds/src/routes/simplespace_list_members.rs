// pattern: Imperative Shell

//! com.atproto.simplespace.listMembers — page through a space's member list.

use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::response::Json;
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::oauth_scopes::SpaceOp;
use crate::auth::space::authenticate_space_owner;
use crate::lexicon::LexiconParams;
use common::{ApiError, ErrorCode};

const DEFAULT_LIMIT: i64 = 100;

#[derive(Deserialize)]
pub struct ListMembersParams {
    space: String,
    limit: Option<i64>,
    cursor: Option<String>,
}

/// GET /xrpc/com.atproto.simplespace.listMembers
///
/// OAuth only, and owner only: the member list is the authority's own state, so a space
/// credential does not reach it and a member hosted elsewhere cannot enumerate it. Keyset
/// paged by DID; the cursor is the last DID of a full page.
pub async fn simplespace_list_members(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<ListMembersParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let space = super::space_views::parse_space(&params.space)?;
    authenticate_space_owner(&state, &headers, &method, &uri, &space, SpaceOp::ReadSelf).await?;
    super::space_views::load_active_simplespace(&state.db, &space).await?;

    // The lexicon layer has already bounded `limit` to 1..=1000.
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT);
    let dids =
        crate::db::spaces::list_members(&state.db, &space.uri, params.cursor.as_deref(), limit)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, space = %space.uri, "failed to list members");
                ApiError::new(ErrorCode::InternalError, "internal server error")
            })?;

    let next = (dids.len() as i64 == limit)
        .then(|| dids.last().cloned())
        .flatten();
    let mut body = serde_json::json!({
        "members": dids.iter().map(|did| serde_json::json!({ "did": did })).collect::<Vec<_>>(),
    });
    if let Some(cursor) = next {
        body["cursor"] = serde_json::Value::String(cursor);
    }
    Ok(Json(body))
}
