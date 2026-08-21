// pattern: Imperative Shell

//! com.atproto.space.listSpaces — the spaces the authenticated account holds a repo in.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::jwt::AuthScope;
use crate::auth::oauth_scopes::{self, SpaceOp, SpaceRequest};
use crate::lexicon::LexiconParams;
use common::{ApiError, ErrorCode};

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 100;

#[derive(Deserialize)]
pub struct SpaceListSpacesParams {
    /// Filter to spaces of this type.
    #[serde(rename = "type")]
    space_type: Option<String>,
    /// Filter to spaces under this authority DID.
    did: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

/// GET /xrpc/com.atproto.space.listSpaces
///
/// Lists the spaces the caller has *written to*, which is not "spaces I'm a member of" — a
/// member's PDS only ever learns about a space by storing a repo in it.
pub async fn space_list_spaces(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceListSpacesParams>,
) -> Result<impl IntoResponse, ApiError> {
    let user = crate::auth::space::authenticate_space_caller(&state, &headers, &method, &uri)?;

    // There is no one space to check a grant against here, so the *filters* are the target: an
    // unfiltered listing needs a wildcard grant, and narrowing the query narrows what the grant
    // has to cover. The listing is the caller's own, so `read_self` is the action that fits;
    // a whole-space `read` grant satisfies it too. This is the one space route whose check
    // cannot go through `auth::space`'s space-ref-keyed seam, because it names no space.
    if user.scope == AuthScope::Access {
        oauth_scopes::require_space(
            &user.scope_claim,
            &SpaceRequest {
                space_type: params.space_type.as_deref().unwrap_or("*"),
                authority: params.did.as_deref().unwrap_or("*"),
                skey: "*",
                op: SpaceOp::ReadSelf,
                account_did: &user.did,
                declared_collections: &[],
            },
        )?;
    }

    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let uris = crate::db::space_repos::list_spaces_for_account(
        &state.db,
        &user.did,
        params.space_type.as_deref(),
        params.did.as_deref(),
        params.cursor.as_deref(),
        limit,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, did = %user.did, "failed to list spaces");
        ApiError::new(ErrorCode::InternalError, "failed to list spaces")
    })?;

    let next = (uris.len() as i64 == limit)
        .then(|| uris.last().cloned())
        .flatten();
    let mut body = serde_json::json!({
        "spaces": uris.iter().map(|uri| serde_json::json!({ "uri": uri })).collect::<Vec<_>>(),
    });
    if let Some(cursor) = next {
        body["cursor"] = serde_json::Value::String(cursor);
    }
    Ok((StatusCode::OK, axum::Json(body)))
}
