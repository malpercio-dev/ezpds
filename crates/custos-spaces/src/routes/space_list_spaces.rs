// pattern: Imperative Shell

//! com.atproto.space.listSpaces — the spaces the authenticated account holds a repo in or is
//! the authority for.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use custos_core::CoreState;
use serde::Deserialize;

use common::{ApiError, ErrorCode};
use custos_core::auth::jwt::AuthScope;
use custos_core::auth::oauth_scopes::{self, SpaceOp, SpaceRequest};
use custos_core::lexicon::LexiconParams;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 100;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceListSpacesParams {
    /// Filter to spaces of this type.
    space_type: Option<String>,
    /// Filter to spaces under this authority DID.
    space_did: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

/// GET /xrpc/com.atproto.space.listSpaces
///
/// Lists the spaces the caller has *written to* or is the authority for, which is not "spaces
/// I'm a member of" — a member's PDS only ever learns about a space by storing a repo in it.
/// Each entry carries the caller's repo head there (`repoRev` and its commit `data`) when it has
/// one, and the space's revision (`spaceRev`) when the caller is its authority.
pub async fn space_list_spaces(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceListSpacesParams>,
) -> Result<impl IntoResponse, ApiError> {
    let user =
        crate::auth::space::authenticate_space_caller(&state, &headers, &method, &uri).await?;

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
                authority: params.space_did.as_deref().unwrap_or("*"),
                skey: "*",
                op: SpaceOp::ReadSelf,
                account_did: &user.did,
                declared_collections: &[],
            },
        )?;
    }

    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let spaces = crate::db::space_repos::list_spaces_for_account(
        &state.db,
        &user.did,
        params.space_type.as_deref(),
        params.space_did.as_deref(),
        params.cursor.as_deref(),
        limit,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, did = %user.did, "failed to list spaces");
        ApiError::new(ErrorCode::InternalError, "failed to list spaces")
    })?;

    let next = (spaces.len() as i64 == limit)
        .then(|| spaces.last().map(|space| space.uri.clone()))
        .flatten();
    let views = spaces
        .iter()
        .map(|space| {
            let mut view = serde_json::json!({ "space": space.uri });
            if let (Some(rev), Some(state)) = (&space.repo_rev, &space.lthash_state) {
                let digest = crypto::LtHash::from_state(state)
                    .map_err(|e| {
                        ApiError::internal_as(
                            e,
                            "stored LtHash state is malformed",
                            "failed to list spaces",
                        )
                    })?
                    .digest();
                view["repoRev"] = rev.clone().into();
                view["data"] = crate::views::lex_bytes(&digest);
            }
            if let Some(space_rev) = &space.space_rev {
                view["spaceRev"] = space_rev.clone().into();
            }
            Ok(view)
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let mut body = serde_json::json!({ "spaces": views });
    if let Some(cursor) = next {
        body["cursor"] = serde_json::Value::String(cursor);
    }
    Ok((StatusCode::OK, axum::Json(body)))
}
