// pattern: Imperative Shell

//! com.atproto.simplespace.createSpace — create a space anchored on the caller's own DID.

use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::response::Json;
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::oauth_scopes::{RepoAction, SpaceOp};
use crate::auth::space::{authenticate_space_caller, require_space_grant};
use crate::db::spaces::{create_space, NewSpace};
use crate::lexicon::LexiconInput;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSpaceInput {
    /// The space type NSID.
    #[serde(rename = "type")]
    space_type: String,
    /// Optional space key (record-key syntax); a TID is generated when absent.
    skey: Option<String>,
    /// `policy` union — mapped by `space_views::policy_from_lex`.
    policy: serde_json::Value,
    /// `appAccess` union — mapped by `space_views::app_access_from_lex`.
    app_access: serde_json::Value,
}

/// POST /xrpc/com.atproto.simplespace.createSpace
///
/// The space URI is built from the authenticated DID, so the caller is the owner by
/// construction; what the `manage=create` grant is matched against is that URI. Both config
/// unions are open: an unimplemented member is refused (`UnsupportedPolicy` /
/// `UnsupportedAppAccess`) before anything is stored.
pub async fn simplespace_create_space(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<CreateSpaceInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = authenticate_space_caller(&state, &headers, &method, &uri).await?;
    let skey = input.skey.unwrap_or_else(repo_engine::generate_tid);
    let space = super::space_views::parse_space(&format!(
        "at://{}/space/{}/{skey}",
        user.did, input.space_type
    ))?;
    require_space_grant(&state, &user, &space, SpaceOp::Manage(RepoAction::Create)).await?;

    let (policy, managing_app) = super::space_views::policy_from_lex(&input.policy)?;
    let (app_access, app_allowed) = super::space_views::app_access_from_lex(&input.app_access)?;

    let created = create_space(
        &state.db,
        &NewSpace {
            uri: &space.uri,
            authority_did: &space.authority,
            space_type: &space.space_type,
            skey: &space.skey,
            policy: Some(policy),
            app_access: Some(app_access),
            app_allowed: app_allowed.as_deref(),
            managing_app: managing_app.as_deref(),
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, space = %space.uri, "failed to create space");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    })?;
    if !created {
        return Err(ApiError::new(
            ErrorCode::SpaceAlreadyExists,
            "space already exists",
        ));
    }
    Ok(Json(serde_json::json!({ "uri": space.uri })))
}
