// pattern: Imperative Shell

//! com.atproto.space.createSpace — create a space with the caller as its authority.

use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::response::Json;
use custos_core::CoreState;
use serde::Deserialize;

use crate::auth::space::{authenticate_space_caller, require_space_grant};
use crate::db::spaces::{create_space, NewSpace};
use crate::policy::SpacePolicy;
use common::{ApiError, ErrorCode};
use custos_core::auth::oauth_scopes::{RepoAction, SpaceOp};
use custos_core::lexicon::LexiconInput;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSpaceInput {
    /// The space type NSID.
    space_type: String,
    /// Optional space key (record-key syntax); a TID is generated when absent.
    skey: Option<String>,
    /// The space policy union, normalized by `SpacePolicy::from_lex`.
    policy: serde_json::Value,
}

/// POST /xrpc/com.atproto.space.createSpace
///
/// The space URI is built from the authenticated DID, so the caller is the authority by
/// construction; what the `manage=create` grant is matched against is that URI. An unsupported
/// policy is refused (`UnsupportedPolicy`) before anything is stored, and a policy that asks to
/// be published is written to the authority's repo in the same transaction as the space.
pub async fn space_create_space(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<CreateSpaceInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = authenticate_space_caller(&state, &headers, &method, &uri).await?;
    let skey = input.skey.unwrap_or_else(repo_engine::generate_tid);
    let space = crate::views::parse_space(&custos_core::space_uri::space_uri(
        &user.did,
        &input.space_type,
        &skey,
    ))?;
    require_space_grant(&state, &user, &space, SpaceOp::Manage(RepoAction::Create)).await?;
    let policy = SpacePolicy::from_lex(&input.policy)?;

    let internal = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space.uri, "failed to create space");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    };
    let mut tx = state.db.begin().await.map_err(internal)?;
    let created = create_space(
        &mut *tx,
        &NewSpace {
            uri: &space.uri,
            authority_did: &space.authority,
            space_type: &space.space_type,
            skey: &space.skey,
        },
        &policy.to_json().to_string(),
    )
    .await
    .map_err(internal)?;
    if !created {
        return Err(ApiError::new(
            ErrorCode::SpaceAlreadyExists,
            "Space already exists",
        ));
    }
    let ops = crate::policy::policy_record_ops(&mut tx, &space, &policy).await?;
    crate::policy::commit_with_published(&state, tx, &space, &ops).await?;
    Ok(Json(serde_json::json!({ "space": space.uri })))
}
