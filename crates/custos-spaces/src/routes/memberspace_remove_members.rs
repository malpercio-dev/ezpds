// pattern: Imperative Shell

//! com.atproto.memberspace.removeMembers — remove members from a memberspace in one commit.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use custos_core::CoreState;
use serde::Deserialize;

use crate::auth::space::authenticate_space_authority;
use common::{ApiError, Did, ErrorCode};
use custos_core::auth::oauth_scopes::{RepoAction, SpaceOp};
use custos_core::lexicon::LexiconInput;

#[derive(Deserialize)]
pub struct RemoveMembersInput {
    space: String,
    /// At most 100, bounded by the lexicon layer.
    dids: Vec<Did>,
}

/// POST /xrpc/com.atproto.memberspace.removeMembers
///
/// `manage=update`, authority only, memberspace only (`PolicyMismatch` otherwise). A DID that
/// is not a member is ignored. A removed member leaves the writer set and its published member
/// record is withdrawn, both in the same transaction; each writer removal then goes to the
/// registered syncers as a `repoRemoved`.
pub async fn memberspace_remove_members(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<RemoveMembersInput>,
) -> Result<impl IntoResponse, ApiError> {
    let space = crate::views::parse_space(&input.space)?;
    authenticate_space_authority(
        &state,
        &headers,
        &method,
        &uri,
        &space,
        SpaceOp::Manage(RepoAction::Update),
    )
    .await?;

    let internal = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space.uri, "failed to remove members");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    };
    let mut tx = state.db.begin().await.map_err(internal)?;
    let (_, policy) = crate::views::load_active_space(&mut *tx, &space).await?;
    policy.require_memberspace()?;
    let mut ops = Vec::new();
    let mut removed_writers = Vec::new();
    for did in &input.dids {
        if !crate::db::spaces::remove_member(&mut *tx, &space.uri, did.as_str())
            .await
            .map_err(internal)?
        {
            continue;
        }
        if let Some(revs) =
            crate::db::space_notify::remove_writer(&mut tx, &space.uri, did.as_str())
                .await
                .map_err(internal)?
        {
            removed_writers.push((did, revs));
        }
        ops.extend(
            crate::policy::member_record_ops(&mut tx, &space, &policy, did.as_str(), None).await?,
        );
    }
    crate::policy::commit_with_published(&state, tx, &space, &ops).await?;
    for (did, revs) in removed_writers {
        drop(crate::space_notify::forward_removed(
            &state,
            &space,
            did.as_str(),
            revs,
        ));
    }
    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
