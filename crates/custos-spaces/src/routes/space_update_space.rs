// pattern: Imperative Shell

//! com.atproto.space.updateSpace — replace a space's policy.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use custos_core::CoreState;
use serde::Deserialize;

use crate::auth::space::authenticate_space_authority;
use crate::policy::SpacePolicy;
use common::{ApiError, ErrorCode};
use custos_core::auth::oauth_scopes::{RepoAction, SpaceOp};
use custos_core::lexicon::LexiconInput;

#[derive(Deserialize)]
pub struct UpdateSpaceInput {
    space: String,
    policy: serde_json::Value,
}

/// POST /xrpc/com.atproto.space.updateSpace
///
/// Replaces the policy wholesale. A policy of the same `$type` is a configuration change; a
/// different `$type` migrates the space and discards the previous policy's state — the member
/// list is deleted (switching back does not restore it) while the writer set is left alone.
/// The published policy record, and the member records when publishing them turns on or off,
/// follow in the same transaction. Identical to the reference.
pub async fn space_update_space(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<UpdateSpaceInput>,
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
    let next = SpacePolicy::from_lex(&input.policy)?;

    let internal = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space.uri, "failed to update space");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    };
    // The active check and the write share a transaction so a concurrent `deleteSpace` (itself
    // transactional) is ordered wholly before this — refusing the update — or after, never
    // between; a policy written onto a fresh tombstone could never be created again.
    let mut tx = state.db.begin().await.map_err(internal)?;
    let (_, current) = crate::views::load_active_space(&mut *tx, &space).await?;

    let mut ops = crate::policy::policy_record_ops(&mut tx, &space, &next).await?;
    // Before the member list is cleared: withdrawing a published list needs its entries.
    ops.extend(crate::policy::member_list_ops(&mut tx, &space, &current, &next).await?);
    crate::db::spaces::set_space_policy(&mut *tx, &space.uri, &next.to_json().to_string())
        .await
        .map_err(internal)?;
    if current.type_name() != next.type_name() {
        crate::db::spaces::delete_members(&mut *tx, &space.uri)
            .await
            .map_err(internal)?;
    }
    crate::policy::commit_with_published(&state, tx, &space, &ops).await?;
    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
