// pattern: Imperative Shell

//! com.atproto.space.deleteSpace — tombstone a space and delete the authority's own repo.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use custos_core::CoreState;
use serde::Deserialize;

use crate::auth::space::authenticate_space_authority;
use crate::db::spaces::{delete_members, delete_notify_registrations, mark_space_deleted};
use common::{ApiError, ErrorCode};
use custos_core::auth::oauth_scopes::{RepoAction, SpaceOp};
use custos_core::lexicon::LexiconInput;

#[derive(Deserialize)]
pub struct DeleteSpaceInput {
    space: String,
}

/// POST /xrpc/com.atproto.space.deleteSpace
///
/// The `spaces` row survives as a tombstone (so `authorizeSpaceSync` keeps answering
/// `SpaceDeleted`) with its policy cleared; the member list, notify registrations and the
/// authority's own repo (and the writer set) go with it, and every syncer that was registered,
/// lapsed or not, is owed a `spaceDeleted` notice: queued in the same transaction and retried
/// for 72 h (`space_notify_retry`), with no cap on how many. Other members' repos are left where
/// they are — their records are theirs — and simply stop being readable or writable (spec
/// deletion semantics); their hosts are deliberately not notified.
/// Idempotent: a space already deleted answers 200; one that never existed, `SpaceNotFound`.
pub async fn space_delete_space(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<DeleteSpaceInput>,
) -> Result<impl IntoResponse, ApiError> {
    let space = crate::views::parse_space(&input.space)?;
    authenticate_space_authority(
        &state,
        &headers,
        &method,
        &uri,
        &space,
        SpaceOp::Manage(RepoAction::Delete),
    )
    .await?;

    let internal = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space.uri, "failed to delete space");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    };
    let row = crate::db::spaces::get_space(&state.db, &space.uri)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::new(ErrorCode::SpaceNotFound, "space not found"))?;
    if row.deleted_at.is_some() {
        return Ok((StatusCode::OK, axum::Json(serde_json::json!({}))));
    }

    let mut tx = state.db.begin().await.map_err(internal)?;
    mark_space_deleted(&mut *tx, &space.uri)
        .await
        .map_err(internal)?;
    delete_members(&mut *tx, &space.uri)
        .await
        .map_err(internal)?;
    // Before the registrations it reads are dropped.
    crate::space_notify_retry::queue_space_deleted(&mut tx, &space.uri)
        .await
        .map_err(internal)?;
    delete_notify_registrations(&mut *tx, &space.uri)
        .await
        .map_err(internal)?;
    crate::db::space_notify::delete_writers(&mut *tx, &space.uri)
        .await
        .map_err(internal)?;
    crate::db::space_repos::delete_repo(&mut tx, &space.uri, &space.authority)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;

    // The first attempt, post-commit. A crash before it loses nothing: the sweep finds the rows.
    drop(crate::space_notify_retry::deliver_untried(
        &state, &space.uri,
    ));

    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
