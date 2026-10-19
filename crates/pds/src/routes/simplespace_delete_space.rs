// pattern: Imperative Shell

//! com.atproto.simplespace.deleteSpace — tombstone a space and delete the authority's own repo.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::oauth_scopes::{RepoAction, SpaceOp};
use crate::auth::space::authenticate_space_owner;
use crate::db::spaces::{delete_members, delete_notify_registrations, mark_space_deleted};
use crate::lexicon::LexiconInput;
use common::{ApiError, ErrorCode};

/// Most syncers one deletion notifies. The same bound the write fan-out carries; past it a
/// space's syncers are better served by the `SpaceDeleted` renewal error than by delivery.
const NOTIFY_DELETED_FANOUT_MAX: i64 = 100;

#[derive(Deserialize)]
pub struct DeleteSpaceInput {
    space: String,
}

/// POST /xrpc/com.atproto.simplespace.deleteSpace
///
/// The `spaces` row survives as a tombstone (so `getSpaceCredential` keeps answering
/// `SpaceDeleted`) with its config cleared; the member list, notify registrations and the
/// authority's own repo (and the writer set) go with it, and every service that was subscribed
/// is told to drop its copies. Other members' repos are left where they are — their records are
/// theirs — and simply stop being readable or writable (spec deletion semantics); their hosts
/// are deliberately not notified.
/// Idempotent: a space already deleted answers 200; one that never existed, `SpaceNotFound`.
pub async fn simplespace_delete_space(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<DeleteSpaceInput>,
) -> Result<impl IntoResponse, ApiError> {
    let space = super::space_views::parse_space(&input.space)?;
    authenticate_space_owner(
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

    // Captured before the transaction drops the registrations: the recipients of
    // `notifySpaceDeleted` are exactly who was subscribed at the moment of deletion.
    let subscribers = crate::db::space_notify::subscribers_for_space(
        &state.db,
        &space.uri,
        NOTIFY_DELETED_FANOUT_MAX,
    )
    .await
    .map_err(internal)?;

    let mut tx = state.db.begin().await.map_err(internal)?;
    mark_space_deleted(&mut *tx, &space.uri)
        .await
        .map_err(internal)?;
    delete_members(&mut *tx, &space.uri)
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

    // Best-effort, post-commit: tell the syncers to drop their copies. A syncer that misses this
    // still learns durably — its next credential renewal answers `SpaceDeleted` off the tombstone
    // this transaction just wrote.
    crate::space_notify::fan_out_space_deleted(&state, &space, subscribers);

    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
