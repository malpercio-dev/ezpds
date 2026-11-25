// pattern: Imperative Shell

//! com.atproto.space.removeWriter — take an account out of a space's writer set.

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
pub struct RemoveWriterInput {
    space: String,
    repo: Did,
}

/// POST /xrpc/com.atproto.space.removeWriter
///
/// `manage=update`, authority only, under every policy. The removal takes a new `spaceRev` and
/// goes to the registered syncers as a `repoRemoved`. Does nothing for an account that isn't in
/// the writer set. The account is not barred: its next authorized write puts it back.
pub async fn space_remove_writer(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<RemoveWriterInput>,
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
        tracing::error!(error = %e, space = %space.uri, "failed to remove writer");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    };
    let mut tx = state.db.begin().await.map_err(internal)?;
    crate::views::load_active_space(&mut *tx, &space).await?;
    let removed = crate::db::space_notify::remove_writer(&mut tx, &space.uri, input.repo.as_str())
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    if let Some(revs) = removed {
        drop(crate::space_notify::forward_removed(
            &state,
            &space,
            input.repo.as_str(),
            revs,
        ));
    }
    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
