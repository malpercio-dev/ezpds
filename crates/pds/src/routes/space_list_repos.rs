// pattern: Imperative Shell

//! com.atproto.space.listRepos — the space host's writer set.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::lexicon::LexiconParams;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
pub struct SpaceListReposParams {
    space: String,
    limit: Option<i64>,
    cursor: Option<String>,
}

/// GET /xrpc/com.atproto.space.listRepos
///
/// The sync boundary, never an access-control list: rows are accounts that have *written* into
/// the space, so a member who has only ever read is absent and a reader is never enumerable from
/// here. Each row's `rev`/`hash` are what the authority was last told — for a repo hosted
/// elsewhere they may lag, and that repo's host is the source of truth.
///
/// Answered only for a space this host is the authority for. A space whose row carries no
/// simplespace config is one this host merely keeps repos in, and its authority is the one to
/// ask, so it reads as `SpaceNotFound` — the same reply an unknown space gets.
pub async fn space_list_repos(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceListReposParams>,
) -> Result<impl IntoResponse, ApiError> {
    let space = super::space_views::parse_space(&params.space)?;
    crate::auth::space::authenticate_space_access(&state, &headers, &method, &uri, &space).await?;

    super::space_views::require_local_authority(&state, &space).await?;

    let internal = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space.uri, "failed to list space repos");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    };
    let limit = params.limit.unwrap_or(100).clamp(1, 1000);
    let writers = crate::db::space_notify::list_writers(
        &state.db,
        &space.uri,
        params.cursor.as_deref(),
        limit,
    )
    .await
    .map_err(internal)?;

    // A full page may have more behind it; a short one has reached the end.
    let cursor = (writers.len() as i64 == limit)
        .then(|| writers.last().map(|w| w.repo_did.clone()))
        .flatten();
    let repos: Vec<_> = writers
        .into_iter()
        .map(|w| {
            serde_json::json!({
                "did": w.repo_did,
                "rev": w.rev,
                "hash": super::space_views::lex_bytes(&w.hash),
            })
        })
        .collect();

    let mut body = serde_json::json!({ "repos": repos });
    if let Some(cursor) = cursor {
        body["cursor"] = serde_json::Value::String(cursor);
    }
    Ok((StatusCode::OK, axum::Json(body)))
}
