// pattern: Imperative Shell

//! com.atproto.space.listWriters — the space host's writer set.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use custos_core::CoreState;
use serde::Deserialize;

use common::{ApiError, ErrorCode};
use custos_core::lexicon::LexiconParams;

#[derive(Deserialize)]
pub struct SpaceListWritersParams {
    space: String,
    limit: Option<i64>,
    cursor: Option<String>,
}

/// GET /xrpc/com.atproto.space.listWriters
///
/// The sync boundary, never an access-control list: entries are accounts that have *written*
/// into the space, so a member who has only ever read is absent and a reader is never enumerable
/// from here. Each entry is the latest update to its repo: a `repoWrite` with the `repoRev`/`data`
/// the authority was last told (for a repo hosted elsewhere they may lag, and that repo's host is
/// the source of truth), or a `repoRemoved` once the repo has been taken out of the set. Ordered
/// by `spaceRev`, which is also the cursor; `prevSpaceRev` is never set. A taken-down writer is
/// listed like any other.
///
/// Answered only for a space this host is the authority for. A space whose row carries no
/// policy is one this host merely keeps repos in, and its authority is the one to
/// ask, so it reads as `SpaceNotFound` — the same reply an unknown space gets. A taken-down or
/// deactivated authority answers `RepoTakendown` / `RepoDeactivated`.
pub async fn space_list_writers(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceListWritersParams>,
) -> Result<impl IntoResponse, ApiError> {
    let space = crate::views::parse_space(&params.space)?;
    crate::auth::space::authenticate_space_access(&state, &headers, &method, &uri, &space).await?;
    // The authority's own status gates the writer listing, whoever is asking.
    crate::auth::space::require_active_space_host(&state, &space).await?;

    crate::views::require_local_authority(&state, &space).await?;

    let internal = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space.uri, "failed to list space writers");
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

    // The cursor is the last `spaceRev` seen even on a short page, so a syncer can resume from it
    // later and pick up only what changed.
    let cursor = writers.last().map(|w| w.space_rev.clone());
    let repos: Vec<_> = writers
        .into_iter()
        .map(|w| {
            if w.removed {
                serde_json::json!({
                    "$type": "com.atproto.space.defs#repoRemoved",
                    "repo": w.repo_did,
                    "spaceRev": w.space_rev,
                })
            } else {
                serde_json::json!({
                    "$type": "com.atproto.space.defs#repoWrite",
                    "repo": w.repo_did,
                    "repoRev": w.rev,
                    "data": crate::views::lex_bytes(&w.hash),
                    "spaceRev": w.space_rev,
                })
            }
        })
        .collect();

    let mut body = serde_json::json!({ "repos": repos });
    if let Some(cursor) = cursor {
        body["cursor"] = serde_json::Value::String(cursor);
    }
    Ok((StatusCode::OK, axum::Json(body)))
}
