// pattern: Imperative Shell

//! com.atproto.space.getLatestCommit — mint the current signed commit for a permissioned repo.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::lexicon::LexiconParams;
use common::ApiError;

#[derive(Deserialize)]
pub struct SpaceGetLatestCommitParams {
    space: String,
    repo: String,
}

/// GET /xrpc/com.atproto.space.getLatestCommit
///
/// The commit is minted per serving (`space_views::sign_current_commit`) — never a cached
/// artifact. `RepoNotFound` covers the member who has never written, too: with no rev and no
/// state there is no commit to sign, and the lexicon says so explicitly.
pub async fn space_get_latest_commit(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceGetLatestCommitParams>,
) -> Result<impl IntoResponse, ApiError> {
    let space = super::space_views::parse_space(&params.space)?;
    crate::auth::space::authenticate_space_read(
        &state,
        &headers,
        &method,
        &uri,
        &space,
        &params.repo,
    )
    .await?;

    let repo = super::space_views::load_repo(&state, &space.uri, &params.repo).await?;
    let commit =
        super::space_views::sign_current_commit(&state, &space, &params.repo, &repo).await?;

    Ok((
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "commit": super::space_views::commit_json(&commit),
        })),
    ))
}
