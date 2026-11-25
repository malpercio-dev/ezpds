// pattern: Imperative Shell

//! com.atproto.space.getLatestCommit — the current commit of a space repo.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use custos_core::CoreState;
use serde::Deserialize;

use common::{ApiError, Did};
use crypto::http_signature::MacProfile;
use custos_core::lexicon::LexiconParams;

#[derive(Deserialize)]
pub struct SpaceGetLatestCommitParams {
    space: String,
    repo: Did,
}

/// GET /xrpc/com.atproto.space.getLatestCommit
///
/// The commit is unsigned; a requested MAC authenticates it (`space_mac`). `RepoNotFound` covers
/// the member who has never written, too: with no rev and no state there is no commit.
pub async fn space_get_latest_commit(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceGetLatestCommitParams>,
) -> Result<Response, ApiError> {
    let space = crate::views::parse_space(&params.space)?;
    let reader = crate::auth::space::authenticate_space_read(
        &state,
        &headers,
        &method,
        &uri,
        &space,
        &params.repo,
    )
    .await?;
    let mac =
        crate::space_mac::mac_grant(&state, &headers, &reader, &params.repo, MacProfile::Commit)
            .await?;

    let repo = crate::views::load_repo(&state, &space.uri, &params.repo).await?;
    let commit = crate::views::current_commit(&space, &params.repo, &repo)?;

    let response = (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "commit": commit.to_json() })),
    )
        .into_response();
    crate::space_mac::with_commit_mac(response, &commit, mac.as_ref())
}
