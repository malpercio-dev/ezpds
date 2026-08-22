// pattern: Imperative Shell

//! com.atproto.space.getLatestCommit — mint the current signed commit for a permissioned repo.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::lexicon::LexiconParams;
use common::{ApiError, ErrorCode};
use crypto::{LtHash, SpaceCommitCtx};

#[derive(Deserialize)]
pub struct SpaceGetLatestCommitParams {
    space: String,
    repo: String,
}

/// GET /xrpc/com.atproto.space.getLatestCommit
///
/// A commit is **minted per serving**, never stored: fresh `ikm`, a fresh signature over the
/// `(space, author, rev, ikm)` context, and a fresh MAC binding the repo hash to that context.
/// The signature deliberately does not cover the hash, so a leaked commit proves only that the
/// user signed a context — anyone holding the `ikm` in it can forge a matching MAC for any hash.
/// That deniability is the whole point, and it is why this cannot be a cached artifact.
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

    // `RepoNotFound` covers the member who has never written, too: with no rev and no state
    // there is no commit to sign, and the lexicon says so explicitly.
    let repo = crate::db::space_repos::get_repo(&state.db, &space.uri, &params.repo)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, "failed to load space repo");
            internal_error()
        })?
        .ok_or_else(|| crate::auth::space::repo_not_found(&params.repo))?;

    let hash = LtHash::from_state(&repo.lthash_state)
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, did = %params.repo, "stored LtHash state is malformed");
            internal_error()
        })?
        .digest();

    let master_key: &[u8; 32] = state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|s| &*s.0)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::ServiceUnavailable,
                "signing key master key not configured",
            )
        })?;
    let signing_key =
        crate::auth::signing_key::load_repo_signing_key(&state.db, &params.repo, master_key)
            .await?;

    let commit = crypto::sign_space_commit(
        &SpaceCommitCtx {
            space: &space.uri,
            author: &params.repo,
            rev: &repo.rev,
        },
        hash,
        &signing_key,
    )
    .map_err(|e| {
        tracing::error!(error = %e, space = %space.uri, did = %params.repo, "failed to sign space commit");
        internal_error()
    })?;

    Ok((
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "commit": {
                "ver": commit.ver,
                "hash": super::space_views::lex_bytes(&commit.hash),
                "ikm": super::space_views::lex_bytes(&commit.ikm),
                "sig": super::space_views::lex_bytes(&commit.sig),
                "mac": super::space_views::lex_bytes(&commit.mac),
                "rev": commit.rev,
            }
        })),
    ))
}

fn internal_error() -> ApiError {
    ApiError::new(ErrorCode::InternalError, "failed to read space commit")
}
