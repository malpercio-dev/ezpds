// pattern: Imperative Shell

//! com.atproto.space.clearRecords — delete every record in the caller's repo in a space.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use custos_core::CoreState;
use serde::Deserialize;

use common::{ApiError, ErrorCode};
use custos_core::auth::oauth_scopes::{RepoAction, SpaceOp};
use custos_core::lexicon::LexiconInput;

#[derive(Deserialize)]
pub struct SpaceClearRecordsBody {
    space: String,
    repo: String,
}

/// POST /xrpc/com.atproto.space.clearRecords
///
/// Deletes every record in the caller's own repo in `space` as one commit: the repo stays, empty,
/// at a new rev, its oplog is cleared, and the commit is announced like any other write. In the
/// authority's own repo the published policy and member records are kept: they are the PDS's copy
/// of the space's configuration, so keeping them takes no grant. Every other collection the repo
/// holds needs a `delete` grant. Nothing to delete (no repo, or only kept records) commits
/// nothing.
pub async fn space_clear_records(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(body): LexiconInput<SpaceClearRecordsBody>,
) -> Result<impl IntoResponse, ApiError> {
    let space = crate::views::parse_space(&body.space)?;
    let user =
        crate::auth::space::authenticate_space_write(&state, &headers, &method, &uri, &body.repo)
            .await?;
    // Refused until the writer's DID document publishes its KEM key (ADR-0043).
    crate::kem_gate::require_kem_key_published(&state, &user.did).await?;

    let keep: &[&str] = if space.authority == user.did {
        &crate::policy::PUBLISHED_COLLECTIONS
    } else {
        &[]
    };
    let collections = crate::db::space_repos::list_collections(&state.db, &space.uri, &user.did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, "failed to list space collections");
            ApiError::new(ErrorCode::InternalError, "internal server error")
        })?;
    let granted: Vec<String> = collections
        .into_iter()
        .filter(|collection| !keep.contains(&collection.as_str()))
        .collect();
    for collection in &granted {
        crate::auth::space::require_space_grant(
            &state,
            &user,
            &space,
            SpaceOp::Record {
                action: RepoAction::Delete,
                collection,
            },
        )
        .await?;
    }

    crate::space_record_write::clear_space_records(&state, &space, &user.did, keep, &granted)
        .await?;
    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
