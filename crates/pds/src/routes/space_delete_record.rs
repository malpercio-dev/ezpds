// pattern: Imperative Shell

//! com.atproto.space.deleteRecord — remove a record from a permissioned space repo.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::oauth_scopes::{RepoAction, SpaceOp};
use crate::lexicon::LexiconInput;
use crate::space_record_write::{SpaceWriteAction, SpaceWriteOp};
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
pub struct SpaceDeleteRecordBody {
    space: String,
    repo: String,
    collection: String,
    rkey: String,
}

/// POST /xrpc/com.atproto.space.deleteRecord
///
/// Succeeds whether or not the record was present, as the lexicon promises. That idempotence is
/// this route's, not the store's: an absent record means there is nothing to commit, so no
/// commit is made — no rev is burned and no oplog entry is appended for a write that changed
/// nothing. The store keeps the strict precondition that `applyWrites` needs to report
/// `RecordNotFound`.
pub async fn space_delete_record(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(body): LexiconInput<SpaceDeleteRecordBody>,
) -> Result<impl IntoResponse, ApiError> {
    let space = super::space_views::parse_space(&body.space)?;
    let user =
        crate::auth::space::authenticate_space_write(&state, &headers, &method, &uri, &body.repo)?;
    crate::auth::space::require_space_grant(
        &state,
        &user,
        &space,
        SpaceOp::Record {
            action: RepoAction::Delete,
            collection: &body.collection,
        },
    )
    .await?;

    let exists = crate::db::space_repos::get_record(
        &state.db,
        &space.uri,
        &user.did,
        &body.collection,
        &body.rkey,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, space = %space.uri, "failed to read space record");
        ApiError::new(ErrorCode::InternalError, "failed to delete space record")
    })?
    .is_some();

    if exists {
        crate::space_record_write::apply_space_writes(
            &state,
            &space,
            &user.did,
            &[SpaceWriteOp {
                action: SpaceWriteAction::Delete,
                collection: body.collection,
                rkey: body.rkey,
                value: None,
            }],
        )
        .await?;
    }

    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
