// pattern: Imperative Shell

//! com.atproto.space.createRecord — create a record in a permissioned space repo.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::oauth_scopes::{RepoAction, SpaceOp};
use crate::lexicon::LexiconInput;
use crate::space_record_write::{SpaceWriteAction, SpaceWriteOp};
use common::ApiError;

#[derive(Deserialize)]
pub struct SpaceCreateRecordBody {
    /// The space to write into, as a canonical space ref. The lexicon's `space-ref` format has
    /// already established the shape by the time this deserializes.
    space: String,
    /// The repo to write to. A DID, never a handle: a space's membership is keyed on DIDs.
    repo: String,
    collection: String,
    /// Optional record key; a TID is generated when absent.
    rkey: Option<String>,
    record: serde_json::Value,
    #[serde(default)]
    validate: Option<bool>,
}

/// POST /xrpc/com.atproto.space.createRecord
pub async fn space_create_record(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(body): LexiconInput<SpaceCreateRecordBody>,
) -> Result<impl IntoResponse, ApiError> {
    let space = super::space_views::parse_space(&body.space)?;
    let user =
        crate::auth::space::authenticate_space_write(&state, &headers, &method, &uri, &body.repo)?;
    crate::auth::space::require_space_grant(
        &state,
        &user,
        &space,
        SpaceOp::Record {
            action: RepoAction::Create,
            collection: &body.collection,
        },
    )
    .await?;

    // Treat an empty rkey as absent, as the public createRecord does.
    let rkey = body
        .rkey
        .filter(|r| !r.is_empty())
        .unwrap_or_else(repo_engine::generate_tid);
    let validation_status =
        super::space_views::validate_record(&body.collection, &rkey, &body.record, body.validate)?;

    let outcome = crate::space_record_write::apply_space_writes(
        &state,
        &space,
        &user.did,
        &[SpaceWriteOp {
            action: SpaceWriteAction::Create,
            collection: body.collection.clone(),
            rkey: rkey.clone(),
            value: Some(body.record),
        }],
    )
    .await?;

    Ok((
        StatusCode::OK,
        axum::Json(super::space_views::write_result(
            &space,
            &user.did,
            &body.collection,
            &rkey,
            &outcome,
            validation_status,
        )?),
    ))
}
