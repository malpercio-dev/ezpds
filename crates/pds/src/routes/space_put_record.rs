// pattern: Imperative Shell

//! com.atproto.space.putRecord — create or update a record in a permissioned space repo.

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
pub struct SpacePutRecordBody {
    space: String,
    repo: String,
    collection: String,
    rkey: String,
    record: serde_json::Value,
    #[serde(default)]
    validate: Option<bool>,
}

/// POST /xrpc/com.atproto.space.putRecord
///
/// An upsert, so it is the one write whose required `space:` action is not known from the method
/// alone: the record's presence decides whether this is a `create` or an `update`, and an app
/// granted only one of the two must not be asked for both. The presence read therefore happens
/// before the scope check.
pub async fn space_put_record(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(body): LexiconInput<SpacePutRecordBody>,
) -> Result<impl IntoResponse, ApiError> {
    let space = super::space_views::parse_space(&body.space)?;
    let user =
        crate::auth::space::authenticate_space_write(&state, &headers, &method, &uri, &body.repo)
            .await?;

    // Read before the scope check, unlike the reference, which reads inside the write
    // transaction. The gap only ever mis-picks `update` for a record concurrently deleted (or
    // `create` for one concurrently written) — in either case a record the caller was entitled
    // to overwrite a moment earlier, so the write it authorizes is one it would have authorized
    // anyway. The commit itself stays atomic; only this labelling is advisory.
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
        common::ApiError::new(
            common::ErrorCode::InternalError,
            "failed to write space record",
        )
    })?
    .is_some();

    crate::auth::space::require_space_grant(
        &state,
        &user,
        &space,
        SpaceOp::Record {
            action: if exists {
                RepoAction::Update
            } else {
                RepoAction::Create
            },
            collection: &body.collection,
        },
    )
    .await?;

    let validation_status = super::space_views::validate_record(
        &body.collection,
        &body.rkey,
        &body.record,
        body.validate,
    )?;

    let outcome = crate::space_record_write::apply_space_writes(
        &state,
        &space,
        &user.did,
        &[SpaceWriteOp {
            action: SpaceWriteAction::Put,
            collection: body.collection.clone(),
            rkey: body.rkey.clone(),
            value: Some(body.record),
        }],
        crate::space_record_write::SpaceWriteAdmission::Active,
    )
    .await?;

    Ok((
        StatusCode::OK,
        axum::Json(super::space_views::write_result(
            &space,
            &user.did,
            &body.collection,
            &body.rkey,
            &outcome,
            validation_status,
        )?),
    ))
}
