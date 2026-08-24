// pattern: Imperative Shell

//! com.atproto.simplespace.updateSpace — replace a space's policy and/or appAccess.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::oauth_scopes::{RepoAction, SpaceOp};
use crate::auth::space::authenticate_space_owner;
use crate::db::spaces::set_space_config;
use crate::lexicon::LexiconInput;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSpaceInput {
    space: String,
    policy: Option<serde_json::Value>,
    app_access: Option<serde_json::Value>,
}

/// POST /xrpc/com.atproto.simplespace.updateSpace
///
/// Each supplied union replaces its axis wholesale (a new `policy` also resets `managingApp`);
/// an omitted one is left alone. Unimplemented union members are refused before the row is
/// touched, so a space can never end up carrying a config this host does not enforce.
pub async fn simplespace_update_space(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<UpdateSpaceInput>,
) -> Result<impl IntoResponse, ApiError> {
    let space = super::space_views::parse_space(&input.space)?;
    authenticate_space_owner(
        &state,
        &headers,
        &method,
        &uri,
        &space,
        SpaceOp::Manage(RepoAction::Update),
    )
    .await?;

    let policy = input
        .policy
        .as_ref()
        .map(super::space_views::policy_from_lex)
        .transpose()?;
    let app_access = input
        .app_access
        .as_ref()
        .map(super::space_views::app_access_from_lex)
        .transpose()?;

    let internal = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space.uri, "failed to update space");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    };
    // The active check and the write share a transaction so a concurrent `deleteSpace`
    // (itself transactional) is ordered wholly before this — refusing the update — or after,
    // never between; a config written onto a fresh tombstone could never be created again.
    let mut tx = state.db.begin().await.map_err(internal)?;
    let row = super::space_views::load_active_simplespace(&mut *tx, &space).await?;
    let (policy, managing_app) = match policy {
        Some((policy, managing_app)) => (policy.to_string(), managing_app),
        None => (
            row.policy.clone().unwrap_or_default(),
            row.managing_app.clone(),
        ),
    };
    let app_access = app_access
        .map(str::to_string)
        .unwrap_or_else(|| row.app_access.clone().unwrap_or_default());

    set_space_config(
        &mut *tx,
        &space.uri,
        &policy,
        &app_access,
        managing_app.as_deref(),
    )
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
