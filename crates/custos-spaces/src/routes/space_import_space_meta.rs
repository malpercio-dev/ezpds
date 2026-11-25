// pattern: Imperative Shell

//! com.atproto.space.importSpaceMeta — land an `atproto-space-meta` archive from
//! `exportSpaceMeta` on the old host, before the authority's own repo follows with `importRepo`.
//! Semantics and the deliberate divergences are `crate::space_migration`'s.

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode, Uri};
use axum::response::IntoResponse;
use custos_core::CoreState;

use common::{ApiError, ErrorCode};
use custos_core::auth::oauth_scopes::{RepoAction, SpaceOp};

/// POST /xrpc/com.atproto.space.importSpaceMeta
pub async fn space_import_space_meta(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    request: Request<Body>,
) -> Result<impl IntoResponse, ApiError> {
    let user =
        crate::auth::space::authenticate_space_caller(&state, request.headers(), &method, &uri)
            .await?;
    user.require_not_agent()?;
    crate::space_migration::require_deactivated(&state.db, &user.did).await?;

    let bytes = crate::space_migration::read_import_body(request).await?;
    let archive = crate::space_migration::read_space_meta(&bytes)?;

    // Importing both creates the space on this host and sets its configuration. Grants first,
    // authority second, as `authenticate_space_authority` orders them.
    let space = &archive.space;
    for action in [RepoAction::Create, RepoAction::Update] {
        crate::auth::space::require_space_grant(&state, &user, space, SpaceOp::Manage(action))
            .await?;
    }
    if user.did.as_str() != space.authority {
        return Err(ApiError::new(
            ErrorCode::NotAuthorized,
            "Not the space authority",
        ));
    }

    crate::space_migration::import_space_meta(&state, &user.did, &archive).await?;
    tracing::info!(
        did = %user.did,
        space = %space.uri,
        members = archive.members.len(),
        writers = archive.writers.len(),
        "imported space meta"
    );
    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
