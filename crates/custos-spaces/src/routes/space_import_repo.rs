// pattern: Imperative Shell

//! com.atproto.space.importRepo — land an `atproto-space-repo` archive from `getRepo` on the old
//! host as the caller's repo in the space here. Semantics and the deliberate divergences
//! (deactivated account, no KEM check) are `crate::space_migration`'s.

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode, Uri};
use axum::response::IntoResponse;
use custos_core::CoreState;

use common::{ApiError, ErrorCode};
use custos_core::auth::oauth_scopes::{RepoAction, SpaceOp};

/// POST /xrpc/com.atproto.space.importRepo
pub async fn space_import_repo(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    request: Request<Body>,
) -> Result<impl IntoResponse, ApiError> {
    let user =
        crate::auth::space::authenticate_space_caller(&state, request.headers(), &method, &uri)
            .await?;
    // Migration is an account operation, never something an agent performs on the owner's behalf.
    user.require_not_agent()?;
    // Checked before buffering the body, so an active account is refused cheaply; the import
    // checks again inside its transaction.
    crate::space_migration::require_deactivated(&state.db, &user.did).await?;

    let bytes = crate::space_migration::read_import_body(request).await?;
    let archive = crate::space_migration::read_repo_star(&bytes)?;
    if archive.repo != user.did {
        return Err(ApiError::new(
            ErrorCode::RepoMismatch,
            "Repo does not match the authenticated account",
        ));
    }

    // An import replaces the account's whole repo in the space, so it takes full access to the
    // space rather than grants for the collections it happens to hold.
    let space = &archive.space;
    crate::auth::space::require_space_grant(&state, &user, space, SpaceOp::Read).await?;
    for action in [RepoAction::Create, RepoAction::Update, RepoAction::Delete] {
        let op = SpaceOp::Record {
            action,
            collection: "*",
        };
        crate::auth::space::require_space_grant(&state, &user, space, op).await?;
    }

    let rev = crate::space_record_write::import_space_repo(&state, &user.did, &archive).await?;
    tracing::info!(
        did = %user.did,
        space = %space.uri,
        %rev,
        records = archive.records.len(),
        "imported space repo"
    );
    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
