// pattern: Imperative Shell

//! com.atproto.simplespace.addMember — add a DID to a space's member list.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::oauth_scopes::{RepoAction, SpaceOp};
use crate::auth::space::authenticate_space_owner;
use crate::lexicon::LexiconInput;
use common::ApiError;

#[derive(Deserialize)]
pub struct AddMemberInput {
    space: String,
    did: String,
}

/// POST /xrpc/com.atproto.simplespace.addMember
///
/// Membership management is a space-level `manage=update` operation. The member list is
/// host-internal state consulted at credential-mint time under the `member-list` policy; the
/// member is not notified (their PDS materializes a repo on first write). Idempotent.
pub async fn simplespace_add_member(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<AddMemberInput>,
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
    super::space_views::write_membership(
        &state,
        &space,
        &input.did,
        super::space_views::MembershipAction::Add,
    )
    .await?;
    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
