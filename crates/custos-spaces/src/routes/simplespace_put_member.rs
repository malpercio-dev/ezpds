// pattern: Imperative Shell

//! com.atproto.simplespace.putMember — add a DID to a space's member list, or replace its
//! read and write access.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::auth::oauth_scopes::{RepoAction, SpaceOp};
use crate::auth::space::authenticate_space_owner;
use crate::lexicon::LexiconInput;
use crate::SpacesState;
use common::ApiError;

#[derive(Deserialize)]
pub struct PutMemberInput {
    space: String,
    did: String,
    read: bool,
    write: bool,
}

/// POST /xrpc/com.atproto.simplespace.putMember
///
/// Membership management is a space-level `manage=update` operation. The member list is
/// host-internal state consulted under the `member-list` read and write policies (the `read`
/// bit at credential-mint time, the `write` bit when a write notification arrives); the member
/// is not notified (their PDS materializes a repo on first write). Idempotent.
pub async fn simplespace_put_member(
    State(state): State<SpacesState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<PutMemberInput>,
) -> Result<impl IntoResponse, ApiError> {
    let space = crate::views::parse_space(&input.space)?;
    authenticate_space_owner(
        &state,
        &headers,
        &method,
        &uri,
        &space,
        SpaceOp::Manage(RepoAction::Update),
    )
    .await?;
    crate::views::write_membership(
        &state,
        &space,
        &input.did,
        crate::views::MembershipAction::Put {
            read: input.read,
            write: input.write,
        },
    )
    .await?;
    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
