// pattern: Imperative Shell

//! com.atproto.memberspace.putMembers — add members to a memberspace, or replace their access,
//! in one commit.

use std::collections::BTreeMap;

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use custos_core::CoreState;
use serde::Deserialize;

use crate::auth::space::authenticate_space_authority;
use crate::policy::Access;
use common::{ApiError, Did, ErrorCode};
use custos_core::auth::oauth_scopes::{RepoAction, SpaceOp};
use custos_core::lexicon::LexiconInput;

#[derive(Deserialize)]
pub struct PutMembersInput {
    space: String,
    /// At most 100, bounded by the lexicon layer.
    members: Vec<MemberInput>,
}

#[derive(Deserialize)]
struct MemberInput {
    did: Did,
    read: bool,
    write: bool,
}

/// POST /xrpc/com.atproto.memberspace.putMembers
///
/// A space-level `manage=update` operation, authority only, on a memberspace only
/// (`PolicyMismatch` otherwise). A DID listed twice takes its last entry. Published member
/// records follow in the same transaction, and so does each `write: false` member's removal from
/// the writer set, which then goes to the registered syncers as a `repoRemoved`. The member is not notified (their PDS materializes a
/// repo on first write). Idempotent.
pub async fn memberspace_put_members(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<PutMembersInput>,
) -> Result<impl IntoResponse, ApiError> {
    let space = crate::views::parse_space(&input.space)?;
    authenticate_space_authority(
        &state,
        &headers,
        &method,
        &uri,
        &space,
        SpaceOp::Manage(RepoAction::Update),
    )
    .await?;
    let members: BTreeMap<Did, Access> = input
        .members
        .into_iter()
        .map(|m| {
            (
                m.did,
                Access {
                    read: m.read,
                    write: m.write,
                },
            )
        })
        .collect();

    let internal = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space.uri, "failed to put members");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    };
    let mut tx = state.db.begin().await.map_err(internal)?;
    let (_, policy) = crate::views::load_active_space(&mut *tx, &space).await?;
    policy.require_memberspace()?;
    let mut ops = Vec::new();
    let mut removed_writers = Vec::new();
    for (did, access) in members {
        crate::db::spaces::put_member(
            &mut *tx,
            &space.uri,
            did.as_str(),
            access.read,
            access.write,
        )
        .await
        .map_err(internal)?;
        if !access.write {
            if let Some(revs) =
                crate::db::space_notify::remove_writer(&mut tx, &space.uri, did.as_str())
                    .await
                    .map_err(internal)?
            {
                removed_writers.push((did.clone(), revs));
            }
        }
        ops.extend(
            crate::policy::member_record_ops(&mut tx, &space, &policy, did.as_str(), Some(access))
                .await?,
        );
    }
    crate::policy::commit_with_published(&state, tx, &space, &ops).await?;
    for (did, revs) in removed_writers {
        drop(crate::space_notify::forward_removed(
            &state,
            &space,
            did.as_str(),
            revs,
        ));
    }
    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
