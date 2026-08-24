// pattern: Imperative Shell

//! com.atproto.space.listRepoOps — page a permissioned repo's oplog, the primary incremental
//! sync mechanism.
//!
//! The oplog is a transport optimization with no history guarantee: entries are compactable
//! and droppable (`space_oplog_sweep.rs`), so a `since` that predates the retained window
//! simply yields the retained suffix — the syncer's own LtHash fold failing to match the head
//! commit is its signal to heal via `getRepo`, not an error this route can raise.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::lexicon::LexiconParams;
use common::{ApiError, ErrorCode};

const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 1000;

#[derive(Deserialize)]
pub struct SpaceListRepoOpsParams {
    space: String,
    repo: String,
    /// The caller's own sync position: only ops strictly after this rev.
    since: Option<String>,
    limit: Option<i64>,
    /// Opaque continuation from a previous page; applied alongside `since` (it is always at
    /// least as far along, so the conjunction is the cursor's position).
    cursor: Option<String>,
    #[serde(default, rename = "excludeValues")]
    exclude_values: bool,
}

/// GET /xrpc/com.atproto.space.listRepoOps
///
/// A response that reaches the head of the oplog (a short page) carries the current signed
/// commit and no cursor; a full page carries a cursor and no commit. A full page that happens
/// to end exactly on the last op costs the client one extra round trip, as in the reference.
/// Values are the record's *current* block, inlined for creates/updates unless `excludeValues`
/// is set or a later op superseded the record (the join in `db/space_repos.rs` misses then).
pub async fn space_list_repo_ops(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceListRepoOpsParams>,
) -> Result<impl IntoResponse, ApiError> {
    let space = super::space_views::parse_space(&params.space)?;
    crate::auth::space::authenticate_space_read(
        &state,
        &headers,
        &method,
        &uri,
        &space,
        &params.repo,
    )
    .await?;
    let repo = super::space_views::load_repo(&state, &space.uri, &params.repo).await?;

    // The lexicon already rejects a `limit` outside [1, 1000]; this only applies the default.
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let cursor = params.cursor.as_deref().map(parse_cursor).transpose()?;

    let rows = crate::db::space_repos::list_repo_ops(
        &state.db,
        &space.uri,
        &params.repo,
        params.since.as_deref(),
        cursor.as_ref().map(|(rev, idx)| (rev.as_str(), *idx)),
        params.exclude_values,
        limit,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, space = %space.uri, "failed to list space repo ops");
        ApiError::new(ErrorCode::InternalError, "failed to list space repo ops")
    })?;

    let at_head = (rows.len() as i64) < limit;
    let next = (!at_head)
        .then(|| rows.last().map(|row| format!("{}/{}", row.rev, row.idx)))
        .flatten();

    let ops: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            // `cid` and `prev` are required-but-nullable on the wire: null carries meaning
            // (delete / create), so they are always present, never omitted.
            let mut entry = serde_json::json!({
                "rev": row.rev,
                "collection": row.collection,
                "rkey": row.rkey,
                "cid": row.cid,
                "prev": row.prev,
            });
            if let Some(value) = row.value {
                entry["value"] = super::space_views::decode_value(&value)?;
            }
            Ok(entry)
        })
        .collect::<Result<_, ApiError>>()?;

    let mut body = serde_json::json!({ "ops": ops });
    if at_head {
        let commit =
            super::space_views::sign_current_commit(&state, &space, &params.repo, &repo).await?;
        body["commit"] = super::space_views::commit_json(&commit);
    }
    if let Some(cursor) = next {
        body["cursor"] = serde_json::Value::String(cursor);
    }
    Ok((StatusCode::OK, axum::Json(body)))
}

/// A cursor is the last op's `rev/idx`. Opaque to clients, but it must round-trip into the
/// two keyset columns.
fn parse_cursor(cursor: &str) -> Result<(String, i64), ApiError> {
    cursor
        .split_once('/')
        .and_then(|(rev, idx)| idx.parse::<i64>().ok().map(|idx| (rev.to_string(), idx)))
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "malformed cursor"))
}
