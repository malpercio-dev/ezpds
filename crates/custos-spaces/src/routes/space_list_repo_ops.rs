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
use axum::response::{IntoResponse, Response};
use custos_core::CoreState;
use serde::Deserialize;

use common::{ApiError, Did, ErrorCode};
use crypto::http_signature::MacProfile;
use custos_core::lexicon::LexiconParams;

const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 1000;

#[derive(Deserialize)]
pub struct SpaceListRepoOpsParams {
    space: String,
    repo: Did,
    /// The caller's own sync position: only ops strictly after this rev.
    since: Option<String>,
    limit: Option<i64>,
    /// Opaque continuation from a previous page; takes precedence over `since` when both are
    /// supplied (the cursor is itself a position).
    cursor: Option<String>,
    #[serde(default, rename = "excludeValues")]
    exclude_values: bool,
}

/// GET /xrpc/com.atproto.space.listRepoOps
///
/// Every page carries the repo's current commit, and a requested MAC over it (`space_mac`); a
/// full page also carries a cursor. A full page that happens to end exactly on the last op
/// costs the client one extra round trip, as in the reference.
/// Values are the record's *current* block, inlined for creates/updates unless `excludeValues`
/// is set or a later op superseded the record (the join in `db/space_repos.rs` misses then).
pub async fn space_list_repo_ops(
    State(state): State<CoreState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceListRepoOpsParams>,
) -> Result<Response, ApiError> {
    let space = crate::views::parse_space(&params.space)?;
    let reader = crate::auth::space::authenticate_space_read(
        &state,
        &headers,
        &method,
        &uri,
        &space,
        &params.repo,
    )
    .await?;
    let mac =
        crate::space_mac::mac_grant(&state, &headers, &reader, &params.repo, MacProfile::Commit)
            .await?;
    let repo = crate::views::load_repo(&state, &space.uri, &params.repo).await?;

    // The lexicon already rejects a `limit` outside [1, 1000]; this only applies the default.
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let cursor = params.cursor.as_deref().map(parse_cursor).transpose()?;
    // The cursor takes precedence over `since` when both arrive — the cursor IS a
    // position, so conjoining a later `since` would silently skip the ops between them.
    let since = if cursor.is_some() {
        None
    } else {
        params.since.as_deref()
    };

    let rows = crate::db::space_repos::list_repo_ops(
        &state.db,
        &space.uri,
        &params.repo,
        since,
        cursor.as_ref().map(|(rev, idx)| (rev.as_str(), *idx)),
        params.exclude_values,
        limit,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, space = %space.uri, "failed to list space repo ops");
        ApiError::new(ErrorCode::InternalError, "failed to list space repo ops")
    })?;

    let next = ((rows.len() as i64) == limit)
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
                entry["value"] = crate::views::decode_value(&value)?;
            }
            Ok(entry)
        })
        .collect::<Result<_, ApiError>>()?;

    let commit = crate::views::current_commit(&space, &params.repo, &repo)?;
    let mut body = serde_json::json!({ "ops": ops, "commit": commit.to_json() });
    if let Some(cursor) = next {
        body["cursor"] = serde_json::Value::String(cursor);
    }
    let response = (StatusCode::OK, axum::Json(body)).into_response();
    crate::space_mac::with_commit_mac(response, &commit, mac.as_ref())
}

/// A cursor is the last op's `rev/idx`. Opaque to clients, but it must round-trip into the
/// two keyset columns.
fn parse_cursor(cursor: &str) -> Result<(String, i64), ApiError> {
    cursor
        .split_once('/')
        .and_then(|(rev, idx)| idx.parse::<i64>().ok().map(|idx| (rev.to_string(), idx)))
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "malformed cursor"))
}
