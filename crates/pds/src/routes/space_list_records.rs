// pattern: Imperative Shell

//! com.atproto.space.listRecords — page an account's records in one permissioned space repo.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::lexicon::LexiconParams;
use common::{ApiError, ErrorCode};

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 1000;

#[derive(Deserialize)]
pub struct SpaceListRecordsParams {
    space: String,
    repo: String,
    collection: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
    #[serde(default)]
    reverse: bool,
    /// Values are inlined by default; this asks for a metadata-only listing, which is what the
    /// healing path wants — it diffs cids against its own copy and fetches only what changed.
    #[serde(default, rename = "excludeValues")]
    exclude_values: bool,
}

/// GET /xrpc/com.atproto.space.listRecords
///
/// Throws `RepoNotFound` when the account holds no repo in the space. That does not distinguish
/// a member who has never written from a non-member: a repo host tracks writers, not membership.
pub async fn space_list_records(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconParams(params): LexiconParams<SpaceListRecordsParams>,
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
    require_repo(&state, &space.uri, &params.repo).await?;

    // The lexicon already rejects a `limit` outside [1, 1000], so this only applies the default.
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let cursor = params.cursor.as_deref().map(parse_cursor).transpose()?;

    let rows = crate::db::space_repos::list_repo_records(
        &state.db,
        &space.uri,
        &params.repo,
        params.collection.as_deref(),
        cursor.as_ref().map(|(c, r)| (c.as_str(), r.as_str())),
        params.reverse,
        params.exclude_values,
        limit,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, space = %space.uri, "failed to list space records");
        ApiError::new(ErrorCode::InternalError, "failed to list space records")
    })?;

    // A short page is the last one, so it carries no cursor — the same rule the reference uses,
    // and what lets a syncer stop without a extra empty round trip.
    let next = (rows.len() as i64 == limit)
        .then(|| {
            rows.last()
                .map(|row| format!("{}/{}", row.collection, row.rkey))
        })
        .flatten();

    let records: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            let mut entry = serde_json::json!({
                "collection": row.collection,
                "rkey": row.rkey,
                "cid": row.cid,
            });
            if let Some(value) = row.value {
                entry["value"] = super::space_views::decode_value(&value)?;
            }
            Ok(entry)
        })
        .collect::<Result<_, ApiError>>()?;

    let mut body = serde_json::json!({ "records": records });
    if let Some(cursor) = next {
        body["cursor"] = serde_json::Value::String(cursor);
    }
    Ok((StatusCode::OK, axum::Json(body)))
}

/// A cursor is the last row's `collection/rkey`. Opaque to clients — it is only ever echoed back
/// to the server that issued it — but it must still round-trip into the two keyset columns.
fn parse_cursor(cursor: &str) -> Result<(String, String), ApiError> {
    cursor
        .split_once('/')
        .map(|(collection, rkey)| (collection.to_string(), rkey.to_string()))
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "malformed cursor"))
}

/// `RepoNotFound` unless the account actually holds a repo in the space.
///
/// Without this an unwritten repo would answer with an empty page, which reads to a syncer as
/// "this repo is empty" rather than "there is no such repo" — the two are different facts, and
/// only the second means stop.
async fn require_repo(state: &AppState, space_uri: &str, did: &str) -> Result<(), ApiError> {
    let repo = crate::db::space_repos::get_repo(&state.db, space_uri, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space_uri, "failed to load space repo");
            ApiError::new(ErrorCode::InternalError, "failed to list space records")
        })?;
    if repo.is_none() {
        return Err(crate::auth::space::repo_not_found(did));
    }
    Ok(())
}
