// pattern: Imperative Shell

//! com.atproto.space.applyWrites — apply a batch of creates, updates and deletes to one
//! permissioned space repo as a single commit.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::oauth_scopes::{RepoAction, SpaceOp};
use crate::lexicon::{LexiconInput, RecordValidation};
use crate::space_record_write::{SpaceWriteAction, SpaceWriteOp};
use common::{ApiError, ErrorCode};

/// Matches `com.atproto.repo.applyWrites`, and the reference's space batch.
const MAX_WRITES: usize = 200;

#[derive(Deserialize)]
pub struct SpaceApplyWritesBody {
    space: String,
    repo: String,
    #[serde(default)]
    validate: Option<bool>,
    writes: Vec<SpaceWrite>,
}

/// One entry of the closed `#create`/`#update`/`#delete` union. The lexicon layer has already
/// rejected any other `$type` by the time this deserializes.
#[derive(Deserialize)]
#[serde(tag = "$type")]
enum SpaceWrite {
    #[serde(rename = "com.atproto.space.applyWrites#create")]
    Create {
        collection: String,
        rkey: Option<String>,
        value: serde_json::Value,
    },
    #[serde(rename = "com.atproto.space.applyWrites#update")]
    Update {
        collection: String,
        rkey: String,
        value: serde_json::Value,
    },
    #[serde(rename = "com.atproto.space.applyWrites#delete")]
    Delete { collection: String, rkey: String },
}

/// POST /xrpc/com.atproto.space.applyWrites
///
/// Every op in the batch is authorized before any of it lands, and the whole batch commits or
/// none of it does — the store applies it in one transaction under a single `rev`.
pub async fn space_apply_writes(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(body): LexiconInput<SpaceApplyWritesBody>,
) -> Result<impl IntoResponse, ApiError> {
    let space = super::space_views::parse_space(&body.space)?;
    let user =
        crate::auth::space::authenticate_space_write(&state, &headers, &method, &uri, &body.repo)?;
    if body.writes.len() > MAX_WRITES {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            format!("too many writes; max: {MAX_WRITES}"),
        ));
    }

    // Resolve each op to its record path first: a create without an rkey gets one here, so the
    // rkey the scope check, the commit, and the response all speak of is the same one.
    let mut ops: Vec<SpaceWriteOp> = Vec::with_capacity(body.writes.len());
    let mut statuses: Vec<Option<RecordValidation>> = Vec::with_capacity(body.writes.len());
    for write in body.writes {
        let (action, collection, rkey, value) = match write {
            SpaceWrite::Create {
                collection,
                rkey,
                value,
            } => (
                SpaceWriteAction::Create,
                collection,
                rkey.filter(|r| !r.is_empty())
                    .unwrap_or_else(repo_engine::generate_tid),
                Some(value),
            ),
            SpaceWrite::Update {
                collection,
                rkey,
                value,
            } => (SpaceWriteAction::Update, collection, rkey, Some(value)),
            SpaceWrite::Delete { collection, rkey } => {
                (SpaceWriteAction::Delete, collection, rkey, None)
            }
        };

        crate::auth::space::require_space_grant(
            &state,
            &user,
            &space,
            SpaceOp::Record {
                action: match action {
                    SpaceWriteAction::Create => RepoAction::Create,
                    SpaceWriteAction::Delete => RepoAction::Delete,
                    _ => RepoAction::Update,
                },
                collection: &collection,
            },
        )
        .await?;

        statuses.push(match &value {
            Some(record) => {
                super::space_views::validate_record(&collection, &rkey, record, body.validate)?
            }
            None => None,
        });
        ops.push(SpaceWriteOp {
            action,
            collection,
            rkey,
            value,
        });
    }

    if ops.is_empty() {
        // Nothing was written, so there is nothing to report — and no commit is made.
        return Ok((
            StatusCode::OK,
            axum::Json(serde_json::json!({ "results": [] })),
        ));
    }

    let outcome =
        crate::space_record_write::apply_space_writes(&state, &space, &user.did, &ops).await?;

    // Results are positional and preserve request order: with every action carrying a
    // precondition, an op either lands or the whole batch fails, so the store returns exactly
    // one result per op. The result *kind* comes from the op, not from the result's shape — a
    // `#create` reports `createResult` because that is what was asked for.
    let results: Vec<serde_json::Value> = ops
        .iter()
        .zip(&outcome.results)
        .zip(statuses)
        .map(|((op, result), status)| {
            if op.action == SpaceWriteAction::Delete {
                return serde_json::json!({ "$type": "com.atproto.space.applyWrites#deleteResult" });
            }
            let mut entry = serde_json::json!({
                "$type": if op.action == SpaceWriteAction::Create {
                    "com.atproto.space.applyWrites#createResult"
                } else {
                    "com.atproto.space.applyWrites#updateResult"
                },
                "uri": space.record_uri(&user.did, &result.collection, &result.rkey),
                "cid": result.cid,
            });
            if let Some(status) = status {
                entry["validationStatus"] = serde_json::Value::String(status.as_str().to_string());
            }
            entry
        })
        .collect();

    Ok((
        StatusCode::OK,
        axum::Json(serde_json::json!({ "results": results })),
    ))
}
