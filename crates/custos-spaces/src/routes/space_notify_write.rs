// pattern: Imperative Shell

//! com.atproto.space.notifyWrite — inbound write notification from a repo host.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::SpacesState;
use crate::auth::extract_bearer_token;
use crate::auth::jwt::peek_jwt_iss;
use crate::auth::service_auth::verify_service_auth_resolving_key;
use crate::auth::space::unix_now;
use crate::lexicon::LexiconInput;
use common::{ApiError, ErrorCode};

const LXM: &str = "com.atproto.space.notifyWrite";

/// How far ahead of this host's clock a `repoRev` may be.
const MAX_REV_SKEW_SECS: u64 = 5 * 60;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotifyWriteInput {
    space: String,
    repo: String,
    repo_rev: String,
    /// Lex-JSON `{"$bytes": "<base64>"}` — the repo's commit hash after the write.
    hash: serde_json::Value,
}

/// POST /xrpc/com.atproto.space.notifyWrite
///
/// Service-auth authenticated, but deliberately **not** through
/// [`crate::auth::service_auth::require_service_auth`]: that guard requires the issuer to be an
/// account hosted here, and the whole point of this method is that the issuer is somewhere else.
/// The issuer's key is resolved from the network instead, and it must be one of the two parties
/// entitled to speak about this write — the repo whose head moved (a repo host reporting its own
/// user's commit) or the space's authority (a space host forwarding to a registered syncer).
///
/// An authenticated notification about a space this host is not the authority for is accepted and
/// dropped rather than refused, because a syncer forwarding into a space it merely holds a copy
/// of has nothing to do with the report either way. A `repoRev` further ahead of this host's
/// clock than [`MAX_REV_SKEW_SECS`] is refused (`FutureRev`) — such a revision would pin the
/// repo's writer-set entry ahead of every honest update. When this host is the authority the
/// repo must also pass the space's write policy; a repo it refuses is acknowledged and not
/// tracked or forwarded.
pub async fn space_notify_write(
    State(state): State<SpacesState>,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<NotifyWriteInput>,
) -> Result<impl IntoResponse, ApiError> {
    let space = crate::views::parse_space(&input.space)?;
    let hash = decode_hash(&input.hash)?;
    let now = unix_now()?;
    if repo_engine::tid_micros(&input.repo_rev) / 1_000_000 > now + MAX_REV_SKEW_SECS {
        return Err(ApiError::new(
            ErrorCode::FutureRev,
            "repoRev is ahead of the permitted clock skew",
        ));
    }

    let token = extract_bearer_token(&headers)?;
    let iss = peek_jwt_iss(token)
        .filter(|i| i.starts_with("did:"))
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidToken,
                "service auth token issuer is missing or not a DID",
            )
        })?;
    if iss != input.repo && iss != space.authority {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "issuer is neither the repo nor the space authority",
        ));
    }
    let server_did = state.config.resolve_server_did();
    verify_service_auth_resolving_key(&state, token, &iss, &server_did, LXM, now).await?;

    // The claim goes into the writer set only when this host is the space's authority — the
    // query's own guard — and only for a space it already knows about; a notification about an
    // unknown space is not a licence to create one.
    let internal = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space.uri, "failed to record space writer");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    };
    let row = crate::db::spaces::get_space(&state.db, &space.uri)
        .await
        .map_err(internal)?;
    if let Some(row) = row.filter(|r| r.deleted_at.is_none() && r.policy.is_some()) {
        if !crate::auth::space::authorize_write_notification(&state, &row, &input.repo).await? {
            return Ok((StatusCode::OK, axum::Json(serde_json::json!({}))));
        }
    }
    let mut conn = state.db.acquire().await.map_err(internal)?;
    let revs = crate::db::space_notify::upsert_writer(
        &mut conn,
        &space.uri,
        &input.repo,
        &input.repo_rev,
        &hash,
    )
    .await
    .map_err(internal)?;
    drop(conn);

    // Forward to the registered syncers, skipping the repo whose host just told us.
    drop(crate::space_notify::fan_out_write(
        &state,
        &space,
        &input.repo,
        &input.repo_rev,
        &hash,
        revs,
    ));

    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}

/// The lexicon's `bytes` type on the wire is `{"$bytes": "<base64>"}`; a commit hash is a
/// sha256, so exactly 32 bytes.
fn decode_hash(value: &serde_json::Value) -> Result<Vec<u8>, ApiError> {
    use base64::Engine as _;
    let invalid = || ApiError::new(ErrorCode::InvalidRequest, "hash must be 32 bytes");
    let encoded = value
        .get("$bytes")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid())?;
    if bytes.len() != 32 {
        return Err(invalid());
    }
    Ok(bytes)
}
