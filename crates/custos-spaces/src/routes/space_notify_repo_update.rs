// pattern: Imperative Shell

//! com.atproto.space.notifyRepoUpdate — inbound write notification from a repo host.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use custos_core::CoreState;
use serde::Deserialize;

use crate::auth::space::unix_now;
use common::{ApiError, ErrorCode};
use custos_core::auth::extract_bearer_token;
use custos_core::auth::jwt::{peek_jwt_aud, peek_jwt_iss};
use custos_core::auth::service_auth::verify_service_auth_resolving_key;
use custos_core::lexicon::LexiconInput;

const LXM: &str = "com.atproto.space.notifyRepoUpdate";

/// How far ahead of this host's clock a `repoRev` may be.
const MAX_REV_SKEW_SECS: u64 = 5 * 60;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotifyRepoUpdateInput {
    space: String,
    repo: String,
    repo_rev: String,
    /// Lex-JSON `{"$bytes": "<base64>"}` — the repo's commit hash after the write.
    data: serde_json::Value,
}

/// POST /xrpc/com.atproto.space.notifyRepoUpdate
///
/// Service-auth authenticated, but deliberately **not** through
/// [`custos_core::auth::service_auth::require_service_auth`]: that guard requires the issuer to be an
/// account hosted here, and the whole point of this method is that the issuer is somewhere else.
/// The issuer's key is resolved from the network instead, and it must be the repo whose head
/// moved, as the reference requires, so no host reports on another account's behalf. The
/// audience is the space's authority, `<did>#atproto_pds` or the bare DID, as the reference
/// accepts. Deliberately beyond the reference, this server's own DID is accepted too.
///
/// An authenticated notification is acknowledged without effect when this host is not the
/// space's authority, when the space is deleted or taken down, when the space's write policy
/// refuses the repo, or when `repoRev` is stale (see
/// [`upsert_writer`](crate::db::space_notify::upsert_writer)). A `repoRev` further ahead of this
/// host's clock than [`MAX_REV_SKEW_SECS`] is refused (`FutureRev`): such a revision would pin
/// the repo's writer-set entry ahead of every honest update.
pub async fn space_notify_repo_update(
    State(state): State<CoreState>,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<NotifyRepoUpdateInput>,
) -> Result<impl IntoResponse, ApiError> {
    let space = crate::views::parse_space(&input.space)?;
    let hash = decode_hash(&input.data)?;
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
    if iss != input.repo {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "issuer is not the repo",
        ));
    }
    // A PDS answers for many authorities, so the audience comes from the space: the reference
    // addresses the authority's `#atproto_pds` service, and accepts the bare authority DID.
    // This server's own DID is accepted too.
    let aud = peek_jwt_aud(token).unwrap_or_default();
    let space_host_aud = format!("{}#atproto_pds", space.authority);
    if aud != space.authority && aud != space_host_aud && aud != state.config.resolve_server_did() {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "service auth token audience is not the space authority",
        ));
    }
    verify_service_auth_resolving_key(&state, token, &iss, &aud, LXM, now).await?;

    // Recorded only when this host is the space's authority, and only for a space it already
    // knows about and still serves; a notification about an unknown space is not a licence to
    // create one.
    let internal = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space.uri, "failed to record space writer");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    };
    let ack = || Ok((StatusCode::OK, axum::Json(serde_json::json!({}))));
    let Some(row) = crate::db::spaces::get_space(&state.db, &space.uri)
        .await
        .map_err(internal)?
        .filter(|r| r.deleted_at.is_none() && r.takendown_at.is_none())
    else {
        return ack();
    };
    let Some(policy) = row.space_policy()? else {
        return ack();
    };
    if !crate::auth::space::authorize_write_notification(&state, &row, &policy, &input.repo).await?
    {
        return ack();
    }
    let mut conn = state.db.acquire().await.map_err(internal)?;
    let update = crate::db::space_notify::upsert_writer(
        &mut conn,
        &space.uri,
        &input.repo,
        &input.repo_rev,
        &hash,
    )
    .await
    .map_err(internal)?;
    drop(conn);

    if let crate::db::space_notify::WriterUpdate::Accepted(revs) = update {
        drop(crate::space_notify::forward_write(
            &state,
            &space,
            &input.repo,
            &input.repo_rev,
            &hash,
            revs,
        ));
    }

    ack()
}

/// The lexicon's `bytes` type on the wire is `{"$bytes": "<base64>"}`, unpadded as the data
/// model writes it (and the reference sends it); padded is accepted too. A commit hash is a
/// sha256, so exactly 32 bytes.
fn decode_hash(value: &serde_json::Value) -> Result<Vec<u8>, ApiError> {
    use base64::Engine as _;
    let invalid = || ApiError::new(ErrorCode::InvalidRequest, "data must be 32 bytes");
    let encoded = value
        .get("$bytes")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid)?;
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        .map_err(|_| invalid())?;
    if bytes.len() != 32 {
        return Err(invalid());
    }
    Ok(bytes)
}
