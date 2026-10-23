// pattern: Imperative Shell

//! com.atproto.space.notifyCredentialRevoked — a space authority telling this repo host that
//! credentials it issued are revoked.
//!
//! Short credential lifetime is the spec's main revocation mechanism; this is the fast path. Each
//! revoked `jti` is recorded against the space for
//! [`CREDENTIAL_REVOCATION_RETENTION_SECS`], past the last instant any credential carrying it
//! could verify, and the credential verifier in `auth::space` refuses it until then.
//!
//! This is only the receiving side. As an authority, this server does not yet send it on
//! `removeMember` or `deleteSpace`; its credentials lapse within their ten-minute lifetime.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::auth::extract_bearer_token;
use crate::auth::jwt::{peek_jwt_aud, peek_jwt_iss};
use crate::auth::service_auth::verify_service_auth_resolving_key;
use crate::auth::space::{unix_now, CREDENTIAL_REVOCATION_RETENTION_SECS};
use crate::lexicon::LexiconInput;
use crate::SpacesState;
use common::{ApiError, ErrorCode};

const LXM: &str = "com.atproto.space.notifyCredentialRevoked";

#[derive(Deserialize)]
pub struct NotifyCredentialRevokedInput {
    space: String,
    credentials: Vec<String>,
}

/// POST /xrpc/com.atproto.space.notifyCredentialRevoked
///
/// Service auth, verified like `notifyWrite`'s: the issuer's key is resolved from the network,
/// and the issuer must be the space's authority, since only it issues the space's credentials.
/// The lexicon addresses the call to a repo DID, so `aud` may be any account hosted here as well
/// as this server's own DID.
///
/// Idempotent. Recorded only for a space this host already knows; a revocation for a space it
/// holds nothing of is acknowledged without effect, so no foreign DID can grow the table by
/// naming spaces of its own.
pub async fn space_notify_credential_revoked(
    State(state): State<SpacesState>,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<NotifyCredentialRevokedInput>,
) -> Result<impl IntoResponse, ApiError> {
    let space = crate::views::parse_space(&input.space)?;
    let now = unix_now()?;

    let token = extract_bearer_token(&headers)?;
    if peek_jwt_iss(token).as_deref() != Some(space.authority.as_str()) {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "issuer is not the space authority",
        ));
    }
    let server_did = state.config.resolve_server_did();
    let aud = peek_jwt_aud(token).unwrap_or_default();
    if aud != server_did && !crate::db::accounts::account_exists(&state.db, &aud).await? {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "service auth audience is neither this server nor an account it hosts",
        ));
    }
    verify_service_auth_resolving_key(&state, token, &space.authority, &aud, LXM, now).await?;

    let internal = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space.uri, "failed to record credential revocation");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    };
    let known = crate::db::spaces::get_space(&state.db, &space.uri)
        .await
        .map_err(internal)?
        .is_some();
    if known {
        crate::db::space_jti::revoke_credentials(
            &state.db,
            &space.uri,
            &input.credentials,
            CREDENTIAL_REVOCATION_RETENTION_SECS,
        )
        .await
        .map_err(internal)?;
    }

    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
