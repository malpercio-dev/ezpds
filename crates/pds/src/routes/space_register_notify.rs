// pattern: Imperative Shell

//! com.atproto.space.registerNotify — subscribe a service to a space's write notifications.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::db::space_notify::WHOLE_SPACE;
use crate::lexicon::LexiconInput;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
pub struct RegisterNotifyInput {
    space: String,
    service: String,
}

/// POST /xrpc/com.atproto.space.registerNotify
///
/// Registers a *service identifier* — a DID with an optional `#fragment` naming the DID-document
/// entry to deliver to — rather than a URL, because `notifyWrite` is delivered with service auth
/// addressed to that identifier. The identifier is resolved here so a syncer that mistyped it
/// learns immediately (`ServiceNotResolvable`) instead of owning a subscription that silently
/// never delivers.
///
/// Answered only for a space this host is the authority for, and only to a caller holding a
/// space credential (or the owner's own OAuth grant) — the same admission
/// `simplespace.getSpace` uses. Re-registering renews the existing row's expiry.
pub async fn space_register_notify(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<RegisterNotifyInput>,
) -> Result<impl IntoResponse, ApiError> {
    let space = super::space_views::parse_space(&input.space)?;
    crate::auth::space::authenticate_space_access(&state, &headers, &method, &uri, &space).await?;
    super::space_views::require_local_authority(&state, &space).await?;

    if !crate::space_notify::service_is_resolvable(&state, &input.service).await {
        return Err(ApiError::new(
            ErrorCode::ServiceNotResolvable,
            "could not resolve the service identifier to a delivery endpoint",
        ));
    }

    let expires_at = crate::db::space_notify::upsert_registration(
        &state.db,
        &space.uri,
        &input.service,
        WHOLE_SPACE,
        crate::space_notify::REGISTRATION_TTL_SECS,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, space = %space.uri, "failed to register notify subscriber");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    })?;

    Ok((
        StatusCode::OK,
        axum::Json(serde_json::json!({ "expiresAt": rfc3339(&expires_at) })),
    ))
}

/// SQLite's `datetime()` yields `YYYY-MM-DD HH:MM:SS`; the lexicon's `datetime` format wants
/// RFC 3339. The stored value is always UTC, so the conversion is textual.
fn rfc3339(sqlite_datetime: &str) -> String {
    format!("{}Z", sqlite_datetime.replacen(' ', "T", 1))
}
