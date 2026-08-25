// pattern: Imperative Shell

//! com.atproto.space.unregisterNotify — withdraw a write-notification registration.

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::lexicon::LexiconInput;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
pub struct UnregisterNotifyInput {
    space: String,
    service: String,
}

/// POST /xrpc/com.atproto.space.unregisterNotify
///
/// Idempotent by lexicon: succeeds whether or not a matching registration existed, so a syncer
/// tearing itself down never has to know what it still holds. Registrations lapse on their own
/// at their expiry, so this is explicit withdrawal, not cleanup.
///
/// Only the whole-space registrations `registerNotify` creates are withdrawable. The per-repo
/// rows a repo host writes for itself are its own bookkeeping about where to report its users'
/// writes, not a subscription anyone else may cancel.
pub async fn space_unregister_notify(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    LexiconInput(input): LexiconInput<UnregisterNotifyInput>,
) -> Result<impl IntoResponse, ApiError> {
    let space = super::space_views::parse_space(&input.space)?;
    crate::auth::space::authenticate_space_access(&state, &headers, &method, &uri, &space).await?;
    super::space_views::require_local_authority(&state, &space).await?;

    crate::db::space_notify::delete_registration(&state.db, &space.uri, &input.service)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, "failed to unregister notify subscriber");
            ApiError::new(ErrorCode::InternalError, "internal server error")
        })?;

    Ok((StatusCode::OK, axum::Json(serde_json::json!({}))))
}
