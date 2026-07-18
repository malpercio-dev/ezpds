// pattern: Imperative Shell
//
// Gathers: admin credentials (master token or signed device request)
// Processes: admin auth → list every account with an in-flight escrow release
// Returns: JSON list of pending releases on success; ApiError on all failure paths

//! GET /v1/admin/recovery-releases - Operator visibility into in-flight escrow releases.
//!
//! The Brass Console's window onto the escrow release flow: which accounts currently have a
//! recovery-share release open, when it was requested, and when it becomes (or became)
//! collectable. Literal facts only — no verdicts — like `admin_health.rs`. An operator watching a
//! suspicious release composes this with `revoke-credentials` (kill the attacker's sessions) and
//! the account owner's `POST /v1/recovery/release/cancel` to interrupt it.
//!
//! The share ciphertext is never returned — only the release timing. Admin-authed via
//! [`require_admin`] (master token **or** an active companion-app device's signed request).

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::Json;
use serde::Serialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::require_admin;
use crate::db::recovery_escrow::list_pending_releases;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryReleasesResponse {
    releases: Vec<PendingReleaseView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PendingReleaseView {
    did: String,
    /// When the release was opened (SQLite datetime, UTC).
    requested_at: String,
    /// When the release becomes collectable.
    available_at: Option<String>,
    /// Whether the delay window has already elapsed — the share is collectable now. An operator
    /// seeing `available: true` on a release they don't recognize has a closing window to cancel.
    available: bool,
}

/// GET /v1/admin/recovery-releases
///
/// List every account with an in-flight escrow release, newest request first.
pub async fn admin_recovery_releases(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<RecoveryReleasesResponse>, ApiError> {
    // Auth first so an unauthenticated caller cannot enumerate in-flight releases.
    require_admin(method.as_str(), uri.path(), &headers, &body, &state).await?;

    let releases = list_pending_releases(&state.db).await.map_err(|e| {
        tracing::error!(error = %e, "failed to list pending recovery releases");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to list pending recovery releases",
        )
    })?;

    Ok(Json(RecoveryReleasesResponse {
        releases: releases
            .into_iter()
            .map(|r| PendingReleaseView {
                did: r.did,
                requested_at: r.release_requested_at,
                available_at: r.release_pending_until,
                available: r.available,
            })
            .collect(),
    }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::app::app;
    use crate::routes::test_utils::test_state_with_admin_token;

    async fn seed_account(db: &sqlx::SqlitePool, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(db)
        .await
        .unwrap();
    }

    async fn get(router: axum::Router, token: Option<&str>) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder().uri("/v1/admin/recovery-releases");
        if let Some(token) = token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        let response = router
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, json)
    }

    #[tokio::test]
    async fn requires_admin_auth() {
        let router = app(test_state_with_admin_token().await);
        let (status, _) = get(router.clone(), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = get(router, Some("wrong")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn lists_only_in_flight_releases_newest_first_without_the_share() {
        let state = test_state_with_admin_token().await;
        // Two accounts with escrow; only one has an in-flight release.
        for did in ["did:plc:arr_idle", "did:plc:arr_pending"] {
            seed_account(&state.db, did).await;
            sqlx::query(
                "INSERT INTO recovery_escrow (did, share_encrypted, created_at) \
                 VALUES (?, 'ciphertext', datetime('now'))",
            )
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
        }
        // Open a release on one, its window already elapsed (available = true).
        sqlx::query(
            "UPDATE recovery_escrow SET release_requested_at = datetime('now'), \
             release_pending_until = datetime('now', '-1 second') WHERE did = 'did:plc:arr_pending'",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let router = app(state);
        let (status, json) = get(router, Some("test-admin-token")).await;
        assert_eq!(status, StatusCode::OK);
        let releases = json["releases"].as_array().unwrap();
        assert_eq!(releases.len(), 1, "only the in-flight release is listed");
        assert_eq!(releases[0]["did"], "did:plc:arr_pending");
        assert_eq!(releases[0]["available"], true);
        assert!(
            releases[0].get("share").is_none() && releases[0].get("shareEncrypted").is_none(),
            "the share ciphertext must never be returned"
        );
    }
}
