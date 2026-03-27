// pattern: Imperative Shell
//
// DELETE /v1/handles/:handle — Remove a handle from the account and clean up DNS.
//
// Inputs:
//   - Authorization: Bearer <session_token>
//   - Path: :handle (e.g., "alice.example.com")
//
// Processing steps:
//   1. require_session → SessionInfo { did }
//   2. SELECT did FROM handles WHERE handle = ? → 404 HANDLE_NOT_FOUND if absent
//   3. Verify session.did == handle_row.did → 403 FORBIDDEN if not owner
//   4. If state.dns_provider is Some: call delete_record(name) → 502 DNS_ERROR on failure
//      (DNS deletion precedes DB deletion: a DB row without a DNS record is operator-fixable;
//       a DNS record without a DB row is an invisible orphan that can corrupt future
//       registrations for the same subdomain)
//   5. DELETE FROM handles WHERE handle = ?
//   6. Return 204 No Content
//
// Outputs (success):  204 No Content
// Outputs (error):    401 UNAUTHORIZED, 403 FORBIDDEN, 404 HANDLE_NOT_FOUND,
//                     502 DNS_ERROR, 500 INTERNAL_ERROR

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::app::AppState;
use crate::routes::auth::require_session;
use common::{ApiError, ErrorCode};

pub async fn delete_handle_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // Step 1: Authenticate via session Bearer token.
    let session = require_session(&headers, &state.db).await?;

    // Step 2: Fetch the handle row; 404 if it does not exist.
    let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
        .bind(&handle)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, handle = %handle, "failed to fetch handle");
            ApiError::new(ErrorCode::InternalError, "failed to look up handle")
        })?;

    let (owner_did,) = row.ok_or_else(|| ApiError::new(ErrorCode::HandleNotFound, "handle not found"))?;

    // Step 3: Verify ownership — session DID must match the handle owner.
    if session.did != owner_did {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "you do not own this handle",
        ));
    }

    // Step 4: Delete DNS record before deleting the DB row.
    // DNS deletion precedes DB deletion: a DB row without a DNS record is operator-fixable
    // (admin can retry), whereas a DNS record without a DB row is an invisible orphan that
    // could corrupt a future handle registration for the same subdomain.
    if let Some(provider) = &state.dns_provider {
        let name = handle.split_once('.').map(|(n, _)| n).unwrap_or(&handle);
        provider.delete_record(name).await.map_err(|e| {
            tracing::error!(
                error = %e,
                handle = %handle,
                did = %session.did,
                "DNS record deletion failed"
            );
            ApiError::new(ErrorCode::DnsError, "failed to delete DNS record")
        })?;
    }

    // Step 5: Delete the handle row.
    sqlx::query("DELETE FROM handles WHERE handle = ?")
        .bind(&handle)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, handle = %handle, "failed to delete handle row");
            ApiError::new(ErrorCode::InternalError, "failed to delete handle")
        })?;

    // Step 6: Return 204 No Content.
    Ok(StatusCode::NO_CONTENT)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::app::test_state;
    use crate::routes::test_utils::seed_handle;
    use crate::routes::token::generate_token;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    // ── DNS provider test doubles ──────────────────────────────────────────────

    struct AlwaysOkDns;
    struct AlwaysErrDns;

    impl crate::dns::DnsProvider for AlwaysOkDns {
        fn create_record<'a>(
            &'a self,
            _name: &'a str,
            _target: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), crate::dns::DnsError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn delete_record<'a>(
            &'a self,
            _name: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), crate::dns::DnsError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
    }

    impl crate::dns::DnsProvider for AlwaysErrDns {
        fn create_record<'a>(
            &'a self,
            _name: &'a str,
            _target: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), crate::dns::DnsError>> + Send + 'a>> {
            Box::pin(async { Err(crate::dns::DnsError("simulated provider error".to_string())) })
        }

        fn delete_record<'a>(
            &'a self,
            _name: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), crate::dns::DnsError>> + Send + 'a>> {
            Box::pin(async { Err(crate::dns::DnsError("simulated provider error".to_string())) })
        }
    }

    async fn state_with_ok_dns() -> crate::app::AppState {
        let base = test_state().await;
        crate::app::AppState {
            dns_provider: Some(Arc::new(AlwaysOkDns)),
            ..base
        }
    }

    async fn state_with_err_dns() -> crate::app::AppState {
        let base = test_state().await;
        crate::app::AppState {
            dns_provider: Some(Arc::new(AlwaysErrDns)),
            ..base
        }
    }

    // ── Test session helpers ───────────────────────────────────────────────────

    /// Insert a session for an existing account row. Returns the plaintext token.
    async fn insert_session(db: &sqlx::SqlitePool, did: &str) -> String {
        let token = generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(did)
        .bind(&token.hash)
        .execute(db)
        .await
        .expect("insert session");
        token.plaintext
    }

    fn delete_handle_request(session_token: &str, handle: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(format!("/v1/handles/{handle}"))
            .header("Authorization", format!("Bearer {session_token}"))
            .body(Body::empty())
            .unwrap()
    }

    // ── Happy path ─────────────────────────────────────────────────────────────

    /// Deleting an owned handle with no DNS provider removes the row and returns 204.
    #[tokio::test]
    async fn happy_path_deletes_handle_no_dns_provider() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = format!("did:plc:{}", &Uuid::new_v4().to_string().replace('-', "")[..24]);
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        seed_handle(&db, &handle, &did).await;
        let token = insert_session(&db, &did).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(delete_handle_request(&token, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Verify the row was removed.
        let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(row.is_none(), "handle row must be removed after deletion");
    }

    /// DNS provider succeeds: row is deleted and DNS is cleaned up; returns 204.
    #[tokio::test]
    async fn dns_provider_success_deletes_handle_and_dns() {
        let state = state_with_ok_dns().await;
        let db = state.db.clone();
        let did = format!("did:plc:{}", &Uuid::new_v4().to_string().replace('-', "")[..24]);
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        seed_handle(&db, &handle, &did).await;
        let token = insert_session(&db, &did).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(delete_handle_request(&token, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(row.is_none(), "handle row must be removed when DNS succeeds");
    }

    /// DNS provider fails: returns 502 DNS_ERROR and the DB row is NOT deleted.
    #[tokio::test]
    async fn dns_provider_failure_returns_502_and_row_survives() {
        let state = state_with_err_dns().await;
        let db = state.db.clone();
        let did = format!("did:plc:{}", &Uuid::new_v4().to_string().replace('-', "")[..24]);
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        seed_handle(&db, &handle, &did).await;
        let token = insert_session(&db, &did).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(delete_handle_request(&token, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "DNS_ERROR");

        // DNS precedes DB: the row must still exist when DNS deletion fails.
        let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(
            row.is_some(),
            "handle row must survive when DNS deletion fails"
        );
    }

    // ── Auth failures ──────────────────────────────────────────────────────────

    /// Missing Authorization header returns 401.
    #[tokio::test]
    async fn missing_auth_returns_401() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = format!("did:plc:{}", &Uuid::new_v4().to_string().replace('-', "")[..24]);
        let handle = format!("alice.{}", state.config.available_user_domains[0]);
        seed_handle(&db, &handle, &did).await;

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/handles/{handle}"))
            .body(Body::empty())
            .unwrap();

        let app = crate::app::app(state);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Authorization (ownership) ─────────────────────────────────────────────

    /// Session DID that does not own the handle returns 403.
    #[tokio::test]
    async fn non_owner_session_returns_403() {
        let state = test_state().await;
        let db = state.db.clone();

        // Owner account + handle.
        let owner_did =
            format!("did:plc:{}", &Uuid::new_v4().to_string().replace('-', "")[..24]);
        let handle = format!("alice.{}", state.config.available_user_domains[0]);
        seed_handle(&db, &handle, &owner_did).await;

        // Different account that tries to delete the handle.
        let other_did =
            format!("did:plc:{}", &Uuid::new_v4().to_string().replace('-', "")[..24]);
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&other_did)
        .bind(format!("{other_did}@test.example.com"))
        .execute(&db)
        .await
        .unwrap();
        let other_token = insert_session(&db, &other_did).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(delete_handle_request(&other_token, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "FORBIDDEN");
    }

    // ── Not found ─────────────────────────────────────────────────────────────

    /// Deleting a handle that doesn't exist returns 404.
    #[tokio::test]
    async fn nonexistent_handle_returns_404() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = format!("did:plc:{}", &Uuid::new_v4().to_string().replace('-', "")[..24]);

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind(format!("{did}@test.example.com"))
        .execute(&db)
        .await
        .unwrap();
        let token = insert_session(&db, &did).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(delete_handle_request(&token, "ghost.test.example.com"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "HANDLE_NOT_FOUND");
    }
}
