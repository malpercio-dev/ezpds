// pattern: Imperative Shell
//
// Admin account repair: authenticate the operator, bind the target DID from the path,
// then atomically apply the repair and append its durable audit event.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::require_admin_json;
use crate::auth::token::generate_token;

#[derive(Deserialize)]
pub struct SetEmailRequest {
    email: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetEmailResponse {
    did: String,
    email: String,
    email_confirmed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetTokenResponse {
    did: String,
    token: String,
    expires_in: u32,
}

fn db_error(error: sqlx::Error, operation: &'static str) -> ApiError {
    tracing::error!(%error, operation, "DB error repairing account");
    ApiError::new(ErrorCode::InternalError, "failed to repair account")
}

pub async fn set_account_email(
    State(state): State<AppState>,
    Path(did): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let actor = match require_admin_json(method.as_str(), uri.path(), &headers, &body, &state).await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let payload = match Json::<SetEmailRequest>::from_bytes(&body) {
        Ok(Json(payload)) => payload,
        Err(rejection) => return rejection.into_response(),
    };
    let email = crate::uniqueness::normalize_email(&payload.email);
    if !crate::routes::update_email::is_plausible_email(&email) {
        return ApiError::new(ErrorCode::InvalidRequest, "invalid email address").into_response();
    }

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(error) => return db_error(error, "begin email repair").into_response(),
    };
    let previous: Option<String> =
        match sqlx::query_scalar("SELECT email FROM accounts WHERE did = ?")
            .bind(&did)
            .fetch_optional(&mut *tx)
            .await
        {
            Ok(value) => value,
            Err(error) => return db_error(error, "load account email").into_response(),
        };
    let Some(previous) = previous else {
        return ApiError::new(ErrorCode::NotFound, "account not found").into_response();
    };
    if let Err(error) = sqlx::query(
        "UPDATE accounts SET email = ?, email_confirmed_at = NULL, updated_at = datetime('now') WHERE did = ?",
    )
    .bind(&email)
    .bind(&did)
    .execute(&mut *tx)
    .await
    {
        if crate::db::is_unique_violation(&error) {
            return ApiError::new(ErrorCode::InvalidRequest, "this email address is already in use")
                .into_response();
        }
        return db_error(error, "update account email").into_response();
    }
    let detail = serde_json::json!({ "previousEmail": previous, "newEmail": email }).to_string();
    if let Err(error) = sqlx::query(
        "INSERT INTO operator_account_audit_events (id, did, actor, action, detail) VALUES (?, ?, ?, 'email_updated', ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&did)
    .bind(actor.as_log_str().as_ref())
    .bind(detail)
    .execute(&mut *tx)
    .await
    {
        return db_error(error, "audit email repair").into_response();
    }
    if let Err(error) = tx.commit().await {
        return db_error(error, "commit email repair").into_response();
    }
    tracing::info!(did = %did, actor = %actor.as_log_str(), "account email repaired by operator");
    Json(SetEmailResponse {
        did,
        email,
        email_confirmed: false,
    })
    .into_response()
}

pub async fn issue_reset_token(
    State(state): State<AppState>,
    Path(did): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let actor = match crate::auth::guards::require_admin(
        method.as_str(),
        uri.path(),
        &headers,
        &body,
        &state,
    )
    .await
    {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let token = generate_token();
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(error) => return db_error(error, "begin reset-token issuance").into_response(),
    };
    let exists: bool =
        match sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE did = ?)")
            .bind(&did)
            .fetch_one(&mut *tx)
            .await
        {
            Ok(value) => value,
            Err(error) => return db_error(error, "load reset-token account").into_response(),
        };
    if !exists {
        return ApiError::new(ErrorCode::NotFound, "account not found").into_response();
    }
    if let Err(error) = sqlx::query(
        "INSERT INTO password_reset_tokens (token_hash, did, expires_at, created_at) VALUES (?, ?, datetime('now', '+1 hour'), datetime('now'))",
    )
    .bind(&token.hash)
    .bind(&did)
    .execute(&mut *tx)
    .await
    {
        return db_error(error, "insert reset token").into_response();
    }
    if let Err(error) = sqlx::query(
        "INSERT INTO operator_account_audit_events (id, did, actor, action) VALUES (?, ?, ?, 'reset_token_issued')",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&did)
    .bind(actor.as_log_str().as_ref())
    .execute(&mut *tx)
    .await
    {
        return db_error(error, "audit reset-token issuance").into_response();
    }
    if let Err(error) = tx.commit().await {
        return db_error(error, "commit reset-token issuance").into_response();
    }
    tracing::info!(did = %did, actor = %actor.as_log_str(), "password reset token issued by operator");
    (
        StatusCode::OK,
        Json(ResetTokenResponse {
            did,
            token: token.plaintext,
            expires_in: 3600,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::app::app;
    use crate::auth::token::hash_bearer_token;
    use crate::routes::test_utils::{
        body_json, insert_account_with_password, test_state_with_admin_token,
    };

    const ADMIN: &str = "test-admin-token";

    fn post(path: &str, body: Option<&str>, authenticated: bool) -> Request<Body> {
        let mut request = Request::builder().method("POST").uri(path);
        if authenticated {
            request = request.header("Authorization", format!("Bearer {ADMIN}"));
        }
        if body.is_some() {
            request = request.header("Content-Type", "application/json");
        }
        request
            .body(Body::from(body.unwrap_or_default().to_owned()))
            .unwrap()
    }

    #[tokio::test]
    async fn repairs_email_resets_confirmation_and_audits_atomically() {
        let state = test_state_with_admin_token().await;
        let did = "did:plc:repair-email";
        insert_account_with_password(
            &state.db,
            did,
            "repair-email.test.example.com",
            "wrong@example.com",
            "password",
        )
        .await;
        sqlx::query("UPDATE accounts SET email_confirmed_at = datetime('now'), taken_down_at = datetime('now') WHERE did = ?")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();

        let response = app(state.clone())
            .oneshot(post(
                &format!("/v1/admin/accounts/{did}/email"),
                Some(r#"{"email":" Correct@Example.COM "}"#),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["email"], "correct@example.com");
        assert_eq!(json["emailConfirmed"], false);

        let row: (String, Option<String>) =
            sqlx::query_as("SELECT email, email_confirmed_at FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(row, ("correct@example.com".into(), None));
        let audit: (String, String, String) = sqlx::query_as(
            "SELECT actor, action, detail FROM operator_account_audit_events WHERE did = ?",
        )
        .bind(did)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(audit.0, "master-token");
        assert_eq!(audit.1, "email_updated");
        assert!(audit.2.contains("wrong@example.com"));
        assert!(audit.2.contains("correct@example.com"));
    }

    #[tokio::test]
    async fn issues_usable_one_hour_token_without_auditing_plaintext() {
        let state = test_state_with_admin_token().await;
        let did = "did:plc:repair-token";
        insert_account_with_password(
            &state.db,
            did,
            "repair-token.test.example.com",
            "repair-token@example.com",
            "password",
        )
        .await;
        let response = app(state.clone())
            .oneshot(post(
                &format!("/v1/admin/accounts/{did}/reset-token"),
                None,
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let token = json["token"].as_str().unwrap();
        assert_eq!(json["expiresIn"], 3600);

        let (stored_hash, valid_for): (String, i64) = sqlx::query_as(
            "SELECT token_hash, CAST(strftime('%s', expires_at) AS INTEGER) - CAST(strftime('%s', created_at) AS INTEGER) FROM password_reset_tokens WHERE did = ?",
        )
        .bind(did)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(stored_hash, hash_bearer_token(token).unwrap());
        assert_eq!(valid_for, 3600);
        let detail: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM operator_account_audit_events WHERE did = ? AND action = 'reset_token_issued'",
        )
        .bind(did)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(detail, None);
    }

    #[tokio::test]
    async fn repair_routes_require_admin_authentication() {
        let state = test_state_with_admin_token().await;
        let email = app(state.clone())
            .oneshot(post(
                "/v1/admin/accounts/did:plc:nope/email",
                Some(r#"{"email":"valid@example.com"}"#),
                false,
            ))
            .await
            .unwrap();
        assert_eq!(email.status(), StatusCode::UNAUTHORIZED);
        let token = app(state)
            .oneshot(post(
                "/v1/admin/accounts/did:plc:nope/reset-token",
                None,
                false,
            ))
            .await
            .unwrap();
        assert_eq!(token.status(), StatusCode::UNAUTHORIZED);
    }
}
