// pattern: Imperative Shell
//
// Gathers: admin Bearer token (Authorization header), JSON request body, config, DB pool
// Processes: auth check → handle validation → tier validation → email uniqueness →
//            handle uniqueness → account_id generation → claim code generation →
//            DB transaction (claim_codes + pending_accounts insert)
// Returns: JSON { account_id, did, claim_code, status } on success; ApiError on all failure paths

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::routes::auth::require_admin_token;
use crate::routes::code_gen::generate_code;

const CLAIM_CODE_EXPIRES_IN_HOURS: u32 = 24;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountRequest {
    email: String,
    handle: String,
    tier: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResponse {
    account_id: String,
    did: Option<String>,
    claim_code: String,
    status: String,
}

pub async fn create_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateAccountRequest>,
) -> Result<(StatusCode, Json<CreateAccountResponse>), ApiError> {
    // --- Auth: require matching Bearer token ---
    require_admin_token(&headers, &state)?;

    // --- Validate handle format ---
    if let Err(msg) = validate_handle(&payload.handle) {
        return Err(ApiError::new(ErrorCode::InvalidHandle, msg));
    }

    // --- Validate tier ---
    if !is_valid_tier(&payload.tier) {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "tier must be one of: free, pro, business",
        ));
    }

    // --- Email uniqueness: fast-path rejection before INSERT ---
    if crate::routes::uniqueness::email_taken(&state.db, &payload.email)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to check email uniqueness");
            ApiError::new(ErrorCode::InternalError, "failed to create account")
        })?
    {
        return Err(ApiError::new(
            ErrorCode::AccountExists,
            "an account with this email already exists",
        ));
    }

    // --- Handle uniqueness: fast-path rejection before INSERT ---
    if crate::routes::uniqueness::handle_taken(&state.db, &payload.handle)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to check handle uniqueness");
            ApiError::new(ErrorCode::InternalError, "failed to create account")
        })?
    {
        return Err(ApiError::new(
            ErrorCode::HandleTaken,
            "this handle is already claimed",
        ));
    }

    // --- Insert: generate account_id + claim code, write in one transaction ---
    // Retry up to 3 times on the rare event of a claim code collision.
    let account_id = Uuid::new_v4().to_string();
    let offset = format!("+{CLAIM_CODE_EXPIRES_IN_HOURS} hours");

    for attempt in 0..3_usize {
        let claim_code = generate_code();
        match insert_pending_account(
            &state.db,
            &account_id,
            &payload.email,
            &payload.handle,
            &payload.tier,
            &claim_code,
            &offset,
        )
        .await
        {
            Ok(()) => {
                return Ok((
                    StatusCode::CREATED,
                    Json(CreateAccountResponse {
                        account_id,
                        did: None,
                        claim_code,
                        status: "pending".to_string(),
                    }),
                ))
            }
            Err(e) if crate::db::is_unique_violation(&e) => {
                match unique_violation_column_in_pending(&e) {
                    Some("email") => {
                        return Err(ApiError::new(
                            ErrorCode::AccountExists,
                            "an account with this email already exists",
                        ));
                    }
                    Some("handle") => {
                        return Err(ApiError::new(
                            ErrorCode::HandleTaken,
                            "this handle is already claimed",
                        ));
                    }
                    _ => {
                        // Not a pending_accounts constraint — treat as claim code collision.
                        tracing::warn!(attempt, "claim code collision; retrying");
                        continue;
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to insert pending account");
                return Err(ApiError::new(
                    ErrorCode::InternalError,
                    "failed to create account",
                ));
            }
        }
    }

    tracing::error!("exhausted all claim code generation attempts");
    Err(ApiError::new(
        ErrorCode::InternalError,
        "failed to create account",
    ))
}

/// Validate that a handle string passes basic format checks.
/// ATProto handles are domain names; this enforces only the least-controversial rules
/// (non-empty, ASCII, no whitespace, max length) to avoid incorrect rejections.
/// More thorough validation (segment structure, domain policy) is deferred to a later wave.
pub(crate) fn validate_handle(handle: &str) -> Result<(), &'static str> {
    if handle.is_empty() {
        return Err("handle must not be empty");
    }
    if handle.len() > 253 {
        return Err("handle must be at most 253 characters");
    }
    if !handle.is_ascii() {
        return Err("handle must contain only ASCII characters");
    }
    if handle.chars().any(|c| c.is_ascii_whitespace()) {
        return Err("handle must not contain whitespace");
    }
    Ok(())
}

fn is_valid_tier(tier: &str) -> bool {
    matches!(tier, "free" | "pro" | "business")
}

/// Insert a claim code and its associated pending account in a single transaction.
async fn insert_pending_account(
    db: &sqlx::SqlitePool,
    account_id: &str,
    email: &str,
    handle: &str,
    tier: &str,
    claim_code: &str,
    expires_offset: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await.inspect_err(|e| {
        tracing::error!(error = %e, "failed to begin pending_account transaction");
    })?;

    sqlx::query(
        "INSERT INTO claim_codes (code, expires_at, created_at) \
         VALUES (?, datetime('now', ?), datetime('now'))",
    )
    .bind(claim_code)
    .bind(expires_offset)
    .execute(&mut *tx)
    .await
    .inspect_err(|e| {
        tracing::error!(error = %e, "failed to insert claim_codes row in pending account transaction");
    })?;

    sqlx::query(
        "INSERT INTO pending_accounts (id, email, handle, tier, claim_code, created_at) \
         VALUES (?, ?, ?, ?, ?, datetime('now'))",
    )
    .bind(account_id)
    .bind(email)
    .bind(handle)
    .bind(tier)
    .bind(claim_code)
    .execute(&mut *tx)
    .await
    .inspect_err(|e| {
        tracing::error!(error = %e, "failed to insert pending_accounts row in pending account transaction");
    })?;

    tx.commit().await.inspect_err(|e| {
        tracing::error!(error = %e, "failed to commit pending_account transaction");
    })?;

    Ok(())
}

/// Classify a unique violation from the transaction (which spans claim_codes and
/// pending_accounts). Returns `Some("email")` or `Some("handle")` for pending_accounts
/// violations, `None` (treated as claim_code collision) for everything else.
fn unique_violation_column_in_pending(e: &sqlx::Error) -> Option<&str> {
    crate::db::unique_violation_column(e, "pending_accounts")
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::routes::test_utils::test_state_with_admin_token;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn post_create_account(body: &str, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/accounts")
            .header("Content-Type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn returns_201_with_correct_shape() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_create_account(
                r#"{"email":"alice@example.com","handle":"alice.example.com","tier":"free"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["accountId"].as_str().is_some(),
            "accountId must be present"
        );
        assert_eq!(json["did"], serde_json::Value::Null, "did must be null");
        assert!(
            json["claimCode"].as_str().is_some(),
            "claimCode must be present"
        );
        assert_eq!(json["status"], "pending");
    }

    #[tokio::test]
    async fn claim_code_is_6_char_uppercase_alphanumeric() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_create_account(
                r#"{"email":"bob@example.com","handle":"bob.example.com","tier":"pro"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let code = json["claimCode"].as_str().unwrap();
        assert_eq!(code.len(), 6, "claim code must be 6 chars");
        assert!(
            code.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
            "claim code must be uppercase alphanumeric, got: {code}"
        );
    }

    #[tokio::test]
    async fn records_persisted_in_db() {
        let state = test_state_with_admin_token().await;
        let db = state.db.clone();

        let response = app(state)
            .oneshot(post_create_account(
                r#"{"email":"charlie@example.com","handle":"charlie.example.com","tier":"business"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let account_id = json["accountId"].as_str().unwrap();
        let claim_code = json["claimCode"].as_str().unwrap();

        // pending_accounts row
        let row: (String, String, String, String) = sqlx::query_as(
            "SELECT email, handle, tier, claim_code FROM pending_accounts WHERE id = ?",
        )
        .bind(account_id)
        .fetch_one(&db)
        .await
        .expect("pending_accounts row must exist");

        assert_eq!(row.0, "charlie@example.com");
        assert_eq!(row.1, "charlie.example.com");
        assert_eq!(row.2, "business");
        assert_eq!(row.3, claim_code);

        // claim_codes row with redeemed_at NULL and ~24h expiry
        let within_window: bool = sqlx::query_scalar(
            "SELECT ABS(strftime('%s', expires_at) - strftime('%s', datetime('now', '+24 hours'))) < 5 \
             FROM claim_codes WHERE code = ?",
        )
        .bind(claim_code)
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(
            within_window,
            "claim code must expire approximately 24h from now"
        );
    }

    // ── Duplicate email ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn duplicate_email_in_pending_returns_409() {
        let state = test_state_with_admin_token().await;
        let app = app(state);

        let first = app
            .clone()
            .oneshot(post_create_account(
                r#"{"email":"dup@example.com","handle":"dup1.example.com","tier":"free"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);

        let second = app
            .oneshot(post_create_account(
                r#"{"email":"dup@example.com","handle":"dup2.example.com","tier":"free"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(second.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "ACCOUNT_EXISTS");
    }

    #[tokio::test]
    async fn duplicate_email_in_accounts_returns_409() {
        // email already used by a fully-provisioned account also returns 409
        let state = test_state_with_admin_token().await;

        // Seed a fully-provisioned account directly.
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:existing', 'existing@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let response = app(state)
            .oneshot(post_create_account(
                r#"{"email":"existing@example.com","handle":"new.example.com","tier":"free"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "ACCOUNT_EXISTS");
    }

    // ── Duplicate handle ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn duplicate_handle_in_pending_returns_409() {
        let state = test_state_with_admin_token().await;
        let app = app(state);

        let first = app
            .clone()
            .oneshot(post_create_account(
                r#"{"email":"h1@example.com","handle":"taken.example.com","tier":"free"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);

        let second = app
            .oneshot(post_create_account(
                r#"{"email":"h2@example.com","handle":"taken.example.com","tier":"free"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(second.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "HANDLE_TAKEN");
    }

    #[tokio::test]
    async fn duplicate_handle_in_handles_returns_409() {
        let state = test_state_with_admin_token().await;

        // Seed a fully-provisioned account with an active handle.
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:active1', 'active1@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO handles (handle, did, created_at) \
             VALUES ('active.example.com', 'did:plc:active1', datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let response = app(state)
            .oneshot(post_create_account(
                r#"{"email":"new@example.com","handle":"active.example.com","tier":"free"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "HANDLE_TAKEN");
    }

    // ── Handle validation ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn empty_handle_returns_400() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_create_account(
                r#"{"email":"x@example.com","handle":"","tier":"free"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn non_ascii_handle_returns_400() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_create_account(
                r#"{"email":"x@example.com","handle":"älice.example.com","tier":"free"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn handle_with_whitespace_returns_400() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_create_account(
                r#"{"email":"x@example.com","handle":"alice example.com","tier":"free"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn handle_exceeding_253_chars_returns_400() {
        let long_handle = "a".repeat(254);
        let body = format!(r#"{{"email":"x@example.com","handle":"{long_handle}","tier":"free"}}"#);
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_create_account(&body, Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ── Tier validation ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn invalid_tier_returns_400() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_create_account(
                r#"{"email":"x@example.com","handle":"x.example.com","tier":"enterprise"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ── Missing required fields ───────────────────────────────────────────────

    #[tokio::test]
    async fn missing_email_returns_422() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_create_account(
                r#"{"handle":"x.example.com","tier":"free"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn missing_handle_returns_422() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_create_account(
                r#"{"email":"x@example.com","tier":"free"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn missing_tier_returns_422() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_create_account(
                r#"{"email":"x@example.com","handle":"x.example.com"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    // ── Auth ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn missing_authorization_header_returns_401() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_create_account(
                r#"{"email":"x@example.com","handle":"x.example.com","tier":"free"}"#,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_bearer_token_returns_401() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_create_account(
                r#"{"email":"x@example.com","handle":"x.example.com","tier":"free"}"#,
                Some("wrong-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_token_not_configured_returns_401() {
        let response = app(test_state().await)
            .oneshot(post_create_account(
                r#"{"email":"x@example.com","handle":"x.example.com","tier":"free"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn closed_db_pool_returns_500() {
        let state = test_state_with_admin_token().await;
        state.db.close().await;

        let response = app(state)
            .oneshot(post_create_account(
                r#"{"email":"x@example.com","handle":"x.example.com","tier":"free"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ── Pure unit tests ───────────────────────────────────────────────────────

    #[test]
    fn validate_handle_rejects_empty() {
        assert!(super::validate_handle("").is_err());
    }

    #[test]
    fn validate_handle_rejects_non_ascii() {
        assert!(super::validate_handle("älice.example.com").is_err());
    }

    #[test]
    fn validate_handle_rejects_whitespace() {
        assert!(super::validate_handle("alice example.com").is_err());
        assert!(super::validate_handle("alice\t.example.com").is_err());
    }

    #[test]
    fn validate_handle_rejects_too_long() {
        assert!(super::validate_handle(&"a".repeat(254)).is_err());
    }

    #[test]
    fn validate_handle_accepts_valid_handles() {
        assert!(super::validate_handle("alice.example.com").is_ok());
        assert!(super::validate_handle("malpercio.dev").is_ok());
        assert!(super::validate_handle("a.b").is_ok());
        assert!(super::validate_handle(&"a".repeat(253)).is_ok());
    }

    #[test]
    fn is_valid_tier_accepts_known_tiers() {
        assert!(super::is_valid_tier("free"));
        assert!(super::is_valid_tier("pro"));
        assert!(super::is_valid_tier("business"));
    }

    #[test]
    fn is_valid_tier_rejects_unknown() {
        assert!(!super::is_valid_tier("enterprise"));
        assert!(!super::is_valid_tier(""));
        assert!(!super::is_valid_tier("Free")); // case-sensitive
    }
}
