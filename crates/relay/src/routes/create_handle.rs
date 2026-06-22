// pattern: Imperative Shell
//
// POST /v1/handles — Initial handle creation for a provisioned account
//
// Inputs:
//   - Authorization: Bearer <session_token>
//   - JSON body: {
//       "account_id": "did:plc:...",
//       "handle": "alice.example.com"
//     }
//
// Processing steps:
//   1. require_session → SessionInfo { did }
//   2. Validate account_id matches session did (prevents acting on other accounts)
//   3. validate_handle(handle, available_user_domains) → 400 INVALID_HANDLE on failure
//   4. INSERT INTO handles (handle, did, created_at) → 409 HANDLE_TAKEN on UNIQUE violation
//   5. If state.dns_provider is Some: call create_record(name, hostname); dns_status = "propagating"
//      If state.dns_provider is None: dns_status = "not_configured"
//   6. Return { "handle": "...", "dns_status": "...", "did": "..." }
//
// Note: INSERT precedes the DNS call (step 4 before step 5) so that a DB row
// without a DNS record is a recoverable/operator-fixable state, whereas a DNS
// record without a DB row would be an invisible orphan.
//
// Outputs (success):  200 { "handle": "...", "dns_status": "not_configured"|"propagating", "did": "..." }
// Outputs (error):    400 INVALID_HANDLE, 401 UNAUTHORIZED, 409 HANDLE_TAKEN,
//                     502 DNS_ERROR, 500 INTERNAL_ERROR

use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::db::dids::update_also_known_as;
use crate::routes::auth::require_session;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateHandleRequest {
    pub account_id: String,
    pub handle: String,
}

#[derive(Serialize)]
pub struct CreateHandleResponse {
    pub handle: String,
    pub dns_status: &'static str,
    pub did: String,
}

pub async fn create_handle_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateHandleRequest>,
) -> Result<Json<CreateHandleResponse>, ApiError> {
    // Step 1: Authenticate via session Bearer token.
    let session = require_session(&headers, &state.db).await?;

    // Step 2: Validate account_id matches the authenticated session.
    if payload.account_id != session.did {
        return Err(ApiError::new(
            ErrorCode::Unauthorized,
            "account_id does not match authenticated session",
        ));
    }

    // Step 3: Validate handle format.
    let name = validate_handle(&payload.handle, &state.config.available_user_domains)
        .map_err(|msg| ApiError::new(ErrorCode::InvalidHandle, msg))?;

    // Step 4: Insert the handle. A UNIQUE violation means the handle is already taken.
    sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
        .bind(&payload.handle)
        .bind(&session.did)
        .execute(&state.db)
        .await
        .map_err(|e| {
            if crate::db::is_unique_violation(&e) {
                return ApiError::new(ErrorCode::HandleTaken, "handle is already taken");
            }
            tracing::error!(error = %e, "failed to insert handle");
            ApiError::new(ErrorCode::InternalError, "failed to register handle")
        })?;

    // Step 4b: Update DID document alsoKnownAs to include the new handle.
    // Fetch all handles for this DID and update the document.
    let handles: Vec<(String,)> = sqlx::query_as("SELECT handle FROM handles WHERE did = ?")
        .bind(&session.did)
        .fetch_all(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to fetch handles for alsoKnownAs update");
            ApiError::new(ErrorCode::InternalError, "failed to update DID document")
        })?;

    let also_known_as: Vec<String> = handles
        .into_iter()
        .map(|(h,)| format!("at://{h}"))
        .collect();

    if let Err(e) = update_also_known_as(&state.db, &session.did, &also_known_as).await {
        // Log the error but don't fail the request — handle is already inserted.
        tracing::error!(
            error = %e,
            did = %session.did,
            handle = %payload.handle,
            "failed to update DID document alsoKnownAs after handle creation"
        );
    }

    // Step 5: Create DNS record if a provider is configured.
    // INSERT precedes this call: a row with no DNS record is recoverable; a DNS record
    // with no row would be an invisible orphan.
    let public_url = &state.config.public_url;
    let hostname = public_url
        .strip_prefix("https://")
        .or_else(|| public_url.strip_prefix("http://"))
        .unwrap_or(public_url.as_str());

    let dns_status = if let Some(provider) = &state.dns_provider {
        provider.create_record(name, hostname).await.map_err(|e| {
            tracing::error!(
                error = %e,
                handle = %payload.handle,
                did = %session.did,
                "DNS record creation failed"
            );
            ApiError::new(ErrorCode::DnsError, "failed to create DNS record")
        })?;
        "propagating"
    } else {
        "not_configured"
    };

    // Step 6: Return the result.
    Ok(Json(CreateHandleResponse {
        handle: payload.handle,
        dns_status,
        did: session.did,
    }))
}

/// Validate a handle string against the server's available user domains.
///
/// A valid handle is `<name>.<domain>` where:
/// - `name` is non-empty, at most 63 characters (RFC 1035 label limit), contains only
///   ASCII alphanumerics and hyphens, and does not start or end with a hyphen.
/// - `domain` is one of the server's `available_user_domains`.
///
/// Returns the `name` portion on success so callers can use it for DNS record creation.
///
/// # Errors
/// Returns a static error message string suitable for surfacing as a 400 body.
fn validate_handle<'a>(
    handle: &'a str,
    available_domains: &[String],
) -> Result<&'a str, &'static str> {
    let dot = handle
        .find('.')
        .ok_or("handle must be in the format <name>.<domain>")?;

    let name = &handle[..dot];
    let domain = &handle[dot + 1..];

    if name.is_empty() {
        return Err("handle name cannot be empty");
    }
    if name.len() > 63 {
        return Err("handle name exceeds maximum DNS label length of 63 characters");
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err("handle name cannot start or end with a hyphen");
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("handle name may only contain letters, digits, and hyphens");
    }
    if domain.is_empty() {
        return Err("handle domain cannot be empty");
    }
    if !available_domains.iter().any(|d| d == domain) {
        return Err("handle domain is not served by this relay");
    }

    Ok(name)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use crate::routes::test_utils::{state_with_err_dns, state_with_ok_dns};
    use crate::routes::token::generate_token;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use uuid::Uuid;

    // ── validate_handle unit tests ─────────────────────────────────────────────

    #[test]
    fn validate_handle_accepts_valid_handle() {
        let domains = vec!["example.com".to_string()];
        assert_eq!(
            validate_handle("alice.example.com", &domains),
            Ok("alice"),
            "valid handle should return the name portion"
        );
    }

    #[test]
    fn validate_handle_rejects_no_dot() {
        let domains = vec!["example.com".to_string()];
        assert!(validate_handle("aliceexample", &domains).is_err());
    }

    #[test]
    fn validate_handle_rejects_empty_name() {
        let domains = vec!["example.com".to_string()];
        assert!(validate_handle(".example.com", &domains).is_err());
    }

    #[test]
    fn validate_handle_rejects_leading_hyphen() {
        let domains = vec!["example.com".to_string()];
        assert!(validate_handle("-alice.example.com", &domains).is_err());
    }

    #[test]
    fn validate_handle_rejects_trailing_hyphen() {
        let domains = vec!["example.com".to_string()];
        assert!(validate_handle("alice-.example.com", &domains).is_err());
    }

    #[test]
    fn validate_handle_rejects_invalid_chars() {
        let domains = vec!["example.com".to_string()];
        assert!(validate_handle("ali_ce.example.com", &domains).is_err());
        assert!(validate_handle("ali ce.example.com", &domains).is_err());
    }

    #[test]
    fn validate_handle_rejects_unavailable_domain() {
        let domains = vec!["example.com".to_string()];
        assert!(validate_handle("alice.other.com", &domains).is_err());
    }

    #[test]
    fn validate_handle_accepts_hyphen_in_middle_of_name() {
        let domains = vec!["example.com".to_string()];
        assert_eq!(
            validate_handle("al-ice.example.com", &domains),
            Ok("al-ice")
        );
    }

    #[test]
    fn validate_handle_rejects_name_exceeding_63_chars() {
        let domains = vec!["example.com".to_string()];
        let long_name = "a".repeat(64);
        assert!(validate_handle(&format!("{long_name}.example.com"), &domains).is_err());
    }

    #[test]
    fn validate_handle_accepts_name_exactly_63_chars() {
        let domains = vec!["example.com".to_string()];
        let name = "a".repeat(63);
        assert!(validate_handle(&format!("{name}.example.com"), &domains).is_ok());
    }

    // ── Integration test helpers ───────────────────────────────────────────────

    struct TestSession {
        did: String,
        session_token: String,
    }

    /// Insert a promoted account and session directly into the DB.
    ///
    /// Skips the full DID ceremony — sets up only what the create_handle handler needs.
    async fn insert_account_and_session(db: &sqlx::SqlitePool) -> TestSession {
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind(format!("{}@test.example.com", &did[8..16]))
        .execute(db)
        .await
        .expect("insert account");

        let token = generate_token();

        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&did)
        .bind(&token.hash)
        .execute(db)
        .await
        .expect("insert session");

        TestSession {
            did,
            session_token: token.plaintext,
        }
    }

    fn create_handle_request(session_token: &str, account_id: &str, handle: &str) -> Request<Body> {
        let body = serde_json::json!({
            "accountId": account_id,
            "handle": handle,
        });
        Request::builder()
            .method("POST")
            .uri("/v1/handles")
            .header("Authorization", format!("Bearer {session_token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    // ── Happy path ─────────────────────────────────────────────────────────────

    /// Valid handle creates a handles row and returns dns_status: "not_configured".
    #[tokio::test]
    async fn happy_path_creates_handle_with_no_dns_provider() {
        let state = test_state().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(&ts.session_token, &ts.did, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["handle"].as_str(), Some(handle.as_str()));
        assert_eq!(body["dns_status"].as_str(), Some("not_configured"));
        assert_eq!(body["did"].as_str(), Some(ts.did.as_str()));

        // Verify handles row was inserted.
        let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        let (stored_did,) = row.expect("handles row should exist");
        assert_eq!(stored_did, ts.did);
    }

    // ── DNS provider tests ─────────────────────────────────────────────────────

    /// DNS provider succeeds: row is inserted, response has dns_status: "propagating".
    #[tokio::test]
    async fn dns_provider_success_returns_propagating_status() {
        let state = state_with_ok_dns().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(&ts.session_token, &ts.did, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["dns_status"].as_str(), Some("propagating"));

        let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(row.is_some(), "handles row must be inserted on DNS success");
    }

    /// DNS provider fails: returns 502 DNS_ERROR; the handles row is inserted before DNS
    /// is attempted and persists (recoverable/retryable by an operator).
    #[tokio::test]
    async fn dns_provider_failure_returns_502_and_row_persists() {
        let state = state_with_err_dns().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(&ts.session_token, &ts.did, &handle))
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

        // INSERT precedes the DNS call: the row is durable even when DNS fails.
        let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
            .bind(&handle)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(
            row.is_some(),
            "handles row is inserted before DNS and persists even when DNS fails"
        );
    }

    // ── Duplicate handle ───────────────────────────────────────────────────────

    /// Creating the same handle twice returns 409 HANDLE_TAKEN.
    #[tokio::test]
    async fn duplicate_handle_returns_409() {
        let state = test_state().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;
        let handle = format!("bob.{}", state.config.available_user_domains[0]);

        // Pre-insert the handle (simulate it already being taken).
        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind(&handle)
            .bind(&ts.did)
            .execute(&db)
            .await
            .expect("pre-insert handle");

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(&ts.session_token, &ts.did, &handle))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "HANDLE_TAKEN");
    }

    // ── Invalid handle format ──────────────────────────────────────────────────

    /// Handle with no dot returns 400 INVALID_HANDLE.
    #[tokio::test]
    async fn invalid_handle_format_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(
                &ts.session_token,
                &ts.did,
                "nodothandle",
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "INVALID_HANDLE");
    }

    /// Handle with a domain not in available_user_domains returns 400.
    #[tokio::test]
    async fn unavailable_domain_returns_400() {
        let state = test_state().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(
                &ts.session_token,
                &ts.did,
                "alice.not-our-domain.com",
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "INVALID_HANDLE");
    }

    // ── Auth failures ──────────────────────────────────────────────────────────

    /// Missing Authorization header returns 401.
    #[tokio::test]
    async fn missing_auth_returns_401() {
        let state = test_state().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/handles")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({"accountId": ts.did, "handle": handle}).to_string(),
            ))
            .unwrap();

        let app = crate::app::app(state);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// account_id that doesn't match the session DID returns 401.
    #[tokio::test]
    async fn mismatched_account_id_returns_401() {
        let state = test_state().await;
        let db = state.db.clone();
        let ts = insert_account_and_session(&db).await;
        let handle = format!("alice.{}", state.config.available_user_domains[0]);

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_handle_request(
                &ts.session_token,
                "did:plc:somebodyelse",
                &handle,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
