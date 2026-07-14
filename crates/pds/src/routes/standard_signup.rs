// pattern: Imperative Shell
//
// Standard-client signup interop endpoints. These map ezpds's operator-issued
// claim-code and handle-uniqueness primitives onto the AT Protocol NSIDs used by
// generic signup clients, without changing the custom mobile provisioning flow.

use axum::{
    body::Bytes,
    extract::Query,
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::guards::require_admin_json;
use crate::auth::jwt::AuthScope;
use crate::db::claim_codes::{mint_claim_codes, MintClaimCodesError};

const MAX_INVITE_CODE_COUNT: u32 = 10;
const INVITE_CODE_EXPIRES_IN_HOURS: u32 = 24;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInviteCodeRequest {
    use_count: u32,
    #[allow(dead_code)]
    for_account: Option<String>,
}

#[derive(Serialize)]
pub struct CreateInviteCodeResponse {
    code: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInviteCodesRequest {
    #[serde(default = "default_code_count")]
    code_count: u32,
    use_count: u32,
    #[serde(default)]
    for_accounts: Vec<String>,
}

#[derive(Serialize)]
pub struct CreateInviteCodesResponse {
    codes: Vec<AccountCodes>,
}

#[derive(Serialize)]
pub struct AccountCodes {
    account: String,
    codes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAccountInviteCodesParams {
    #[serde(default = "default_true")]
    include_used: bool,
    #[serde(default = "default_true")]
    create_available: bool,
}

#[derive(Serialize)]
pub struct GetAccountInviteCodesResponse {
    codes: Vec<InviteCodeView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCodeView {
    code: String,
    available: i64,
    disabled: bool,
    for_account: String,
    created_by: String,
    created_at: String,
    uses: Vec<InviteCodeUse>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCodeUse {
    used_by: String,
    used_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckHandleAvailabilityParams {
    handle: String,
    #[allow(dead_code)]
    email: Option<String>,
    #[allow(dead_code)]
    birth_date: Option<String>,
}

#[derive(Serialize)]
pub struct CheckHandleAvailabilityResponse {
    handle: String,
    result: HandleAvailabilityResult,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum HandleAvailabilityResult {
    Available(ResultAvailable),
    Unavailable(ResultUnavailable),
}

#[derive(Serialize)]
pub struct ResultAvailable {
    #[serde(rename = "$type")]
    r#type: &'static str,
}

#[derive(Serialize)]
pub struct ResultUnavailable {
    #[serde(rename = "$type")]
    r#type: &'static str,
    suggestions: Vec<HandleSuggestion>,
}

#[derive(Serialize)]
pub struct HandleSuggestion {
    handle: String,
    method: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSignupQueueResponse {
    activated: bool,
}

fn default_code_count() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

pub async fn create_invite_code(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<CreateInviteCodeResponse>, Response> {
    require_admin_json(method.as_str(), uri.path(), &headers, &body, &state).await?;
    let Json(payload) =
        Json::<CreateInviteCodeRequest>::from_bytes(&body).map_err(IntoResponse::into_response)?;

    create_invite_code_inner(&state, payload)
        .await
        .map_err(IntoResponse::into_response)
}

async fn create_invite_code_inner(
    state: &AppState,
    payload: CreateInviteCodeRequest,
) -> Result<Json<CreateInviteCodeResponse>, ApiError> {
    require_single_use(payload.use_count)?;
    reject_account_bound_invites(payload.for_account.as_deref())?;

    let mut codes = mint_claim_codes(&state.db, 1, INVITE_CODE_EXPIRES_IN_HOURS)
        .await
        .map_err(map_mint_error)?;
    let code = codes.pop().ok_or_else(|| {
        tracing::error!("claim-code mint returned an empty batch for createInviteCode");
        ApiError::new(ErrorCode::InternalError, "failed to mint invite code")
    })?;
    Ok(Json(CreateInviteCodeResponse { code }))
}

pub async fn create_invite_codes(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<CreateInviteCodesResponse>, Response> {
    require_admin_json(method.as_str(), uri.path(), &headers, &body, &state).await?;
    let Json(payload) =
        Json::<CreateInviteCodesRequest>::from_bytes(&body).map_err(IntoResponse::into_response)?;

    create_invite_codes_inner(&state, payload)
        .await
        .map_err(IntoResponse::into_response)
}

async fn create_invite_codes_inner(
    state: &AppState,
    payload: CreateInviteCodesRequest,
) -> Result<Json<CreateInviteCodesResponse>, ApiError> {
    require_single_use(payload.use_count)?;
    validate_code_count(payload.code_count)?;
    if !payload.for_accounts.is_empty() {
        return Err(account_bound_invites_unsupported());
    }

    let accounts = vec![String::new()];
    let total = payload.code_count;

    let mut minted = mint_claim_codes(&state.db, total, INVITE_CODE_EXPIRES_IN_HOURS)
        .await
        .map_err(map_mint_error)?;
    let mut codes = Vec::with_capacity(accounts.len());
    for account in accounts {
        let account_codes = minted.drain(..payload.code_count as usize).collect();
        codes.push(AccountCodes {
            account,
            codes: account_codes,
        });
    }

    Ok(Json(CreateInviteCodesResponse { codes }))
}

pub async fn get_account_invite_codes(
    user: AuthenticatedUser,
    Query(params): Query<GetAccountInviteCodesParams>,
) -> Result<Json<GetAccountInviteCodesResponse>, ApiError> {
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "full access token required",
        ));
    }
    let _ = (params.include_used, params.create_available);

    // ezpds claim codes are operator-issued and not attributed to individual accounts, so
    // authenticated accounts have no self-service invite inventory to list.
    Ok(Json(GetAccountInviteCodesResponse { codes: Vec::new() }))
}

pub async fn check_handle_availability(
    State(state): State<AppState>,
    Query(params): Query<CheckHandleAvailabilityParams>,
) -> Result<Json<CheckHandleAvailabilityResponse>, ApiError> {
    let available = crate::identity::handle::validate_handle(
        &params.handle,
        &state.config.available_user_domains,
        &state.config.reserved_handles,
    )
        .is_ok()
        && !crate::uniqueness::handle_taken(&state.db, &params.handle)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, handle = %params.handle, "failed to check handle availability");
                ApiError::new(ErrorCode::InternalError, "failed to check handle availability")
            })?;

    let result = if available {
        HandleAvailabilityResult::Available(ResultAvailable {
            r#type: "com.atproto.temp.checkHandleAvailability#resultAvailable",
        })
    } else {
        HandleAvailabilityResult::Unavailable(ResultUnavailable {
            r#type: "com.atproto.temp.checkHandleAvailability#resultUnavailable",
            suggestions: Vec::new(),
        })
    };

    Ok(Json(CheckHandleAvailabilityResponse {
        handle: params.handle,
        result,
    }))
}

pub async fn check_signup_queue() -> Json<CheckSignupQueueResponse> {
    Json(CheckSignupQueueResponse { activated: true })
}

fn require_single_use(use_count: u32) -> Result<(), ApiError> {
    if use_count != 1 {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "ezpds invite codes are single-use; useCount must be 1",
        ));
    }
    Ok(())
}

fn validate_code_count(count: u32) -> Result<(), ApiError> {
    if count == 0 || count > MAX_INVITE_CODE_COUNT {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            format!("codeCount must be between 1 and {MAX_INVITE_CODE_COUNT}"),
        ));
    }
    Ok(())
}

fn reject_account_bound_invites(for_account: Option<&str>) -> Result<(), ApiError> {
    if for_account.is_some() {
        return Err(account_bound_invites_unsupported());
    }
    Ok(())
}

fn account_bound_invites_unsupported() -> ApiError {
    ApiError::new(
        ErrorCode::InvalidClaim,
        "account-bound invite codes are not supported by this PDS",
    )
}

fn map_mint_error(error: MintClaimCodesError) -> ApiError {
    match error {
        MintClaimCodesError::Store(e) => {
            tracing::error!(error = %e, "failed to insert invite claim codes");
            ApiError::new(ErrorCode::InternalError, "failed to store invite codes")
        }
        MintClaimCodesError::Exhausted => {
            tracing::error!("failed to generate unique invite codes after retries");
            ApiError::new(
                ErrorCode::InternalError,
                "failed to generate unique invite codes after retries",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::routes::test_utils::{
        access_jwt, app_pass_jwt, insert_account_with_password, test_state_with_admin_token,
    };

    fn authed_post(path: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("Authorization", "Bearer test-admin-token")
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn create_invite_code_mints_claim_code() {
        let state = test_state_with_admin_token().await;
        let db = state.db.clone();

        let response = app(state)
            .oneshot(authed_post(
                "/xrpc/com.atproto.server.createInviteCode",
                r#"{"useCount":1}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let code = json["code"].as_str().expect("code string");
        assert_eq!(code.len(), 6);

        let row: Option<(String,)> = sqlx::query_as("SELECT code FROM claim_codes WHERE code = ?")
            .bind(code)
            .fetch_optional(&db)
            .await
            .unwrap();
        assert!(
            row.is_some(),
            "standard invite code must be backed by claim_codes"
        );
    }

    #[tokio::test]
    async fn create_invite_code_rejects_multi_use() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(authed_post(
                "/xrpc/com.atproto.server.createInviteCode",
                r#"{"useCount":2}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_invite_code_requires_admin_auth_and_mints_nothing() {
        let state = test_state_with_admin_token().await;
        let db = state.db.clone();

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.server.createInviteCode")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"useCount":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claim_codes")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(
            count, 0,
            "unauthorized invite mint must not create claim codes"
        );
    }

    #[tokio::test]
    async fn create_invite_codes_mints_requested_batch() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(authed_post(
                "/xrpc/com.atproto.server.createInviteCodes",
                r#"{"codeCount":2,"useCount":1}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["codes"][0]["codes"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn check_handle_availability_reports_available() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.temp.checkHandleAvailability?handle=alice.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["handle"], "alice.example.com");
        assert_eq!(
            json["result"]["$type"],
            "com.atproto.temp.checkHandleAvailability#resultAvailable"
        );
    }

    #[tokio::test]
    async fn check_handle_availability_reports_taken() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:taken",
            "taken.example.com",
            "taken@example.com",
            "correct horse battery staple",
        )
        .await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.temp.checkHandleAvailability?handle=taken.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["result"]["$type"],
            "com.atproto.temp.checkHandleAvailability#resultUnavailable"
        );
        assert_eq!(json["result"]["suggestions"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn check_signup_queue_is_open() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.temp.checkSignupQueue")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["activated"], true);
    }

    #[tokio::test]
    async fn get_account_invite_codes_requires_auth() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.getAccountInviteCodes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_account_invite_codes_returns_empty_for_full_access_token() {
        let state = test_state().await;
        let token = access_jwt(&state.jwt_secret, "did:plc:invites");

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.getAccountInviteCodes")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["codes"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn get_account_invite_codes_rejects_app_password_token() {
        let state = test_state().await;
        let token = app_pass_jwt(&state.jwt_secret, "did:plc:invites", false);

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.getAccountInviteCodes")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
