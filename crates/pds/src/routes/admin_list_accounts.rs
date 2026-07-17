// pattern: Imperative Shell
//
// Gathers: admin credentials (master token or signed device request), pagination/filter
//          query params, DB pool, config quota
// Processes: admin auth → filtered cursor page of accounts (flagged first) with per-row
//            blob storage and in-force labeler flags
// Returns: JSON account page on success; ApiError on all failure paths

//! GET /v1/admin/accounts - Operator account listing/search with pagination.

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method, Uri};
use axum::Json;
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::require_admin;
use crate::db::accounts::AccountLifecycle;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 100;

#[derive(Deserialize)]
pub struct ListAccountsParams {
    limit: Option<i64>,
    cursor: Option<String>,
    /// Derived-lifecycle filter: `active`, `deactivated`, `suspended`, or `takendown`.
    status: Option<String>,
    /// Literal substring match against the DID or any of the account's handles.
    q: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountEntry {
    did: String,
    /// The account's first-created handle, or `null` when it has none.
    handle: Option<String>,
    created_at: String,
    /// Derived lifecycle status. Unlike the lexicon sync endpoints (where `active` is
    /// expressed by omitting `status`), the operator list always states it explicitly.
    status: &'static str,
    /// Total bytes of the account's owned blobs.
    total_bytes: i64,
    /// `total_bytes` as a percentage of the response-level `quota_bytes` (0.0 when the
    /// quota is 0). Carried per row so the console renders a capacity readout per account
    /// without a per-account storage round-trip.
    quota_used_pct: f64,
    /// Labels currently in force on this account from watched labelers, newest first.
    /// Empty for an unflagged account (and always empty when labeler watching is off).
    flags: Vec<AccountFlag>,
}

/// One in-force label on an account, as observed from a watched labeler.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountFlag {
    /// The label value (e.g. `spam`, `!hide`).
    val: String,
    /// DID of the labeler that applied the label.
    labeler_did: String,
    /// The labeler's label-creation timestamp.
    cts: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAccountsResponse {
    accounts: Vec<AccountEntry>,
    /// The per-account storage quota in bytes (`[blobs] max_storage_per_account`). One
    /// configured value applies to every account in v0.1, so it is stated once here rather
    /// than repeated per row.
    quota_bytes: i64,
    /// Accounts matching the current `status`/`q` filters that carry at least one flag —
    /// the console's badge count, stated per response because flagged accounts may sit on
    /// later pages.
    flagged_total: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
}

/// Parse an opaque page cursor (`<0|1>:<did>` — the previous page's last row's flagged bit
/// and DID; the sort key is two-dimensional, so both halves are needed to resume).
///
/// A malformed cursor (including one minted before flagged-first ordering existed, which
/// was a bare DID) restarts from the first page rather than erroring: the caller re-sees
/// rows once and pagination proceeds normally with freshly minted cursors.
fn parse_cursor(raw: &str) -> Option<(bool, &str)> {
    let (flag, did) = raw.split_once(':')?;
    let flagged = match flag {
        "1" => true,
        "0" => false,
        _ => return None,
    };
    (!did.is_empty() && did.starts_with("did:")).then_some((flagged, did))
}

/// GET /v1/admin/accounts?limit=50&cursor=<cursor>&status=<lifecycle>&q=<term>
///
/// Operator account listing/search with cursor pagination — the console's entry point for
/// all per-account work, replacing pasted DIDs. Flagged accounts (any in-force label from
/// a watched labeler) sort first, DID order within each group, turning the roster into a
/// triage view; each row carries its flags and the response carries `flaggedTotal` for the
/// badge. Includes accounts in every lifecycle state (and those without a repo).
/// Admin-authed: the master token **or** an active companion-app device's signed request
/// ([`require_admin`]).
pub async fn list_accounts(
    State(state): State<AppState>,
    Query(params): Query<ListAccountsParams>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ListAccountsResponse>, ApiError> {
    // Auth first so an unauthenticated caller cannot probe which accounts exist.
    require_admin(method.as_str(), uri.path(), &headers, &body, &state).await?;

    let status = params
        .status
        .as_deref()
        .map(|s| {
            AccountLifecycle::from_status_filter(s).ok_or_else(|| {
                ApiError::new(
                    ErrorCode::InvalidRequest,
                    "status must be one of: active, deactivated, suspended, takendown",
                )
            })
        })
        .transpose()?;

    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let cursor = params.cursor.as_deref().and_then(parse_cursor);
    // A blank search box means "no filter", not "match the empty substring everywhere".
    let q = params.q.as_deref().map(str::trim).filter(|t| !t.is_empty());

    let rows = crate::db::accounts::list_accounts_admin(&state.db, cursor, limit, status, q)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to list accounts");
            ApiError::new(ErrorCode::InternalError, "failed to list accounts")
        })?;

    // A full page means more rows may follow — surface the last row's (flagged, did)
    // position as the next cursor.
    let next_cursor = (rows.len() as i64 == limit)
        .then(|| {
            rows.last()
                .map(|r| format!("{}:{}", u8::from(r.flagged), r.did))
        })
        .flatten();

    let flagged_total = crate::db::accounts::count_accounts_admin_flagged(&state.db, status, q)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to count flagged accounts");
            ApiError::new(ErrorCode::InternalError, "failed to list accounts")
        })?;

    // One query for the whole page's flags (empty map when nothing is flagged).
    let page_dids: Vec<String> = rows.iter().map(|r| r.did.clone()).collect();
    let mut flags_by_did = crate::db::account_labels::labels_for_dids(&state.db, &page_dids)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to load account labels");
            ApiError::new(ErrorCode::InternalError, "failed to list accounts")
        })?;

    // Quota is u64 in config; clamp into i64 for the JSON number (1 GiB default is far below
    // i64::MAX, and an operator would not set a quota anywhere near it).
    let quota_bytes = i64::try_from(state.config.blobs.max_storage_per_account).unwrap_or(i64::MAX);

    let accounts = rows
        .into_iter()
        .map(|row| {
            let quota_used_pct = if quota_bytes > 0 {
                (row.blob_bytes as f64 / quota_bytes as f64) * 100.0
            } else {
                0.0
            };
            let flags = flags_by_did
                .remove(&row.did)
                .unwrap_or_default()
                .into_iter()
                .map(|label| AccountFlag {
                    val: label.val,
                    labeler_did: label.labeler_did,
                    cts: label.cts,
                })
                .collect();
            AccountEntry {
                did: row.did,
                handle: row.handle,
                created_at: row.created_at,
                status: row.lifecycle.as_status_str().unwrap_or("active"),
                total_bytes: row.blob_bytes,
                quota_used_pct,
                flags,
            }
        })
        .collect();

    Ok(Json(ListAccountsResponse {
        accounts,
        quota_bytes,
        flagged_total,
        cursor: next_cursor,
    }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
    use tower::ServiceExt;

    use crate::routes::test_utils::{body_json, test_state_with_admin_token};

    const ADMIN: &str = "test-admin-token";

    async fn list(
        app: &axum::Router,
        query: &str,
        token: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/v1/admin/accounts{query}"));
        if let Some(token) = token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        let resp = app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    async fn insert_account(db: &sqlx::SqlitePool, did: &str) {
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

    #[tokio::test]
    async fn missing_token_returns_401() {
        let state = test_state_with_admin_token().await;
        let app = crate::app::app(state);
        let (status, _) = list(&app, "", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    async fn insert_label(db: &sqlx::SqlitePool, did: &str, labeler: &str, val: &str, cts: &str) {
        sqlx::query("INSERT INTO account_labels (did, labeler_did, val, cts) VALUES (?, ?, ?, ?)")
            .bind(did)
            .bind(labeler)
            .bind(val)
            .bind(cts)
            .execute(db)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn empty_pds_returns_empty_list_with_quota() {
        let state = test_state_with_admin_token().await;
        let quota = state.config.blobs.max_storage_per_account as i64;
        let app = crate::app::app(state);

        let (status, body) = list(&app, "", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["accounts"].as_array().unwrap().len(), 0);
        assert_eq!(body["quotaBytes"], quota);
        assert_eq!(body["flaggedTotal"], 0);
        assert!(body.get("cursor").is_none());
    }

    #[tokio::test]
    async fn unknown_status_filter_returns_400() {
        let state = test_state_with_admin_token().await;
        let app = crate::app::app(state);
        let (status, body) = list(&app, "?status=banned", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn lists_accounts_with_status_and_quota_fields() {
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:ala_one").await;
        insert_account(&state.db, "did:plc:ala_two").await;
        sqlx::query("UPDATE accounts SET taken_down_at = datetime('now') WHERE did = ?")
            .bind("did:plc:ala_two")
            .execute(&state.db)
            .await
            .unwrap();
        crate::db::blobs::insert_blob(
            &state.db,
            "bafalablob",
            "did:plc:ala_one",
            "image/jpeg",
            500,
            "blobs/xx/bafalablob",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();
        let quota = state.config.blobs.max_storage_per_account as i64;
        let app = crate::app::app(state);

        let (status, body) = list(&app, "", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        let accounts = body["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0]["did"], "did:plc:ala_one");
        assert_eq!(accounts[0]["status"], "active");
        assert_eq!(accounts[0]["totalBytes"], 500);
        assert!(accounts[0]["handle"].is_null());
        let expected_pct = (500.0 / quota as f64) * 100.0;
        assert!((accounts[0]["quotaUsedPct"].as_f64().unwrap() - expected_pct).abs() < 1e-9);
        assert_eq!(accounts[1]["did"], "did:plc:ala_two");
        assert_eq!(accounts[1]["status"], "takendown");
        assert_eq!(accounts[1]["totalBytes"], 0);
        assert_eq!(accounts[1]["quotaUsedPct"], 0.0);
        // No labeler flags anywhere: every row carries an empty flags array.
        assert_eq!(accounts[0]["flags"].as_array().unwrap().len(), 0);
        assert_eq!(body["flaggedTotal"], 0);
    }

    #[tokio::test]
    async fn flagged_accounts_sort_first_with_their_flags() {
        let state = test_state_with_admin_token().await;
        // DID order alone would put aaa first; the flag on zzz must override it.
        insert_account(&state.db, "did:plc:ala_fl_aaa").await;
        insert_account(&state.db, "did:plc:ala_fl_zzz").await;
        insert_label(
            &state.db,
            "did:plc:ala_fl_zzz",
            "did:plc:labeler",
            "spam",
            "2026-01-05T00:00:00Z",
        )
        .await;
        insert_label(
            &state.db,
            "did:plc:ala_fl_zzz",
            "did:plc:labeler",
            "!hide",
            "2026-01-06T00:00:00Z",
        )
        .await;
        let app = crate::app::app(state);

        let (status, body) = list(&app, "", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        let accounts = body["accounts"].as_array().unwrap();
        assert_eq!(accounts[0]["did"], "did:plc:ala_fl_zzz");
        assert_eq!(accounts[1]["did"], "did:plc:ala_fl_aaa");
        assert_eq!(body["flaggedTotal"], 1);

        // Flags carry value + labeler + time, newest first.
        let flags = accounts[0]["flags"].as_array().unwrap();
        assert_eq!(flags.len(), 2);
        assert_eq!(flags[0]["val"], "!hide");
        assert_eq!(flags[0]["labelerDid"], "did:plc:labeler");
        assert_eq!(flags[0]["cts"], "2026-01-06T00:00:00Z");
        assert_eq!(flags[1]["val"], "spam");
    }

    #[tokio::test]
    async fn paginates_across_the_flagged_boundary() {
        let state = test_state_with_admin_token().await;
        for did in ["did:plc:ala_fb_a", "did:plc:ala_fb_b", "did:plc:ala_fb_c"] {
            insert_account(&state.db, did).await;
        }
        insert_label(
            &state.db,
            "did:plc:ala_fb_c",
            "did:plc:labeler",
            "spam",
            "2026-01-01T00:00:00Z",
        )
        .await;
        let app = crate::app::app(state);

        // Page 1: the flagged account, then the first unflagged one.
        let (status, page1) = list(&app, "?limit=2", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        let accounts1 = page1["accounts"].as_array().unwrap();
        assert_eq!(accounts1[0]["did"], "did:plc:ala_fb_c");
        assert_eq!(accounts1[1]["did"], "did:plc:ala_fb_a");
        let cursor = page1["cursor"].as_str().unwrap();
        assert_eq!(cursor, "0:did:plc:ala_fb_a");

        // Page 2 resumes inside the unflagged group without repeating the flagged row.
        let (status, page2) = list(&app, &format!("?limit=2&cursor={cursor}"), Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        let accounts2 = page2["accounts"].as_array().unwrap();
        assert_eq!(accounts2.len(), 1);
        assert_eq!(accounts2[0]["did"], "did:plc:ala_fb_b");
        assert!(page2.get("cursor").is_none());
    }

    #[tokio::test]
    async fn malformed_cursor_restarts_from_the_first_page() {
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:ala_mc").await;
        let app = crate::app::app(state);

        // A pre-flagged-ordering cursor was a bare DID; it restarts rather than erroring.
        let (status, body) = list(&app, "?cursor=did:plc:ala_mc", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["accounts"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn filters_by_status_and_search_term() {
        let state = test_state_with_admin_token().await;
        insert_account(&state.db, "did:plc:ala_f_active").await;
        insert_account(&state.db, "did:plc:ala_f_suspended").await;
        sqlx::query("UPDATE accounts SET suspended_at = datetime('now') WHERE did = ?")
            .bind("did:plc:ala_f_suspended")
            .execute(&state.db)
            .await
            .unwrap();
        let app = crate::app::app(state);

        let (status, body) = list(&app, "?status=suspended", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        let accounts = body["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0]["did"], "did:plc:ala_f_suspended");

        let (status, body) = list(&app, "?q=f_active", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        let accounts = body["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0]["did"], "did:plc:ala_f_active");

        // Blank q is no filter, not match-nothing.
        let (status, body) = list(&app, "?q=", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["accounts"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn paginates_with_cursor() {
        let state = test_state_with_admin_token().await;
        for did in ["did:plc:ala_pg_a", "did:plc:ala_pg_b", "did:plc:ala_pg_c"] {
            insert_account(&state.db, did).await;
        }
        let app = crate::app::app(state);

        let (status, page1) = list(&app, "?limit=2", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        let accounts1 = page1["accounts"].as_array().unwrap();
        assert_eq!(accounts1.len(), 2);
        let cursor = page1["cursor"].as_str().unwrap();
        assert_eq!(cursor, "0:did:plc:ala_pg_b");

        let (status, page2) = list(&app, &format!("?limit=2&cursor={cursor}"), Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        let accounts2 = page2["accounts"].as_array().unwrap();
        assert_eq!(accounts2.len(), 1);
        assert_eq!(accounts2[0]["did"], "did:plc:ala_pg_c");
        assert!(page2.get("cursor").is_none());
    }

    #[tokio::test]
    async fn signed_device_request_lists_accounts() {
        use crate::auth::guards::{
            admin_request_sign_string, ADMIN_DEVICE_HEADER, ADMIN_NONCE_HEADER,
            ADMIN_SIGNATURE_HEADER, ADMIN_TIMESTAMP_HEADER,
        };
        use crate::db::admin_devices::{insert_device, NewAdminDevice};
        use std::time::{SystemTime, UNIX_EPOCH};

        // A state with NO master token: proves the device path is independent of it.
        let state = crate::app::test_state().await;
        let keypair = crypto::generate_p256_keypair().unwrap();
        let device_id = uuid::Uuid::new_v4().to_string();
        insert_device(
            &state.db,
            &NewAdminDevice {
                id: &device_id,
                label: "Operator iPhone",
                public_key: &keypair.key_id.0,
                platform: "ios",
            },
        )
        .await
        .unwrap();
        insert_account(&state.db, "did:plc:ala_signed").await;

        // The signature covers the bare path only — the query string can vary per page
        // without re-signing, matching how the companion app appends cursor/filter params.
        let path = "/v1/admin/accounts";
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let nonce = "list-accounts-nonce-1";
        let sign_string = admin_request_sign_string("GET", path, ts, nonce, b"");
        let signature = crate::routes::test_utils::sign_p256(&keypair, sign_string.as_bytes());

        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("{path}?limit=10"))
            .header(ADMIN_DEVICE_HEADER, &device_id)
            .header(ADMIN_TIMESTAMP_HEADER, ts.to_string())
            .header(ADMIN_NONCE_HEADER, nonce)
            .header(ADMIN_SIGNATURE_HEADER, signature)
            .body(Body::empty())
            .unwrap();

        let response = crate::app::app(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        let accounts = body["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0]["did"], "did:plc:ala_signed");
    }
}
