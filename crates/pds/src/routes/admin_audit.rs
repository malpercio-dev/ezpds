// pattern: Imperative Shell
//
// Gathers: admin credentials (master token or signed device request), pagination/filter
//          query params, DB pool
// Processes: admin auth → filtered rowid-cursor page of the server-wide admin audit log
// Returns: JSON audit-event page on success; ApiError on all failure paths

//! GET /v1/admin/audit - Server-wide admin action audit log.

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method, Uri};
use axum::Json;
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::require_admin;
use crate::db::admin_audit::{list_admin_audit_events, AdminAuditAction, AdminAuditFilter};

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 100;

#[derive(Deserialize)]
pub struct AuditQuery {
    limit: Option<i64>,
    /// Opaque cursor from the prior response (the last row's insertion sequence,
    /// exclusive); absent for the first page.
    cursor: Option<String>,
    /// Exact-match action filter (one of the `AdminAuditAction` words); unknown → 400.
    action: Option<String>,
    /// Exact-match actor filter (`master-token`, `device:<id>`, `pairing-code`).
    actor: Option<String>,
    /// Exact-match subject filter (account DID, admin-device id, transfer id, claim code).
    subject: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventView {
    id: String,
    /// The acting credential: `master-token`, `device:<id>`, or `pairing-code`.
    actor: String,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    outcome: String,
    /// Mechanical facts recorded with the action (counts, resulting status), as stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<serde_json::Value>,
    created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditListResponse {
    events: Vec<AuditEventView>,
    /// Present when another page may exist; pass back as the `cursor` query param.
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
}

/// GET /v1/admin/audit?limit=50&cursor=<seq>&action=<word>&actor=<actor>&subject=<subject>
///
/// The unified answer to "what have admins done on this relay?": every privileged mutating
/// admin action — takedowns/restores, credential sweeps, claim-code mints/revokes, device
/// pairings and revocations, transfer cancels, account repairs, crawl requests, signing-key
/// creation — newest first, each attributed to the credential that signed it. Admin-authed:
/// the master token **or** an active companion-app device's signed request
/// ([`require_admin`]); the signature covers the bare path, so paging/filter params vary
/// without re-signing.
pub async fn list_admin_audit(
    State(state): State<AppState>,
    Query(params): Query<AuditQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<AuditListResponse>, ApiError> {
    // Auth first so an unauthenticated caller cannot probe the log's existence or shape.
    require_admin(method.as_str(), uri.path(), &headers, &body, &state).await?;

    // Validate the action filter against the vocabulary — a typo'd filter silently
    // matching nothing would read as "no such events", which is exactly the wrong failure
    // mode for an audit surface.
    let action = params
        .action
        .as_deref()
        .map(|value| {
            AdminAuditAction::from_filter(value)
                .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "unknown action filter"))
        })
        .transpose()?;

    let before_seq = params
        .cursor
        .as_deref()
        .map(|raw| {
            raw.parse::<i64>()
                .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "malformed cursor"))
        })
        .transpose()?;

    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let filter = AdminAuditFilter {
        action: action.map(AdminAuditAction::as_str),
        actor: params.actor.as_deref(),
        subject: params.subject.as_deref(),
    };

    let rows = list_admin_audit_events(&state.db, filter, before_seq, limit).await?;

    // A full page means more rows may follow — surface the last seq as the next cursor.
    let cursor = (rows.len() as i64 == limit)
        .then(|| rows.last().map(|r| r.seq.to_string()))
        .flatten();
    let events = rows
        .into_iter()
        .map(|row| AuditEventView {
            id: row.id,
            actor: row.actor,
            action: row.action,
            subject: row.subject,
            outcome: row.outcome,
            // Stored as compact JSON; re-parse so the response carries structure, not a
            // doubly-encoded string. A row that somehow holds non-JSON is surfaced verbatim.
            detail: row
                .detail
                .map(|raw| serde_json::from_str(&raw).unwrap_or(serde_json::Value::String(raw))),
            created_at: row.created_at,
        })
        .collect();

    Ok(Json(AuditListResponse { events, cursor }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
    use tower::ServiceExt;

    use crate::db::admin_audit::{record_admin_audit_event, AdminAuditAction};
    use crate::routes::test_utils::{body_json, test_state_with_admin_token};

    const ADMIN: &str = "test-admin-token";

    async fn get_audit(
        app: &axum::Router,
        query: &str,
        token: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/v1/admin/audit{query}"));
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

    #[tokio::test]
    async fn missing_token_returns_401() {
        let state = test_state_with_admin_token().await;
        let app = crate::app::app(state);
        let (status, _) = get_audit(&app, "", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unknown_action_filter_returns_400() {
        let state = test_state_with_admin_token().await;
        let app = crate::app::app(state);
        let (status, body) = get_audit(&app, "?action=banned", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn malformed_cursor_returns_400() {
        let state = test_state_with_admin_token().await;
        let app = crate::app::app(state);
        let (status, body) = get_audit(&app, "?cursor=not-a-seq", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn lists_newest_first_with_filters_and_cursor() {
        let state = test_state_with_admin_token().await;
        record_admin_audit_event(
            &state.db,
            "master-token",
            AdminAuditAction::AccountTakedown,
            Some("did:plc:aud_a"),
            "ok",
            Some(r#"{"resultingStatus":"takendown"}"#),
        )
        .await
        .unwrap();
        record_admin_audit_event(
            &state.db,
            "device:aud-dev-1",
            AdminAuditAction::CredentialsRevoked,
            Some("did:plc:aud_a"),
            "ok",
            None,
        )
        .await
        .unwrap();
        record_admin_audit_event(
            &state.db,
            "master-token",
            AdminAuditAction::RequestCrawl,
            None,
            "ok",
            Some(r#"{"requested":1,"accepted":1}"#),
        )
        .await
        .unwrap();
        let app = crate::app::app(state);

        // Newest first, with structural (not doubly-encoded) detail.
        let (status, body) = get_audit(&app, "", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        let events = body["events"].as_array().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["action"], "request_crawl");
        assert_eq!(events[0]["detail"]["accepted"], 1);
        assert!(events[0].get("subject").is_none());
        assert_eq!(events[2]["action"], "account_takedown");
        assert_eq!(events[2]["detail"]["resultingStatus"], "takendown");
        assert!(body.get("cursor").is_none());

        // Filters.
        let (status, body) = get_audit(&app, "?actor=device:aud-dev-1", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        let events = body["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["action"], "credentials_revoked");

        let (status, body) = get_audit(&app, "?subject=did:plc:aud_a", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["events"].as_array().unwrap().len(), 2);

        // Cursor pagination.
        let (status, page1) = get_audit(&app, "?limit=2", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page1["events"].as_array().unwrap().len(), 2);
        let cursor = page1["cursor"].as_str().unwrap().to_string();
        let (status, page2) =
            get_audit(&app, &format!("?limit=2&cursor={cursor}"), Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        let events2 = page2["events"].as_array().unwrap();
        assert_eq!(events2.len(), 1);
        assert_eq!(events2[0]["action"], "account_takedown");
        assert!(page2.get("cursor").is_none());
    }

    #[tokio::test]
    async fn admin_actions_land_in_the_log_attributed() {
        // End-to-end through the HTTP surface: a device revocation performed with the
        // master token must surface in the audit log attributed to it — and the
        // idempotent repeat must not write a second event.
        use crate::db::admin_devices::{insert_device, NewAdminDevice};

        let state = test_state_with_admin_token().await;
        let keypair = crypto::generate_p256_keypair().unwrap();
        insert_device(
            &state.db,
            &NewAdminDevice {
                id: "aud-target-dev",
                label: "Operator iPhone",
                public_key: &keypair.key_id.0,
                platform: "ios",
            },
        )
        .await
        .unwrap();
        let app = crate::app::app(state);

        for _ in 0..2 {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(http::Method::POST)
                        .uri("/v1/admin/devices/aud-target-dev/revoke")
                        .header("Authorization", format!("Bearer {ADMIN}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let (status, body) = get_audit(&app, "?action=device_revoked", Some(ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        let events = body["events"].as_array().unwrap();
        assert_eq!(events.len(), 1, "idempotent repeat writes no second event");
        assert_eq!(events[0]["actor"], "master-token");
        assert_eq!(events[0]["subject"], "aud-target-dev");
        assert_eq!(events[0]["outcome"], "revoked");
    }

    #[tokio::test]
    async fn device_signed_actions_are_attributed_to_the_device() {
        use crate::auth::guards::{
            admin_request_sign_string, ADMIN_DEVICE_HEADER, ADMIN_NONCE_HEADER,
            ADMIN_SIGNATURE_HEADER, ADMIN_TIMESTAMP_HEADER,
        };
        use crate::db::admin_devices::{insert_device, NewAdminDevice};
        use std::time::{SystemTime, UNIX_EPOCH};

        // A state with NO master token: the acting device is the only credential.
        let state = crate::app::test_state().await;
        let keypair = crypto::generate_p256_keypair().unwrap();
        let acting = uuid::Uuid::new_v4().to_string();
        insert_device(
            &state.db,
            &NewAdminDevice {
                id: &acting,
                label: "Acting iPhone",
                public_key: &keypair.key_id.0,
                platform: "ios",
            },
        )
        .await
        .unwrap();
        let target_keypair = crypto::generate_p256_keypair().unwrap();
        insert_device(
            &state.db,
            &NewAdminDevice {
                id: "aud-peer-dev",
                label: "Peer iPhone",
                public_key: &target_keypair.key_id.0,
                platform: "ios",
            },
        )
        .await
        .unwrap();
        let app = crate::app::app(state);

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let signed = |method: &str, path: &str, nonce: &str| {
            let sign_string = admin_request_sign_string(method, path, ts, nonce, b"");
            crate::routes::test_utils::sign_p256(&keypair, sign_string.as_bytes())
        };

        // The acting device revokes its peer via a signed request.
        let revoke_path = "/v1/admin/devices/aud-peer-dev/revoke";
        let signature = signed("POST", revoke_path, "aud-nonce-revoke");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(revoke_path)
                    .header(ADMIN_DEVICE_HEADER, &acting)
                    .header(ADMIN_TIMESTAMP_HEADER, ts.to_string())
                    .header(ADMIN_NONCE_HEADER, "aud-nonce-revoke")
                    .header(ADMIN_SIGNATURE_HEADER, signature)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The audit log — read via a signed request too (the signature covers the bare
        // path, so filter params ride along unsigned) — attributes it to the device.
        let audit_path = "/v1/admin/audit";
        let signature = signed("GET", audit_path, "aud-nonce-read");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("{audit_path}?action=device_revoked"))
                    .header(ADMIN_DEVICE_HEADER, &acting)
                    .header(ADMIN_TIMESTAMP_HEADER, ts.to_string())
                    .header(ADMIN_NONCE_HEADER, "aud-nonce-read")
                    .header(ADMIN_SIGNATURE_HEADER, signature)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let events = body["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["actor"], format!("device:{acting}"));
        assert_eq!(events[0]["subject"], "aud-peer-dev");
    }
}
