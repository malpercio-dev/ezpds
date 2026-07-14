// pattern: Imperative Shell
//
// Custos-managed did:web hosting control surface (MM-279), account-owner authed:
//
//   POST /v1/did-web/hosting   — opt in/out of having Custos serve `.well-known/did.json`
//   POST /v1/did-web/document  — authenticated direct edit of the served DID document
//
// Both are gated to `did:web` accounts: a `did:plc` document lives on plc.directory and is mutated
// through `submitPlcOperation`, never edited here. The document-update path is the deliberately
// non-PLC mutation the issue calls for — it overwrites the stored document directly and emits an
// `#identity` firehose frame so relays re-resolve, the same propagation `updateHandle` and
// `refreshIdentity` use, without any plc.directory round trip.
//
// Auth is `auth::guards::authenticate_account_owner` (wallet session token or full-access
// OAuth/XRPC token; agent-derived and app-password credentials refused) — the same owner guard the
// `/v1/agents` surface uses. These live on the same-origin `/v1/*` surface (no permissive CORS).

use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::guards::{authenticate_account_owner, OwnerAuthError};
use crate::db::dids::{
    did_document_exists, did_web_hosting_enabled, rewrite_did_document, set_did_web_hosting,
};
use common::{ApiError, ErrorCode};

/// Authenticate the account owner and map the neutral rejection into this surface's vocabulary.
/// Mirrors `agents.rs`'s wrapper (routes may not import one another).
async fn authenticate_owner(headers: &HeaderMap, state: &AppState) -> Result<String, ApiError> {
    authenticate_account_owner(headers, state)
        .await
        .map_err(|err| match err {
            OwnerAuthError::Unauthenticated(e) => e,
            OwnerAuthError::AgentDerived => ApiError::new(
                ErrorCode::InsufficientScope,
                "this operation is not available to agent-derived credentials",
            ),
            OwnerAuthError::NotFullAccess => ApiError::new(
                ErrorCode::InvalidToken,
                "a session or full-access token is required",
            ),
        })
}

/// Reject a non-`did:web` caller: managed hosting and direct document edits are only for
/// user-owned-domain `did:web` identities. A `did:plc` account repoints through PLC operations.
fn require_did_web(did: &str) -> Result<(), ApiError> {
    if did.starts_with("did:web:") {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "managed did:web hosting is only available for did:web accounts",
        ))
    }
}

// ── POST /v1/did-web/hosting ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SetHostingRequest {
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct SetHostingResponse {
    pub enabled: bool,
}

pub async fn set_did_web_hosting_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SetHostingRequest>,
) -> Result<Json<SetHostingResponse>, ApiError> {
    let did = authenticate_owner(&headers, &state).await?;
    require_did_web(&did)?;

    // Enabling requires something to serve: a stored DID document must already exist (populated by
    // the account's migration onto Custos). Disabling never needs one.
    if payload.enabled && !did_document_exists(&state.db, &did).await? {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "no stored DID document to serve; complete migration onto this server first",
        ));
    }

    let updated = set_did_web_hosting(&state.db, &did, payload.enabled).await?;
    if !updated {
        // The owner authenticated, so the account exists; a missing row here is a real error.
        return Err(ApiError::new(
            ErrorCode::InternalError,
            "failed to update did:web hosting",
        ));
    }

    Ok(Json(SetHostingResponse {
        enabled: payload.enabled,
    }))
}

// ── POST /v1/did-web/document ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateDocumentRequest {
    pub document: serde_json::Value,
}

#[derive(Serialize)]
pub struct UpdateDocumentResponse {}

pub async fn update_did_web_document_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateDocumentRequest>,
) -> Result<Json<UpdateDocumentResponse>, ApiError> {
    let did = authenticate_owner(&headers, &state).await?;
    require_did_web(&did)?;

    // Only edit the document Custos actually serves: hosting must be enabled. This keeps the stored
    // document from diverging from an externally-authoritative one while serving is off.
    if !did_web_hosting_enabled(&state.db, &did).await? {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "managed did:web hosting is not enabled for this account",
        ));
    }

    // The submitted document must be a JSON object whose `id` is exactly this DID — a direct edit
    // may not re-point the subject.
    let doc_id = payload
        .document
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "document is missing an `id`"))?;
    if doc_id != did {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "document `id` does not match your DID",
        ));
    }

    // Overwrite the stored document (UPDATE-only; the row exists because hosting is enabled, which
    // required a stored document).
    let updated = rewrite_did_document(&state.db, &did, &payload.document).await?;
    if !updated {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "no stored DID document to update",
        ));
    }

    // Announce the identity change so relays re-resolve the served document. `None` handle = "the
    // identity changed, re-resolve" without asserting a specific handle — the honest signal for a
    // direct document edit.
    if let Err(e) = state.firehose.emit_identity(did.clone(), None).await {
        tracing::warn!(
            error = %e,
            did = %did,
            "failed to sequence #identity firehose event after did:web document update (non-fatal)"
        );
    }

    Ok(Json(UpdateDocumentResponse {}))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::app::{app, test_state, AppState};
    use crate::auth::token::generate_token;

    struct TestOwner {
        did: String,
        session_token: String,
    }

    /// Insert a `did:web` account with a stored document and an owner session token.
    async fn seed_did_web_owner(state: &AppState, host: &str, hosting_enabled: bool) -> TestOwner {
        let did = format!("did:web:{host}");
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind(format!("{host}@example.invalid"))
        .execute(&state.db)
        .await
        .expect("insert account");

        if hosting_enabled {
            // Flip the opt-in through the real parameterized toggle rather than an inlined column.
            crate::db::dids::set_did_web_hosting(&state.db, &did, true)
                .await
                .expect("enable hosting");
        }

        let doc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [],
            "service": [],
        });
        sqlx::query(
            "INSERT INTO did_documents (did, document, created_at, updated_at) \
             VALUES (?, ?, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind(doc.to_string())
        .execute(&state.db)
        .await
        .expect("insert did_document");

        let token = generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&did)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .expect("insert session");

        TestOwner {
            did,
            session_token: token.plaintext,
        }
    }

    fn post(uri: &str, token: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn hosting_col(db: &sqlx::SqlitePool, did: &str) -> Option<String> {
        sqlx::query_scalar("SELECT did_web_hosting_enabled_at FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_one(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn enable_hosting_sets_the_flag() {
        let state = test_state().await;
        let owner = seed_did_web_owner(&state, "toggle.example.com", false).await;
        let db = state.db.clone();

        let response = app(state)
            .oneshot(post(
                "/v1/did-web/hosting",
                &owner.session_token,
                serde_json::json!({ "enabled": true }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(hosting_col(&db, &owner.did).await.is_some());
    }

    #[tokio::test]
    async fn enable_hosting_requires_stored_document() {
        let state = test_state().await;
        // A did:web account + session but no did_documents row — nothing to serve.
        let did = "did:web:nodoc.example.com".to_string();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind("nodoc@example.invalid")
        .execute(&state.db)
        .await
        .unwrap();
        let token = generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&did)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .unwrap();
        let db = state.db.clone();

        let response = app(state)
            .oneshot(post(
                "/v1/did-web/hosting",
                &token.plaintext,
                serde_json::json!({ "enabled": true }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // The opt-in flag must not have been set.
        let enabled: Option<String> =
            sqlx::query_scalar("SELECT did_web_hosting_enabled_at FROM accounts WHERE did = ?")
                .bind(&did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(enabled.is_none());
    }

    #[tokio::test]
    async fn disable_hosting_clears_the_flag() {
        let state = test_state().await;
        let owner = seed_did_web_owner(&state, "off.example.com", true).await;
        let db = state.db.clone();

        let response = app(state)
            .oneshot(post(
                "/v1/did-web/hosting",
                &owner.session_token,
                serde_json::json!({ "enabled": false }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(hosting_col(&db, &owner.did).await.is_none());
    }

    #[tokio::test]
    async fn non_did_web_account_is_rejected() {
        let state = test_state().await;
        // A did:plc owner.
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind("plc@example.invalid")
        .execute(&state.db)
        .await
        .unwrap();
        let token = generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&did)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .unwrap();

        let response = app(state)
            .oneshot(post(
                "/v1/did-web/hosting",
                &token.plaintext,
                serde_json::json!({ "enabled": true }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_auth_returns_401() {
        let state = test_state().await;
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/did-web/hosting")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "enabled": true }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn update_document_overwrites_and_emits_identity() {
        let state = test_state().await;
        let owner = seed_did_web_owner(&state, "edit.example.com", true).await;
        let db = state.db.clone();

        let firehose = state.firehose.clone();
        let mut rx = firehose.subscribe();
        let frontier = firehose.current_seq();

        let new_doc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": owner.did,
            "alsoKnownAs": ["at://edited.example.com"],
            "verificationMethod": [],
            "service": [],
        });

        let response = app(state)
            .oneshot(post(
                "/v1/did-web/document",
                &owner.session_token,
                serde_json::json!({ "document": new_doc }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let stored: String = sqlx::query_scalar("SELECT document FROM did_documents WHERE did = ?")
            .bind(&owner.did)
            .fetch_one(&db)
            .await
            .unwrap();
        let stored: serde_json::Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(stored["alsoKnownAs"][0], "at://edited.example.com");

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("identity frame was emitted")
            .expect("receiver not closed");
        let crate::firehose::FirehoseEvent::Identity(identity) = event else {
            panic!("expected an #identity frame, got {event:?}");
        };
        assert_eq!(identity.did, owner.did);
        assert_eq!(identity.seq, frontier + 1);
        drop(firehose);
    }

    #[tokio::test]
    async fn update_document_rejects_mismatched_id() {
        let state = test_state().await;
        let owner = seed_did_web_owner(&state, "mismatch.example.com", true).await;

        let response = app(state)
            .oneshot(post(
                "/v1/did-web/document",
                &owner.session_token,
                serde_json::json!({ "document": { "id": "did:web:someone-else.example.com" } }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn update_document_requires_hosting_enabled() {
        let state = test_state().await;
        let owner = seed_did_web_owner(&state, "nothosting.example.com", false).await;

        let response = app(state)
            .oneshot(post(
                "/v1/did-web/document",
                &owner.session_token,
                serde_json::json!({ "document": { "id": owner.did } }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
