// pattern: Imperative Shell
//
// Gathers: handle from query param, DID from local handles table, DNS TXT record, or HTTP well-known
// Processes: none (resolution priority is local → DNS TXT → HTTP well-known)
// Returns: JSON { did: "..." } matching com.atproto.identity.resolveHandle Lexicon

use axum::{
    extract::{Query, State},
    Json,
};
use common::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::app::AppState;

#[derive(Deserialize)]
pub struct ResolveHandleQuery {
    pub handle: String,
}

#[derive(Serialize)]
pub struct ResolveHandleResponse {
    pub did: String,
}

pub async fn resolve_handle_handler(
    State(state): State<AppState>,
    Query(params): Query<ResolveHandleQuery>,
) -> Result<Json<ResolveHandleResponse>, ApiError> {
    // 1. Check local handles table.
    let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
        .bind(&params.handle)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, handle = %params.handle, "failed to query handle");
            ApiError::new(ErrorCode::InternalError, "handle lookup failed")
        })?;

    if let Some((did,)) = row {
        return Ok(Json(ResolveHandleResponse { did }));
    }

    // 2. DNS TXT fallback: look for `did=<did>` in `_atproto.<handle>` records.
    if let Some(resolver) = &state.txt_resolver {
        let name = format!("_atproto.{}", params.handle);
        let records = resolver.txt_lookup(&name).await.map_err(|e| {
            tracing::error!(error = %e, handle = %params.handle, "DNS TXT lookup failed");
            ApiError::new(ErrorCode::InternalError, "handle resolution failed")
        })?;

        for record in records {
            if let Some(did) = record.strip_prefix("did=") {
                return Ok(Json(ResolveHandleResponse {
                    did: did.to_string(),
                }));
            }
        }
    }

    // 3. HTTP well-known fallback: GET https://<handle>/.well-known/atproto-did
    if let Some(resolver) = &state.well_known_resolver {
        match resolver.resolve(&params.handle).await {
            Ok(Some(did)) => return Ok(Json(ResolveHandleResponse { did })),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    handle = %params.handle,
                    "HTTP well-known lookup failed"
                );
            }
        }
    }

    Err(ApiError::new(ErrorCode::HandleNotFound, "handle not found"))
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin, sync::Arc};

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state, AppState};
    use crate::dns::{DnsError, TxtResolver, WellKnownError, WellKnownResolver};

    // ── Test doubles ──────────────────────────────────────────────────────────

    /// Returns a fixed list of TXT records for any lookup.
    struct FixedTxtResolver {
        records: Vec<String>,
    }

    impl TxtResolver for FixedTxtResolver {
        fn txt_lookup<'a>(
            &'a self,
            _name: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsError>> + Send + 'a>> {
            let records = self.records.clone();
            Box::pin(async move { Ok(records) })
        }
    }

    fn state_with_dns(state: AppState, records: Vec<String>) -> AppState {
        AppState {
            txt_resolver: Some(Arc::new(FixedTxtResolver { records })),
            ..state
        }
    }

    // ── Well-known test doubles ────────────────────────────────────────────────

    struct FixedWellKnownResolver {
        did: Option<String>,
    }

    impl WellKnownResolver for FixedWellKnownResolver {
        fn resolve<'a>(
            &'a self,
            _handle: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<String>, WellKnownError>> + Send + 'a>>
        {
            let did = self.did.clone();
            Box::pin(async move { Ok(did) })
        }
    }

    fn state_with_well_known(state: AppState, did: Option<String>) -> AppState {
        AppState {
            well_known_resolver: Some(Arc::new(FixedWellKnownResolver { did })),
            ..state
        }
    }

    fn resolve_handle_request(handle: &str) -> Request<Body> {
        Request::builder()
            .uri(format!(
                "/xrpc/com.atproto.identity.resolveHandle?handle={handle}"
            ))
            .body(Body::empty())
            .unwrap()
    }

    async fn seed_handle(db: &sqlx::SqlitePool, handle: &str, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@test.example.com"))
        .execute(db)
        .await
        .expect("insert account");

        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind(handle)
            .bind(did)
            .execute(db)
            .await
            .expect("insert handle");
    }

    // ── Local DB lookup ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn local_handle_resolves_to_did() {
        let state = test_state().await;
        let did = "did:plc:localuser123456789012345678";
        seed_handle(&state.db, "alice.test.example.com", did).await;

        let response = app(state)
            .oneshot(resolve_handle_request("alice.test.example.com"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["did"], did);
    }

    // ── DNS fallback ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn dns_fallback_resolves_did_from_txt_record() {
        let state = test_state().await;
        let external_did = "did:plc:externaluser12345678901234";
        let state = state_with_dns(state, vec![format!("did={external_did}")]);

        let response = app(state)
            .oneshot(resolve_handle_request("alice.external.example.com"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["did"], external_did);
    }

    #[tokio::test]
    async fn dns_fallback_returns_404_when_txt_record_has_no_did_prefix() {
        let state = test_state().await;
        let state = state_with_dns(state, vec!["v=spf1 include:example.com ~all".to_string()]);

        let response = app(state)
            .oneshot(resolve_handle_request("nobody.external.example.com"))
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

    // ── Not found ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn unknown_handle_without_dns_resolver_returns_404() {
        let state = test_state().await; // txt_resolver is None

        let response = app(state)
            .oneshot(resolve_handle_request("nobody.example.com"))
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

    #[tokio::test]
    async fn unknown_handle_with_empty_dns_response_returns_404() {
        let state = state_with_dns(test_state().await, vec![]);

        let response = app(state)
            .oneshot(resolve_handle_request("nobody.example.com"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ── HTTP well-known fallback ───────────────────────────────────────────────

    #[tokio::test]
    async fn well_known_fallback_resolves_did() {
        let did = "did:plc:wellknownuser12345678901234";
        let state = state_with_well_known(test_state().await, Some(did.to_string()));

        let response = app(state)
            .oneshot(resolve_handle_request("jcsalterego.bsky.social"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["did"], did);
    }

    #[tokio::test]
    async fn well_known_fallback_returns_404_when_resolver_returns_none() {
        let state = state_with_well_known(test_state().await, None);

        let response = app(state)
            .oneshot(resolve_handle_request("nobody.bsky.social"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn dns_takes_priority_over_well_known() {
        let dns_did = "did:plc:fromdns123456789012345678";
        let well_known_did = "did:plc:fromwellknown123456789012";
        let state = test_state().await;
        let state = state_with_dns(state, vec![format!("did={dns_did}")]);
        let state = state_with_well_known(state, Some(well_known_did.to_string()));

        let response = app(state)
            .oneshot(resolve_handle_request("alice.external.example.com"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["did"], dns_did);
    }

    // ── Response shape ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn resolve_handle_returns_json_content_type() {
        let state = test_state().await;
        seed_handle(
            &state.db,
            "alice.test.example.com",
            "did:plc:abcdef123456789012345678",
        )
        .await;

        let response = app(state)
            .oneshot(resolve_handle_request("alice.test.example.com"))
            .await
            .unwrap();

        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
    }
}
