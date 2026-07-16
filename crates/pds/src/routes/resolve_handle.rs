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
use crate::identity::resolution::resolve_handle_to_did;

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
    let Some(did) = resolve_handle_to_did(&state, &params.handle).await? else {
        return Err(ApiError::new(ErrorCode::HandleNotFound, "handle not found"));
    };

    Ok(Json(ResolveHandleResponse { did }))
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        sync::{Arc, Mutex},
    };

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state, AppState};
    use crate::identity::dns::{DnsError, TxtResolver};
    use crate::identity::well_known::{WellKnownError, WellKnownResolver};
    use crate::routes::test_utils::seed_handle;

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

    /// Always returns a transport-level error; simulates a broken DNS resolver.
    struct ErrTxtResolver;

    impl TxtResolver for ErrTxtResolver {
        fn txt_lookup<'a>(
            &'a self,
            _name: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsError>> + Send + 'a>> {
            Box::pin(async move { Err(DnsError("connection refused".to_string())) })
        }
    }

    /// Records the last name it was queried with; always returns an empty vec.
    struct CapturingTxtResolver {
        last_name: Arc<Mutex<Option<String>>>,
    }

    impl TxtResolver for CapturingTxtResolver {
        fn txt_lookup<'a>(
            &'a self,
            name: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsError>> + Send + 'a>> {
            let captured = self.last_name.clone();
            let name = name.to_string();
            Box::pin(async move {
                *captured.lock().unwrap() = Some(name);
                Ok(vec![])
            })
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

    // ── Local DB priority ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn local_db_takes_priority_over_dns() {
        let state = test_state().await;
        let local_did = "did:plc:localuser123456789012345678";
        let dns_did = "did:plc:dnsuser1234567890123456789";
        seed_handle(&state.db, "alice.test.example.com", local_did).await;
        let state = state_with_dns(state, vec![format!("did={dns_did}")]);

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
        assert_eq!(body["did"], local_did);
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

    /// A DNS resolver error (timeout / SERVFAIL / transport — not NXDOMAIN, which the resolver
    /// already maps to an empty list) must not abort resolution: it falls through to the next
    /// method and, if nothing resolves, returns 404. A 500 here would break the fallback chain
    /// and surface transient DNS failures as server errors.
    #[tokio::test]
    async fn dns_error_falls_through_to_404() {
        let state = AppState {
            txt_resolver: Some(Arc::new(ErrTxtResolver)),
            ..test_state().await
        };

        let response = app(state)
            .oneshot(resolve_handle_request("alice.external.example.com"))
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

    /// A DNS resolver error must not prevent the HTTP well-known fallback from resolving the
    /// handle — the fallback chain continues past a failed DNS lookup.
    #[tokio::test]
    async fn dns_error_falls_through_to_well_known() {
        let did = "did:plc:wellknownuser12345678901234";
        let state = AppState {
            txt_resolver: Some(Arc::new(ErrTxtResolver)),
            well_known_resolver: Some(Arc::new(FixedWellKnownResolver {
                did: Some(did.to_string()),
            })),
            ..test_state().await
        };

        let response = app(state)
            .oneshot(resolve_handle_request("alice.bsky.social"))
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
    async fn dns_lookup_uses_atproto_prefix() {
        let captured = Arc::new(Mutex::new(None::<String>));
        let state = AppState {
            txt_resolver: Some(Arc::new(CapturingTxtResolver {
                last_name: captured.clone(),
            })),
            ..test_state().await
        };

        app(state)
            .oneshot(resolve_handle_request("alice.example.com"))
            .await
            .unwrap();

        let name = captured
            .lock()
            .unwrap()
            .clone()
            .expect("txt_lookup not called");
        assert_eq!(name, "_atproto.alice.example.com");
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
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "HANDLE_NOT_FOUND");
    }

    // ── HTTP well-known fallback ───────────────────────────────────────────────

    #[tokio::test]
    async fn ip_literal_is_rejected_before_network_resolution() {
        let last_name = Arc::new(Mutex::new(None));
        let state = AppState {
            txt_resolver: Some(Arc::new(CapturingTxtResolver {
                last_name: last_name.clone(),
            })),
            ..test_state().await
        };

        let response = app(state)
            .oneshot(resolve_handle_request("169.254.169.254"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(last_name.lock().unwrap().is_none());
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "INVALID_HANDLE");
    }

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
