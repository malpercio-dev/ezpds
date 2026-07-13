// pattern: Imperative Shell
//
// Gathers: request host (forwarded/Host header or URI authority)
// Processes: host → did:web:{host} → opted-in, active, document-bearing account (single gated read)
// Returns: 200 application/did+json with the stored DID document, or 404 if the host is not an
//          opted-in Custos-hosted did:web account
//
// This is the serving half of Custos-managed did:web hosting (MM-279): the operator (and, later,
// any user-owned domain) can route `https://{host}/.well-known/did.json` here so the DID document
// is served by Custos instead of a standalone web server. Host-keyed exactly like
// `atproto_did.rs`'s `.well-known/atproto-did`; the opt-in gate lives in
// `db::dids::serve_hosted_did_document`, so a host that hasn't enabled hosting 404s identically to
// an unknown one (no opt-in existence oracle).

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};

use crate::app::AppState;
use crate::request_host::request_host;

/// Map a request host to the `did:web` DID it would identify. The host is lowercased first — `Host`
/// and `X-Forwarded-Host` are case-insensitive, but a did:web DID is a lowercased hostname, so a
/// mixed-case request must normalise to the same DID the account was minted with. A port's `:` is
/// then percent-encoded per the did:web method spec (`did:web:host%3A8080`), matching
/// `Config::resolve_server_did`.
fn host_to_did_web(host: &str) -> String {
    format!("did:web:{}", host.to_ascii_lowercase().replace(':', "%3A"))
}

pub async fn did_json_handler(
    headers: HeaderMap,
    uri: Uri,
    State(state): State<AppState>,
) -> Response {
    let Some(host) = request_host(&headers, &uri) else {
        // No Host/:authority at all — not resolvable to a did:web DID.
        return StatusCode::BAD_REQUEST.into_response();
    };
    let did = host_to_did_web(&host);

    match crate::db::dids::serve_hosted_did_document(&state.db, &did).await {
        Ok(Some(document)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/did+json")],
            document.to_string(),
        )
            .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => e.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state, AppState};

    /// Insert an opted-in `did:web:{host}` account with a stored DID document.
    async fn seed_hosted_did_web(
        state: &AppState,
        host: &str,
        document: serde_json::Value,
    ) -> String {
        let did = format!("did:web:{host}");
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, did_web_hosting_enabled_at, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind(format!("{host}@example.invalid"))
        .execute(&state.db)
        .await
        .expect("insert account");

        sqlx::query(
            "INSERT INTO did_documents (did, document, created_at, updated_at) \
             VALUES (?, ?, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind(document.to_string())
        .execute(&state.db)
        .await
        .expect("insert did_document");

        did
    }

    fn did_json_request(host: &str) -> Request<Body> {
        Request::builder()
            .uri("/.well-known/did.json")
            .header("host", host)
            .body(Body::empty())
            .unwrap()
    }

    fn sample_doc(did: &str) -> serde_json::Value {
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "alsoKnownAs": ["at://example.com"],
            "verificationMethod": [],
            "service": [],
        })
    }

    #[tokio::test]
    async fn opted_in_host_returns_document() {
        let state = test_state().await;
        let did = "did:web:example.com";
        seed_hosted_did_web(&state, "example.com", sample_doc(did)).await;

        let response = app(state)
            .oneshot(did_json_request("example.com"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/did+json",
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let served: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(served["id"], did);
    }

    #[tokio::test]
    async fn forwarded_host_takes_precedence() {
        let state = test_state().await;
        let did = "did:web:example.com";
        seed_hosted_did_web(&state, "example.com", sample_doc(did)).await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/.well-known/did.json")
                    .header("host", "internal.railway.local")
                    .header("x-forwarded-host", "example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn mixed_case_host_normalises_to_lowercase_did() {
        let state = test_state().await;
        let did = "did:web:example.com";
        seed_hosted_did_web(&state, "example.com", sample_doc(did)).await;

        // A case-insensitive Host header must still resolve to the lowercased did:web DID.
        let response = app(state)
            .oneshot(did_json_request("Example.COM"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_host_returns_404() {
        let state = test_state().await;
        let response = app(state)
            .oneshot(did_json_request("nobody.example.com"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn account_without_opt_in_returns_404() {
        let state = test_state().await;
        // Account + document exist, but hosting was never enabled.
        let did = "did:web:optout.example.com";
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind("optout@example.invalid")
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO did_documents (did, document, created_at, updated_at) \
             VALUES (?, ?, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(sample_doc(did).to_string())
        .execute(&state.db)
        .await
        .unwrap();

        let response = app(state)
            .oneshot(did_json_request("optout.example.com"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn deactivated_account_is_not_served() {
        let state = test_state().await;
        let did = seed_hosted_did_web(
            &state,
            "gone.example.com",
            sample_doc("did:web:gone.example.com"),
        )
        .await;
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind(&did)
            .execute(&state.db)
            .await
            .unwrap();

        let response = app(state)
            .oneshot(did_json_request("gone.example.com"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn missing_host_returns_400() {
        let state = test_state().await;
        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/.well-known/did.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_returns_405() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/.well-known/did.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
