use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    extract::Path,
    http::Request,
    routing::{delete, get, post},
    Router,
};
use common::{ApiError, Config, ErrorCode};
use opentelemetry::propagation::Extractor;
use reqwest::Client;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::auth::{DpopNonceStore, OAuthSigningKey};
use crate::dns::{DnsProvider, TxtResolver};
use crate::routes::atproto_did::atproto_did_handler;
use crate::routes::claim_codes::claim_codes;
use crate::routes::create_account::create_account;
use crate::routes::create_did::create_did_handler;
use crate::routes::create_handle::create_handle_handler;
use crate::routes::create_mobile_account::create_mobile_account;
use crate::routes::create_record::create_record;
use crate::routes::create_session::create_session;
use crate::routes::create_signing_key::create_signing_key;
use crate::routes::delete_handle::delete_handle_handler;
use crate::routes::delete_record::delete_record;
use crate::routes::delete_session::delete_session;
use crate::routes::describe_server::describe_server;
use crate::routes::get_blob::get_blob;
use crate::routes::get_device_relay::get_device_relay;
use crate::routes::get_did::get_did_handler;
use crate::routes::get_record::get_record;
use crate::routes::get_relay_signing_key::get_relay_signing_key;
use crate::routes::get_repo::get_repo;
use crate::routes::get_repo_signing_key::get_repo_signing_key;
use crate::routes::get_session::get_session;
use crate::routes::health::health;
use crate::routes::list_blobs::list_blobs;
use crate::routes::list_records::list_records;
use crate::routes::oauth_authorize::{get_authorization, post_authorization};
use crate::routes::oauth_client_metadata::oauth_client_metadata;
use crate::routes::oauth_jwks::oauth_jwks;
use crate::routes::oauth_par::post_par;
use crate::routes::oauth_server_metadata::oauth_server_metadata;
use crate::routes::oauth_token::post_token;
use crate::routes::provisioning_session::create_provisioning_session;
use crate::routes::put_record::put_record;
use crate::routes::refresh_session::refresh_session;
use crate::routes::register_device::register_device;
use crate::routes::request_password_reset::request_password_reset;
use crate::routes::reset_password::reset_password;
use crate::routes::resolve_handle::resolve_handle_handler;
use crate::routes::static_assets::static_handler;
use crate::routes::upload_blob::upload_blob;
use crate::well_known::WellKnownResolver;

/// In-memory store for failed login attempts per identifier, shared across all login endpoints.
/// Maps identifier string → timestamps of recent failures.
/// `std::sync::Mutex` is used because the critical section never awaits.
///
/// **Known limitation:** `createSession` keys by DID or handle; `POST /v1/accounts/sessions`
/// keys by email. Both share this store, so an attacker gets `RATE_LIMIT_MAX_FAILURES` attempts
/// per endpoint independently against the same account. Acceptable for v0.1; a future revision
/// should normalise all identifiers to DID before keying.
pub type FailedLoginStore = Arc<Mutex<HashMap<String, VecDeque<Instant>>>>;

/// Wraps an `axum::http::HeaderMap` as an OTel text-map [`Extractor`] so that
/// the W3C `traceparent` and `tracestate` headers can be read by the global propagator.
struct HeaderMapCarrier<'a>(&'a axum::http::HeaderMap);

impl Extractor for HeaderMapCarrier<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| {
            v.to_str().map_or_else(
                |_| {
                    tracing::debug!(
                        header = key,
                        "trace propagation header contains non-UTF-8 bytes; ignoring"
                    );
                    None
                },
                Some,
            )
        })
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Custom `MakeSpan` for [`TraceLayer`] that:
///  1. Creates an `info_span` with standard HTTP attributes pre-declared.
///  2. Extracts an incoming W3C `traceparent` header and sets it as the parent context
///     on the new span so upstream traces are joined correctly.
#[derive(Clone, Default)]
struct OtelMakeSpan;

impl<B> tower_http::trace::MakeSpan<B> for OtelMakeSpan {
    fn make_span(&mut self, request: &Request<B>) -> tracing::Span {
        let span = tracing::info_span!(
            "HTTP request",
            http.method = %request.method(),
            http.target = request.uri().path_and_query().map_or("", |pq| pq.as_str()),
            http.status_code = tracing::field::Empty,
            otel.status_code = tracing::field::Empty,
        );

        // Inject parent trace context from incoming W3C traceparent/tracestate headers.
        // When telemetry is disabled the global propagator is a no-op, so this is free.
        let parent_cx = opentelemetry::global::get_text_map_propagator(|p| {
            p.extract(&HeaderMapCarrier(request.headers()))
        });
        span.set_parent(parent_cx);
        span
    }
}

/// Shared application state cloned into every request handler via Axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: sqlx::SqlitePool,
    pub http_client: Client,
    /// Optional DNS provider for subdomain record creation on handle registration.
    /// `None` in v0.1 — operators manage DNS records manually.
    /// Populated by real provider implementations (Cloudflare, Route53) when configured.
    pub dns_provider: Option<Arc<dyn DnsProvider>>,
    /// Optional DNS TXT resolver for handle resolution fallback.
    /// When `None`, `resolveHandle` skips DNS and returns `HandleNotFound` for
    /// handles not present in the local database.
    pub txt_resolver: Option<Arc<dyn TxtResolver>>,
    /// Optional HTTP well-known resolver for handle resolution fallback.
    /// Used as the third step after local DB and DNS TXT: calls
    /// `GET https://<handle>/.well-known/atproto-did`.
    pub well_known_resolver: Option<Arc<dyn WellKnownResolver>>,
    /// HS256 signing secret for JWT access/refresh tokens.
    /// Generated randomly at startup via OsRng (ephemeral — rotates on restart).
    pub jwt_secret: [u8; 32],
    /// Persistent ES256 keypair for signing OAuth access tokens.
    /// Loaded at startup from `oauth_signing_key` table (or generated + stored on first boot).
    pub oauth_signing_keypair: OAuthSigningKey,
    /// In-memory store for server-issued DPoP nonces. Shared across all token endpoint requests.
    #[allow(dead_code)]
    pub dpop_nonces: DpopNonceStore,
    /// In-memory sliding-window store for failed createSession attempts (rate limiting).
    /// Shared across all requests via Arc<Mutex<...>>.
    pub failed_login_attempts: FailedLoginStore,
}

/// Build the Axum router with middleware and routes.
///
/// Keeping router construction separate from `main` makes it testable without a real TCP
/// listener — callers can use `tower::ServiceExt::oneshot` to drive requests in tests.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/atproto-did", get(atproto_did_handler))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_server_metadata),
        )
        .route(
            "/oauth/authorize",
            get(get_authorization).post(post_authorization),
        )
        .route("/oauth/client-metadata.json", get(oauth_client_metadata))
        .route("/oauth/jwks", get(oauth_jwks))
        .route("/oauth/par", post(post_par))
        .route("/oauth/token", post(post_token))
        .route("/xrpc/_health", get(health))
        .route(
            "/xrpc/com.atproto.server.describeServer",
            get(describe_server),
        )
        .route(
            "/xrpc/com.atproto.server.createSession",
            post(create_session),
        )
        .route("/xrpc/com.atproto.server.getSession", get(get_session))
        .route(
            "/xrpc/com.atproto.server.refreshSession",
            post(refresh_session),
        )
        .route(
            "/xrpc/com.atproto.server.deleteSession",
            post(delete_session),
        )
        .route(
            "/xrpc/com.atproto.server.requestPasswordReset",
            post(request_password_reset),
        )
        .route(
            "/xrpc/com.atproto.server.resetPassword",
            post(reset_password),
        )
        .route(
            "/xrpc/com.atproto.identity.resolveHandle",
            get(resolve_handle_handler),
        )
        .route("/xrpc/com.atproto.repo.uploadBlob", post(upload_blob))
        .route("/xrpc/com.atproto.sync.getBlob", get(get_blob))
        .route("/xrpc/com.atproto.sync.getRepo", get(get_repo))
        .route("/xrpc/com.atproto.sync.listBlobs", get(list_blobs))
        .route("/xrpc/com.atproto.repo.createRecord", post(create_record))
        .route("/xrpc/com.atproto.repo.getRecord", get(get_record))
        .route("/xrpc/com.atproto.repo.listRecords", get(list_records))
        .route("/xrpc/com.atproto.repo.putRecord", post(put_record))
        .route("/xrpc/com.atproto.repo.deleteRecord", post(delete_record))
        .route("/xrpc/:method", get(xrpc_handler).post(xrpc_handler))
        .route("/v1/accounts", post(create_account))
        .route("/v1/accounts/claim-codes", post(claim_codes))
        .route("/v1/accounts/mobile", post(create_mobile_account))
        .route("/v1/accounts/sessions", post(create_provisioning_session))
        .route("/v1/devices", post(register_device))
        .route("/v1/devices/:id/relay", get(get_device_relay))
        .route("/v1/dids", post(create_did_handler))
        .route("/v1/dids/:did", get(get_did_handler))
        .route("/v1/handles", post(create_handle_handler))
        .route("/v1/handles/:handle", delete(delete_handle_handler))
        .route(
            "/v1/relay/keys",
            get(get_relay_signing_key).post(create_signing_key),
        )
        .route("/v1/repo-signing-key", get(get_repo_signing_key))
        .route("/static/*path", get(static_handler))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http().make_span_with(OtelMakeSpan))
        .with_state(state)
}

/// Catch-all XRPC handler — returns `MethodNotImplemented` for any unrecognised NSID.
///
/// Axum gives static path segments priority over parameterised ones, so specific routes
/// registered for individual NSIDs will match before this catch-all.
async fn xrpc_handler(Path(method): Path<String>) -> ApiError {
    ApiError::new(
        ErrorCode::MethodNotImplemented,
        format!("XRPC method {method:?} is not implemented"),
    )
}

#[cfg(test)]
pub(crate) async fn test_state() -> AppState {
    test_state_with_plc_url("https://plc.directory".to_string()).await
}

#[cfg(test)]
pub async fn test_state_with_plc_url(plc_directory_url: String) -> AppState {
    use crate::auth::new_nonce_store;
    use crate::db::{open_pool, run_migrations};
    use common::{BlobsConfig, IrohConfig, OAuthConfig, TelemetryConfig};
    use p256::pkcs8::EncodePrivateKey;
    use rand_core::OsRng;
    use std::path::PathBuf;
    use std::time::Duration;

    let db = open_pool("sqlite::memory:").await.expect("test pool");
    run_migrations(&db).await.expect("test migrations");

    let http_client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("test http client");

    // Generate a fresh ephemeral P-256 keypair for tests (no DB persistence needed).
    let test_signing_key = {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
        let pkcs8 = sk
            .to_pkcs8_der()
            .expect("PKCS#8 encoding must succeed for test key");
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("P-256 x"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("P-256 y"));
        let public_key_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        });
        OAuthSigningKey {
            key_id: "test-oauth-key-01".to_string(),
            encoding_key: jsonwebtoken::EncodingKey::from_ec_der(pkcs8.as_bytes()),
            public_key_jwk,
        }
    };
    let dpop_nonces = new_nonce_store();

    AppState {
        config: Arc::new(Config {
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
            data_dir: PathBuf::from("/tmp"),
            database_url: "sqlite::memory:".to_string(),
            public_url: "https://test.example.com".to_string(),
            server_did: None,
            available_user_domains: vec!["test.example.com".to_string()],
            invite_code_required: true,
            links: common::ServerLinksConfig::default(),
            contact: common::ContactConfig::default(),
            blobs: BlobsConfig::default(),
            oauth: OAuthConfig::default(),
            iroh: IrohConfig::default(),
            telemetry: TelemetryConfig::default(),
            admin_token: None,
            signing_key_master_key: None,
            plc_directory_url,
        }),
        db,
        http_client,
        dns_provider: None,
        txt_resolver: None,
        well_known_resolver: None,
        // Fixed key for tests — predictable JWTs in unit tests.
        jwt_secret: [0x42u8; 32],
        oauth_signing_keypair: test_signing_key,
        dpop_nonces,
        failed_login_attempts: Arc::new(Mutex::new(HashMap::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn xrpc_get_unknown_method_returns_501() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.example.unknownMethod")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn xrpc_post_unknown_method_returns_501() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.example.unknownMethod")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // XRPC only defines GET (queries) and POST (procedures); other methods are not part of
    // the protocol and correctly return 405.
    #[tokio::test]
    async fn xrpc_delete_returns_405() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/xrpc/com.example.unknownMethod")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn xrpc_response_has_json_content_type() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.example.unknownMethod")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn xrpc_response_body_is_method_not_implemented() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.example.notImplemented")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(json["error"]["code"], "MethodNotImplemented");
    }

    #[tokio::test]
    async fn appstate_db_pool_is_queryable() {
        let state = test_state().await;
        sqlx::query("SELECT 1")
            .execute(&state.db)
            .await
            .expect("db pool in AppState must be queryable");
    }
}

#[cfg(test)]
mod header_carrier_tests {
    use super::*;
    use axum::http::HeaderMap;
    use opentelemetry::propagation::Extractor;

    #[test]
    fn get_returns_ascii_header_value() {
        let mut map = HeaderMap::new();
        map.insert("traceparent", "00-abc123-def456-01".parse().unwrap());

        let carrier = HeaderMapCarrier(&map);
        assert_eq!(carrier.get("traceparent"), Some("00-abc123-def456-01"));
    }

    #[test]
    fn get_returns_none_for_absent_header() {
        let map = HeaderMap::new();
        let carrier = HeaderMapCarrier(&map);
        assert_eq!(carrier.get("traceparent"), None);
    }

    #[test]
    fn get_is_case_insensitive_via_header_map() {
        let mut map = HeaderMap::new();
        // HTTP/2 headers are lower-case; HeaderMap normalises on insert.
        map.insert("tracestate", "vendor=value".parse().unwrap());

        let carrier = HeaderMapCarrier(&map);
        // HeaderMap normalises to lower-case, so look-up is case-insensitive.
        assert_eq!(carrier.get("tracestate"), Some("vendor=value"));
    }

    #[test]
    fn keys_returns_all_header_names() {
        let mut map = HeaderMap::new();
        map.insert("traceparent", "value1".parse().unwrap());
        map.insert("tracestate", "value2".parse().unwrap());

        let carrier = HeaderMapCarrier(&map);
        let keys = carrier.keys();
        assert!(keys.contains(&"traceparent"));
        assert!(keys.contains(&"tracestate"));
        assert_eq!(keys.len(), 2);
    }
}
