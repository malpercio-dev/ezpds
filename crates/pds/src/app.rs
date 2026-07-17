// pattern: Imperative Shell

use axum::{
    http::Request,
    routing::{delete, get, post},
    Router,
};
use opentelemetry::propagation::Extractor;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::routes::account_storage::account_storage;
use crate::routes::account_usage::account_usage;
use crate::routes::activate_account::activate_account_handler;
use crate::routes::admin_account_repair::{issue_reset_token, set_account_email};
use crate::routes::admin_devices::{
    list_admin_devices, mint_pairing_code, register_admin_device, revoke_admin_device,
};
use crate::routes::admin_health::admin_health;
use crate::routes::admin_list_accounts::list_accounts;
use crate::routes::admin_relay_status::relay_status;
use crate::routes::admin_request_crawl::request_crawl;
use crate::routes::admin_revoke_credentials::revoke_account_credentials;
use crate::routes::admin_transfers::{cancel_admin_transfer, list_admin_transfers};
use crate::routes::agent_child::{delete_child, list_children, mint_child, revoke_child};
use crate::routes::agent_claim::{post_agent_claim, post_agent_claim_confirm};
use crate::routes::agent_event::post_agent_event;
use crate::routes::agent_identity::post_agent_identity;
use crate::routes::agents::{agent_audit_log, claim_preview, list_agents, revoke_agent};
use crate::routes::apply_writes::apply_writes;
use crate::routes::atproto_did::atproto_did_handler;
use crate::routes::auth_md::serve_auth_md;
use crate::routes::check_account_status::check_account_status;
use crate::routes::claim_codes::{claim_codes, list_claim_code_inventory, revoke_claim_code_route};
use crate::routes::confirm_email::confirm_email;
use crate::routes::create_account::create_account;
use crate::routes::create_account_xrpc::create_account as create_account_xrpc;
use crate::routes::create_app_password::create_app_password;
use crate::routes::create_did::create_did_handler;
use crate::routes::create_handle::create_handle_handler;
use crate::routes::create_mobile_account::create_mobile_account;
use crate::routes::create_record::create_record;
use crate::routes::create_session::create_session;
use crate::routes::create_signing_key::create_signing_key;
use crate::routes::deactivate_account::deactivate_account_handler;
use crate::routes::delete_account::delete_account_handler;
use crate::routes::delete_handle::delete_handle_handler;
use crate::routes::delete_record::delete_record;
use crate::routes::delete_session::delete_session;
use crate::routes::describe_repo::describe_repo;
use crate::routes::describe_server::describe_server;
use crate::routes::did_json::did_json_handler;
use crate::routes::did_web_hosting::{
    set_did_web_hosting_handler, update_did_web_document_handler,
};
use crate::routes::get_blob::get_blob;
use crate::routes::get_device_pds::get_device_pds;
use crate::routes::get_did::get_did_handler;
use crate::routes::get_metrics::get_metrics;
use crate::routes::get_pds_signing_key::get_pds_signing_key;
use crate::routes::get_preferences::get_preferences_handler;
use crate::routes::get_recommended_did_credentials::get_recommended_did_credentials;
use crate::routes::get_record::get_record;
use crate::routes::get_repo::get_repo;
use crate::routes::get_repo_signing_key::get_repo_signing_key;
use crate::routes::get_service_auth::get_service_auth;
use crate::routes::get_session::get_session;
use crate::routes::get_subject_status::get_subject_status;
use crate::routes::health::health;
use crate::routes::import_repo::import_repo;
use crate::routes::landing::landing;
use crate::routes::list_app_passwords::list_app_passwords_handler;
use crate::routes::list_blobs::list_blobs;
use crate::routes::list_missing_blobs::list_missing_blobs;
use crate::routes::list_records::list_records;
use crate::routes::list_repos::list_repos;
use crate::routes::oauth_authorize::{get_authorization, post_authorization};
use crate::routes::oauth_client_metadata::oauth_client_metadata;
use crate::routes::oauth_jwks::oauth_jwks;
use crate::routes::oauth_par::post_par;
use crate::routes::oauth_protected_resource::oauth_protected_resource_metadata;
use crate::routes::oauth_revoke::post_revoke;
use crate::routes::oauth_server_metadata::oauth_server_metadata;
use crate::routes::oauth_token::post_token;
use crate::routes::provisioning_session::create_provisioning_session;
use crate::routes::put_preferences::put_preferences_handler;
use crate::routes::put_record::put_record;
use crate::routes::refresh_session::refresh_session;
use crate::routes::register_device::register_device;
use crate::routes::repo_key_rotation::{begin_repo_key_rotation, complete_repo_key_rotation};
use crate::routes::request_account_delete::request_account_delete;
use crate::routes::request_email_confirmation::request_email_confirmation;
use crate::routes::request_email_update::request_email_update;
use crate::routes::request_password_reset::request_password_reset;
use crate::routes::request_plc_operation_signature::request_plc_operation_signature;
use crate::routes::reserve_signing_key::reserve_signing_key;
use crate::routes::reset_password::reset_password;
use crate::routes::resolve_handle::resolve_handle_handler;
use crate::routes::resolve_identity::{
    refresh_identity_handler, resolve_did_handler, resolve_identity_handler,
};
use crate::routes::revoke_app_password::revoke_app_password;
use crate::routes::sign_plc_operation::sign_plc_operation;
use crate::routes::sovereign_session::create_sovereign_session;
use crate::routes::standard_signup::{
    check_handle_availability, check_signup_queue, create_invite_code, create_invite_codes,
    get_account_invite_codes,
};
use crate::routes::static_assets::static_handler;
use crate::routes::submit_plc_operation::submit_plc_operation;
use crate::routes::sync_get_blocks::sync_get_blocks;
use crate::routes::sync_get_latest_commit::sync_get_latest_commit;
use crate::routes::sync_get_record::sync_get_record;
use crate::routes::sync_get_repo_status::sync_get_repo_status;
use crate::routes::sync_subscribe_repos::subscribe_repos;
use crate::routes::transfer_accept::transfer_accept;
use crate::routes::transfer_complete::transfer_complete;
use crate::routes::transfer_initiate::transfer_initiate;
use crate::routes::update_email::update_email;
use crate::routes::update_handle::update_handle_handler;
use crate::routes::update_subject_status::update_subject_status;
use crate::routes::upload_blob::upload_blob;
#[cfg(test)]
pub(crate) use crate::state::test_state;
#[cfg(test)]
pub use crate::state::test_state_with_plc_url;
pub use crate::state::{AppState, FailedLoginStore};
use crate::xrpc_dispatch::xrpc_handler;

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
        // set_parent only errs when the span has no OTel layer attached (telemetry
        // disabled) — the request must still be served, just without a joined trace.
        if let Err(e) = span.set_parent(parent_cx) {
            tracing::trace!(error = %e, "could not attach parent trace context to span");
        }
        span
    }
}

/// Apply the middleware every route group shares, in the order axum layers them (outermost →
/// inner): Trace, then HTTP metrics, then rate limiting. Applied to each group *before* that
/// group's own (optional) CORS layer, so CORS — where present — stays the outermost layer:
/// preflight `OPTIONS` are answered before throttling, and a 429 still carries the CORS headers a
/// cross-origin client needs to read it. Trace stays outside the rate limiter so throttled
/// requests are still traced; the metrics counter sits outside the rate limiter so a 429 still
/// lands in `http_requests_total`, but inside CORS so short-circuited preflights don't pollute the
/// series. `from_fn_with_state` needs its own state clone.
fn apply_shared_layers(router: Router<AppState>, state: &AppState) -> Router<AppState> {
    router
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::rate_limit::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::metrics::http_metrics_middleware,
        ))
        .layer(TraceLayer::new_for_http().make_span_with(OtelMakeSpan))
}

/// Build the Axum router with middleware and routes.
///
/// Keeping router construction separate from `main` makes it testable without a real TCP
/// listener — callers can use `tower::ServiceExt::oneshot` to drive requests in tests.
///
/// The router is split into two groups that differ only in CORS: the **public** surface
/// (landing, `.well-known`, OAuth, agent registration, all XRPC, static assets) gets
/// `CorsLayer::permissive()` because it has legitimate cross-origin callers; the **admin +
/// provisioning** surface (`/v1/*`, including `/v1/admin/*`) gets no CORS layer at all, since it is
/// only ever called same-origin by first-party native/mobile clients and operators. Both groups
/// share the trace/metrics/rate-limit stack.
pub fn app(state: AppState) -> Router {
    let public = Router::new()
        .route("/", get(landing))
        .route("/auth.md", get(serve_auth_md))
        .route("/.well-known/atproto-did", get(atproto_did_handler))
        .route("/.well-known/did.json", get(did_json_handler))
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource_metadata),
        )
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
        .route("/oauth/revoke", post(post_revoke))
        .route("/agent/identity", post(post_agent_identity))
        .route("/agent/child", get(list_children).post(mint_child))
        .route("/agent/child/revoke", post(revoke_child))
        .route("/agent/child/delete", post(delete_child))
        .route("/agent/identity/claim", post(post_agent_claim))
        .route(
            "/agent/identity/claim/confirm",
            post(post_agent_claim_confirm),
        )
        .route("/agent/event/notify", post(post_agent_event))
        .route("/xrpc/_health", get(health))
        .route(
            "/xrpc/com.atproto.server.describeServer",
            get(describe_server),
        )
        .route(
            "/xrpc/com.atproto.server.createAccount",
            post(create_account_xrpc),
        )
        .route(
            "/xrpc/com.atproto.server.createSession",
            post(create_session),
        )
        .route("/xrpc/com.atproto.server.getSession", get(get_session))
        .route(
            "/xrpc/com.atproto.server.getServiceAuth",
            get(get_service_auth),
        )
        .route(
            "/xrpc/com.atproto.server.refreshSession",
            post(refresh_session),
        )
        .route(
            "/xrpc/com.atproto.server.deleteSession",
            post(delete_session),
        )
        .route(
            "/xrpc/com.atproto.server.activateAccount",
            post(activate_account_handler),
        )
        .route(
            "/xrpc/com.atproto.server.deactivateAccount",
            post(deactivate_account_handler),
        )
        .route(
            "/xrpc/com.atproto.server.requestAccountDelete",
            post(request_account_delete),
        )
        .route(
            "/xrpc/com.atproto.server.deleteAccount",
            post(delete_account_handler),
        )
        .route(
            "/xrpc/com.atproto.server.checkAccountStatus",
            get(check_account_status),
        )
        .route(
            "/xrpc/com.atproto.server.createAppPassword",
            post(create_app_password),
        )
        .route(
            "/xrpc/com.atproto.server.listAppPasswords",
            get(list_app_passwords_handler),
        )
        .route(
            "/xrpc/com.atproto.server.revokeAppPassword",
            post(revoke_app_password),
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
            "/xrpc/com.atproto.server.requestEmailConfirmation",
            post(request_email_confirmation),
        )
        .route("/xrpc/com.atproto.server.confirmEmail", post(confirm_email))
        .route(
            "/xrpc/com.atproto.server.requestEmailUpdate",
            post(request_email_update),
        )
        .route("/xrpc/com.atproto.server.updateEmail", post(update_email))
        // Operator/moderation surface: account-level takedown. Admin-authed (master token or
        // signed companion-app device request), unlike every other com.atproto.* route above.
        .route(
            "/xrpc/com.atproto.admin.updateSubjectStatus",
            post(update_subject_status),
        )
        .route(
            "/xrpc/com.atproto.admin.getSubjectStatus",
            get(get_subject_status),
        )
        .route(
            "/xrpc/com.atproto.server.reserveSigningKey",
            post(reserve_signing_key),
        )
        .route(
            "/xrpc/com.atproto.server.createInviteCode",
            post(create_invite_code),
        )
        .route(
            "/xrpc/com.atproto.server.createInviteCodes",
            post(create_invite_codes),
        )
        .route(
            "/xrpc/com.atproto.server.getAccountInviteCodes",
            get(get_account_invite_codes),
        )
        .route(
            "/xrpc/com.atproto.temp.checkHandleAvailability",
            get(check_handle_availability),
        )
        .route(
            "/xrpc/com.atproto.temp.checkSignupQueue",
            get(check_signup_queue),
        )
        .route(
            "/xrpc/com.atproto.identity.resolveHandle",
            get(resolve_handle_handler),
        )
        .route(
            "/xrpc/com.atproto.identity.resolveDid",
            get(resolve_did_handler),
        )
        .route(
            "/xrpc/com.atproto.identity.resolveIdentity",
            get(resolve_identity_handler),
        )
        .route(
            "/xrpc/com.atproto.identity.refreshIdentity",
            post(refresh_identity_handler),
        )
        .route(
            "/xrpc/com.atproto.identity.updateHandle",
            post(update_handle_handler),
        )
        .route(
            "/xrpc/com.atproto.identity.getRecommendedDidCredentials",
            get(get_recommended_did_credentials),
        )
        .route(
            "/xrpc/com.atproto.identity.requestPlcOperationSignature",
            post(request_plc_operation_signature),
        )
        .route(
            "/xrpc/com.atproto.identity.signPlcOperation",
            post(sign_plc_operation),
        )
        .route(
            "/xrpc/com.atproto.identity.submitPlcOperation",
            post(submit_plc_operation),
        )
        .route("/xrpc/com.atproto.repo.uploadBlob", post(upload_blob))
        .route("/xrpc/com.atproto.sync.getBlob", get(get_blob))
        .route("/xrpc/com.atproto.sync.getBlocks", get(sync_get_blocks))
        .route(
            "/xrpc/com.atproto.sync.getLatestCommit",
            get(sync_get_latest_commit),
        )
        .route("/xrpc/com.atproto.sync.getRecord", get(sync_get_record))
        .route("/xrpc/com.atproto.sync.getRepo", get(get_repo))
        .route(
            "/xrpc/com.atproto.sync.getRepoStatus",
            get(sync_get_repo_status),
        )
        .route("/xrpc/com.atproto.sync.listBlobs", get(list_blobs))
        .route("/xrpc/com.atproto.sync.listRepos", get(list_repos))
        .route(
            "/xrpc/com.atproto.sync.subscribeRepos",
            get(subscribe_repos),
        )
        .route("/xrpc/com.atproto.repo.applyWrites", post(apply_writes))
        .route("/xrpc/com.atproto.repo.importRepo", post(import_repo))
        .route(
            "/xrpc/com.atproto.repo.listMissingBlobs",
            get(list_missing_blobs),
        )
        .route("/xrpc/com.atproto.repo.createRecord", post(create_record))
        .route("/xrpc/com.atproto.repo.getRecord", get(get_record))
        .route("/xrpc/com.atproto.repo.listRecords", get(list_records))
        .route("/xrpc/com.atproto.repo.putRecord", post(put_record))
        .route("/xrpc/com.atproto.repo.deleteRecord", post(delete_record))
        .route("/xrpc/com.atproto.repo.describeRepo", get(describe_repo))
        // Stored locally for user data sovereignty rather than proxied to the AppView, so they
        // must be registered explicitly ahead of the `app.bsky.*` catch-all below.
        .route(
            "/xrpc/app.bsky.actor.getPreferences",
            get(get_preferences_handler),
        )
        .route(
            "/xrpc/app.bsky.actor.putPreferences",
            post(put_preferences_handler),
        )
        .route("/xrpc/{method}", get(xrpc_handler).post(xrpc_handler))
        .route("/static/{*path}", get(static_handler));
    // Permissive CORS wraps only the public surface, applied *after* the shared layers so it stays
    // the outermost layer (see `apply_shared_layers`). This is safe ONLY because authentication is
    // never cookie-based (all Bearer/DPoP/signed-request), so a permissive policy cannot be abused
    // to ride ambient cookie credentials — see the invariant in crates/pds/AGENTS.md.
    let public = apply_shared_layers(public, &state).layer(CorsLayer::permissive());

    // Admin (`/v1/admin/*`) and provisioning (`/v1/*`) routes have no cross-origin use case — they
    // are called same-origin by first-party native/mobile clients and operators, never a browser
    // on another origin — so they get NO CORS layer, narrowing the browser-reachable surface. They
    // still share the same trace/metrics/rate-limit stack as the public group.
    let internal = Router::new()
        .route("/v1/accounts", post(create_account))
        .route(
            "/v1/accounts/claim-codes",
            post(claim_codes).get(list_claim_code_inventory),
        )
        .route(
            "/v1/accounts/claim-codes/revoke",
            post(revoke_claim_code_route),
        )
        .route("/v1/accounts/mobile", post(create_mobile_account))
        .route("/v1/accounts/sessions", post(create_provisioning_session))
        .route("/v1/sessions/sovereign", post(create_sovereign_session))
        .route("/v1/accounts/{id}/usage", get(account_usage))
        .route("/v1/accounts/{id}/storage", get(account_storage))
        .route("/v1/did-web/hosting", post(set_did_web_hosting_handler))
        .route(
            "/v1/did-web/document",
            post(update_did_web_document_handler),
        )
        .route("/v1/repo-keys/rotation", post(begin_repo_key_rotation))
        .route(
            "/v1/repo-keys/rotation/complete",
            post(complete_repo_key_rotation),
        )
        .route("/v1/agents", get(list_agents))
        .route("/v1/agents/claim-preview", post(claim_preview))
        .route("/v1/agents/{registration_id}/revoke", post(revoke_agent))
        .route("/v1/agents/{registration_id}/audit", get(agent_audit_log))
        .route("/v1/admin/accounts", get(list_accounts))
        .route("/v1/admin/accounts/{id}/email", post(set_account_email))
        .route(
            "/v1/admin/accounts/{id}/reset-token",
            post(issue_reset_token),
        )
        .route("/v1/admin/health", get(admin_health))
        .route("/v1/admin/relay-status", get(relay_status))
        .route("/v1/admin/request-crawl", post(request_crawl))
        .route(
            "/v1/admin/accounts/{id}/revoke-credentials",
            post(revoke_account_credentials),
        )
        .route("/v1/admin/transfers", get(list_admin_transfers))
        .route(
            "/v1/admin/transfers/{id}/cancel",
            post(cancel_admin_transfer),
        )
        .route("/v1/admin/pairing-codes", post(mint_pairing_code))
        .route(
            "/v1/admin/devices",
            post(register_admin_device).get(list_admin_devices),
        )
        .route("/v1/admin/devices/{id}/revoke", post(revoke_admin_device))
        .route("/v1/devices", post(register_device))
        .route("/v1/devices/{id}/pds", get(get_device_pds))
        .route("/v1/transfer/initiate", post(transfer_initiate))
        .route("/v1/transfer/accept", post(transfer_accept))
        .route("/v1/transfer/complete", post(transfer_complete))
        .route("/v1/dids", post(create_did_handler))
        .route("/v1/dids/{did}", get(get_did_handler))
        .route("/v1/handles", post(create_handle_handler))
        .route("/v1/handles/{handle}", delete(delete_handle_handler))
        .route(
            "/v1/pds/keys",
            get(get_pds_signing_key).post(create_signing_key),
        )
        .route("/v1/repo-signing-key", get(get_repo_signing_key));
    let internal = apply_shared_layers(internal, &state);

    let router = public.merge(internal);

    // Registered *after* the layer stack, so the scrape endpoint sits outside permissive
    // CORS, tracing, and rate-limit accounting (`Router::layer` only wraps routes added
    // before it). Not registering the route at all when metrics are disabled is what
    // produces the documented 404.
    let router = if state.config.telemetry.metrics_enabled {
        router.route("/metrics", get(get_metrics))
    } else {
        router
    };
    router.with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::sync::Arc;
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
    async fn cors_is_scoped_to_public_surface_only() {
        // Permissive CORS covers the public XRPC/OAuth surface but not the admin/provisioning
        // (`/v1/*`) surface, which has no cross-origin use case.
        let router = app(test_state().await);

        // Preflight against a public XRPC route → answered with Access-Control-Allow-Origin.
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/xrpc/com.atproto.server.describeServer")
                    .header("origin", "https://example.com")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.headers().contains_key("access-control-allow-origin"),
            "public XRPC surface must answer a CORS preflight with Access-Control-Allow-Origin"
        );

        // The same preflight against an admin route → no CORS header (same-origin only).
        let resp = router
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/v1/admin/devices")
                    .header("origin", "https://example.com")
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            !resp.headers().contains_key("access-control-allow-origin"),
            "admin/provisioning surface must not emit Access-Control-Allow-Origin"
        );
    }

    #[tokio::test]
    async fn rate_limited_public_response_still_carries_cors_headers() {
        // Regression guard co-located with `apply_shared_layers`: on the public surface CORS must
        // stay OUTSIDE the rate limiter, so a request throttled *before* the handler runs still
        // carries the Access-Control-Allow-Origin header a cross-origin client needs to read the
        // 429. If the layering is ever reordered so CORS sits inside the limiter (e.g. the
        // `.layer(CorsLayer::permissive())` call is moved ahead of `apply_shared_layers`), the
        // throttled response loses its CORS header and this fails.
        let mut state = test_state().await;
        state.rate_limiter = Arc::new(crate::rate_limit::RateLimiterState::new(
            &common::RateLimitConfig {
                enabled: true,
                global_ip_per_5min: 1,
                ..common::RateLimitConfig::default()
            },
        ));
        let router = app(state);
        let req = |ip: &str| {
            Request::builder()
                .uri("/xrpc/com.atproto.server.describeServer")
                .header("origin", "https://example.com")
                .header("x-forwarded-for", ip)
                .body(Body::empty())
                .unwrap()
        };

        // First request from the IP is within the cap of 1.
        let first = router.clone().oneshot(req("203.0.113.40")).await.unwrap();
        assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);

        // Second trips the global cap → 429, thrown by the rate limiter before the handler, yet
        // it must still carry the CORS allow-origin header (CORS wraps the limiter).
        let throttled = router.oneshot(req("203.0.113.40")).await.unwrap();
        assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            throttled
                .headers()
                .contains_key("access-control-allow-origin"),
            "a throttled 429 on the public surface must still carry CORS headers"
        );
    }

    #[tokio::test]
    async fn non_privileged_app_password_cannot_reach_chat_proxy() {
        // A plain `com.atproto.appPass` session must be refused before any request reaches the
        // chat (DM) service — only full access or a privileged app password may. The refusal
        // happens at the proxy gate, so no account/repo key setup is needed.
        let state = test_state().await;
        let token = crate::routes::test_utils::app_pass_jwt(&state.jwt_secret, "did:plc:x", false);

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/chat.bsky.convo.sendMessage")
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "FORBIDDEN");
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
