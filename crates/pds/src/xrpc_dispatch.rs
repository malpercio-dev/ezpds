// pattern: Imperative Shell

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use common::{ApiError, ErrorCode};

use crate::state::AppState;

/// The three upstream namespaces the catch-all XRPC handler proxies to. `AppView` and `Chat`
/// forward to one configured default each, unless the caller's `atproto-proxy` header names a
/// different target; `Moderation` has no single upstream at all (the client always picks which
/// labeler to report to), so its target is always resolved per-request from that header.
enum ProxyUpstream {
    AppView,
    Chat,
    Moderation,
}

/// NSIDs that undergo read-after-write munging: the AppView response is buffered and merged
/// with the requester's own unindexed records before returning. An explicit `atproto-proxy`
/// header naming a target bypasses this path entirely (see `xrpc_handler`), since the munge
/// assumes it's talking to the configured AppView.
const READ_AFTER_WRITE_NSIDS: [&str; 6] = [
    "app.bsky.actor.getProfile",
    "app.bsky.actor.getProfiles",
    "app.bsky.feed.getAuthorFeed",
    "app.bsky.feed.getPostThread",
    "app.bsky.feed.getTimeline",
    "app.bsky.feed.getActorLikes",
];

/// Catch-all XRPC handler.
///
/// `app.bsky.*` NSIDs with no local handler are forwarded to the configured AppView (feeds,
/// notifications, search); `chat.bsky.*` NSIDs are forwarded to the configured chat service
/// (direct messages); `com.atproto.moderation.*` NSIDs (e.g. `createReport`) are forwarded to
/// whichever labeler the client names via the `atproto-proxy` header — all three via
/// [`service_proxy`]. Any other unrecognised NSID returns `MethodNotImplemented`.
///
/// An explicit `atproto-proxy` header is honored for **any** proxied NSID, not just
/// `com.atproto.moderation.*`: when present, the request is routed to the header-named service
/// (resolved and SSRF-guarded exactly like the moderation branch) instead of the namespace's
/// configured default. This is what lets the official app's `app.bsky.video.*` calls — sent with
/// `atproto-proxy: did:web:video.bsky.app#bsky_video` — reach the video service rather than the
/// AppView. An absent header keeps the default routing (AppView / chat); moderation still has
/// no default of its own, so its header remains mandatory.
///
/// All three proxied namespaces are forwarded *on behalf of an authenticated user*, so the
/// caller's session is validated locally (the `AuthenticatedUser` extractor) before anything
/// leaves the PDS; the proxy then mints a fresh ES256 service-auth JWT signed by that user's repo
/// key for the upstream to verify (the caller's PDS session token is never forwarded) — the JWT's
/// `aud` is the header's target DID whenever a header is present, not the namespace's default.
/// Unauthenticated callers are rejected here rather than at the upstream. The auth check is
/// scoped to the proxy branches: an unrecognised NSID still returns `501` without an auth
/// challenge, so probing for supported methods does not require credentials.
///
/// Axum gives static path segments priority over parameterised ones, so specific routes
/// registered for individual NSIDs will match before this catch-all.
pub async fn xrpc_handler(
    State(state): State<AppState>,
    Path(method): Path<String>,
    auth: Result<crate::auth::extractors::AuthenticatedUser, ApiError>,
    req: axum::extract::Request,
) -> Response {
    use crate::auth::jwt::AuthScope;
    use crate::auth::oauth_scopes;
    use crate::identity::proxy::{resolve_atproto_proxy_target, HeaderProxyGuard};
    use crate::routes::service_proxy::proxy_xrpc;

    let upstream = if method.starts_with("app.bsky.") {
        Some(ProxyUpstream::AppView)
    } else if method.starts_with("chat.bsky.") {
        Some(ProxyUpstream::Chat)
    } else if method.starts_with("com.atproto.moderation.") {
        Some(ProxyUpstream::Moderation)
    } else {
        None
    };

    let Some(upstream) = upstream else {
        return ApiError::new(
            ErrorCode::MethodNotImplemented,
            format!("XRPC method {method:?} is not implemented"),
        )
        .into_response();
    };

    // The proxy mints a service-auth JWT signed by the *authenticated user's* repo key, so the
    // user DID — not just a pass/fail gate result — has to flow into `proxy_xrpc`.
    let user = match auth {
        Ok(user) => user,
        Err(rejection) => return rejection.into_response(),
    };

    let header_value = req
        .headers()
        .get("atproto-proxy")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if matches!(upstream, ProxyUpstream::Moderation) && header_value.is_none() {
        return ApiError::new(
            ErrorCode::InvalidRequest,
            "atproto-proxy header is required to proxy com.atproto.moderation.* methods",
        )
        .into_response();
    }

    // The scope check's `aud` is the raw header value when present — resolving it (a DID-doc
    // fetch + SSRF check) is deferred until after auth/scope pass, so a scope-rejected caller
    // never costs the PDS an outbound request for a header it wasn't entitled to use anyway.
    let proxy_aud = match header_value.as_deref() {
        Some(hv) => hv,
        None => match upstream {
            ProxyUpstream::AppView => state.config.appview.did.as_str(),
            ProxyUpstream::Chat => state.config.chat.did.as_str(),
            ProxyUpstream::Moderation => unreachable!("missing header returned above"),
        },
    };
    if !user.scope.is_access() {
        return ApiError::new(ErrorCode::InvalidToken, "access token required").into_response();
    }
    if user.scope == AuthScope::Access {
        if let Err(err) = oauth_scopes::require_rpc(
            &user.scope_claim,
            &method,
            proxy_aud,
            "token scope does not permit proxying this RPC",
        ) {
            return err.into_response();
        }
    }

    // Direct messages require a privileged credential: full access or a *privileged* app
    // password. A plain `com.atproto.appPass` session must not reach the chat service — this is
    // what the app-password privileged flag gates, regardless of whether a header retargets the
    // request away from the configured chat service.
    if matches!(upstream, ProxyUpstream::Chat) && user.scope == AuthScope::AppPass {
        return ApiError::new(
            ErrorCode::Forbidden,
            "this app password lacks the privileged scope required for chat access",
        )
        .into_response();
    }

    // Resolve the header to its validated target now (DID-doc fetch + SSRF guard) — only reached
    // once auth/scope/chat-privilege have all passed. `None` when no header was sent (moderation
    // already returned above in that case).
    let header_target = match header_value.as_deref() {
        Some(hv) => match resolve_atproto_proxy_target(&state, hv).await {
            Ok(target) => Some(target),
            Err(err) => return err.into_response(),
        },
        None => None,
    };

    // Branch read-after-write NSIDs to the buffered munged path before resolving the upstream
    // target details. The munge path hardcodes the *configured* AppView (`pipethrough_munged`
    // always calls `state.config.appview.url`/`.did` directly) — an explicit header naming a
    // target must bypass it and go through the generic streaming proxy instead, since the munge
    // assumes the configured AppView's response shape.
    if matches!(upstream, ProxyUpstream::AppView)
        && READ_AFTER_WRITE_NSIDS.contains(&method.as_str())
        && header_target.is_none()
    {
        let response =
            crate::read_after_write::pipethrough_munged(&state, &method, &user.did, req).await;
        count_proxy_request(&state, "appview", response.status().as_u16());
        return response;
    }

    let (url, proxy_did, guard, upstream_label): (
        String,
        String,
        Option<HeaderProxyGuard>,
        &'static str,
    ) = match header_target {
        // Always a guard, whether or not the host needed DNS pinning: the caller-controlled
        // target still requires the redirect-disabled hardened client. `moderation` keeps its own
        // label (it always resolves this way); an `app.bsky.*`/`chat.bsky.*` request that used a
        // header to override its namespace's default gets the bounded `header_target` label
        // instead of the raw destination, per the metrics cardinality rule.
        Some(target) => {
            let label = if matches!(upstream, ProxyUpstream::Moderation) {
                "moderation"
            } else {
                "header_target"
            };
            (
                target.url,
                target.header_value,
                Some(HeaderProxyGuard {
                    pinned: target.pinned,
                }),
                label,
            )
        }
        None => match upstream {
            ProxyUpstream::AppView => (
                state.config.appview.url.clone(),
                state.config.appview.did.clone(),
                None,
                "appview",
            ),
            ProxyUpstream::Chat => (
                state.config.chat.url.clone(),
                state.config.chat.did.clone(),
                None,
                "chat",
            ),
            ProxyUpstream::Moderation => unreachable!("moderation always resolves a header target"),
        },
    };

    let response = proxy_xrpc(
        &state,
        &url,
        &proxy_did,
        &method,
        &user.did,
        guard.as_ref(),
        req,
    )
    .await;
    count_proxy_request(&state, upstream_label, response.status().as_u16());
    response
}

/// Count one proxied upstream response into `proxy_requests_total{upstream, status_class}`.
/// Called with the response actually returned to the client, so a transport failure shows
/// up as the 503 the caller saw.
fn count_proxy_request(state: &AppState, upstream: &'static str, status: u16) {
    state.metrics.proxy_requests.add(
        1,
        &[
            crate::metrics::label(crate::metrics::names::LABEL_UPSTREAM, upstream),
            crate::metrics::label(
                crate::metrics::names::LABEL_STATUS_CLASS,
                crate::metrics::status_class(status),
            ),
        ],
    );
}
