// pattern: Mixed (unavoidable)
//
// Types: AppState, PendingOAuthFlow, OAuthSession, CallbackParams (Functional Core)
// handle_deep_link: Imperative Shell (reads OS callback, routes to pending channel)

use std::sync::Mutex;
use tracing;

// ── Shared state ──────────────────────────────────────────────────────────────

/// App-wide OAuth state registered via `.manage()` in lib.rs.
///
/// Both fields are Option-wrapped so the state is cleanly empty before any
/// OAuth flow starts and after a flow completes.
pub struct AppState {
    /// The pending OAuth flow waiting for the deep-link callback.
    /// Set by `start_oauth_flow` before opening Safari; cleared by `handle_deep_link`.
    pub pending_auth: Mutex<Option<PendingOAuthFlow>>,
    /// The active authenticated session after a successful token exchange.
    /// Set by `start_oauth_flow` on success; read by `OAuthClient` for every request.
    pub oauth_session: Mutex<Option<OAuthSession>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            pending_auth: Mutex::new(None),
            oauth_session: Mutex::new(None),
        }
    }
}

// ── Pending flow (stub — filled out in Phase 5) ───────────────────────────────

/// State parked inside `AppState.pending_auth` while `start_oauth_flow` waits
/// for the deep-link callback.
///
/// Phase 5 adds: oneshot::Sender<CallbackParams>, pkce_verifier, csrf_state.
pub struct PendingOAuthFlow {
    /// The CSRF state parameter generated at the start of the flow.
    /// Used by `handle_deep_link` to validate the callback state.
    pub csrf_state: String,
}

// ── OAuth session (stub — filled out in Phase 5) ──────────────────────────────

/// Active OAuth session stored after a successful token exchange.
///
/// Phase 5 adds: access_token, refresh_token, expires_at, dpop_nonce.
pub struct OAuthSession {
    pub access_token: String,
    pub refresh_token: String,
}

// ── Callback params ───────────────────────────────────────────────────────────

/// Parameters extracted from the OAuth deep-link callback URL.
pub struct CallbackParams {
    pub code: String,
    pub state: String,
}

// ── Deep-link handler ─────────────────────────────────────────────────────────

/// Process URLs received from the deep-link plugin's `on_open_url` event.
///
/// Filters for the OAuth callback path and logs receipt. Phase 5 completes this
/// by extracting `code`+`state` and sending them on the pending `oneshot` channel.
pub fn handle_deep_link(urls: Vec<url::Url>, app_state: &AppState) {
    for url in &urls {
        let scheme = url.scheme();
        let path = url.path();

        if scheme == "dev.malpercio.identitywallet" && path == "/oauth/callback" {
            tracing::info!(url = %url, "OAuth deep-link callback received");

            // Phase 5: extract code+state, validate CSRF, send on oneshot channel.
            // For now, just log that the callback arrived.
            let _pending = app_state.pending_auth.lock().unwrap();
            tracing::info!("pending_auth slot present: {}", _pending.is_some());

            return;
        }

        tracing::debug!(url = %url, "ignoring non-OAuth deep-link");
    }
}
