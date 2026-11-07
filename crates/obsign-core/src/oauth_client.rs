// pattern: Mixed (unavoidable)

//! Re-exports [`custos_client::OAuthClient`] — the authenticated XRPC HTTP client (Bearer
//! sessions) — under this module's historical path, plus [`diagnostics_observer`], the
//! one wallet-side seam a real (non-test) `new_bearer_with_observer` call site should pass so
//! transport/server failures still reach the exportable diagnostics log. See
//! `custos_client::oauth_client`'s module doc for the client's own behavior (lazy refresh).
//!
//! `OAuthClient::new_bearer`'s plain 3-arg form records no breadcrumbs — every call site in
//! this app today is a test fixture (verified: none live outside a `#[cfg(any(test, feature = "test-support"))]` module).
//! This silent-by-default form is new to this extraction, not inherited from it: pre-extraction
//! there was one `OAuthClient` and it recorded breadcrumbs unconditionally. Use
//! `new_bearer_with_observer` with [`diagnostics_observer`] for any client whose failures a
//! user could plausibly need to export — which today means every production call site.

pub use custos_client::{OAuthClient, OAuthError};

use std::sync::Arc;

/// The wallet's `custos_client::TransportObserver`, for `OAuthClient::new_bearer_with_observer`
/// call sites. A free function rather than a method on `OAuthClient` (that type lives in
/// `custos-client`, which knows nothing about `crate::diagnostics`).
pub fn diagnostics_observer() -> Arc<dyn custos_client::TransportObserver> {
    Arc::new(crate::diagnostics::WalletTransportObserver)
}
