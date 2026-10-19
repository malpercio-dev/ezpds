// pattern: Mixed (unavoidable)

//! Re-exports [`custos_client::OAuthClient`] — the authenticated XRPC HTTP client (DPoP and
//! Bearer modes) — under this module's historical path, plus [`diagnostics_observer`], the
//! one wallet-side seam a real (non-test) `new_bearer_with_observer` call site should pass so
//! transport/server failures still reach the exportable diagnostics log. See
//! `custos_client::oauth_client`'s module doc for the client's own behavior (lazy refresh,
//! nonce retry, auth modes).
//!
//! `OAuthClient::new_bearer`'s plain 3-arg form records no breadcrumbs — every call site in
//! this app today is a test fixture (verified: none live outside a `#[cfg(test)]` module).
//! This silent-by-default form is new to this extraction, not inherited from it: pre-extraction
//! there was one `OAuthClient` and it recorded breadcrumbs unconditionally. Use
//! `new_bearer_with_observer` with [`diagnostics_observer`] for any client whose failures a
//! user could plausibly need to export — which today means every production call site.

pub use custos_client::{OAuthClient, OAuthError, OAuthSession};

use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

/// The wallet's `custos_client::TransportObserver`, for `OAuthClient::new_bearer_with_observer`
/// call sites. A free function rather than a method on `OAuthClient` (that type lives in
/// `custos-client`, which knows nothing about `crate::diagnostics`).
pub(crate) fn diagnostics_observer() -> Arc<dyn custos_client::TransportObserver> {
    Arc::new(crate::oauth::WalletTransportObserver)
}

/// Build a DPoP-mode test client with no diagnostics/persistence wiring — the wallet-side
/// equivalent of the old `OAuthClient::new_for_test`, which `custos_client`'s own
/// `#[cfg(test)]` constructor can't serve (a dependency's `#[cfg(test)]` items don't compile
/// into a downstream crate's test build). `custos_client::OAuthClient::new` already takes a
/// pre-built keypair, so this is a thin no-op-observer/no-op-persister wrapper over it.
#[cfg(test)]
pub(crate) fn new_for_test(
    keypair: custos_client::DpopKeypair,
    session: Arc<Mutex<OAuthSession>>,
    base_url: String,
) -> OAuthClient {
    OAuthClient::new(
        keypair,
        "test-client".to_string(),
        session,
        base_url,
        Arc::new(custos_client::NoopObserver),
        Arc::new(custos_client::NoopTokenPersister),
    )
}
