//! `pds`'s test fixtures: everything in `custos_core::test_support` (re-exported below), with the
//! state constructors returning a full `AppState` instead of a `CoreState`, plus the fixtures that
//! need a `pds`-only type (the email sender, the `app()` router).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use custos_core::test_support as core;
pub use custos_core::test_support::*;

use crate::app::AppState;
// Shadow the glob's `CoreState` constructors for every `use test_utils::*` caller.
pub(crate) use crate::app::test_state;

// ── `AppState` versions of the core state constructors ──────────────────────
//
// Each shadows the glob-imported `CoreState` constructor of the same name.

/// `test_state()` with an `AlwaysOkDns` provider wired in.
pub async fn state_with_ok_dns() -> AppState {
    AppState::for_test(core::state_with_ok_dns().await).await
}

/// `test_state()` with an `AlwaysErrDns` provider wired in.
pub async fn state_with_err_dns() -> AppState {
    AppState::for_test(core::state_with_err_dns().await).await
}

/// Minimal test state with admin_token set to `"test-admin-token"`.
pub async fn test_state_with_admin_token() -> AppState {
    AppState::for_test(core::test_state_with_admin_token().await).await
}

/// `test_state()` with the signing-key master key configured (see [`test_master_key`]).
pub async fn state_with_master_key() -> AppState {
    AppState::for_test(core::state_with_master_key().await).await
}

/// `state` with a [`FixedTxtResolver`] wired in, answering every TXT lookup with `records`.
pub(crate) fn state_with_txt_records(state: AppState, records: Vec<String>) -> AppState {
    AppState {
        core: core::state_with_txt_records(state.core, records),
        ..state
    }
}

/// [`state_with_master_key`] plus a promoted account with a genesis repo.
pub(crate) async fn setup_account_with_repo() -> (AppState, String) {
    let (core, did) = core::setup_account_with_repo().await;
    (AppState::for_test(core).await, did)
}

/// [`state_with_master_key`] with `public_url` overridden and invite codes not required.
pub(crate) async fn state_with_master_key_and_url(public_url: &str) -> AppState {
    AppState::for_test(core::state_with_master_key_and_url(public_url).await).await
}

/// `test_state()` with the given agent-auth config swapped in (every flow is off by default).
pub(crate) async fn state_with_agent_auth(agent_auth: common::AgentAuthConfig) -> AppState {
    AppState::for_test(core::state_with_agent_auth(agent_auth).await).await
}

// ── Email sender test double ───────────────────────────────────────────────

/// Email sender that fails on every `send`, for exercising the delivery-failure branches of the
/// token-minting routes (which map a send error to `ServiceUnavailable`).
pub struct AlwaysErrEmail;

impl crate::email::EmailSender for AlwaysErrEmail {
    fn send<'a>(
        &'a self,
        _message: crate::email::EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::email::EmailError>> + Send + 'a>> {
        Box::pin(async {
            Err(crate::email::EmailError(
                "simulated delivery failure".to_string(),
            ))
        })
    }

    #[cfg(test)]
    fn kind(&self) -> crate::email::EmailSenderKind {
        crate::email::EmailSenderKind::Fake
    }
}

/// `test_state()` with an email sender that always fails delivery.
pub async fn state_with_failing_email() -> AppState {
    let base = test_state().await;
    AppState {
        email: Arc::new(AlwaysErrEmail),
        ..base
    }
}

/// [`custos_core::test_support::post_json_with_bearer`] against a fresh `app(state)` router.
pub(crate) async fn post_json_with_bearer(
    state: AppState,
    uri: &str,
    body: serde_json::Value,
    token: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    core::post_json_with_bearer(crate::app::app(state), uri, body, token).await
}
