//! `pds`'s test fixtures: everything in `custos_core::test_support` (re-exported below), with the
//! state constructors returning a full `AppState` instead of a `CoreState`, plus the fixtures that
//! need a `pds`-only type (the email sender, the space request signer, the `app()` router).

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

/// `test_state()` with `mutate` applied to a clone of the config.
pub async fn state_with(mutate: impl FnOnce(&mut common::Config)) -> AppState {
    AppState::for_test(core::state_with(mutate).await).await
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

/// A P-256 key a space client binds its credential to, plus the RFC 9421 `atproto-space`
/// signatures it attaches: [`SpaceSigKey::delegation_headers`] for the `getSpaceCredential`
/// exchange (whose `keyid` becomes the credential's `cnf.kid`), and
/// [`SpaceSigKey::credential_headers`] for each credential-authed request. Both return the full
/// header set, so a request builder takes them with `headers_mut().extend(..)`.
pub(crate) struct SpaceSigKey {
    signer: repo_engine::CommitSigner,
    key_id: String,
}

impl SpaceSigKey {
    pub(crate) fn generate() -> Self {
        let kp = crypto::generate_p256_keypair().unwrap();
        Self {
            signer: repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap(),
            key_id: kp.key_id.0,
        }
    }

    /// The key's `did:key` — what a credential minted for it carries as `cnf.kid`.
    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    fn signed(&self, authorization: &str, audience: Option<&str>) -> axum::http::HeaderMap {
        use crate::auth::http_signature::{sign_space_request, AUDIENCE_HEADER};
        let (input, signature) = sign_space_request(
            |b| self.signer.sign(b),
            &self.key_id,
            authorization,
            audience,
        );
        let mut h = axum::http::HeaderMap::new();
        h.insert("authorization", authorization.parse().unwrap());
        h.insert("signature-input", input.parse().unwrap());
        h.insert("signature", signature.parse().unwrap());
        if let Some(audience) = audience {
            h.insert(AUDIENCE_HEADER, audience.parse().unwrap());
        }
        h
    }

    /// `Authorization: Bearer <delegation token>` signed for the credential exchange.
    pub(crate) fn delegation_headers(&self, delegation_token: &str) -> axum::http::HeaderMap {
        self.signed(&format!("Bearer {delegation_token}"), None)
    }

    /// `Authorization: Atproto-Space <credential>` addressed to `audience` and signed.
    pub(crate) fn credential_headers(
        &self,
        credential: &str,
        audience: &str,
    ) -> axum::http::HeaderMap {
        self.signed(&format!("Atproto-Space {credential}"), Some(audience))
    }
}

/// POST `body` as JSON to `uri` against a fresh `app(state)` router, with an optional `Bearer`
/// token, and return `(status, parsed_json_body)` (`Value::Null` if the body doesn't parse) —
/// the auth.md agent-flow route tests' one-shot request/response helper.
pub(crate) async fn post_json_with_bearer(
    state: AppState,
    uri: &str,
    body: serde_json::Value,
    token: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt;

    let mut builder = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        builder = builder.header("Authorization", format!("Bearer {t}"));
    }
    let response = crate::app::app(state)
        .oneshot(
            builder
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}
