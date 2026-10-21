// pattern: Imperative Shell

//! The auth.md agent route table. `pds` merges [`router`] into its public (CORS'd) group and
//! [`internal_router`] into its no-CORS `/v1/*` group, both before the shared layer stack. No
//! router-level gate: each registration flow checks its own `[agent_auth]` switch.

use axum::{
    extract::FromRef,
    routing::{get, post},
    Router,
};
use custos_core::CoreState;

use crate::routes::*;

/// The agent-facing surface: the auth.md document, registration, the claim ceremony, sovereign
/// child agents, and the provider event endpoint.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    CoreState: FromRef<S>,
{
    Router::new()
        .route("/auth.md", get(serve_auth_md))
        .route("/agent/identity", post(post_agent_identity))
        .route("/agent/child", get(list_children).post(mint_child))
        .route("/agent/child/assertion", post(remint_child_assertion))
        .route("/agent/child/revoke", post(revoke_child))
        .route("/agent/child/delete", post(delete_child))
        .route("/agent/identity/claim", post(post_agent_claim))
        .route(
            "/agent/identity/claim/confirm",
            post(post_agent_claim_confirm),
        )
        .route("/agent/event/notify", post(post_agent_event))
}

/// The owner's "My agents" management API, called same-origin by the wallet.
pub fn internal_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    CoreState: FromRef<S>,
{
    Router::new()
        .route("/v1/agents", get(list_agents))
        .route("/v1/agents/claim-preview", post(claim_preview))
        .route("/v1/agents/{registration_id}/revoke", post(revoke_agent))
        .route("/v1/agents/{registration_id}/audit", get(agent_audit_log))
}
