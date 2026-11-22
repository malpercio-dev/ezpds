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

/// The agent-facing surface: the auth.md document, registration, the claim ceremony, minting a
/// sovereign child, and the provider event endpoint.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    CoreState: FromRef<S>,
{
    Router::new()
        .route("/auth.md", get(serve_auth_md))
        .route("/agent/identity", post(post_agent_identity))
        .route("/agent/child", post(mint_child))
        .route("/agent/identity/claim", post(post_agent_claim))
        .route(
            "/agent/identity/claim/confirm",
            post(post_agent_claim_confirm),
        )
        .route("/agent/event/notify", post(post_agent_event))
}

/// The owner's "My agents" management API, called same-origin by the wallet: every lifecycle verb
/// over an agent or a sovereign child, keyed by registration id.
pub fn internal_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    CoreState: FromRef<S>,
{
    Router::new()
        .route("/v1/agents", get(list_agents))
        .route("/v1/agents/children", get(list_children))
        .route("/v1/agents/claim-preview", post(claim_preview))
        .route("/v1/agents/{registration_id}/revoke", post(revoke_agent))
        .route(
            "/v1/agents/{registration_id}/assertion",
            post(remint_child_assertion),
        )
        .route("/v1/agents/{registration_id}/delete", post(delete_child))
        .route("/v1/agents/{registration_id}/audit", get(agent_audit_log))
        .route(
            "/v1/agents/{registration_id}/scopes",
            post(widen_agent_scopes),
        )
}
