//! The auth.md agent route handlers, one file per surface. Only the handler functions leave this
//! module; shared support lives outside it (`crate::agent_child_core`, `crate::auth`, `crate::db`).

mod agent_child;
mod agent_claim;
mod agent_event;
mod agent_identity;
mod agents;
mod auth_md;

pub(crate) use agent_child::{
    delete_child, list_children, mint_child, remint_child_assertion, revoke_child,
};
pub(crate) use agent_claim::{post_agent_claim, post_agent_claim_confirm};
pub(crate) use agent_event::post_agent_event;
pub(crate) use agent_identity::post_agent_identity;
pub(crate) use agents::{agent_audit_log, claim_preview, list_agents, revoke_agent};
pub(crate) use auth_md::serve_auth_md;
