//! `pds`'s auth modules: the OAuth-server response mode and the auth.md agent machinery. The
//! verification core (`authenticate_access`, DPoP, JWTs, guards, scopes)
//! lives in `custos_core::auth` and is re-exported here, so `crate::auth::…` paths resolve to it.

pub mod agent_assertion;
pub mod oauth_response_mode;

pub use custos_core::auth::*;

pub use agent_assertion::{new_claim_poll_tracker, ClaimPollTracker};
