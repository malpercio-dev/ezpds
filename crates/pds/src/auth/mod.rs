//! `pds`'s auth modules: the OAuth-server response mode, the auth.md agent machinery, and the
//! Atproto Spaces seam. The verification core (`authenticate_access`, DPoP, JWTs, guards, scopes)
//! lives in `custos_core::auth` and is re-exported here, so `crate::auth::…` paths resolve to it.

pub mod agent_assertion;
pub mod client_attestation;
pub mod http_signature;
pub mod oauth_response_mode;
pub mod space;
pub mod space_consent;

pub use custos_core::auth::*;

pub use agent_assertion::{new_claim_poll_tracker, ClaimPollTracker};
pub use space_consent::{new_space_type_cache, SpaceTypeCache};
