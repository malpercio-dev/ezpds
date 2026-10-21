//! The verification core (`authenticate_access`, DPoP, JWTs, guards, scopes) and the auth.md agent
//! machinery live in `custos_core::auth`; re-exported here so `crate::auth::…` paths resolve to it.

pub use custos_core::auth::*;
