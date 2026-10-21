//! `pds`'s auth modules: the OAuth-server response mode. The verification core
//! (`authenticate_access`, DPoP, JWTs, guards, scopes) and the auth.md agent machinery live in `custos_core::auth` and is re-exported here, so `crate::auth::…` paths resolve to it.

pub mod oauth_response_mode;

pub use custos_core::auth::*;

