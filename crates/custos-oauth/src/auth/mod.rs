//! The OAuth server's response mode. The verification core lives in `custos_core::auth` and is
//! re-exported here, so `crate::auth::…` paths resolve to it.

pub(crate) use custos_core::auth::*;

pub(crate) mod oauth_response_mode;
