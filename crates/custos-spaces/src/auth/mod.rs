//! The Spaces authorization seam (`space`), the client-attestation verifier it calls, and the
//! RFC 9421 signature profile both share. The verification core lives in `custos_core::auth` and
//! is re-exported here, so `crate::auth::…` paths resolve to it.

pub(crate) use custos_core::auth::*;

pub(crate) mod client_attestation;
pub(crate) mod http_signature;
pub(crate) mod space;
