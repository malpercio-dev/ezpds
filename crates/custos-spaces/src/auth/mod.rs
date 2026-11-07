//! The Spaces authorization seam (`space`), the client-attestation verifier it calls, and the
//! RFC 9421 signature profile both share. The verification core is `custos_core::auth`'s and is
//! named there.

pub(crate) mod client_attestation;
pub(crate) mod http_signature;
pub(crate) mod space;
