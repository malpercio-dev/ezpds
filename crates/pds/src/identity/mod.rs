// pattern: Imperative Shell
//
// Everything answering "who is this handle/DID": the resolution chain (local handles table → DNS
// TXT → HTTP well-known → did:plc/did:web document fetch), the `atproto-proxy` header target SSRF
// guard, handle validation, and the did:plc genesis/rotation-op machinery.

pub mod did;
pub mod dns;
pub mod genesis;
pub mod handle;
pub mod plc;
pub mod proxy;
pub mod resolution;
pub mod well_known;
