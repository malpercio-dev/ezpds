// pattern: Imperative Shell
//
// The relay is a binary, but it is also a library — because the Custos sender must speak
// exactly this protocol, and the workspace's loopback end-to-end test drives a real relay
// in-process (pds ↔ notify-relay ↔ a stand-in Apple) rather than a stub. Sharing the crate
// makes a wire mismatch a compile error instead of a request the relay answers with
// `badRequest` in production, and makes the e2e test exercise the real accept loop, the real
// store, and the real APNs client.
//
// Module privacy is not what protects the relay: an instance reaches it over QUIC, and every
// authorization decision is made from the verified `connection.remote_id()`. Nothing here is
// reachable by a peer through the library surface.

pub mod apns;
pub mod config;
pub mod db;
pub mod identity;
pub mod protocol;
pub mod rate_limit;
pub mod service;
pub mod transport;
