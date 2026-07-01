// pattern: Functional Core
//
// Shared `com.atproto.admin.defs` wire types for the admin subject-status endpoints
// (`get_subject_status.rs`, `update_subject_status.rs`). Not a route handler itself — mirrors
// `oauth_templates.rs`'s precedent for non-handler support code living under `routes/` and
// imported by the handlers that use it, so the two handlers can't drift out of sync on these
// shapes without one importing from the other.

use serde::Serialize;

/// `com.atproto.admin.defs#repoRef` — the only subject type ezpds's admin endpoints accept.
/// Account-level only: ezpds does not model record- or blob-level takedown.
#[derive(Serialize)]
pub(super) struct RepoRefView {
    #[serde(rename = "$type")]
    pub(super) type_: &'static str,
    pub(super) did: String,
}

/// `com.atproto.admin.defs#statusAttr`.
#[derive(Serialize)]
pub(super) struct StatusAttrView {
    pub(super) applied: bool,
}
