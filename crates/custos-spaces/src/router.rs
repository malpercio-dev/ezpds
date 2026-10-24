// pattern: Imperative Shell

//! The Spaces route table. `pds` merges both routers into its own before the shared layer stack,
//! unconditionally; the `[spaces] enabled` gate lives here. Disabled, [`router`] registers
//! nothing, so a space method falls into `pds`'s `/xrpc/{method}` catch-all and answers
//! `MethodNotImplemented`, the same response a PDS that never implemented spaces gives.

use axum::{
    extract::FromRef,
    routing::{get, post},
    Router,
};
use common::SpacesConfig;
use custos_core::CoreState;

use crate::routes::*;
use crate::SpacesState;

/// The public (CORS'd) half of the Spaces surface: every `com.atproto.space.*` and
/// `com.atproto.simplespace.*` method. Empty when `[spaces] enabled` is off.
pub fn router<S>(config: &SpacesConfig) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    SpacesState: FromRef<S>,
    CoreState: FromRef<S>,
{
    if !config.enabled {
        return Router::new();
    }
    Router::new()
        // The space-credential mint pair: an OAuth session trades a delegation token for a
        // key-bound space credential.
        .route(
            "/xrpc/com.atproto.space.getDelegationToken",
            get(get_delegation_token),
        )
        .route(
            "/xrpc/com.atproto.space.getSpaceCredential",
            post(get_space_credential),
        )
        // Atproto Spaces: the permissioned-data surface for a user's own space repos. Reads and
        // writes are OAuth-authed here; the space-credential branch a syncer uses arrives with
        // the credential mint.
        .route(
            "/xrpc/com.atproto.space.applyWrites",
            post(space_apply_writes),
        )
        .route(
            "/xrpc/com.atproto.space.createRecord",
            post(space_create_record),
        )
        .route(
            "/xrpc/com.atproto.space.deleteRecord",
            post(space_delete_record),
        )
        .route(
            "/xrpc/com.atproto.space.getLatestCommit",
            get(space_get_latest_commit),
        )
        .route("/xrpc/com.atproto.space.getBlob", get(space_get_blob))
        .route("/xrpc/com.atproto.space.getRecord", get(space_get_record))
        .route("/xrpc/com.atproto.space.getRepo", get(space_get_repo))
        .route("/xrpc/com.atproto.space.listBlobs", get(space_list_blobs))
        .route(
            "/xrpc/com.atproto.space.listRecords",
            get(space_list_records),
        )
        .route(
            "/xrpc/com.atproto.space.listRepoOps",
            get(space_list_repo_ops),
        )
        .route("/xrpc/com.atproto.space.listRepos", get(space_list_repos))
        .route("/xrpc/com.atproto.space.listSpaces", get(space_list_spaces))
        .route("/xrpc/com.atproto.space.putRecord", post(space_put_record))
        // The notification surface: syncers subscribe here, repo hosts report here, and authorities
        // revoke credentials here.
        .route(
            "/xrpc/com.atproto.space.notifyCredentialRevoked",
            post(space_notify_credential_revoked),
        )
        .route(
            "/xrpc/com.atproto.space.notifyWrite",
            post(space_notify_write),
        )
        .route(
            "/xrpc/com.atproto.space.registerNotify",
            post(space_register_notify),
        )
        .route(
            "/xrpc/com.atproto.space.unregisterNotify",
            post(space_unregister_notify),
        )
        // The PDS-required simplespace management surface: spaces anchored on a local account's
        // own DID, managed by that account under `manage=` grants.
        .route(
            "/xrpc/com.atproto.simplespace.putMember",
            post(simplespace_put_member),
        )
        .route(
            "/xrpc/com.atproto.simplespace.createSpace",
            post(simplespace_create_space),
        )
        .route(
            "/xrpc/com.atproto.simplespace.deleteSpace",
            post(simplespace_delete_space),
        )
        .route(
            "/xrpc/com.atproto.simplespace.getSpace",
            get(simplespace_get_space),
        )
        .route(
            "/xrpc/com.atproto.simplespace.listMembers",
            get(simplespace_list_members),
        )
        .route(
            "/xrpc/com.atproto.simplespace.removeMember",
            post(simplespace_remove_member),
        )
        .route(
            "/xrpc/com.atproto.simplespace.updateSpace",
            post(simplespace_update_space),
        )
}

/// The `/v1/*` (no-CORS) half: the operator's per-space moderation pair, registered regardless of
/// `[spaces] enabled` because it governs data already stored (ADR-0035), and the inbound
/// permissioned-repo migration leg, gated with the rest of the surface.
pub fn internal_router<S>(config: &SpacesConfig) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    SpacesState: FromRef<S>,
    CoreState: FromRef<S>,
{
    let router = Router::new()
        .route("/v1/admin/spaces", get(list_hosted_spaces))
        .route("/v1/admin/spaces/takedown", post(set_space_takedown));
    if !config.enabled {
        return router;
    }
    // A Custos-native `/v1/*` route rather than a `com.atproto.space.*` method: the alpha
    // lexicons define no space import, so the namespace stays free for whatever the spec
    // eventually names.
    router.route("/v1/space/import-repo", post(space_import_repo))
}
