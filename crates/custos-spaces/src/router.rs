// pattern: Imperative Shell

//! The Spaces route table. `pds` merges both routers into its own before the shared layer stack,
//! unconditionally; the `[spaces] enabled` gate lives here. Disabled, [`router`] registers
//! nothing, so a space method falls into `pds`'s `/xrpc/{method}` catch-all and answers
//! `MethodNotImplemented`, the same response a PDS that never implemented spaces gives.

use axum::{
    extract::FromRef,
    middleware::map_response,
    routing::{get, post},
    Router,
};
use common::SpacesConfig;
use custos_core::CoreState;

use crate::routes::*;
use crate::space_mac::vary_accept_signature;

/// The public (CORS'd) half of the Spaces surface: every `com.atproto.space.*` and
/// `com.atproto.memberspace.*` method. Empty when `[spaces] enabled` is off.
pub fn router<S>(config: &SpacesConfig) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    CoreState: FromRef<S>,
{
    if !config.enabled {
        return Router::new();
    }
    Router::new()
        // The space-credential mint pair: an OAuth session mints a delegation token, and the space
        // authority trades it for a key-bound space credential.
        .route(
            "/xrpc/com.atproto.space.getDelegationToken",
            get(get_delegation_token),
        )
        .route(
            "/xrpc/com.atproto.space.authorizeSpaceSync",
            post(authorize_space_sync),
        )
        // Atproto Spaces: the permissioned-data surface for a user's own space repos. Reads and
        // writes are OAuth-authed here; the space-credential branch a syncer uses arrives with
        // the credential mint.
        .route(
            "/xrpc/com.atproto.space.applyWrites",
            post(space_apply_writes),
        )
        .route(
            "/xrpc/com.atproto.space.clearRecords",
            post(space_clear_records),
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
            get(space_get_latest_commit).layer(map_response(vary_accept_signature)),
        )
        .route("/xrpc/com.atproto.space.getBlob", get(space_get_blob))
        .route(
            "/xrpc/com.atproto.space.getRecord",
            get(space_get_record).layer(map_response(vary_accept_signature)),
        )
        .route(
            "/xrpc/com.atproto.space.getRepo",
            get(space_get_repo).layer(map_response(vary_accept_signature)),
        )
        .route("/xrpc/com.atproto.space.listBlobs", get(space_list_blobs))
        .route(
            "/xrpc/com.atproto.space.listRecords",
            get(space_list_records),
        )
        .route(
            "/xrpc/com.atproto.space.listRepoOps",
            get(space_list_repo_ops).layer(map_response(vary_accept_signature)),
        )
        .route(
            "/xrpc/com.atproto.space.listWriters",
            get(space_list_writers),
        )
        .route("/xrpc/com.atproto.space.listSpaces", get(space_list_spaces))
        .route("/xrpc/com.atproto.space.putRecord", post(space_put_record))
        // The notification surface: repo hosts report here, and authorities revoke credentials
        // here. Syncers register through `authorizeSpaceSync`.
        .route(
            "/xrpc/com.atproto.space.notifyCredentialsRevoked",
            post(space_notify_credentials_revoked),
        )
        .route(
            "/xrpc/com.atproto.space.notifyRepoUpdate",
            post(space_notify_repo_update),
        )
        // Space management: spaces anchored on a local account's own DID, managed by that
        // account under `manage=` grants, and the memberspace policy's member list.
        .route(
            "/xrpc/com.atproto.space.createSpace",
            post(space_create_space),
        )
        .route(
            "/xrpc/com.atproto.space.deleteSpace",
            post(space_delete_space),
        )
        .route("/xrpc/com.atproto.space.getSpace", get(space_get_space))
        .route(
            "/xrpc/com.atproto.space.removeWriter",
            post(space_remove_writer),
        )
        // Migration: the authority's space meta archive, then each repo's archive (`getRepo`).
        .route(
            "/xrpc/com.atproto.space.exportSpaceMeta",
            get(space_export_space_meta),
        )
        .route(
            "/xrpc/com.atproto.space.importSpaceMeta",
            post(space_import_space_meta),
        )
        .route(
            "/xrpc/com.atproto.space.importRepo",
            post(space_import_repo),
        )
        .route(
            "/xrpc/com.atproto.space.updateSpace",
            post(space_update_space),
        )
        .route(
            "/xrpc/com.atproto.memberspace.listMembers",
            get(memberspace_list_members),
        )
        .route(
            "/xrpc/com.atproto.memberspace.putMembers",
            post(memberspace_put_members),
        )
        .route(
            "/xrpc/com.atproto.memberspace.removeMembers",
            post(memberspace_remove_members),
        )
}

/// The `/v1/*` (no-CORS) half: the operator's per-space moderation pair, registered regardless of
/// `[spaces] enabled` because it governs data already stored (ADR-0035).
pub fn internal_router<S>(_config: &SpacesConfig) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    CoreState: FromRef<S>,
{
    Router::new()
        .route("/v1/admin/spaces", get(list_hosted_spaces))
        .route("/v1/admin/spaces/takedown", post(set_space_takedown))
}
