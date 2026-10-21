// pattern: Imperative Shell

//! The blob route table. `pds` merges it into its public (CORS'd) group before the shared layer
//! stack. Always on.

use axum::{
    extract::FromRef,
    routing::{get, post},
    Router,
};
use custos_core::CoreState;

use crate::routes::*;

/// `uploadBlob`, `listMissingBlobs`, and the two sync reads (`getBlob`, `listBlobs`).
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    CoreState: FromRef<S>,
{
    Router::new()
        .route("/xrpc/com.atproto.repo.uploadBlob", post(upload_blob))
        .route("/xrpc/com.atproto.sync.getBlob", get(get_blob))
        .route("/xrpc/com.atproto.sync.listBlobs", get(list_blobs))
        .route(
            "/xrpc/com.atproto.repo.listMissingBlobs",
            get(list_missing_blobs),
        )
}
