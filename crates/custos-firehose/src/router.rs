// pattern: Imperative Shell

//! The firehose serving route table. `pds` merges [`router`] into its public (CORS'd) group and
//! [`internal_router`] into its no-CORS `/v1/*` group, both before the shared layer stack.

use axum::{
    extract::FromRef,
    routing::{get, post},
    Router,
};
use custos_core::CoreState;

use crate::routes::*;

/// `com.atproto.sync.subscribeRepos`, the WebSocket firehose.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    CoreState: FromRef<S>,
{
    Router::new().route(
        "/xrpc/com.atproto.sync.subscribeRepos",
        get(subscribe_repos),
    )
}

/// The operator's federation-health pair: what the upstream relay reports about this PDS, and a
/// manual `requestCrawl` to every configured crawler.
pub fn internal_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    CoreState: FromRef<S>,
{
    Router::new()
        .route("/v1/admin/relay-status", get(relay_status))
        .route("/v1/admin/request-crawl", post(request_crawl))
}
