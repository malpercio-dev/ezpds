//! The firehose serving routes, one file per endpoint. Only the handler functions leave this module.

mod admin_relay_status;
mod admin_request_crawl;
mod sync_subscribe_repos;

pub(crate) use admin_relay_status::relay_status;
pub(crate) use admin_request_crawl::request_crawl;
pub(crate) use sync_subscribe_repos::subscribe_repos;
