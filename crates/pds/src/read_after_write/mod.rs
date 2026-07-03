// pattern: Imperative Shell
//
// Proxy a munged NSID to the AppView, buffer the response, and (in later phases) merge the
// requester's own unindexed records. In Phase 1 this is a behavioral no-op: it buffers and
// returns the AppView response verbatim.

mod munge;
mod types;
mod viewer;

pub use types::{LocalRecords, RecordDescript};

use axum::{
    body::Body,
    extract::Request,
    http::header,
    response::Response,
};
use common::{ApiError, ErrorCode};

use crate::app::AppState;

/// Proxy a munged NSID to the AppView, buffer the response, and (in later phases) merge the
/// requester's own unindexed records. In Phase 1 this is a behavioral no-op: it buffers and
/// returns the AppView response verbatim.
pub(crate) async fn pipethrough_munged(
    state: &AppState,
    nsid: &str,
    did: &str,
    req: Request,
) -> Response {
    let upstream = match crate::routes::service_proxy::proxy_request(
        state,
        &state.config.appview.url,
        &state.config.appview.did,
        nsid,
        did,
        None,
        req,
    )
    .await
    {
        Ok(resp) => resp,
        Err(resp) => return resp,
    };

    // Buffer status + content-type + body, rebuild an axum Response. Reads the body fully
    // (response buffer cap introduced in Phase 7); returns the bytes verbatim for now.
    let status =
        axum::http::StatusCode::from_u16(upstream.status().as_u16())
            .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    let content_type = upstream.headers().get(header::CONTENT_TYPE).cloned();

    let body_bytes = match axum::body::to_bytes(upstream.into_body(), usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(error = %err, nsid, "failed to read upstream response body");
            return ApiError::new(ErrorCode::InternalError, "failed to read upstream response")
                .into_response();
        }
    };

    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }

    match builder.body(Body::from(body_bytes)) {
        Ok(resp) => resp,
        Err(err) => {
            tracing::error!(error = %err, nsid, "failed to build munged proxy response");
            ApiError::new(ErrorCode::InternalError, "response build failed").into_response()
        }
    }
}
