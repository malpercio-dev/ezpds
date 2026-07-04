// pattern: Imperative Shell
//
// Proxy a munged NSID to the AppView, buffer the response, and (in later phases) merge the
// requester's own unindexed records. In Phase 1 this is a behavioral no-op: it buffers and
// returns the AppView response verbatim.

mod munge;
mod types;
mod viewer;

#[allow(unused_imports)]
pub use types::{LocalRecords, RecordDescript};

use axum::{
    body::Body,
    extract::Request,
    http::header,
    response::{IntoResponse, Response},
};
use common::{ApiError, ErrorCode};
use std::collections::HashMap;

use crate::app::AppState;
use crate::db::blocks::SqliteBlockStore;
use atrium_repo::Cid;
use repo_engine::Repository;

/// Maximum size of a munged response body. AppView endpoints return modest JSON
/// (typically < 1 MiB). This cap guards against unbounded buffering on broken upstream
/// or deliberate abuse. Exceeding the cap triggers fallback to the original error envelope.
const MAX_MUNGE_RESPONSE_BODY: usize = 10 * 1024 * 1024;

/// Build the requester's unindexed LocalRecords relative to the AppView's indexed rev.
/// Returns an empty LocalRecords when `header_rev` is None (missing header) or nothing is newer.
#[allow(dead_code)]
pub(crate) async fn get_records_since_rev(
    state: &AppState,
    did: &str,
    header_rev: Option<&str>,
) -> LocalRecords {
    let Some(header_rev) = header_rev else {
        return LocalRecords::default();
    };

    // 1. Fetch recent commits for this DID (200-record limit is ample).
    let rows = match crate::db::firehose_seq::recent_commits_for_did(&state.db, did, 200).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(error = %err, did, "failed to fetch recent commits");
            return LocalRecords::default();
        }
    };

    // 2. Decode each row and walk newest-first, stopping at rev <= header_rev.
    // Collect distinct (collection, rkey), keeping the newest CommitEvent.time per key.
    let mut touched: HashMap<(String, String), (String, Cid)> = HashMap::new(); // (coll, rkey) -> (time, cid)

    for row in rows {
        let event =
            match crate::firehose::decode_stored_event(row.seq as u64, &row.event_type, &row.event)
            {
                Ok(crate::firehose::FirehoseEvent::Commit(c)) => c,
                Ok(_) => continue, // Should not happen; we filtered for 'commit' in the query
                Err(err) => {
                    tracing::debug!(error = %err, seq = row.seq, "failed to decode commit event");
                    continue; // best-effort: skip this record
                }
            };

        // Stop if this commit's rev is at or below the header rev (string comparison: TIDs sort by time)
        if event.rev.as_str() <= header_rev {
            break;
        }

        // Collect ops from this commit
        for op in &event.ops {
            let key = (op.collection.clone(), op.rkey.clone());
            // Keep the first (newest) occurrence since we're walking newest-first
            if let std::collections::hash_map::Entry::Vacant(e) = touched.entry(key) {
                if let Some(cid_str) = &op.cid {
                    if let Ok(cid) = Cid::try_from(cid_str.as_str()) {
                        e.insert((event.time.clone(), cid));
                    }
                }
            }
        }
    }

    // 3. Get the repo root CID and open the repository once.
    let root_str = match crate::db::accounts::get_repo_root_cid(&state.db, did).await {
        Ok(Some(cid)) => cid,
        Ok(None) => {
            // Account has no repo; return empty records.
            return LocalRecords::default();
        }
        Err(err) => {
            tracing::error!(error = %err, did, "failed to fetch repo root CID");
            return LocalRecords::default();
        }
    };

    let root_cid = match Cid::try_from(root_str.as_str()) {
        Ok(cid) => cid,
        Err(err) => {
            tracing::error!(error = %err, did, "invalid root CID");
            return LocalRecords::default();
        }
    };

    let block_store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = match Repository::open(block_store, root_cid).await {
        Ok(repo) => repo,
        Err(err) => {
            tracing::error!(error = %err, did, "failed to open repository");
            return LocalRecords::default();
        }
    };

    // 4. Read current values for each touched record.
    let mut profile_val: Option<RecordDescript> = None;
    let mut posts: Vec<RecordDescript> = Vec::new();

    for ((collection, rkey), (indexed_at_time, op_cid)) in touched.iter() {
        let record_path = format!("{}/{}", collection, rkey);
        let json_val = match repo_engine::get_record_json(&mut repo, &record_path).await {
            Ok(Some(val)) => val,
            Ok(None) => continue, // Record was deleted after write; skip.
            Err(err) => {
                // best-effort: skip this record on error
                tracing::debug!(error = %err, collection, rkey, "failed to read record");
                continue;
            }
        };

        let uri = format!("at://{}/{}/{}", did, collection, rkey);

        let descript = RecordDescript {
            uri,
            cid: op_cid.to_string(),
            indexed_at: indexed_at_time.clone(),
            record: json_val,
        };

        // 4b. Bucket by collection
        match collection.as_str() {
            "app.bsky.actor.profile" if rkey == "self" => {
                profile_val = Some(descript);
            }
            "app.bsky.feed.post" => {
                posts.push(descript);
            }
            _ => {
                // Ignore other collections
            }
        }
    }

    let count = profile_val.is_some() as usize + posts.len();

    LocalRecords {
        count,
        profile: profile_val,
        posts,
    }
}

/// Milliseconds since the oldest merged record's indexed_at, or None when there are none.
#[allow(dead_code)]
fn local_lag_ms(local: &LocalRecords) -> Option<i64> {
    if local.count == 0 {
        return None;
    }

    // Find the oldest indexed_at among all records
    let mut oldest = local
        .profile
        .as_ref()
        .map(|p| p.indexed_at.as_str())
        .or_else(|| local.posts.first().map(|p| p.indexed_at.as_str()));

    for post in &local.posts {
        if let Some(current_oldest) = oldest {
            if post.indexed_at.as_str() < current_oldest {
                oldest = Some(post.indexed_at.as_str());
            }
        } else {
            oldest = Some(post.indexed_at.as_str());
        }
    }

    let oldest_str = oldest?;

    // Parse RFC 3339 timestamp
    let oldest_time = match chrono::DateTime::parse_from_rfc3339(oldest_str) {
        Ok(dt) => dt,
        Err(err) => {
            tracing::warn!(error = %err, indexed_at = oldest_str, "failed to parse RFC3339 timestamp");
            return None;
        }
    };

    // Get current time
    let now = chrono::Local::now();

    // Calculate milliseconds elapsed
    let duration = now.signed_duration_since(oldest_time);
    Some(duration.num_milliseconds())
}

/// Extract a query parameter from the request URI by key.
fn extract_query_param(req: &Request, key: &str) -> Option<String> {
    let uri = req.uri();
    uri.query().and_then(|q| {
        for pair in q.split('&') {
            if let Some(value) = pair.strip_prefix(&format!("{}=", key)) {
                return Some(urlencoding::decode(value).ok()?.into_owned());
            }
        }
        None
    })
}

/// Extract the `actor` query param from the request for getAuthorFeed.
fn extract_actor_param(req: &Request, nsid: &str) -> Option<String> {
    if nsid != "app.bsky.feed.getAuthorFeed" {
        return None;
    }

    extract_query_param(req, "actor")
}

/// Parse an XRPC error response body to extract the error code.
/// Best-effort: returns None if parsing fails or the error code is not a string.
fn parsed_error_code(bytes: &[u8]) -> Option<String> {
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(val) => val
            .get("error")
            .and_then(|e| e.as_str())
            .map(|s| s.to_string()),
        Err(_) => None,
    }
}

/// Proxy a munged NSID to the AppView, buffer the response, and merge the requester's own
/// unindexed records. Best-effort: errors in munge steps fall back to the buffered original.
pub(crate) async fn pipethrough_munged(
    state: &AppState,
    nsid: &str,
    did: &str,
    req: Request,
) -> Response {
    let actor = extract_actor_param(&req, nsid);
    let uri = extract_query_param(&req, "uri");

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

    // 1. Capture status, content-type, and atproto-repo-rev header
    let status = axum::http::StatusCode::from_u16(upstream.status().as_u16())
        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    let content_type = upstream.headers().get(header::CONTENT_TYPE).cloned();
    let header_rev = upstream
        .headers()
        .get("atproto-repo-rev")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // 2. Buffer the body with a size cap
    // First check content-length if available to bail early on obviously-oversized responses
    let content_length = upstream.content_length();
    if let Some(len) = content_length {
        if len as usize > MAX_MUNGE_RESPONSE_BODY {
            tracing::warn!(
                content_length = len,
                max = MAX_MUNGE_RESPONSE_BODY,
                nsid,
                "upstream response body exceeds max munge size"
            );
            return ApiError::new(ErrorCode::InternalError, "upstream response too large")
                .into_response();
        }
    }

    let body_bytes = match upstream.bytes().await {
        Ok(bytes) => {
            // Double-check the buffered size in case content-length was absent or lying
            if bytes.len() > MAX_MUNGE_RESPONSE_BODY {
                tracing::warn!(
                    actual_size = bytes.len(),
                    max = MAX_MUNGE_RESPONSE_BODY,
                    nsid,
                    "buffered upstream response body exceeded max munge size"
                );
                return ApiError::new(ErrorCode::InternalError, "upstream response too large")
                    .into_response();
            }
            bytes
        }
        Err(err) => {
            tracing::error!(error = %err, nsid, "failed to read upstream response body");
            return ApiError::new(ErrorCode::InternalError, "failed to read upstream response")
                .into_response();
        }
    };

    // 3. Check if this is a getPostThread NotFound that should be munged
    let is_thread_not_found = nsid == "app.bsky.feed.getPostThread"
        && status == axum::http::StatusCode::BAD_REQUEST
        && parsed_error_code(&body_bytes) == Some("NotFound".to_string());

    // 4. If status is not success and not a thread NotFound, return the buffered response unchanged
    if !status.is_success() && !is_thread_not_found {
        let mut builder = Response::builder().status(status);
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        return match builder.body(Body::from(body_bytes)) {
            Ok(resp) => resp,
            Err(err) => {
                tracing::error!(error = %err, nsid, "failed to build error proxy response");
                ApiError::new(ErrorCode::InternalError, "response build failed").into_response()
            }
        };
    }

    // 4. Parse body as serde_json::Value
    let parsed = match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
        Ok(val) => val,
        Err(err) => {
            tracing::warn!(error = %err, nsid, "failed to parse upstream body as JSON");
            let mut builder = Response::builder().status(status);
            if let Some(content_type) = content_type {
                builder = builder.header(header::CONTENT_TYPE, content_type);
            }
            return match builder.body(Body::from(body_bytes)) {
                Ok(resp) => resp,
                Err(err) => {
                    tracing::error!(error = %err, nsid, "failed to build parse-error proxy response");
                    ApiError::new(ErrorCode::InternalError, "response build failed").into_response()
                }
            };
        }
    };

    // 5. Get local records since the AppView's rev
    let local = get_records_since_rev(state, did, header_rev.as_deref()).await;

    // If local.count == 0 -> return buffered original (no lag header)
    if local.count == 0 {
        let mut builder = Response::builder().status(status);
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        return match builder.body(Body::from(body_bytes)) {
            Ok(resp) => resp,
            Err(err) => {
                tracing::error!(error = %err, nsid, "failed to build no-local proxy response");
                ApiError::new(ErrorCode::InternalError, "response build failed").into_response()
            }
        };
    }

    // 6. Get the handle and build LocalViewer
    let handle = match crate::db::accounts::get_session_account(&state.db, did).await {
        Ok(Some(account)) => account.handle,
        Ok(None) => {
            tracing::warn!(did, "account not found for local viewer");
            let mut builder = Response::builder().status(status);
            if let Some(content_type) = content_type {
                builder = builder.header(header::CONTENT_TYPE, content_type);
            }
            return match builder.body(Body::from(body_bytes)) {
                Ok(resp) => resp,
                Err(err) => {
                    tracing::error!(error = %err, nsid, "failed to build viewer-lookup proxy response");
                    ApiError::new(ErrorCode::InternalError, "response build failed").into_response()
                }
            };
        }
        Err(err) => {
            tracing::warn!(error = %err, did, "failed to get session account for local viewer");
            let mut builder = Response::builder().status(status);
            if let Some(content_type) = content_type {
                builder = builder.header(header::CONTENT_TYPE, content_type);
            }
            return match builder.body(Body::from(body_bytes)) {
                Ok(resp) => resp,
                Err(err) => {
                    tracing::error!(error = %err, nsid, "failed to build viewer-error proxy response");
                    ApiError::new(ErrorCode::InternalError, "response build failed").into_response()
                }
            };
        }
    };

    let profile_val = local.profile.as_ref().map(|p| p.record.clone());
    let viewer = viewer::LocalViewer::new(state, did.to_string(), handle, profile_val);

    // 7. Dispatch and munge
    let munged = match nsid {
        "app.bsky.actor.getProfile" => munge::get_profile(&viewer, parsed, &local, did).await,
        "app.bsky.actor.getProfiles" => munge::get_profiles(&viewer, parsed, &local, did).await,
        "app.bsky.feed.getTimeline" => munge::get_timeline(&viewer, parsed, &local, did).await,
        "app.bsky.feed.getAuthorFeed" => {
            munge::get_author_feed(&viewer, parsed, &local, did, actor.as_deref()).await
        }
        "app.bsky.feed.getActorLikes" => munge::get_actor_likes(&viewer, parsed, &local, did).await,
        "app.bsky.feed.getPostThread" => {
            munge::get_post_thread(&viewer, parsed, &local, did, uri.as_deref().unwrap_or("")).await
        }
        // Other NSIDs: return parsed unchanged (filled in later phases)
        _ => parsed,
    };

    // Serialize munged and build response with lag header if present
    let munged_bytes = match serde_json::to_vec(&munged) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(error = %err, nsid, "failed to serialize munged response");
            let mut builder = Response::builder().status(status);
            if let Some(content_type) = content_type {
                builder = builder.header(header::CONTENT_TYPE, content_type);
            }
            return match builder.body(Body::from(body_bytes)) {
                Ok(resp) => resp,
                Err(err) => {
                    tracing::error!(error = %err, nsid, "failed to build serialize-error proxy response");
                    ApiError::new(ErrorCode::InternalError, "response build failed").into_response()
                }
            };
        }
    };

    // If we munged a NotFound thread successfully, override status to 200.
    // Only override if the munged output actually contains a reconstructed thread.
    let reconstructed = munged.get("thread").map(|t| !t.is_null()).unwrap_or(false);
    let response_status = if is_thread_not_found && status.is_client_error() && reconstructed {
        axum::http::StatusCode::OK
    } else {
        status
    };

    let mut builder = Response::builder().status(response_status);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }

    if let Some(lag_ms) = local_lag_ms(&local) {
        builder = builder.header("Atproto-Upstream-Lag", lag_ms.to_string());
    }

    match builder.body(Body::from(munged_bytes)) {
        Ok(resp) => resp,
        Err(err) => {
            tracing::error!(error = %err, nsid, "failed to build munged proxy response");
            ApiError::new(ErrorCode::InternalError, "response build failed").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_utils::{
        access_jwt, delete_record_request, put_record_request, seed_account_with_repo,
    };
    use tower::ServiceExt;

    #[test]
    fn local_lag_ms_returns_none_for_empty_records() {
        let local = LocalRecords::default();
        assert_eq!(local_lag_ms(&local), None);
    }

    fn author_feed_request(query: &str) -> Request {
        axum::http::Request::builder()
            .uri(format!("/xrpc/app.bsky.feed.getAuthorFeed?{query}"))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[test]
    fn extract_actor_param_returns_did_for_author_feed() {
        let req = author_feed_request("actor=did:plc:abc123");
        assert_eq!(
            extract_actor_param(&req, "app.bsky.feed.getAuthorFeed"),
            Some("did:plc:abc123".to_string())
        );
    }

    #[test]
    fn extract_actor_param_finds_actor_in_any_position() {
        let req = author_feed_request("limit=30&actor=alice.bsky.social&cursor=xyz");
        assert_eq!(
            extract_actor_param(&req, "app.bsky.feed.getAuthorFeed"),
            Some("alice.bsky.social".to_string())
        );
    }

    #[test]
    fn extract_actor_param_returns_none_for_other_nsid() {
        // Even with an actor param present, a non-getAuthorFeed NSID must not resolve it.
        let req = axum::http::Request::builder()
            .uri("/xrpc/app.bsky.feed.getTimeline?actor=did:plc:abc123")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_actor_param(&req, "app.bsky.feed.getTimeline"), None);
    }

    #[test]
    fn extract_actor_param_returns_none_when_absent() {
        let req = author_feed_request("limit=30");
        assert_eq!(
            extract_actor_param(&req, "app.bsky.feed.getAuthorFeed"),
            None
        );
    }

    #[test]
    fn extract_actor_param_percent_decodes_value() {
        // A handle encoded by the client must be decoded before the guard compares it.
        let req = author_feed_request("actor=alice%40example.com");
        assert_eq!(
            extract_actor_param(&req, "app.bsky.feed.getAuthorFeed"),
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn local_lag_ms_returns_some_for_records_with_indexed_at() {
        // Use a known past timestamp
        let iso_past = "2026-01-01T00:00:00.000Z";
        let local = LocalRecords {
            count: 1,
            profile: Some(RecordDescript {
                uri: "at://did:plc:test/app.bsky.actor.profile/self".to_string(),
                cid: "bafy123".to_string(),
                indexed_at: iso_past.to_string(),
                record: serde_json::json!({}),
            }),
            posts: vec![],
        };

        let lag = local_lag_ms(&local);
        assert!(lag.is_some(), "lag should be Some for a past timestamp");
        assert!(
            lag.unwrap() > 0,
            "lag should be positive for a past timestamp"
        );
    }

    #[test]
    fn local_lag_ms_picks_oldest_among_posts() {
        // Multiple posts with different timestamps; oldest should win
        let iso_old = "2026-01-01T00:00:00.000Z";
        let iso_new = "2026-06-30T00:00:00.000Z";

        let local = LocalRecords {
            count: 2,
            profile: None,
            posts: vec![
                RecordDescript {
                    uri: "at://did:plc:test/app.bsky.feed.post/post1".to_string(),
                    cid: "bafy1".to_string(),
                    indexed_at: iso_new.to_string(),
                    record: serde_json::json!({}),
                },
                RecordDescript {
                    uri: "at://did:plc:test/app.bsky.feed.post/post2".to_string(),
                    cid: "bafy2".to_string(),
                    indexed_at: iso_old.to_string(),
                    record: serde_json::json!({}),
                },
            ],
        };

        let lag = local_lag_ms(&local);
        assert!(lag.is_some());
        // The old timestamp should produce a larger lag than a newer one
        let lag_old = lag.unwrap();

        let local_new = LocalRecords {
            count: 1,
            profile: None,
            posts: vec![RecordDescript {
                uri: "at://did:plc:test/app.bsky.feed.post/post3".to_string(),
                cid: "bafy3".to_string(),
                indexed_at: iso_new.to_string(),
                record: serde_json::json!({}),
            }],
        };

        let lag_newer = local_lag_ms(&local_new).unwrap();
        assert!(
            lag_old > lag_newer,
            "lag from older timestamp should be larger than newer"
        );
    }

    #[test]
    fn record_descript_has_expected_fields() {
        let desc = RecordDescript {
            uri: "at://did:plc:test/app.bsky.feed.post/abc123".to_string(),
            cid: "bafy123".to_string(),
            indexed_at: "2026-06-30T12:34:56.789Z".to_string(),
            record: serde_json::json!({ "text": "hello" }),
        };

        assert_eq!(desc.uri, "at://did:plc:test/app.bsky.feed.post/abc123");
        assert_eq!(desc.cid, "bafy123");
        assert_eq!(desc.indexed_at, "2026-06-30T12:34:56.789Z");
        assert_eq!(desc.record["text"], "hello");
    }

    #[test]
    fn local_records_count_is_accurate() {
        let local = LocalRecords {
            count: 3,
            profile: Some(RecordDescript {
                uri: "at://did:plc:test/app.bsky.actor.profile/self".to_string(),
                cid: "bafy1".to_string(),
                indexed_at: "2026-06-30T00:00:00.000Z".to_string(),
                record: serde_json::json!({}),
            }),
            posts: vec![
                RecordDescript {
                    uri: "at://did:plc:test/app.bsky.feed.post/post1".to_string(),
                    cid: "bafy2".to_string(),
                    indexed_at: "2026-06-30T00:00:00.000Z".to_string(),
                    record: serde_json::json!({}),
                },
                RecordDescript {
                    uri: "at://did:plc:test/app.bsky.feed.post/post2".to_string(),
                    cid: "bafy3".to_string(),
                    indexed_at: "2026-06-30T00:00:00.000Z".to_string(),
                    record: serde_json::json!({}),
                },
            ],
        };

        assert_eq!(local.count, 3);
        assert_eq!(local.posts.len(), 2);
        assert!(local.profile.is_some());
    }

    #[test]
    fn parsed_error_code_extracts_valid_error() {
        let body = br#"{"error":"NotFound","message":"not found"}"#;
        assert_eq!(parsed_error_code(body), Some("NotFound".to_string()));
    }

    #[test]
    fn parsed_error_code_returns_none_for_non_error_json() {
        let body = br#"{"thread":null}"#;
        assert_eq!(parsed_error_code(body), None);
    }

    #[test]
    fn parsed_error_code_returns_none_for_garbage_bytes() {
        let body = b"not json";
        assert_eq!(parsed_error_code(body), None);
    }

    #[test]
    fn parsed_error_code_returns_none_when_error_is_not_string() {
        let body = br#"{"error":123}"#;
        assert_eq!(parsed_error_code(body), None);
    }

    #[tokio::test]
    async fn test_get_records_since_rev_ac5_3_none_header_rev_returns_empty() {
        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:test789";
        seed_account_with_repo(&state.db, did).await;

        let local = get_records_since_rev(&state, did, None).await;

        assert_eq!(
            local.count, 0,
            "missing header_rev should return empty LocalRecords"
        );
        assert!(local.profile.is_none());
        assert!(local.posts.is_empty());
    }

    #[tokio::test]
    async fn test_get_records_since_rev_ac5_1_returns_records_after_header_rev() {
        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:test123";
        seed_account_with_repo(&state.db, did).await;

        let app = crate::app::app(state.clone());
        let token = access_jwt(&state.jwt_secret, did);

        let post_req_1 = put_record_request(
            did,
            "app.bsky.feed.post",
            "post1",
            serde_json::json!({ "record": { "text": "first post" } }),
            Some(&token),
        );

        let _post1_resp = app.clone().oneshot(post_req_1).await.unwrap();

        let post_req_2 = put_record_request(
            did,
            "app.bsky.feed.post",
            "post2",
            serde_json::json!({ "record": { "text": "second post" } }),
            Some(&token),
        );

        let _post2_resp = app.clone().oneshot(post_req_2).await.unwrap();

        let profile_req = put_record_request(
            did,
            "app.bsky.actor.profile",
            "self",
            serde_json::json!({ "record": { "displayName": "Test User" } }),
            Some(&token),
        );

        let _profile_resp = app.clone().oneshot(profile_req).await.unwrap();

        let local = get_records_since_rev(&state, did, Some("0")).await;

        assert!(
            local.count >= 3,
            "should have at least 1 profile + 2 posts (got {})",
            local.count
        );
        assert!(
            local.profile.is_some(),
            "should have profile, got: {:?}",
            local.profile
        );
        assert!(
            local.posts.len() >= 2,
            "should have at least 2 posts (got {})",
            local.posts.len()
        );

        if let Some(profile) = &local.profile {
            assert!(profile.uri.contains("app.bsky.actor.profile"));
            assert!(profile.uri.contains("self"));
        }

        for post in &local.posts {
            assert!(post.uri.contains("app.bsky.feed.post"));
        }
    }

    #[tokio::test]
    async fn test_get_records_since_rev_ac5_2_excludes_deleted_records() {
        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:test456";
        seed_account_with_repo(&state.db, did).await;

        let app = crate::app::app(state.clone());
        let token = access_jwt(&state.jwt_secret, did);

        let post_req = put_record_request(
            did,
            "app.bsky.feed.post",
            "post_to_delete",
            serde_json::json!({ "record": { "text": "will be deleted" } }),
            Some(&token),
        );

        let _post_resp = app.clone().oneshot(post_req).await.unwrap();

        let delete_req = delete_record_request(
            did,
            "app.bsky.feed.post",
            "post_to_delete",
            serde_json::json!({}),
            Some(&token),
        );

        let _delete_resp = app.clone().oneshot(delete_req).await.unwrap();

        let local = get_records_since_rev(&state, did, Some("0")).await;

        assert_eq!(
            local.count, 0,
            "deleted record should not appear in local records"
        );
        assert!(local.posts.is_empty());
    }

    #[tokio::test]
    async fn test_get_records_since_rev_indexed_at_per_record() {
        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:test_indexed_at";
        seed_account_with_repo(&state.db, did).await;

        let app = crate::app::app(state.clone());
        let token = access_jwt(&state.jwt_secret, did);

        let post_req = put_record_request(
            did,
            "app.bsky.feed.post",
            "post1",
            serde_json::json!({ "record": { "text": "first" } }),
            Some(&token),
        );

        let _post_resp = app.clone().oneshot(post_req).await.unwrap();

        let profile_req = put_record_request(
            did,
            "app.bsky.actor.profile",
            "self",
            serde_json::json!({ "record": { "displayName": "Test" } }),
            Some(&token),
        );

        let _profile_resp = app.clone().oneshot(profile_req).await.unwrap();

        let local = get_records_since_rev(&state, did, Some("0")).await;

        assert!(local.count > 0);

        if let Some(profile) = &local.profile {
            assert!(
                !profile.indexed_at.is_empty(),
                "profile should have indexed_at"
            );
        }

        for post in &local.posts {
            assert!(!post.indexed_at.is_empty(), "post should have indexed_at");
        }
    }

    #[tokio::test]
    async fn test_pipethrough_munged_ac2_1_stale_appview_plus_fresh_local_profile() {
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let old_rev = "0";
        Mock::given(method("POST"))
            .and(path("/xrpc/app.bsky.actor.getProfile"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("atproto-repo-rev", old_rev)
                    .set_body_json(serde_json::json!({
                        "did": "did:plc:test_ac2_1",
                        "handle": "test.bsky.social",
                        "displayName": "Old AppView Name",
                        "description": "Old AppView Description"
                    })),
            )
            .mount(&server)
            .await;

        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:test_ac2_1";
        seed_account_with_repo(&state.db, did).await;

        // Insert handle
        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("test.bsky.social")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();

        let app = crate::app::app(state.clone());
        let token = access_jwt(&state.jwt_secret, did);

        // Write a profile record locally
        let profile_req = put_record_request(
            did,
            "app.bsky.actor.profile",
            "self",
            serde_json::json!({
                "record": {
                    "displayName": "Local Fresh Name",
                    "description": "Local Fresh Description"
                }
            }),
            Some(&token),
        );

        let _profile_resp = app.clone().oneshot(profile_req).await.unwrap();

        // Update AppView URL in config
        let mut state = state.clone();
        let mut config = (*state.config).clone();
        config.appview.url = server.uri();
        state.config = Arc::new(config);

        // Create request
        let req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/xrpc/app.bsky.actor.getProfile?actor=did:plc:test_ac2_1")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(""))
            .unwrap();

        let resp = pipethrough_munged(&state, "app.bsky.actor.getProfile", did, req).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // Check that lag header is present
        assert!(
            resp.headers().get("Atproto-Upstream-Lag").is_some(),
            "Atproto-Upstream-Lag header should be present"
        );

        // Check munged response
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let munged: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(
            munged["displayName"], "Local Fresh Name",
            "displayName should come from local record"
        );
        assert_eq!(
            munged["description"], "Local Fresh Description",
            "description should come from local record"
        );
    }

    #[tokio::test]
    async fn test_pipethrough_munged_ac2_5_no_local_profile() {
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let fresh_rev = "bafy2bzaced7h";
        Mock::given(method("POST"))
            .and(path("/xrpc/app.bsky.actor.getProfile"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("atproto-repo-rev", fresh_rev)
                    .set_body_json(serde_json::json!({
                        "did": "did:plc:test_ac2_5",
                        "handle": "test.bsky.social",
                        "displayName": "AppView Name",
                        "description": "AppView Description"
                    })),
            )
            .mount(&server)
            .await;

        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:test_ac2_5";
        seed_account_with_repo(&state.db, did).await;

        // Insert handle
        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("test.bsky.social")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();

        // No profile write - repo is at fresh_rev

        let mut state = state.clone();
        let mut config = (*state.config).clone();
        config.appview.url = server.uri();
        state.config = Arc::new(config);

        let token = access_jwt(&state.jwt_secret, did);

        let req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/xrpc/app.bsky.actor.getProfile?actor=did:plc:test_ac2_5")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(""))
            .unwrap();

        let resp = pipethrough_munged(&state, "app.bsky.actor.getProfile", did, req).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // No lag header expected
        assert!(
            resp.headers().get("Atproto-Upstream-Lag").is_none(),
            "Atproto-Upstream-Lag header should NOT be present when no local records"
        );

        // Response should be unchanged
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let munged: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            munged["displayName"], "AppView Name",
            "displayName should be unchanged from AppView"
        );
    }

    #[tokio::test]
    async fn test_pipethrough_munged_ac2_2_getprofiles_overwrites_requester_only() {
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let old_rev = "0";
        Mock::given(method("POST"))
            .and(path("/xrpc/app.bsky.actor.getProfiles"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("atproto-repo-rev", old_rev)
                    .set_body_json(serde_json::json!({
                        "profiles": [
                            {
                                "did": "did:plc:test_ac2_2",
                                "handle": "requester.bsky.social",
                                "displayName": "Old Requester Name",
                                "description": "Old Requester Desc"
                            },
                            {
                                "did": "did:plc:other_ac2_2",
                                "handle": "other.bsky.social",
                                "displayName": "Other Name",
                                "description": "Other Desc"
                            }
                        ]
                    })),
            )
            .mount(&server)
            .await;

        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:test_ac2_2";
        seed_account_with_repo(&state.db, did).await;

        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("requester.bsky.social")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();

        let app = crate::app::app(state.clone());
        let token = access_jwt(&state.jwt_secret, did);

        // Write local profile
        let profile_req = put_record_request(
            did,
            "app.bsky.actor.profile",
            "self",
            serde_json::json!({
                "record": {
                    "displayName": "New Requester Name",
                    "description": "New Requester Desc"
                }
            }),
            Some(&token),
        );

        let _profile_resp = app.clone().oneshot(profile_req).await.unwrap();

        let mut state = state.clone();
        let mut config = (*state.config).clone();
        config.appview.url = server.uri();
        state.config = Arc::new(config);

        let req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/xrpc/app.bsky.actor.getProfiles?actors=did:plc:test_ac2_2&actors=did:plc:other_ac2_2")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(""))
            .unwrap();

        let resp = pipethrough_munged(&state, "app.bsky.actor.getProfiles", did, req).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let munged: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Requester's entry should be overwritten
        assert_eq!(
            munged["profiles"][0]["displayName"], "New Requester Name",
            "requester displayName should be overwritten"
        );

        // Other entry should be unchanged
        assert_eq!(
            munged["profiles"][1]["displayName"], "Other Name",
            "other displayName should be unchanged"
        );
    }

    #[tokio::test]
    async fn test_pipethrough_munged_ac3_1_getpostthread_notfound_reconstructs() {
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let old_rev = "0";

        Mock::given(method("POST"))
            .and(path("/xrpc/app.bsky.feed.getPostThread"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("atproto-repo-rev", old_rev)
                    .set_body_json(serde_json::json!({
                        "error": "NotFound",
                        "message": "post not found"
                    })),
            )
            .mount(&server)
            .await;

        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:test_ac3_1";
        seed_account_with_repo(&state.db, did).await;

        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("test_ac3_1.bsky.social")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();

        let app = crate::app::app(state.clone());
        let token = access_jwt(&state.jwt_secret, did);

        let post_uri = format!("at://{}/app.bsky.feed.post/post123", did);
        let post_req = put_record_request(
            did,
            "app.bsky.feed.post",
            "post123",
            serde_json::json!({
                "record": {
                    "text": "Just created this post",
                    "createdAt": "2024-01-01T00:00:00.000Z"
                }
            }),
            Some(&token),
        );

        let _post_resp = app.clone().oneshot(post_req).await.unwrap();

        let mut state = state.clone();
        let mut config = (*state.config).clone();
        config.appview.url = server.uri();
        state.config = Arc::new(config);

        let req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri(format!(
                "/xrpc/app.bsky.feed.getPostThread?uri={}",
                urlencoding::encode(&post_uri)
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(""))
            .unwrap();

        let resp = pipethrough_munged(&state, "app.bsky.feed.getPostThread", did, req).await;

        // CRITICAL: Status must be 200, not 400
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "Response should be 200 OK when reconstructing NotFound thread"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let munged: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Verify the thread was reconstructed
        assert!(
            munged.get("thread").is_some(),
            "thread field should be present"
        );
        let thread = &munged["thread"];
        assert_eq!(thread["$type"], "app.bsky.feed.defs#threadViewPost");
        assert_eq!(thread["post"]["uri"], post_uri);
        assert_eq!(thread["post"]["author"]["did"], did);
        assert_eq!(thread["post"]["record"]["text"], "Just created this post");
    }

    #[tokio::test]
    async fn test_pipethrough_munged_getpostthread_nonlocal_notfound_stays_400() {
        // A genuine NotFound whose requested uri is NOT one of the requester's local posts must
        // fall back to the original 400 + error body — the 200 override only applies when a thread
        // was actually reconstructed. The requester DOES have an unrelated local post (so the
        // count>0 gate is passed), which is exactly the state that surfaced the masking bug.
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/xrpc/app.bsky.feed.getPostThread"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("atproto-repo-rev", "0")
                    .set_body_json(serde_json::json!({
                        "error": "NotFound",
                        "message": "post not found"
                    })),
            )
            .mount(&server)
            .await;

        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:test_nonlocal_notfound";
        seed_account_with_repo(&state.db, did).await;

        let app = crate::app::app(state.clone());
        let token = access_jwt(&state.jwt_secret, did);

        // Write an unrelated local post so local.count > 0 (passes the early-return gate).
        let post_req = put_record_request(
            did,
            "app.bsky.feed.post",
            "own_post",
            serde_json::json!({
                "record": { "text": "my own unrelated post", "createdAt": "2024-01-01T00:00:00.000Z" }
            }),
            Some(&token),
        );
        let _ = app.clone().oneshot(post_req).await.unwrap();

        let mut state = state.clone();
        let mut config = (*state.config).clone();
        config.appview.url = server.uri();
        state.config = Arc::new(config);

        // Request the thread for a DIFFERENT post (another user's) that is not in local records.
        let requested_uri = "at://did:plc:someone_else/app.bsky.feed.post/unknown";
        let req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri(format!(
                "/xrpc/app.bsky.feed.getPostThread?uri={}",
                urlencoding::encode(requested_uri)
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(""))
            .unwrap();

        let resp = pipethrough_munged(&state, "app.bsky.feed.getPostThread", did, req).await;

        // The genuine NotFound must NOT be masked as 200.
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "a NotFound for a non-local post must stay 400, not be forced to 200"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            body.get("error").and_then(|e| e.as_str()),
            Some("NotFound"),
            "the original error body must be preserved"
        );
        assert!(
            body.get("thread").is_none() || body["thread"].is_null(),
            "no thread should be reconstructed for a non-local post"
        );
    }

    #[tokio::test]
    async fn test_pipethrough_munged_ac3_2_getpostthread_splices_own_replies() {
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let old_rev = "0";
        let parent_uri = "at://did:plc:other_user/app.bsky.feed.post/parent123";

        Mock::given(method("POST"))
            .and(path("/xrpc/app.bsky.feed.getPostThread"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("atproto-repo-rev", old_rev)
                    .set_body_json(serde_json::json!({
                        "thread": {
                            "$type": "app.bsky.feed.defs#threadViewPost",
                            "post": {
                                "uri": parent_uri,
                                "cid": "bafy_parent",
                                "author": {
                                    "did": "did:plc:other_user",
                                    "handle": "other.bsky.social"
                                },
                                "record": {
                                    "$type": "app.bsky.feed.post",
                                    "text": "Parent post from other user",
                                    "createdAt": "2024-01-01T00:00:00.000Z"
                                },
                                "indexedAt": "2024-01-01T00:00:00.000Z",
                                "likeCount": 5,
                                "replyCount": 0,
                                "repostCount": 0
                            },
                            "replies": []
                        }
                    })),
            )
            .mount(&server)
            .await;

        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:test_ac3_2";
        seed_account_with_repo(&state.db, did).await;

        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("test_ac3_2.bsky.social")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();

        let app = crate::app::app(state.clone());
        let token = access_jwt(&state.jwt_secret, did);

        // Write a local reply to the parent post
        let reply_req = put_record_request(
            did,
            "app.bsky.feed.post",
            "reply1",
            serde_json::json!({
                "record": {
                    "text": "My reply to parent",
                    "createdAt": "2024-01-02T00:00:00.000Z",
                    "reply": {
                        "root": {
                            "uri": parent_uri,
                            "cid": "bafy_parent"
                        },
                        "parent": {
                            "uri": parent_uri,
                            "cid": "bafy_parent"
                        }
                    }
                }
            }),
            Some(&token),
        );

        let _reply_resp = app.clone().oneshot(reply_req).await.unwrap();

        let mut state = state.clone();
        let mut config = (*state.config).clone();
        config.appview.url = server.uri();
        state.config = Arc::new(config);

        let req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri(format!(
                "/xrpc/app.bsky.feed.getPostThread?uri={}",
                urlencoding::encode(parent_uri)
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(""))
            .unwrap();

        let resp = pipethrough_munged(&state, "app.bsky.feed.getPostThread", did, req).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let munged: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Verify the reply was spliced into replies
        assert!(munged["thread"]["replies"].is_array());
        let replies = munged["thread"]["replies"].as_array().unwrap();
        assert!(
            !replies.is_empty(),
            "replies array should contain the local reply"
        );

        // Find our reply in the spliced replies
        let found_reply = replies.iter().any(|r| {
            r.get("post")
                .and_then(|p| p.get("record"))
                .and_then(|rec| rec.get("text"))
                .and_then(|t| t.as_str())
                .map(|text| text.contains("My reply to parent"))
                .unwrap_or(false)
        });
        assert!(found_reply, "local reply should appear in thread.replies");
    }

    #[tokio::test]
    async fn test_pipethrough_munged_ac3_3_getpostthread_other_user_unchanged() {
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let fresh_rev = "bafy123";
        let other_post_uri = "at://did:plc:other_user/app.bsky.feed.post/post456";

        let appview_response = serde_json::json!({
            "thread": {
                "$type": "app.bsky.feed.defs#threadViewPost",
                "post": {
                    "uri": other_post_uri,
                    "cid": "bafy_other",
                    "author": {
                        "did": "did:plc:other_user",
                        "handle": "other.bsky.social",
                        "displayName": "Other User"
                    },
                    "record": {
                        "$type": "app.bsky.feed.post",
                        "text": "Post from another user",
                        "createdAt": "2024-01-01T00:00:00.000Z"
                    },
                    "indexedAt": "2024-01-01T00:00:00.000Z",
                    "likeCount": 10,
                    "replyCount": 2,
                    "repostCount": 5
                },
                "replies": []
            }
        });

        Mock::given(method("POST"))
            .and(path("/xrpc/app.bsky.feed.getPostThread"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("atproto-repo-rev", fresh_rev)
                    .set_body_json(appview_response.clone()),
            )
            .mount(&server)
            .await;

        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:test_ac3_3";
        seed_account_with_repo(&state.db, did).await;

        let app = crate::app::app(state.clone());
        let token = access_jwt(&state.jwt_secret, did);

        // Write a post (not a reply to the other user's post)
        let post_req = put_record_request(
            did,
            "app.bsky.feed.post",
            "post1",
            serde_json::json!({
                "record": {
                    "text": "My own post, not a reply",
                    "createdAt": "2024-01-02T00:00:00.000Z"
                }
            }),
            Some(&token),
        );

        let _post_resp = app.clone().oneshot(post_req).await.unwrap();

        let mut state = state.clone();
        let mut config = (*state.config).clone();
        config.appview.url = server.uri();
        state.config = Arc::new(config);

        let req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri(format!(
                "/xrpc/app.bsky.feed.getPostThread?uri={}",
                urlencoding::encode(other_post_uri)
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(""))
            .unwrap();

        let resp = pipethrough_munged(&state, "app.bsky.feed.getPostThread", did, req).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let munged: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Verify response equals AppView body (no local replies spliced)
        assert_eq!(munged["thread"]["post"]["uri"], other_post_uri);
        assert_eq!(
            munged["thread"]["post"]["author"]["did"],
            "did:plc:other_user"
        );
        assert_eq!(
            munged["thread"]["post"]["author"]["displayName"],
            "Other User"
        );
        assert!(munged["thread"]["replies"].is_array());
        assert_eq!(
            munged["thread"]["replies"].as_array().unwrap().len(),
            0,
            "No local replies should be added"
        );
    }

    #[tokio::test]
    async fn test_pipethrough_munged_ac4_1_non_json_body_passthrough() {
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let old_rev = "0";

        Mock::given(method("POST"))
            .and(path("/xrpc/app.bsky.feed.getTimeline"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("atproto-repo-rev", old_rev)
                    .insert_header("content-type", "text/plain")
                    .set_body_string("not valid json at all"),
            )
            .mount(&server)
            .await;

        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:test_ac4_1";
        seed_account_with_repo(&state.db, did).await;

        let app = crate::app::app(state.clone());
        let token = access_jwt(&state.jwt_secret, did);

        // Write a local post so local.count > 0 and we attempt munging
        let post_req = put_record_request(
            did,
            "app.bsky.feed.post",
            "post1",
            serde_json::json!({
                "record": {
                    "text": "Fresh local post",
                    "createdAt": "2024-01-01T00:00:00.000Z"
                }
            }),
            Some(&token),
        );
        let _post_resp = app.clone().oneshot(post_req).await.unwrap();

        let mut state = state.clone();
        let mut config = (*state.config).clone();
        config.appview.url = server.uri();
        state.config = Arc::new(config);

        let req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/xrpc/app.bsky.feed.getTimeline?limit=30")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(""))
            .unwrap();

        let resp = pipethrough_munged(&state, "app.bsky.feed.getTimeline", did, req).await;

        // Must NOT be 500 — the parse error should trigger fallback to the original body
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "non-JSON upstream body should be passed through unchanged"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert_eq!(
            body_str, "not valid json at all",
            "original non-JSON body should be returned verbatim"
        );
    }

    #[tokio::test]
    async fn test_pipethrough_munged_ac4_2_quote_post_with_failed_get_posts() {
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let old_rev = "0";

        Mock::given(method("POST"))
            .and(path("/xrpc/app.bsky.feed.getTimeline"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("atproto-repo-rev", old_rev)
                    .set_body_json(serde_json::json!({
                        "feed": [
                            {
                                "post": {
                                    "uri": "at://did:plc:other/app.bsky.feed.post/post123",
                                    "cid": "bafy_other",
                                    "author": {
                                        "did": "did:plc:other",
                                        "handle": "other.bsky.social"
                                    },
                                    "record": {
                                        "$type": "app.bsky.feed.post",
                                        "text": "Some post",
                                        "createdAt": "2024-01-01T00:00:00.000Z"
                                    },
                                    "indexedAt": "2024-01-01T00:00:00.000Z"
                                }
                            }
                        ]
                    })),
            )
            .mount(&server)
            .await;

        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:test_ac4_2";
        seed_account_with_repo(&state.db, did).await;

        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("test_ac4_2.bsky.social")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();

        let app = crate::app::app(state.clone());
        let token = access_jwt(&state.jwt_secret, did);

        // Write a local quote-post (even though getPosts will fail, the degradation should handle it)
        let quote_post_req = put_record_request(
            did,
            "app.bsky.feed.post",
            "quote_post",
            serde_json::json!({
                "record": {
                    "text": "Quoting something",
                    "createdAt": "2024-01-02T00:00:00.000Z",
                    "embed": {
                        "$type": "app.bsky.embed.record",
                        "record": {
                            "uri": "at://did:plc:other/app.bsky.feed.post/orig_post",
                            "cid": "bafy_quote_orig"
                        }
                    }
                }
            }),
            Some(&token),
        );
        let _quote_resp = app.clone().oneshot(quote_post_req).await.unwrap();

        let mut state = state.clone();
        let mut config = (*state.config).clone();
        config.appview.url = server.uri();
        state.config = Arc::new(config);

        let req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/xrpc/app.bsky.feed.getTimeline?limit=30")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(""))
            .unwrap();

        let resp = pipethrough_munged(&state, "app.bsky.feed.getTimeline", did, req).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let munged: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // The injected local post should be present in the response
        assert!(munged["feed"].is_array(), "feed should be an array");
        let feed = munged["feed"].as_array().unwrap();

        // Verify at least one post from the local write is present
        let local_post_found = feed.iter().any(|item| {
            item.get("post")
                .and_then(|p| p.get("record"))
                .and_then(|rec| rec.get("text"))
                .and_then(|t| t.as_str())
                .map(|text| text.contains("Quoting something"))
                .unwrap_or(false)
        });

        assert!(
            local_post_found,
            "local quote-post should be injected into the feed"
        );
    }

    #[tokio::test]
    async fn test_pipethrough_munged_ac4_4_no_lag_when_current() {
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Rev is at the current head — nothing unindexed
        let current_rev = "bafy_current_head";

        Mock::given(method("POST"))
            .and(path("/xrpc/app.bsky.actor.getProfile"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("atproto-repo-rev", current_rev)
                    .set_body_json(serde_json::json!({
                        "did": "did:plc:test_ac4_4",
                        "handle": "test.bsky.social",
                        "displayName": "Test User",
                        "description": "Test Desc"
                    })),
            )
            .mount(&server)
            .await;

        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:test_ac4_4";
        seed_account_with_repo(&state.db, did).await;

        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("test.bsky.social")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();

        // Update the repo root to match the AppView's rev so local.count == 0
        sqlx::query("UPDATE accounts SET repo_root_cid = ? WHERE did = ?")
            .bind(current_rev)
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();

        let mut state = state.clone();
        let mut config = (*state.config).clone();
        config.appview.url = server.uri();
        state.config = Arc::new(config);

        let token = access_jwt(&state.jwt_secret, did);

        let req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/xrpc/app.bsky.actor.getProfile?actor=did:plc:test_ac4_4")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(""))
            .unwrap();

        let resp = pipethrough_munged(&state, "app.bsky.actor.getProfile", did, req).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // CRITICAL: When local.count == 0 (no unindexed records), there should be NO lag header
        assert!(
            resp.headers().get("Atproto-Upstream-Lag").is_none(),
            "Atproto-Upstream-Lag header must NOT be present when repo is current"
        );
    }
}
