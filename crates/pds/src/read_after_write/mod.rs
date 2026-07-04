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
use repo_engine::Repository;
use atrium_repo::Cid;

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
        let event = match crate::firehose::decode_stored_event(
            row.seq as u64,
            &row.event_type,
            &row.event,
        ) {
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

/// Extract the `actor` query param from the request for getAuthorFeed.
fn extract_actor_param(req: &Request, nsid: &str) -> Option<String> {
    if nsid != "app.bsky.feed.getAuthorFeed" {
        return None;
    }

    let uri = req.uri();
    uri.query()
        .and_then(|q| {
            for pair in q.split('&') {
                if let Some(value) = pair.strip_prefix("actor=") {
                    return Some(urlencoding::decode(value).ok()?.into_owned());
                }
            }
            None
        })
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
    let status =
        axum::http::StatusCode::from_u16(upstream.status().as_u16())
            .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    let content_type = upstream.headers().get(header::CONTENT_TYPE).cloned();
    let header_rev = upstream
        .headers()
        .get("atproto-repo-rev")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // 2. Buffer the body
    let body_bytes = match upstream.bytes().await {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(error = %err, nsid, "failed to read upstream response body");
            return ApiError::new(ErrorCode::InternalError, "failed to read upstream response")
                .into_response();
        }
    };

    // 3. If status is not success, return the buffered response unchanged
    if !status.is_success() {
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

    let mut builder = Response::builder().status(status);
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
    use crate::routes::test_utils::{access_jwt, seed_account_with_repo, put_record_request, delete_record_request};
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
        assert_eq!(extract_actor_param(&req, "app.bsky.feed.getAuthorFeed"), None);
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
        assert!(lag.unwrap() > 0, "lag should be positive for a past timestamp");
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
            assert!(
                !post.indexed_at.is_empty(),
                "post should have indexed_at"
            );
        }
    }

    #[tokio::test]
    async fn test_pipethrough_munged_ac2_1_stale_appview_plus_fresh_local_profile() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use std::sync::Arc;

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
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use std::sync::Arc;

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
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use std::sync::Arc;

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
}
