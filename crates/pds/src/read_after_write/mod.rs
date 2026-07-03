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
    // Collect distinct (collection, rkey) with their newest CommitEvent.
    let mut touched: HashMap<(String, String), String> = HashMap::new(); // (coll, rkey) -> rev
    let mut kept_time: Option<String> = None;

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
                e.insert(event.rev.clone());
                if kept_time.is_none() {
                    kept_time = Some(event.time.clone());
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

    for (collection, rkey) in touched.keys() {
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

        // Get the record's CID
        let cid = match repo_engine::get_record_cid(&mut repo, &record_path).await {
            Ok(Some(cid)) => cid,
            Ok(None) => continue, // Record was deleted; skip.
            Err(err) => {
                tracing::debug!(error = %err, collection, rkey, "failed to get record CID");
                continue;
            }
        };

        let uri = format!("at://{}/{}/{}", did, collection, rkey);
        let indexed_at = kept_time.clone().unwrap_or_default();

        let descript = RecordDescript {
            uri,
            cid: cid.to_string(),
            indexed_at,
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

    let body_bytes = match upstream.bytes().await {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_lag_ms_returns_none_for_empty_records() {
        let local = LocalRecords::default();
        assert_eq!(local_lag_ms(&local), None);
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
}
