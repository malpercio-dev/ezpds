// pattern: Mixed (unavoidable)
//
// Munging functions: transform the AppView response by merging the requester's own unindexed records.
// The profile/likes munges and the `refresh_own_authored_items` / `is_actor_requester` helpers are
// pure transformations of the AppView response + local records → merged output. The two feed-injection
// paths (`get_timeline`, `get_author_feed`) are NOT pure: they orchestrate async hydration and
// insertion through the `LocalViewer` (Imperative Shell), whose `hydrate_quotes` performs an outbound
// service-auth'd `app.bsky.feed.getPosts` call. Hence the whole file is Mixed, not Functional Core.

use serde_json::Value;
use super::types::LocalRecords;
use super::viewer::LocalViewer;

pub(crate) async fn get_profile(
    viewer: &LocalViewer<'_>,
    original: Value,
    local: &LocalRecords,
    requester: &str,
) -> Value {
    if local.profile.is_none() {
        return original;
    }

    if original.get("did").and_then(|v| v.as_str()).unwrap_or("") != requester {
        return original;
    }

    viewer.update_profile_detailed(original)
}

pub(crate) async fn get_profiles(
    viewer: &LocalViewer<'_>,
    mut original: Value,
    local: &LocalRecords,
    requester: &str,
) -> Value {
    if local.profile.is_none() {
        return original;
    }

    if let Some(profiles_arr) = original.get_mut("profiles").and_then(|v| v.as_array_mut()) {
        for entry in profiles_arr {
            if entry.get("did").and_then(|v| v.as_str()).unwrap_or("") == requester {
                *entry = viewer.update_profile_detailed(entry.clone());
            }
        }
    }

    original
}

pub(crate) async fn get_timeline(
    viewer: &LocalViewer<'_>,
    mut original: Value,
    local: &LocalRecords,
    requester: &str,
) -> Value {
    let quotes = viewer.hydrate_quotes(&local.posts).await;

    // These two steps cover disjoint item sets: `refresh_own_authored_items` updates the author on
    // items the AppView already returned, while `insert_posts_in_feed` builds fresh postViews for the
    // requester's unindexed posts (which rev-selection guarantees are absent from the AppView page).
    refresh_own_authored_items(viewer, &mut original, requester);

    if let Some(feed_arr) = original.get_mut("feed").and_then(|v| v.as_array_mut()) {
        viewer.insert_posts_in_feed(feed_arr, &local.posts, &quotes).await;
    }

    original
}

pub(crate) async fn get_author_feed(
    viewer: &LocalViewer<'_>,
    mut original: Value,
    local: &LocalRecords,
    requester: &str,
    actor: Option<&str>,
) -> Value {
    let is_requester_feed = is_actor_requester(viewer, requester, actor, &original);

    if !is_requester_feed {
        return original;
    }

    let quotes = viewer.hydrate_quotes(&local.posts).await;

    refresh_own_authored_items(viewer, &mut original, requester);

    if let Some(feed_arr) = original.get_mut("feed").and_then(|v| v.as_array_mut()) {
        viewer.insert_posts_in_feed(feed_arr, &local.posts, &quotes).await;
    }

    original
}

pub(crate) async fn get_actor_likes(
    viewer: &LocalViewer<'_>,
    mut original: Value,
    _local: &LocalRecords,
    requester: &str,
) -> Value {
    // No insertion: likes are not the requester's own post records, so `_local` is intentionally
    // unused. This only refreshes the author view on items the requester authored.
    refresh_own_authored_items(viewer, &mut original, requester);
    original
}

pub(crate) async fn get_post_thread(
    viewer: &LocalViewer<'_>,
    mut original: Value,
    local: &LocalRecords,
    requester: &str,
    requested_uri: &str,
) -> Value {
    // Early exit: no local records means nothing to munge
    if local.count == 0 {
        return original;
    }

    // Check if the original response has a thread (Case A: AppView returned a threadViewPost)
    if let Some(thread) = original.get_mut("thread").and_then(|t| t.as_object_mut()) {
        // Case A: refresh the focus post's author if it's the requester
        if let Some(post) = thread.get_mut("post").and_then(|p| p.as_object_mut()) {
            if let Some(author) = post.get_mut("author").and_then(|a| a.as_object_mut()) {
                if author.get("did").and_then(|d| d.as_str()).unwrap_or("") == requester {
                    let author_view = viewer.update_profile_view_basic(serde_json::Value::Object(author.clone()));
                    *author = author_view.as_object().unwrap().clone();
                }
            }
        }

        // Case A: splice the requester's unindexed replies into thread.replies
        let mut replies_to_add = Vec::new();
        let quotes = viewer.hydrate_quotes(&local.posts).await;

        for local_post in &local.posts {
            // Check if this local post is a reply to something in the thread
            if let Some(reply) = local_post.record.get("reply") {
                if let Some(parent_uri) = reply.get("parent").and_then(|p| p.get("uri")).and_then(|u| u.as_str()) {
                    // Check if parent_uri is the focus post or any post in the thread
                    let mut is_reply_to_thread = false;

                    if let Some(focus_post) = thread.get("post").and_then(|p| p.get("uri")).and_then(|u| u.as_str()) {
                        if parent_uri == focus_post {
                            is_reply_to_thread = true;
                        }
                    }

                    if !is_reply_to_thread {
                        if let Some(replies_arr) = thread.get("replies").and_then(|r| r.as_array()) {
                            for reply_item in replies_arr {
                                if let Some(reply_post_uri) = reply_item.get("post").and_then(|p| p.get("uri")).and_then(|u| u.as_str()) {
                                    if parent_uri == reply_post_uri {
                                        is_reply_to_thread = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if is_reply_to_thread {
                        let post_view = viewer.post_view(local_post, &quotes).await;
                        let thread_post = serde_json::json!({
                            "$type": "app.bsky.feed.defs#threadViewPost",
                            "post": post_view,
                        });
                        replies_to_add.push((local_post.indexed_at.clone(), thread_post));
                    }
                }
            }
        }

        // Sort by indexed_at and insert into replies
        if !replies_to_add.is_empty() {
            replies_to_add.sort_by(|a, b| b.0.cmp(&a.0)); // descending (newest first)

            if let Some(replies_arr) = thread.get_mut("replies").and_then(|r| r.as_array_mut()) {
                for (_, thread_post) in replies_to_add {
                    // Insert at end for simplicity (best-effort, shallow)
                    replies_arr.push(thread_post);
                }
            } else {
                // If no replies array exists, create one
                thread.insert("replies".to_string(), serde_json::Value::Array(
                    replies_to_add.into_iter().map(|(_, tp)| tp).collect()
                ));
            }
        }

        return original;
    }

    // Case B: NotFound and requested_uri is one of local.posts
    if requested_uri.is_empty() {
        return original;
    }

    for local_post in &local.posts {
        if local_post.uri == requested_uri {
            // Build a threadViewPost from this local record
            let quotes = viewer.hydrate_quotes(&local.posts).await;
            let post_view = viewer.post_view(local_post, &quotes).await;

            // Find local replies to this post
            let mut local_replies = Vec::new();
            for potential_reply in &local.posts {
                if let Some(reply) = potential_reply.record.get("reply") {
                    if let Some(parent_uri) = reply.get("parent").and_then(|p| p.get("uri")).and_then(|u| u.as_str()) {
                        if parent_uri == requested_uri {
                            let reply_view = viewer.post_view(potential_reply, &quotes).await;
                            let reply_post = serde_json::json!({
                                "$type": "app.bsky.feed.defs#threadViewPost",
                                "post": reply_view,
                            });
                            local_replies.push((potential_reply.indexed_at.clone(), reply_post));
                        }
                    }
                }
            }

            // Sort replies by indexed_at (descending)
            local_replies.sort_by(|a, b| b.0.cmp(&a.0));

            let thread_view = serde_json::json!({
                "$type": "app.bsky.feed.defs#threadViewPost",
                "post": post_view,
                "replies": local_replies.into_iter().map(|(_, rp)| rp).collect::<Vec<_>>(),
            });

            original["thread"] = thread_view;
            return original;
        }
    }

    // requested_uri is NOT a local post: return original unchanged (the 400 stands)
    original
}

/// Refresh the author view on any feed items authored by the requester, if a local profile exists.
fn refresh_own_authored_items(
    viewer: &LocalViewer<'_>,
    original: &mut Value,
    requester: &str,
) {
    if let Some(feed_arr) = original.get_mut("feed").and_then(|v| v.as_array_mut()) {
        for item in feed_arr {
            if let Some(post) = item.get_mut("post") {
                if let Some(author) = post.get_mut("author") {
                    if author.get("did").and_then(|v| v.as_str()).unwrap_or("") == requester {
                        *author = viewer.update_profile_view_basic(author.clone());
                    }
                }
            }
        }
    }
}

/// Determine if the actor param resolves to the requester.
/// Checks three conditions (OR):
/// 1. actor equals requester verbatim (DID form)
/// 2. actor equals the requester's handle from LocalViewer.handle
/// 3. feed is non-empty and feed[0].post.author.did equals requester
fn is_actor_requester(
    viewer: &LocalViewer<'_>,
    requester: &str,
    actor: Option<&str>,
    original: &Value,
) -> bool {
    if let Some(actor_str) = actor {
        if actor_str == requester {
            return true;
        }
        if let Some(ref handle) = viewer.handle {
            if actor_str == handle {
                return true;
            }
        }
    }

    if let Some(feed_arr) = original.get("feed").and_then(|v| v.as_array()) {
        if let Some(first_item) = feed_arr.first() {
            if let Some(author_did) = first_item
                .get("post")
                .and_then(|p| p.get("author"))
                .and_then(|a| a.get("did"))
                .and_then(|d| d.as_str())
            {
                if author_did == requester {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app;
    use serde_json::json;
    use tower::ServiceExt;

    #[tokio::test]
    async fn get_profile_returns_original_when_no_local_profile() {
        let state = app::test_state().await;
        let viewer = LocalViewer::new(&state, "did:plc:test".to_string(), None, None);
        let local = LocalRecords::default();
        let original = json!({
            "did": "did:plc:test",
            "displayName": "AppView Name"
        });

        let result = get_profile(&viewer, original.clone(), &local, "did:plc:test").await;
        assert_eq!(result, original);
    }

    #[tokio::test]
    async fn get_profile_returns_original_when_did_mismatch() {
        let state = app::test_state().await;
        let local_profile = json!({"displayName": "Local Name"});
        let viewer = LocalViewer::new(
            &state,
            "did:plc:test".to_string(),
            None,
            Some(local_profile),
        );
        let local = LocalRecords {
            count: 1,
            profile: Some(super::super::types::RecordDescript {
                uri: "at://did:plc:test/app.bsky.actor.profile/self".to_string(),
                cid: "bafy123".to_string(),
                indexed_at: "2026-07-03T12:00:00.000Z".to_string(),
                record: json!({"displayName": "Local Name"}),
            }),
            posts: vec![],
        };
        let original = json!({
            "did": "did:plc:other",
            "displayName": "Other AppView Name"
        });

        let result = get_profile(&viewer, original.clone(), &local, "did:plc:test").await;
        assert_eq!(result, original);
    }

    #[tokio::test]
    async fn get_profiles_returns_original_when_no_local_profile() {
        let state = app::test_state().await;
        let viewer = LocalViewer::new(&state, "did:plc:test".to_string(), None, None);
        let local = LocalRecords::default();
        let original = json!({
            "profiles": [
                {
                    "did": "did:plc:requester",
                    "displayName": "AppView Requester"
                },
                {
                    "did": "did:plc:other",
                    "displayName": "AppView Other"
                }
            ]
        });

        let result = get_profiles(&viewer, original.clone(), &local, "did:plc:requester").await;
        assert_eq!(result, original);
    }

    #[tokio::test]
    async fn get_profiles_overwrites_requester_only() {
        let state = app::test_state().await;
        let local_profile = json!({"displayName": "Local Requester"});
        let viewer = LocalViewer::new(
            &state,
            "did:plc:requester".to_string(),
            None,
            Some(local_profile),
        );
        let local = LocalRecords {
            count: 1,
            profile: Some(super::super::types::RecordDescript {
                uri: "at://did:plc:requester/app.bsky.actor.profile/self".to_string(),
                cid: "bafy123".to_string(),
                indexed_at: "2026-07-03T12:00:00.000Z".to_string(),
                record: json!({"displayName": "Local Requester"}),
            }),
            posts: vec![],
        };
        let original = json!({
            "profiles": [
                {
                    "did": "did:plc:requester",
                    "displayName": "AppView Requester"
                },
                {
                    "did": "did:plc:other",
                    "displayName": "AppView Other"
                }
            ]
        });

        let result = get_profiles(&viewer, original.clone(), &local, "did:plc:requester").await;

        assert_eq!(
            result["profiles"][1],
            original["profiles"][1],
            "other profile should be unchanged"
        );
        assert_eq!(
            result["profiles"][0]["displayName"],
            "Local Requester",
            "requester profile should be overwritten"
        );
    }

    #[tokio::test]
    async fn get_timeline_ac1_1_injects_local_post_at_top() {
        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:timeline_ac1_1";
        crate::routes::test_utils::seed_account_with_repo(&state.db, did).await;

        let app = crate::app::app(state.clone());
        let token = crate::routes::test_utils::access_jwt(&state.jwt_secret, did);

        let post_req = crate::routes::test_utils::put_record_request(
            did,
            "app.bsky.feed.post",
            "post1",
            serde_json::json!({ "record": { "text": "my new post", "createdAt": "2026-07-03T12:00:00.000Z" } }),
            Some(&token),
        );

        let _post_resp = app.clone().oneshot(post_req).await.unwrap();

        let local = super::super::get_records_since_rev(&state, did, Some("0")).await;

        let handle = crate::db::accounts::get_session_account(&state.db, did)
            .await
            .unwrap()
            .unwrap();
        let profile_val = local.profile.as_ref().map(|p| p.record.clone());
        let viewer = super::super::viewer::LocalViewer::new(&state, did.to_string(), handle.handle, profile_val);

        let original_feed = json!({
            "feed": [
                {
                    "post": {
                        "uri": "at://did:plc:other/app.bsky.feed.post/older",
                        "cid": "bafy_older",
                        "author": { "did": "did:plc:other", "handle": "other.bsky.social" },
                        "record": { "text": "older post" },
                        "indexedAt": "2026-07-01T00:00:00.000Z",
                        "likeCount": 0,
                        "replyCount": 0,
                        "repostCount": 0
                    }
                }
            ]
        });

        let result = get_timeline(&viewer, original_feed, &local, did).await;
        let feed = result.get("feed").unwrap().as_array().unwrap();

        assert!(feed.len() > 1, "feed should have injected post");
        assert_eq!(feed[0]["post"]["author"]["did"], did, "first item should be requester's post");
        assert!(
            feed[0]["post"]["uri"].as_str().unwrap().contains("post1"),
            "injected post should be post1"
        );
    }

    #[tokio::test]
    async fn get_timeline_ac1_7_multiple_posts_chronological_order() {
        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:timeline_ac1_7";
        crate::routes::test_utils::seed_account_with_repo(&state.db, did).await;

        let app = crate::app::app(state.clone());
        let token = crate::routes::test_utils::access_jwt(&state.jwt_secret, did);

        let post_req_1 = crate::routes::test_utils::put_record_request(
            did,
            "app.bsky.feed.post",
            "post1",
            serde_json::json!({ "record": { "text": "first", "createdAt": "2026-07-02T10:00:00.000Z" } }),
            Some(&token),
        );
        let _post1_resp = app.clone().oneshot(post_req_1).await.unwrap();

        let post_req_2 = crate::routes::test_utils::put_record_request(
            did,
            "app.bsky.feed.post",
            "post2",
            serde_json::json!({ "record": { "text": "second", "createdAt": "2026-07-02T12:00:00.000Z" } }),
            Some(&token),
        );
        let _post2_resp = app.clone().oneshot(post_req_2).await.unwrap();

        let local = super::super::get_records_since_rev(&state, did, Some("0")).await;

        let handle = crate::db::accounts::get_session_account(&state.db, did)
            .await
            .unwrap()
            .unwrap();
        let profile_val = local.profile.as_ref().map(|p| p.record.clone());
        let viewer = super::super::viewer::LocalViewer::new(&state, did.to_string(), handle.handle, profile_val);

        let original_feed = json!({
            "feed": [
                {
                    "post": {
                        "uri": "at://did:plc:other/app.bsky.feed.post/old1",
                        "cid": "bafy_old1",
                        "author": { "did": "did:plc:other", "handle": "other.bsky.social" },
                        "record": { "text": "old 1" },
                        "indexedAt": "2026-07-02T09:00:00.000Z",
                        "likeCount": 0,
                        "replyCount": 0,
                        "repostCount": 0
                    }
                },
                {
                    "post": {
                        "uri": "at://did:plc:other/app.bsky.feed.post/old2",
                        "cid": "bafy_old2",
                        "author": { "did": "did:plc:other", "handle": "other.bsky.social" },
                        "record": { "text": "old 2" },
                        "indexedAt": "2026-07-02T08:00:00.000Z",
                        "likeCount": 0,
                        "replyCount": 0,
                        "repostCount": 0
                    }
                }
            ]
        });

        let result = get_timeline(&viewer, original_feed.clone(), &local, did).await;
        let feed = result.get("feed").unwrap().as_array().unwrap();

        assert!(feed.len() >= 3, "should have 2 local posts + 2 older posts");

        let times: Vec<&str> = feed
            .iter()
            .filter_map(|item| item["post"]["indexedAt"].as_str())
            .collect();

        for i in 1..times.len() {
            assert!(
                times[i - 1] >= times[i],
                "feed should be in newest-first order: {} < {}",
                times[i - 1],
                times[i]
            );
        }
    }

    #[tokio::test]
    async fn get_author_feed_ac1_2_injects_own_posts_when_actor_is_requester() {
        let state = crate::routes::test_utils::state_with_master_key().await;
        let did = "did:plc:authorfeed_ac1_2";
        crate::routes::test_utils::seed_account_with_repo(&state.db, did).await;

        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("test.bsky.social")
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();

        let app = crate::app::app(state.clone());
        let token = crate::routes::test_utils::access_jwt(&state.jwt_secret, did);

        let post_req = crate::routes::test_utils::put_record_request(
            did,
            "app.bsky.feed.post",
            "post1",
            serde_json::json!({ "record": { "text": "my author feed post", "createdAt": "2026-07-03T12:00:00.000Z" } }),
            Some(&token),
        );
        let _post_resp = app.clone().oneshot(post_req).await.unwrap();

        let local = super::super::get_records_since_rev(&state, did, Some("0")).await;

        let handle = crate::db::accounts::get_session_account(&state.db, did)
            .await
            .unwrap()
            .unwrap();
        let profile_val = local.profile.as_ref().map(|p| p.record.clone());
        let viewer = super::super::viewer::LocalViewer::new(&state, did.to_string(), handle.handle, profile_val);

        let original_feed = json!({
            "feed": []
        });

        let result = get_author_feed(&viewer, original_feed, &local, did, Some(did)).await;
        let feed = result.get("feed").unwrap().as_array().unwrap();

        assert!(!feed.is_empty(), "should have injected own post");
        assert_eq!(feed[0]["post"]["author"]["did"], did);
    }

    #[tokio::test]
    async fn get_author_feed_ac1_6_no_injection_for_other_actor() {
        let state = crate::routes::test_utils::state_with_master_key().await;
        let requester = "did:plc:requester_ac1_6";
        let other = "did:plc:other_ac1_6";
        crate::routes::test_utils::seed_account_with_repo(&state.db, requester).await;

        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("requester.bsky.social")
            .bind(requester)
            .execute(&state.db)
            .await
            .unwrap();

        let app = crate::app::app(state.clone());
        let token = crate::routes::test_utils::access_jwt(&state.jwt_secret, requester);

        let post_req = crate::routes::test_utils::put_record_request(
            requester,
            "app.bsky.feed.post",
            "post1",
            serde_json::json!({ "record": { "text": "requester post", "createdAt": "2026-07-03T12:00:00.000Z" } }),
            Some(&token),
        );
        let _post_resp = app.clone().oneshot(post_req).await.unwrap();

        let local = super::super::get_records_since_rev(&state, requester, Some("0")).await;

        let handle = crate::db::accounts::get_session_account(&state.db, requester)
            .await
            .unwrap()
            .unwrap();
        let profile_val = local.profile.as_ref().map(|p| p.record.clone());
        let viewer = super::super::viewer::LocalViewer::new(&state, requester.to_string(), handle.handle, profile_val);

        let original_feed = json!({
            "feed": [
                {
                    "post": {
                        "uri": "at://did:plc:other/app.bsky.feed.post/post1",
                        "cid": "bafy_other",
                        "author": { "did": other, "handle": "other.bsky.social" },
                        "record": { "text": "other post" },
                        "indexedAt": "2026-07-01T00:00:00.000Z",
                        "likeCount": 0,
                        "replyCount": 0,
                        "repostCount": 0
                    }
                }
            ]
        });

        let result = get_author_feed(&viewer, original_feed.clone(), &local, requester, Some(other)).await;

        assert_eq!(result, original_feed, "response should be unchanged when viewing another actor's feed");
    }

    #[tokio::test]
    async fn get_actor_likes_ac1_3_refreshes_author_only() {
        let state = crate::routes::test_utils::state_with_master_key().await;
        let requester = "did:plc:likes_ac1_3";
        crate::routes::test_utils::seed_account_with_repo(&state.db, requester).await;

        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("test.bsky.social")
            .bind(requester)
            .execute(&state.db)
            .await
            .unwrap();

        let app = crate::app::app(state.clone());
        let token = crate::routes::test_utils::access_jwt(&state.jwt_secret, requester);

        let post_req = crate::routes::test_utils::put_record_request(
            requester,
            "app.bsky.actor.profile",
            "self",
            serde_json::json!({"record": {"displayName": "Fresh Display Name"}}),
            Some(&token),
        );
        let _profile_resp = app.clone().oneshot(post_req).await.unwrap();

        let local = super::super::get_records_since_rev(&state, requester, Some("0")).await;

        let handle = crate::db::accounts::get_session_account(&state.db, requester)
            .await
            .unwrap()
            .unwrap();
        let profile_val = local.profile.as_ref().map(|p| p.record.clone());
        let viewer = super::super::viewer::LocalViewer::new(&state, requester.to_string(), handle.handle, profile_val);

        let original_feed = json!({
            "feed": [
                {
                    "post": {
                        "uri": "at://did:plc:other/app.bsky.feed.post/liked1",
                        "cid": "bafy_liked1",
                        "author": { "did": "did:plc:other", "handle": "other.bsky.social", "displayName": "Old Other Name" },
                        "record": { "text": "liked post from other" },
                        "indexedAt": "2026-07-01T00:00:00.000Z",
                        "likeCount": 10,
                        "replyCount": 2,
                        "repostCount": 1
                    }
                },
                {
                    "post": {
                        "uri": "at://did:plc:requester/app.bsky.feed.post/own",
                        "cid": "bafy_own",
                        "author": { "did": requester, "handle": "test.bsky.social", "displayName": "Old Display Name" },
                        "record": { "text": "my own post" },
                        "indexedAt": "2026-07-02T00:00:00.000Z",
                        "likeCount": 5,
                        "replyCount": 1,
                        "repostCount": 0
                    }
                }
            ]
        });

        let result = get_actor_likes(&viewer, original_feed.clone(), &local, requester).await;
        let feed = result.get("feed").unwrap().as_array().unwrap();

        assert_eq!(feed.len(), 2, "feed length should be unchanged (no injection)");
        assert_eq!(
            feed[1]["post"]["author"]["displayName"], "Fresh Display Name",
            "requester's author view should be refreshed"
        );
        assert_eq!(
            feed[0]["post"]["author"]["displayName"], "Old Other Name",
            "other user's author view should be unchanged"
        );
    }
}
