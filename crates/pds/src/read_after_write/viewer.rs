// pattern: Imperative Shell
//
// Viewer construction: builds ProfileViewBasic and ProfileViewDetailed from local records,
// hydrates post views with embeds, and merges them into feed responses.
// Handles local image/external embeds (CDN URLs) and quote-post embeds (via getPosts service auth).

use std::collections::HashMap;

use crate::app::AppState;
use serde_json::{json, Value};

use super::types::RecordDescript;

pub(crate) type QuoteMap = HashMap<String, Value>;

pub(crate) struct LocalViewer<'a> {
    pub(crate) state: &'a AppState,
    pub(crate) did: String,
    pub(crate) handle: Option<String>,
    pub(crate) profile: Option<Value>,
}

impl<'a> LocalViewer<'a> {
    #[allow(dead_code)]
    pub(crate) fn new(
        state: &'a AppState,
        did: String,
        handle: Option<String>,
        profile: Option<Value>,
    ) -> Self {
        Self {
            state,
            did,
            handle,
            profile,
        }
    }

    #[allow(dead_code)]
    fn profile_view_basic(&self) -> Value {
        let mut view = json!({
            "did": self.did,
        });

        if let Some(ref handle) = self.handle {
            view["handle"] = json!(handle);
        }

        if let Some(ref profile) = self.profile {
            if let Some(name) = profile.get("displayName").and_then(|v| v.as_str()) {
                view["displayName"] = json!(name);
            }
            if let Some(avatar_blob) = profile.get("avatar") {
                if let Some(cid) = self.extract_blob_cid(avatar_blob) {
                    view["avatar"] = json!(self.image_url("avatar", &cid));
                }
            }
        }

        view
    }

    #[allow(dead_code)]
    fn update_profile_view(&self, mut view: Value) -> Value {
        if let Some(ref profile) = self.profile {
            if let Some(name) = profile.get("displayName").and_then(|v| v.as_str()) {
                view["displayName"] = json!(name);
            } else {
                view.as_object_mut().map(|m| m.remove("displayName"));
            }

            if let Some(desc) = profile.get("description").and_then(|v| v.as_str()) {
                view["description"] = json!(desc);
            } else {
                view.as_object_mut().map(|m| m.remove("description"));
            }

            if let Some(avatar_blob) = profile.get("avatar") {
                if let Some(cid) = self.extract_blob_cid(avatar_blob) {
                    view["avatar"] = json!(self.image_url("avatar", &cid));
                }
            } else {
                view.as_object_mut().map(|m| m.remove("avatar"));
            }
        }

        view
    }

    #[allow(dead_code)]
    fn update_profile_detailed(&self, mut view: Value) -> Value {
        view = self.update_profile_view(view);

        if let Some(ref profile) = self.profile {
            if let Some(banner_blob) = profile.get("banner") {
                if let Some(cid) = self.extract_blob_cid(banner_blob) {
                    view["banner"] = json!(self.image_url("banner", &cid));
                }
            } else {
                view.as_object_mut().map(|m| m.remove("banner"));
            }
        }

        view
    }

    #[allow(dead_code)]
    fn image_url(&self, kind: &str, cid: &str) -> String {
        format!(
            "{}/img/{}/plain/{}/{}@jpeg",
            self.state.config.appview.cdn_url, kind, self.did, cid
        )
    }

    #[allow(dead_code)]
    fn extract_blob_cid(&self, blob_value: &Value) -> Option<String> {
        blob_value
            .get("ref")
            .and_then(|ref_val| ref_val.get("$link"))
            .and_then(|link| link.as_str())
            .map(|s| s.to_string())
    }

    #[allow(dead_code)]
    pub(crate) async fn post_view(
        &self,
        post: &RecordDescript,
        quotes: &QuoteMap,
    ) -> Value {
        let mut view = json!({
            "$type": "app.bsky.feed.defs#postView",
            "uri": post.uri,
            "cid": post.cid,
            "author": self.profile_view_basic(),
            "record": post.record,
            "indexedAt": post.indexed_at,
            "likeCount": 0,
            "replyCount": 0,
            "repostCount": 0,
        });

        if let Some(embed) = self.hydrate_embed(post.record.get("embed"), quotes) {
            view["embed"] = embed;
        }

        view
    }

    #[allow(dead_code)]
    fn hydrate_embed(&self, embed: Option<&Value>, quotes: &QuoteMap) -> Option<Value> {
        let embed = embed?;
        let type_val = embed.get("$type").and_then(|v| v.as_str())?;

        match type_val {
            "app.bsky.embed.images" => self.hydrate_images_embed(embed),
            "app.bsky.embed.external" => self.hydrate_external_embed(embed),
            "app.bsky.embed.record" => self.hydrate_record_embed(embed, quotes),
            "app.bsky.embed.recordWithMedia" => self.hydrate_record_with_media_embed(embed, quotes),
            _ => None,
        }
    }

    #[allow(dead_code)]
    fn hydrate_images_embed(&self, embed: &Value) -> Option<Value> {
        let images = embed.get("images")?.as_array()?;

        let mut hydrated_images = Vec::new();
        for image in images {
            let mut hydrated_image = image.clone();

            if let Some(image_blob) = image.get("image") {
                if let Some(cid) = self.extract_blob_cid(image_blob) {
                    hydrated_image["thumb"] = json!(self.image_url("feed_thumbnail", &cid));
                    hydrated_image["fullsize"] = json!(self.image_url("feed_fullsize", &cid));
                }
            }

            hydrated_images.push(hydrated_image);
        }

        Some(json!({
            "$type": "app.bsky.embed.images#view",
            "images": hydrated_images,
        }))
    }

    #[allow(dead_code)]
    fn hydrate_external_embed(&self, embed: &Value) -> Option<Value> {
        let external = embed.get("external")?;

        let mut view = json!({
            "$type": "app.bsky.embed.external#view",
            "external": {
                "uri": external.get("uri").cloned().unwrap_or(json!("")),
                "title": external.get("title").cloned().unwrap_or(json!("")),
                "description": external.get("description").cloned().unwrap_or(json!("")),
            }
        });

        if let Some(thumb_blob) = external.get("thumb") {
            if let Some(cid) = self.extract_blob_cid(thumb_blob) {
                view["external"]["thumb"] = json!(self.image_url("feed_thumbnail", &cid));
            }
        }

        Some(view)
    }

    #[allow(dead_code)]
    fn hydrate_record_embed(&self, embed: &Value, quotes: &QuoteMap) -> Option<Value> {
        let record_uri = embed.get("record")?.get("uri")?.as_str()?;

        let record_view = if let Some(quoted_post) = quotes.get(record_uri) {
            json!({
                "$type": "app.bsky.embed.record#viewRecord",
                "uri": record_uri,
                "cid": quoted_post.get("cid"),
                "author": quoted_post.get("author"),
                "value": quoted_post.get("record"),
                "indexedAt": quoted_post.get("indexedAt"),
                "labels": quoted_post.get("labels").cloned().unwrap_or(json!([])),
                "likeCount": quoted_post.get("likeCount"),
                "replyCount": quoted_post.get("replyCount"),
                "repostCount": quoted_post.get("repostCount"),
                "embed": quoted_post.get("embed"),
            })
        } else {
            json!({
                "$type": "app.bsky.embed.record#viewNotFound",
                "uri": record_uri,
                "notFound": true,
            })
        };

        Some(json!({
            "$type": "app.bsky.embed.record#view",
            "record": record_view,
        }))
    }

    #[allow(dead_code)]
    fn hydrate_record_with_media_embed(&self, embed: &Value, quotes: &QuoteMap) -> Option<Value> {
        let media_embed = embed.get("media")?;
        let record_embed = embed.get("record")?;

        let media_view = self.hydrate_embed(Some(media_embed), quotes)?;
        let record_view = self.hydrate_record_embed(record_embed, quotes)?;

        Some(json!({
            "$type": "app.bsky.embed.recordWithMedia#view",
            "record": record_view.get("record"),
            "media": media_view.get("$type").is_some().then_some(media_view),
        }))
    }

    #[allow(dead_code)]
    pub(crate) async fn hydrate_quotes(
        &self,
        posts: &[RecordDescript],
    ) -> QuoteMap {
        let mut quote_uris = std::collections::HashSet::new();

        for post in posts {
            if let Some(embed) = post.record.get("embed") {
                self.collect_quote_uris(embed, &mut quote_uris);
            }
        }

        if quote_uris.is_empty() {
            return QuoteMap::new();
        }

        let uri_list: Vec<&str> = quote_uris.iter().map(|s| s.as_str()).collect();
        let query = format!("uris={}", uri_list.join("&uris="));

        let appview_url = &self.state.config.appview.url;
        let appview_did = &self.state.config.appview.did;

        match super::super::routes::service_proxy::mint_service_auth(
            self.state,
            &self.did,
            appview_did,
            "app.bsky.feed.getPosts",
        )
        .await
        {
            Ok(service_jwt) => {
                let target = format!("{}/xrpc/app.bsky.feed.getPosts?{}", appview_url, query);

                match self
                    .state
                    .http_client
                    .get(&target)
                    .header("Authorization", format!("Bearer {}", service_jwt))
                    .header("atproto-proxy", appview_did)
                    .send()
                    .await
                {
                    Ok(resp) => match resp.json::<Value>().await {
                        Ok(body) => {
                            let mut map = QuoteMap::new();
                            if let Some(posts_arr) = body.get("posts").and_then(|v| v.as_array()) {
                                for post_view in posts_arr {
                                    if let Some(uri) = post_view.get("uri").and_then(|v| v.as_str()) {
                                        map.insert(uri.to_string(), post_view.clone());
                                    }
                                }
                            }
                            map
                        }
                        Err(err) => {
                            tracing::debug!(
                                error = %err,
                                "failed to parse getPosts response as JSON"
                            );
                            QuoteMap::new()
                        }
                    },
                    Err(err) => {
                        tracing::debug!(error = %err, "getPosts request failed");
                        QuoteMap::new()
                    }
                }
            }
            Err(_) => {
                tracing::debug!("failed to mint service auth for getPosts");
                QuoteMap::new()
            }
        }
    }

    #[allow(dead_code)]
    fn collect_quote_uris(&self, embed: &Value, uris: &mut std::collections::HashSet<String>) {
        if let Some(type_val) = embed.get("$type").and_then(|v| v.as_str()) {
            if type_val == "app.bsky.embed.record" {
                if let Some(uri) = embed
                    .get("record")
                    .and_then(|r| r.get("uri"))
                    .and_then(|u| u.as_str())
                {
                    uris.insert(uri.to_string());
                }
            } else if type_val == "app.bsky.embed.recordWithMedia" {
                if let Some(uri) = embed
                    .get("record")
                    .and_then(|r| r.get("uri"))
                    .and_then(|u| u.as_str())
                {
                    uris.insert(uri.to_string());
                }
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn insert_posts_in_feed(
        &self,
        feed: &mut Vec<Value>,
        posts: &[RecordDescript],
        quotes: &QuoteMap,
    ) {
        let last_time = {
            feed
                .last()
                .and_then(|item| item.get("post"))
                .and_then(|post| post.get("indexedAt"))
                .and_then(|t| t.as_str())
                .unwrap_or("1970-01-01T00:00:00.000Z")
                .to_string()
        };

        for post in posts {
            if post.indexed_at.as_str() <= last_time.as_str() {
                continue;
            }

            let post_view = self.post_view(post, quotes).await;
            let feed_item = json!({ "post": post_view });

            let mut insert_idx = feed.len();
            for (i, item) in feed.iter().enumerate() {
                let item_time = item
                    .get("post")
                    .and_then(|p| p.get("indexedAt"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("1970-01-01T00:00:00.000Z");
                if item_time < post.indexed_at.as_str() {
                    insert_idx = i;
                    break;
                }
            }

            feed.insert(insert_idx, feed_item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app;

    #[tokio::test]
    async fn profile_view_basic_includes_did() {
        let state = app::test_state().await;
        let viewer = LocalViewer::new(
            &state,
            "did:plc:test123".to_string(),
            Some("test.bsky.social".to_string()),
            None,
        );

        let view = viewer.profile_view_basic();
        assert_eq!(view["did"], "did:plc:test123");
        assert_eq!(view["handle"], "test.bsky.social");
    }

    #[tokio::test]
    async fn profile_view_basic_includes_displayname_from_profile() {
        let state = app::test_state().await;
        let profile = json!({
            "displayName": "Test User",
        });

        let viewer = LocalViewer::new(
            &state,
            "did:plc:test123".to_string(),
            Some("test.bsky.social".to_string()),
            Some(profile),
        );

        let view = viewer.profile_view_basic();
        assert_eq!(view["displayName"], "Test User");
    }

    #[tokio::test]
    async fn extract_blob_cid_parses_link_correctly() {
        let state = app::test_state().await;
        let viewer = LocalViewer::new(&state, "did:plc:test".to_string(), None, None);

        let blob_value = json!({
            "$type": "blob",
            "ref": {
                "$link": "bafy123456789"
            }
        });

        let cid = viewer.extract_blob_cid(&blob_value);
        assert_eq!(cid, Some("bafy123456789".to_string()));
    }

    #[tokio::test]
    async fn image_url_formats_correctly() {
        let state = app::test_state().await;
        let viewer = LocalViewer::new(&state, "did:plc:test".to_string(), None, None);

        let url = viewer.image_url("avatar", "bafy123456789");
        assert!(url.contains("/img/avatar/plain/did:plc:test/bafy123456789@jpeg"));
    }

    #[tokio::test]
    async fn update_profile_detailed_overwrites_all_fields() {
        let state = app::test_state().await;
        let profile = json!({
            "displayName": "New Name",
            "description": "New Description",
            "avatar": {
                "ref": { "$link": "bafy_avatar" }
            },
            "banner": {
                "ref": { "$link": "bafy_banner" }
            },
        });

        let viewer = LocalViewer::new(
            &state,
            "did:plc:test".to_string(),
            None,
            Some(profile),
        );

        let initial_view = json!({
            "did": "did:plc:test",
            "displayName": "Old Name",
            "description": "Old Description",
            "avatar": "old_url",
            "banner": "old_url",
        });

        let updated = viewer.update_profile_detailed(initial_view);
        assert_eq!(updated["displayName"], "New Name");
        assert_eq!(updated["description"], "New Description");
        assert!(updated["avatar"].as_str().unwrap().contains("bafy_avatar"));
        assert!(updated["banner"].as_str().unwrap().contains("bafy_banner"));
    }

    #[tokio::test]
    async fn post_view_includes_author_and_zero_counts() {
        let state = app::test_state().await;
        let viewer = LocalViewer::new(
            &state,
            "did:plc:test".to_string(),
            Some("test.bsky.social".to_string()),
            None,
        );

        let post = RecordDescript {
            uri: "at://did:plc:test/app.bsky.feed.post/abc123".to_string(),
            cid: "bafy_post_cid".to_string(),
            indexed_at: "2024-01-01T00:00:00.000Z".to_string(),
            record: json!({
                "$type": "app.bsky.feed.post",
                "text": "Hello world",
                "createdAt": "2024-01-01T00:00:00.000Z",
            }),
        };

        let quotes = QuoteMap::new();
        let view = viewer.post_view(&post, &quotes).await;

        assert_eq!(view["uri"], "at://did:plc:test/app.bsky.feed.post/abc123");
        assert_eq!(view["author"]["did"], "did:plc:test");
        assert_eq!(view["likeCount"], 0);
        assert_eq!(view["replyCount"], 0);
        assert_eq!(view["repostCount"], 0);
    }

    #[tokio::test]
    async fn post_view_hydrates_image_embed_locally() {
        let state = app::test_state().await;
        let viewer = LocalViewer::new(
            &state,
            "did:plc:test".to_string(),
            None,
            None,
        );

        let post = RecordDescript {
            uri: "at://did:plc:test/app.bsky.feed.post/abc123".to_string(),
            cid: "bafy_post".to_string(),
            indexed_at: "2024-01-01T00:00:00.000Z".to_string(),
            record: json!({
                "$type": "app.bsky.feed.post",
                "text": "Check out this image",
                "embed": {
                    "$type": "app.bsky.embed.images",
                    "images": [
                        {
                            "image": {
                                "ref": { "$link": "bafy_image_cid" }
                            },
                            "alt": "test image"
                        }
                    ]
                }
            }),
        };

        let quotes = QuoteMap::new();
        let view = viewer.post_view(&post, &quotes).await;

        assert_eq!(view["embed"]["$type"], "app.bsky.embed.images#view");
        assert!(view["embed"]["images"][0]["thumb"]
            .as_str()
            .unwrap()
            .contains("bafy_image_cid"));
        assert!(view["embed"]["images"][0]["fullsize"]
            .as_str()
            .unwrap()
            .contains("bafy_image_cid"));
    }

    #[tokio::test]
    async fn post_view_hydrates_external_embed_locally() {
        let state = app::test_state().await;
        let viewer = LocalViewer::new(
            &state,
            "did:plc:test".to_string(),
            None,
            None,
        );

        let post = RecordDescript {
            uri: "at://did:plc:test/app.bsky.feed.post/abc123".to_string(),
            cid: "bafy_post".to_string(),
            indexed_at: "2024-01-01T00:00:00.000Z".to_string(),
            record: json!({
                "$type": "app.bsky.feed.post",
                "text": "Check out this link",
                "embed": {
                    "$type": "app.bsky.embed.external",
                    "external": {
                        "uri": "https://example.com",
                        "title": "Example",
                        "description": "An example",
                        "thumb": {
                            "ref": { "$link": "bafy_thumb_cid" }
                        }
                    }
                }
            }),
        };

        let quotes = QuoteMap::new();
        let view = viewer.post_view(&post, &quotes).await;

        assert_eq!(view["embed"]["$type"], "app.bsky.embed.external#view");
        assert_eq!(view["embed"]["external"]["uri"], "https://example.com");
        assert_eq!(view["embed"]["external"]["title"], "Example");
        assert!(view["embed"]["external"]["thumb"]
            .as_str()
            .unwrap()
            .contains("bafy_thumb_cid"));
    }

    #[tokio::test]
    async fn record_embed_view_not_found_when_quote_missing() {
        let state = app::test_state().await;
        let viewer = LocalViewer::new(
            &state,
            "did:plc:test".to_string(),
            None,
            None,
        );

        let post = RecordDescript {
            uri: "at://did:plc:test/app.bsky.feed.post/abc123".to_string(),
            cid: "bafy_post".to_string(),
            indexed_at: "2024-01-01T00:00:00.000Z".to_string(),
            record: json!({
                "$type": "app.bsky.feed.post",
                "text": "Quoting someone",
                "embed": {
                    "$type": "app.bsky.embed.record",
                    "record": {
                        "uri": "at://did:plc:other/app.bsky.feed.post/xyz789"
                    }
                }
            }),
        };

        let quotes = QuoteMap::new();
        let view = viewer.post_view(&post, &quotes).await;

        assert_eq!(view["embed"]["$type"], "app.bsky.embed.record#view");
        assert_eq!(view["embed"]["record"]["$type"], "app.bsky.embed.record#viewNotFound");
        assert_eq!(
            view["embed"]["record"]["uri"],
            "at://did:plc:other/app.bsky.feed.post/xyz789"
        );
        assert_eq!(view["embed"]["record"]["notFound"], true);
    }

    #[tokio::test]
    async fn record_embed_view_includes_post_when_quote_found() {
        let state = app::test_state().await;
        let viewer = LocalViewer::new(
            &state,
            "did:plc:test".to_string(),
            None,
            None,
        );

        let quoted_post_view = json!({
            "uri": "at://did:plc:other/app.bsky.feed.post/xyz789",
            "cid": "bafy_quoted",
            "author": {
                "did": "did:plc:other",
                "handle": "other.bsky.social"
            },
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "Original post"
            },
            "indexedAt": "2023-12-01T00:00:00.000Z",
            "likeCount": 5,
            "replyCount": 2,
            "repostCount": 1,
        });

        let mut quotes = QuoteMap::new();
        quotes.insert(
            "at://did:plc:other/app.bsky.feed.post/xyz789".to_string(),
            quoted_post_view.clone(),
        );

        let post = RecordDescript {
            uri: "at://did:plc:test/app.bsky.feed.post/abc123".to_string(),
            cid: "bafy_post".to_string(),
            indexed_at: "2024-01-01T00:00:00.000Z".to_string(),
            record: json!({
                "$type": "app.bsky.feed.post",
                "text": "Quoting someone",
                "embed": {
                    "$type": "app.bsky.embed.record",
                    "record": {
                        "uri": "at://did:plc:other/app.bsky.feed.post/xyz789"
                    }
                }
            }),
        };

        let view = viewer.post_view(&post, &quotes).await;

        assert_eq!(view["embed"]["$type"], "app.bsky.embed.record#view");
        assert_eq!(view["embed"]["record"]["$type"], "app.bsky.embed.record#viewRecord");
        assert_eq!(
            view["embed"]["record"]["uri"],
            "at://did:plc:other/app.bsky.feed.post/xyz789"
        );
        assert_eq!(view["embed"]["record"]["author"]["did"], "did:plc:other");
    }

    #[tokio::test]
    async fn insert_posts_in_feed_maintains_chronological_order() {
        let state = app::test_state().await;
        let viewer = LocalViewer::new(
            &state,
            "did:plc:test".to_string(),
            None,
            None,
        );

        let mut feed = vec![
            json!({"post": {"uri": "1", "indexedAt": "2024-01-03T00:00:00.000Z"}}),
            json!({"post": {"uri": "2", "indexedAt": "2024-01-01T00:00:00.000Z"}}),
        ];

        let posts = vec![
            RecordDescript {
                uri: "at://did:plc:test/app.bsky.feed.post/new1".to_string(),
                cid: "bafy_new1".to_string(),
                indexed_at: "2024-01-02T00:00:00.000Z".to_string(),
                record: json!({}),
            },
        ];

        let quotes = QuoteMap::new();
        viewer.insert_posts_in_feed(&mut feed, &posts, &quotes).await;

        assert_eq!(feed.len(), 3);
        assert_eq!(feed[1]["post"]["indexedAt"], "2024-01-02T00:00:00.000Z");
    }

    #[tokio::test]
    async fn insert_posts_in_feed_filters_old_posts() {
        let state = app::test_state().await;
        let viewer = LocalViewer::new(
            &state,
            "did:plc:test".to_string(),
            None,
            None,
        );

        let mut feed = vec![
            json!({"post": {"uri": "1", "indexedAt": "2024-01-03T00:00:00.000Z"}}),
        ];

        let posts = vec![
            RecordDescript {
                uri: "at://did:plc:test/app.bsky.feed.post/old".to_string(),
                cid: "bafy_old".to_string(),
                indexed_at: "2024-01-02T00:00:00.000Z".to_string(),
                record: json!({}),
            },
        ];

        let quotes = QuoteMap::new();
        viewer.insert_posts_in_feed(&mut feed, &posts, &quotes).await;

        assert_eq!(feed.len(), 1);
    }
}
