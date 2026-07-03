// pattern: Functional Core
//
// Munging functions: transform the AppView response by merging the requester's own unindexed records.
// Each munge is a pure transformation of the AppView response + local records → merged output.

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app;
    use serde_json::json;

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
}
