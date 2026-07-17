// pattern: Functional Core

//! Label-stream semantics for the labeler watcher: reduce a labeler's raw
//! `com.atproto.label.queryLabels` output to the set of account-level labels currently in
//! force, and diff that set against what is already persisted.
//!
//! Label semantics per the atproto label lexicon: events apply in `cts` order; a later
//! event with `neg: true` retracts an earlier label with the same `(src, uri, val)`; a
//! label whose `exp` has passed is no longer in force. Only account-level labels count
//! here — a `uri` that is a bare DID — because the operator view flags *accounts*, not
//! individual records.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

/// One raw label event as returned by `com.atproto.label.queryLabels`. Unknown fields
/// (`cid`, `sig`, `ver`, …) are ignored.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LabelEvent {
    /// DID of the labeler that created the label.
    pub(crate) src: String,
    /// Subject of the label: an `at://` URI, or a bare DID for an account-level label.
    pub(crate) uri: String,
    /// The label value (e.g. `spam`, `!hide`).
    pub(crate) val: String,
    /// Label creation timestamp (RFC 3339).
    pub(crate) cts: String,
    /// Negation: retracts the earlier label with the same `(src, uri, val)`.
    #[serde(default)]
    pub(crate) neg: bool,
    /// Optional expiry timestamp (RFC 3339).
    #[serde(default)]
    pub(crate) exp: Option<String>,
}

/// One label currently in force on an account, keyed for persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActiveLabel {
    /// The labeled account's DID (the event `uri`).
    pub(crate) did: String,
    /// The label value.
    pub(crate) val: String,
    /// The label's creation timestamp.
    pub(crate) cts: String,
}

/// Reduce raw label events from one labeler to the account-level labels currently in force.
///
/// Filters to events actually attributed to `labeler_did` (defense in depth — the fetch
/// already narrows by `sources`, but a misbehaving labeler could still return foreign
/// events) and, when `watchlist` is non-empty, to the watched label values. Events apply
/// in `cts` order, so the latest event per `(uri, val)` wins: a final negation drops the
/// label, and an `exp` at or before `now` drops it as expired. An unparseable `cts` sorts
/// oldest (it loses to any parseable later event); an unparseable `exp` is treated as
/// non-expiring — err toward showing the operator a flag, never toward hiding one.
pub(crate) fn active_labels(
    events: &[LabelEvent],
    labeler_did: &str,
    watchlist: &[String],
    now: DateTime<Utc>,
) -> Vec<ActiveLabel> {
    let mut relevant: Vec<&LabelEvent> = events
        .iter()
        .filter(|e| e.src == labeler_did)
        .filter(|e| e.uri.starts_with("did:"))
        .filter(|e| watchlist.is_empty() || watchlist.iter().any(|w| w == &e.val))
        .collect();
    relevant.sort_by(|a, b| {
        parse_ts(&a.cts)
            .cmp(&parse_ts(&b.cts))
            .then_with(|| a.cts.cmp(&b.cts))
    });

    // Latest event per (account, value) wins.
    let mut last: HashMap<(&str, &str), &LabelEvent> = HashMap::new();
    for event in relevant {
        last.insert((event.uri.as_str(), event.val.as_str()), event);
    }

    let mut active: Vec<ActiveLabel> = last
        .into_values()
        .filter(|e| !e.neg)
        .filter(|e| match e.exp.as_deref().and_then(parse_ts) {
            Some(exp) => exp > now,
            None => true,
        })
        .map(|e| ActiveLabel {
            did: e.uri.clone(),
            val: e.val.clone(),
            cts: e.cts.clone(),
        })
        .collect();
    // Deterministic output order keeps the reconcile diff (and tests) stable.
    active.sort_by(|a, b| a.did.cmp(&b.did).then_with(|| a.val.cmp(&b.val)));
    active
}

/// The reconcile plan for one labeler: rows to insert/refresh and rows to delete.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct LabelDiff {
    /// Labels in force that are missing from storage or stored with a different `cts`.
    pub(crate) upserts: Vec<ActiveLabel>,
    /// Stored `(did, val)` pairs no longer in force.
    pub(crate) removals: Vec<(String, String)>,
}

/// Diff the labels currently in force against what is persisted for the same labeler.
///
/// An unchanged `(did, val, cts)` triple produces no write at all, so a quiet labeler
/// costs one read per pass; a `cts` change (the labeler re-issued the label) refreshes the
/// stored row without touching its `first_seen_at`.
pub(crate) fn diff_labels(desired: &[ActiveLabel], stored: &[ActiveLabel]) -> LabelDiff {
    let stored_by_key: HashMap<(&str, &str), &str> = stored
        .iter()
        .map(|l| ((l.did.as_str(), l.val.as_str()), l.cts.as_str()))
        .collect();
    let desired_keys: HashSet<(&str, &str)> = desired
        .iter()
        .map(|l| (l.did.as_str(), l.val.as_str()))
        .collect();

    let upserts = desired
        .iter()
        .filter(|l| stored_by_key.get(&(l.did.as_str(), l.val.as_str())) != Some(&l.cts.as_str()))
        .cloned()
        .collect();
    let removals = stored
        .iter()
        .filter(|l| !desired_keys.contains(&(l.did.as_str(), l.val.as_str())))
        .map(|l| (l.did.clone(), l.val.clone()))
        .collect();

    LabelDiff { upserts, removals }
}

/// Parse an RFC 3339 timestamp; `None` for anything unparseable.
fn parse_ts(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(uri: &str, val: &str, cts: &str) -> LabelEvent {
        LabelEvent {
            src: "did:plc:labeler".to_string(),
            uri: uri.to_string(),
            val: val.to_string(),
            cts: cts.to_string(),
            neg: false,
            exp: None,
        }
    }

    fn now() -> DateTime<Utc> {
        "2026-07-17T00:00:00Z".parse().unwrap()
    }

    #[test]
    fn keeps_account_level_labels_and_drops_record_level_ones() {
        let events = vec![
            event("did:plc:alice", "spam", "2026-01-01T00:00:00Z"),
            event(
                "at://did:plc:alice/app.bsky.feed.post/abc",
                "spam",
                "2026-01-01T00:00:00Z",
            ),
        ];
        let active = active_labels(&events, "did:plc:labeler", &[], now());
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].did, "did:plc:alice");
    }

    #[test]
    fn negation_applied_in_cts_order_retracts_a_label() {
        let mut neg = event("did:plc:alice", "spam", "2026-01-02T00:00:00Z");
        neg.neg = true;
        // The negation arrives out of order in the response; cts order must win.
        let events = vec![neg, event("did:plc:alice", "spam", "2026-01-01T00:00:00Z")];
        assert!(active_labels(&events, "did:plc:labeler", &[], now()).is_empty());
    }

    #[test]
    fn relabel_after_negation_is_in_force() {
        let mut neg = event("did:plc:alice", "spam", "2026-01-02T00:00:00Z");
        neg.neg = true;
        let events = vec![
            event("did:plc:alice", "spam", "2026-01-01T00:00:00Z"),
            neg,
            event("did:plc:alice", "spam", "2026-01-03T00:00:00Z"),
        ];
        let active = active_labels(&events, "did:plc:labeler", &[], now());
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].cts, "2026-01-03T00:00:00Z");
    }

    #[test]
    fn expired_labels_are_dropped_and_unparseable_exp_is_kept() {
        let mut expired = event("did:plc:alice", "spam", "2026-01-01T00:00:00Z");
        expired.exp = Some("2026-01-02T00:00:00Z".to_string());
        let mut future = event("did:plc:bob", "spam", "2026-01-01T00:00:00Z");
        future.exp = Some("2999-01-01T00:00:00Z".to_string());
        let mut garbled = event("did:plc:carol", "spam", "2026-01-01T00:00:00Z");
        garbled.exp = Some("not-a-timestamp".to_string());

        let active = active_labels(&[expired, future, garbled], "did:plc:labeler", &[], now());
        let dids: Vec<&str> = active.iter().map(|l| l.did.as_str()).collect();
        assert_eq!(dids, vec!["did:plc:bob", "did:plc:carol"]);
    }

    #[test]
    fn watchlist_narrows_and_empty_watchlist_takes_everything() {
        let events = vec![
            event("did:plc:alice", "spam", "2026-01-01T00:00:00Z"),
            event("did:plc:alice", "rude", "2026-01-01T00:00:00Z"),
        ];
        let all = active_labels(&events, "did:plc:labeler", &[], now());
        assert_eq!(all.len(), 2);
        let narrowed = active_labels(&events, "did:plc:labeler", &["spam".to_string()], now());
        assert_eq!(narrowed.len(), 1);
        assert_eq!(narrowed[0].val, "spam");
    }

    #[test]
    fn foreign_source_events_are_ignored() {
        let mut foreign = event("did:plc:alice", "spam", "2026-01-01T00:00:00Z");
        foreign.src = "did:plc:someone-else".to_string();
        assert!(active_labels(&[foreign], "did:plc:labeler", &[], now()).is_empty());
    }

    #[test]
    fn diff_plans_only_the_changes() {
        let desired = vec![
            ActiveLabel {
                did: "did:plc:alice".to_string(),
                val: "spam".to_string(),
                cts: "2026-01-01T00:00:00Z".to_string(),
            },
            ActiveLabel {
                did: "did:plc:bob".to_string(),
                val: "rude".to_string(),
                cts: "2026-01-02T00:00:00Z".to_string(),
            },
        ];
        let stored = vec![
            // Unchanged: no write.
            desired[0].clone(),
            // Gone from the labeler: removal.
            ActiveLabel {
                did: "did:plc:carol".to_string(),
                val: "spam".to_string(),
                cts: "2026-01-01T00:00:00Z".to_string(),
            },
        ];
        let diff = diff_labels(&desired, &stored);
        assert_eq!(diff.upserts, vec![desired[1].clone()]);
        assert_eq!(
            diff.removals,
            vec![("did:plc:carol".to_string(), "spam".to_string())]
        );
    }

    #[test]
    fn diff_refreshes_a_changed_cts() {
        let desired = vec![ActiveLabel {
            did: "did:plc:alice".to_string(),
            val: "spam".to_string(),
            cts: "2026-02-01T00:00:00Z".to_string(),
        }];
        let stored = vec![ActiveLabel {
            did: "did:plc:alice".to_string(),
            val: "spam".to_string(),
            cts: "2026-01-01T00:00:00Z".to_string(),
        }];
        let diff = diff_labels(&desired, &stored);
        assert_eq!(diff.upserts, desired);
        assert!(diff.removals.is_empty());
    }
}
