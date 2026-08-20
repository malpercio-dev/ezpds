// pattern: Imperative Shell
//
//! Periodic labeler watcher: flag hosted accounts that carry labels from watched labelers.
//!
//! Each pass polls every `[labeler] watched` labeler's `com.atproto.label.queryLabels` for
//! the hosted account DIDs, reduces the returned events to the labels currently in force
//! (`label_state` — `cts` order, negations, expiry, the per-labeler watchlist), and
//! reconciles the `account_labels` table to match. The operator account listing and health
//! readouts read that table; it is an explicitly rebuildable cache, never a source of truth.
//!
//! The labeler's query endpoint is resolved from its DID document's `#atproto_labeler`
//! service entry ([`resolve_atproto_proxy_target`]), and the fetch rides the shared
//! SSRF-hardened client — the endpoint comes from a DID document, which the labeler (not
//! this operator) controls. Resolution is cache-first like the proxy path; a labeler that
//! moves endpoints is picked up whenever its cached document is refreshed.
//!
//! Resilient by design, like the other periodic passes: an error against one labeler is
//! logged and counted but never aborts the pass for the rest, and the task runs for the
//! life of the process (dropped on shutdown rather than joined). Unlike the reaper, the
//! first pass runs immediately at boot — a fresh deploy is exactly when the operator wants
//! flags populated, and the pass only reconciles a rebuildable cache, so running mid-boot
//! is safe.
//!
//! Genuinely new flags also page the operator's admin devices: the diff's insert subset
//! (`LabelDiff::new_flags` — never a `cts` refresh) is collected across every labeler and
//! sent as ONE batched `notify_admin_devices` push per pass. A labeler's first completed
//! reconcile is its *seeding* pass — the backfill of labels that were in force before this
//! instance started watching — and fires nothing; the `labels_seeded` marker (V065) is what
//! makes that suppression survive restarts and follow the labeler out of the config.

use std::time::Duration;

use tokio::task::JoinHandle;

use common::WatchedLabeler;

use crate::app::AppState;
use crate::db::account_labels::{
    delete_label, delete_labels_for_unwatched, delete_seeds_for_unwatched, is_labeler_seeded,
    labels_for_labeler, mark_labeler_seeded, upsert_label,
};
use crate::identity::proxy::resolve_atproto_proxy_target;
use crate::label_state::{active_labels, diff_labels, ActiveLabel, LabelEvent};
use crate::notifications::{notify_admin_devices, NotificationPayload};

/// Ozone's `queryLabels` silently returns *nothing* (not an error) past 20 `uriPatterns`
/// per request, so hosted-DID batches must cap there.
const QUERY_LABELS_MAX_PATTERNS: usize = 20;

/// The lexicon's maximum `limit` per `queryLabels` page.
const QUERY_LABELS_PAGE_LIMIT: usize = 250;

/// Upper bound on cursor pages consumed per DID batch — a defensive stop against a labeler
/// that returns a cursor forever. 100 pages × 250 labels is far beyond any plausible label
/// volume for ≤20 accounts.
const QUERY_LABELS_MAX_PAGES: usize = 100;

/// Tally of what one watcher pass did, for logging and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LabelerWatchStats {
    /// Label rows inserted or refreshed this pass.
    pub upserted: u64,
    /// Label rows removed this pass (negated/expired labels + unwatched labelers' leftovers).
    pub removed: u64,
    /// Labelers whose poll failed this pass (logged, retried next pass).
    pub errors: u64,
}

/// Spawn the periodic labeler watcher.
///
/// The interval's first tick fires immediately, so the first pass runs right after boot
/// (see the module docs for why that is safe here and deliberately skipped in the sweeps).
/// The task loops for the life of the process and is dropped on shutdown.
pub fn spawn_labeler_watch(state: AppState, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            run_labeler_watch(&state).await;
        }
    })
}

/// Run a single watcher pass over every watched labeler.
///
/// Prunes labels from labelers that are no longer watched first (a config edit narrows the
/// flagged view on the next pass), then polls and reconciles each watched labeler. An error
/// against one labeler skips only that labeler.
pub async fn run_labeler_watch(state: &AppState) -> LabelerWatchStats {
    let mut stats = LabelerWatchStats::default();
    let watched = &state.config.labeler.watched;

    let watched_dids: Vec<String> = watched.iter().map(|w| w.did.clone()).collect();
    match delete_labels_for_unwatched(&state.db, &watched_dids).await {
        Ok(0) => {}
        Ok(removed) => {
            stats.removed += removed;
            tracing::info!(
                removed,
                "labeler watch: pruned labels from unwatched labelers"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "labeler watch: failed to prune unwatched labelers' labels");
        }
    }
    // Seeding markers follow their labeler's labels out, so re-adding a labeler re-suppresses
    // its backfill instead of paging the operator with every label it ever applied.
    if let Err(e) = delete_seeds_for_unwatched(&state.db, &watched_dids).await {
        tracing::error!(error = %e, "labeler watch: failed to prune unwatched labelers' seeding markers");
    }

    let dids = match crate::db::accounts::all_account_dids(&state.db).await {
        Ok(dids) => dids,
        Err(e) => {
            tracing::error!(error = %e, "labeler watch: failed to list hosted accounts; skipping pass");
            return stats;
        }
    };

    // New flags collected across every labeler this pass, so N flags cost the operator ONE
    // push, not N — a labeler sweep is a batch event, and a page per row is how operators
    // learn to ignore pages.
    let mut new_flags: Vec<ActiveLabel> = Vec::new();
    for labeler in watched {
        match reconcile_labeler(state, labeler, &dids).await {
            Ok(outcome) => {
                stats.upserted += outcome.upserted;
                stats.removed += outcome.removed;
                new_flags.extend(outcome.new_flags);
                if outcome.upserted > 0 || outcome.removed > 0 {
                    tracing::info!(
                        labeler = %labeler.did,
                        upserted = outcome.upserted,
                        removed = outcome.removed,
                        "labeler watch: reconciled labels"
                    );
                }
            }
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(
                    labeler = %labeler.did,
                    error = %e,
                    "labeler watch: poll failed; will retry next pass"
                );
            }
        }
    }
    if !new_flags.is_empty() {
        notify_admin_devices(
            state,
            flag_notification(&new_flags, &state.config.public_url),
        )
        .await;
    }

    // The failed-to-start early return above skips this on purpose: a stale
    // `labeler_watch_last_run_timestamp` signals that passes are not completing.
    let changes = stats.upserted + stats.removed;
    state.metrics.labeler_watch_changes.add(changes, &[]);
    state
        .metrics
        .labeler_watch_last_run_timestamp
        .record(crate::metrics::unix_now(), &[]);
    state
        .sweeps
        .record_labeler_watch(crate::sweep_status::SweepRun::now(changes));

    stats
}

/// What one labeler's reconcile did, and which of its upserts may page the operator.
struct ReconcileOutcome {
    upserted: u64,
    removed: u64,
    /// The insert subset of the diff — empty on the seeding pass, whose "new" labels are
    /// just backfill of flags that were in force before this instance started watching.
    new_flags: Vec<ActiveLabel>,
}

/// Poll one labeler for the hosted DIDs and reconcile its persisted labels.
async fn reconcile_labeler(
    state: &AppState,
    labeler: &WatchedLabeler,
    dids: &[String],
) -> anyhow::Result<ReconcileOutcome> {
    // Read the seeding marker before touching anything: a labeler is "seeded" only if a
    // PRIOR pass completed, so this pass's own inserts never count as news retroactively.
    let seeded = is_labeler_seeded(&state.db, &labeler.did).await?;

    let events = fetch_labels(state, &labeler.did, dids).await?;
    let desired = active_labels(&events, &labeler.did, &labeler.labels, chrono::Utc::now());

    let stored: Vec<ActiveLabel> = labels_for_labeler(&state.db, &labeler.did)
        .await?
        .into_iter()
        .map(|l| ActiveLabel {
            did: l.did,
            val: l.val,
            cts: l.cts,
        })
        .collect();
    let diff = diff_labels(&desired, &stored);
    let (upserted, removed) = (diff.upserts.len() as u64, diff.removals.len() as u64);

    if upserted > 0 || removed > 0 {
        // One transaction per labeler: the flagged view never shows a half-applied reconcile.
        let mut tx = state.db.begin().await?;
        for label in &diff.upserts {
            upsert_label(&mut *tx, &label.did, &labeler.did, &label.val, &label.cts).await?;
        }
        for (did, val) in &diff.removals {
            delete_label(&mut *tx, did, &labeler.did, val).await?;
        }
        tx.commit().await?;
    }

    // Mark seeded only after the reconcile landed: a pass that failed above retries as the
    // seeding pass, so a crash mid-backfill can't promote the remainder into "news".
    if !seeded {
        mark_labeler_seeded(&state.db, &labeler.did).await?;
    }

    Ok(ReconcileOutcome {
        upserted,
        removed,
        new_flags: if seeded { diff.new_flags } else { Vec::new() },
    })
}

/// The one batched operator push for a pass's new flags.
///
/// The payload travels HPKE-sealed, so naming the account is fine; the `data` block carries
/// what the admin app needs to deep-link into the right server's Accounts screen — the app
/// pairs with several relays at once, and `server` (this instance's public URL) is how it
/// picks the pairing the alert belongs to.
fn flag_notification(new_flags: &[ActiveLabel], public_url: &str) -> NotificationPayload {
    let accounts: std::collections::BTreeSet<&str> =
        new_flags.iter().map(|l| l.did.as_str()).collect();
    let body = if let [flag] = new_flags {
        format!("{} was flagged {}.", flag.did, flag.val)
    } else {
        format!(
            "{} new flags on {} hosted account{} from watched labelers.",
            new_flags.len(),
            accounts.len(),
            if accounts.len() == 1 { "" } else { "s" },
        )
    };
    NotificationPayload::new("accounts_flagged", "Accounts flagged", body).with_data(
        serde_json::json!({
            "server": public_url,
            "screen": "accounts",
            "count": new_flags.len(),
        }),
    )
}

/// Fetch every label event the labeler reports for `dids`, batching `uriPatterns` at the
/// Ozone-safe cap and following each batch's cursor to exhaustion.
async fn fetch_labels(
    state: &AppState,
    labeler_did: &str,
    dids: &[String],
) -> anyhow::Result<Vec<LabelEvent>> {
    // The labeler advertises its query endpoint in its DID document; the resolved URL is
    // SSRF-validated and the request goes out on the hardened client.
    let target = resolve_atproto_proxy_target(state, &format!("{labeler_did}#atproto_labeler"))
        .await
        .map_err(|e| anyhow::anyhow!("failed to resolve labeler service endpoint: {e:?}"))?;
    let base = url::Url::parse(&format!(
        "{}/xrpc/com.atproto.label.queryLabels",
        target.url.trim_end_matches('/')
    ))?;

    let mut events = Vec::new();
    for chunk in dids.chunks(QUERY_LABELS_MAX_PATTERNS) {
        let mut cursor: Option<String> = None;
        for _page in 0..QUERY_LABELS_MAX_PAGES {
            let mut url = base.clone();
            {
                let mut pairs = url.query_pairs_mut();
                for did in chunk {
                    pairs.append_pair("uriPatterns", did);
                }
                pairs.append_pair("sources", labeler_did);
                pairs.append_pair("limit", &QUERY_LABELS_PAGE_LIMIT.to_string());
                if let Some(c) = &cursor {
                    pairs.append_pair("cursor", c);
                }
            }

            let response = state.hardened_http_client.get(url).send().await?;
            if !response.status().is_success() {
                anyhow::bail!("queryLabels returned {}", response.status());
            }
            let page: QueryLabelsPage = response.json().await?;

            let page_len = page.labels.len();
            events.extend(page.labels);
            cursor = page.cursor.filter(|c| !c.is_empty());
            // An empty page ends the batch even with a cursor present — some labeler
            // implementations echo a cursor on the final page.
            if cursor.is_none() || page_len == 0 {
                break;
            }
        }
    }
    Ok(events)
}

/// One `com.atproto.label.queryLabels` response page.
#[derive(Debug, serde::Deserialize)]
struct QueryLabelsPage {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    labels: Vec<LabelEvent>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const LABELER: &str = "did:plc:testlabeler";

    async fn insert_account(db: &sqlx::SqlitePool, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(db)
        .await
        .unwrap();
    }

    /// Point the labeler DID's cached document at a mock labeler service.
    async fn seed_labeler_doc(db: &sqlx::SqlitePool, endpoint: &str) {
        crate::db::dids::seed_did_document(
            db,
            LABELER,
            json!({
                "id": LABELER,
                "service": [{
                    "id": "#atproto_labeler",
                    "type": "AtprotoLabeler",
                    "serviceEndpoint": endpoint,
                }],
            }),
        )
        .await;
    }

    fn watch(labels: &[&str]) -> common::WatchedLabeler {
        common::WatchedLabeler {
            did: LABELER.to_string(),
            labels: labels.iter().map(|s| s.to_string()).collect(),
        }
    }

    async fn state_watching(labels: &[&str]) -> crate::app::AppState {
        let mut state = test_state().await;
        let mut config = (*state.config).clone();
        config.labeler.watched = vec![watch(labels)];
        state.config = std::sync::Arc::new(config);
        state
    }

    async fn stored_labels(db: &sqlx::SqlitePool) -> Vec<(String, String, String)> {
        sqlx::query_as::<_, (String, String, String)>(
            "SELECT did, val, cts FROM account_labels ORDER BY did, val",
        )
        .fetch_all(db)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn pass_persists_active_labels_and_reconciles_removals() {
        let state = state_watching(&[]).await;
        insert_account(&state.db, "did:plc:lw_alice").await;
        insert_account(&state.db, "did:plc:lw_bob").await;

        let server = MockServer::start().await;
        seed_labeler_doc(&state.db, &server.uri()).await;

        // First poll: alice is labeled spam; bob has a negated label (never in force).
        let first = Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.label.queryLabels"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "labels": [
                    {"src": LABELER, "uri": "did:plc:lw_alice", "val": "spam",
                     "cts": "2026-01-01T00:00:00Z"},
                    {"src": LABELER, "uri": "did:plc:lw_bob", "val": "spam",
                     "cts": "2026-01-01T00:00:00Z"},
                    {"src": LABELER, "uri": "did:plc:lw_bob", "val": "spam", "neg": true,
                     "cts": "2026-01-02T00:00:00Z"},
                ]
            })))
            .expect(1)
            .mount_as_scoped(&server)
            .await;

        let stats = run_labeler_watch(&state).await;
        assert_eq!(stats.errors, 0);
        assert_eq!(stats.upserted, 1);
        assert_eq!(
            stored_labels(&state.db).await,
            vec![(
                "did:plc:lw_alice".to_string(),
                "spam".to_string(),
                "2026-01-01T00:00:00Z".to_string()
            )]
        );
        // The pass records its instruments and readable sweep state.
        assert_eq!(state.sweeps.snapshot().labeler_watch.unwrap().swept, 1);
        drop(first);

        // Second poll: the labeler has retracted alice's label.
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.label.queryLabels"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
            .mount(&server)
            .await;

        let stats = run_labeler_watch(&state).await;
        assert_eq!(stats.removed, 1);
        assert!(stored_labels(&state.db).await.is_empty());
    }

    #[tokio::test]
    async fn watchlist_filters_label_values() {
        let state = state_watching(&["spam"]).await;
        insert_account(&state.db, "did:plc:lw_carol").await;

        let server = MockServer::start().await;
        seed_labeler_doc(&state.db, &server.uri()).await;
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.label.queryLabels"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "labels": [
                    {"src": LABELER, "uri": "did:plc:lw_carol", "val": "rude",
                     "cts": "2026-01-01T00:00:00Z"},
                    {"src": LABELER, "uri": "did:plc:lw_carol", "val": "spam",
                     "cts": "2026-01-01T00:00:00Z"},
                ]
            })))
            .mount(&server)
            .await;

        let stats = run_labeler_watch(&state).await;
        assert_eq!(stats.upserted, 1);
        let stored = stored_labels(&state.db).await;
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].1, "spam");
    }

    #[tokio::test]
    async fn labeler_error_is_counted_not_fatal() {
        let state = state_watching(&[]).await;
        insert_account(&state.db, "did:plc:lw_dave").await;

        let server = MockServer::start().await;
        seed_labeler_doc(&state.db, &server.uri()).await;
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.label.queryLabels"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let stats = run_labeler_watch(&state).await;
        assert_eq!(stats.errors, 1);
        assert!(stored_labels(&state.db).await.is_empty());
    }

    // ── Operator-push trigger ─────────────────────────────────────────────────

    use crate::notify_relay_client::{NotifyJob, NotifySender};

    /// Wire a watching state for operator pushes: notifications configured, a master key to
    /// seal with, one active admin device registered with a live relay handle, and a
    /// capturing sender so the test sees exactly which jobs a pass enqueued.
    async fn state_with_admin_push(
        labels: &[&str],
    ) -> (
        crate::app::AppState,
        tokio::sync::mpsc::UnboundedReceiver<NotifyJob>,
    ) {
        let mut state = state_watching(labels).await;
        let mut config = (*state.config).clone();
        config.notifications.relay = Some("relay-node-id".to_string());
        config.signing_key_master_key =
            Some(common::Sensitive(zeroize::Zeroizing::new([0x7u8; 32])));
        state.config = std::sync::Arc::new(config);

        sqlx::query(
            "INSERT INTO admin_devices (id, label, public_key, platform, scopes, created_at) \
             VALUES ('adm-1', 'console', 'zAdm1Key', 'ios', 'admin', datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();
        let device_key = crypto::generate_p256_keypair().unwrap().key_id.0;
        crate::db::notifications::upsert_admin_registration(
            &state.db,
            "adm-1",
            &device_key,
            "feedface",
            "org.obsign.admincompanion",
            false,
        )
        .await
        .unwrap();
        crate::db::notifications::set_admin_registration_handles_for_token(
            &state.db, "feedface", "handle-1",
        )
        .await
        .unwrap();

        let (sender, rx) = NotifySender::capturing();
        state.notify_sender = Some(sender);
        (state, rx)
    }

    fn drain_pushes(rx: &mut tokio::sync::mpsc::UnboundedReceiver<NotifyJob>) -> usize {
        let mut pushes = 0;
        while let Ok(job) = rx.try_recv() {
            if matches!(job, NotifyJob::Push { .. }) {
                pushes += 1;
            }
        }
        pushes
    }

    #[tokio::test]
    async fn the_seeding_backfill_fires_no_operator_push() {
        let (state, mut rx) = state_with_admin_push(&[]).await;
        insert_account(&state.db, "did:plc:lw_seed_a").await;
        insert_account(&state.db, "did:plc:lw_seed_b").await;

        let server = MockServer::start().await;
        seed_labeler_doc(&state.db, &server.uri()).await;
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.label.queryLabels"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "labels": [
                    {"src": LABELER, "uri": "did:plc:lw_seed_a", "val": "spam",
                     "cts": "2026-01-01T00:00:00Z"},
                    {"src": LABELER, "uri": "did:plc:lw_seed_b", "val": "spam",
                     "cts": "2026-01-01T00:00:00Z"},
                ]
            })))
            .mount(&server)
            .await;

        let stats = run_labeler_watch(&state).await;
        assert_eq!(stats.upserted, 2, "the backfill itself must still persist");
        assert_eq!(
            drain_pushes(&mut rx),
            0,
            "pre-existing labels are backfill, not news — the seeding pass must not page"
        );
        assert!(
            crate::db::account_labels::is_labeler_seeded(&state.db, LABELER)
                .await
                .unwrap(),
            "a completed pass marks the labeler seeded"
        );
    }

    #[tokio::test]
    async fn new_flags_after_seeding_fire_one_batched_push() {
        let (state, mut rx) = state_with_admin_push(&[]).await;
        insert_account(&state.db, "did:plc:lw_new_a").await;
        insert_account(&state.db, "did:plc:lw_new_b").await;

        let server = MockServer::start().await;
        seed_labeler_doc(&state.db, &server.uri()).await;

        // Pass 1: nothing labeled yet — this is the seeding pass.
        let empty = Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.label.queryLabels"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
            .mount_as_scoped(&server)
            .await;
        run_labeler_watch(&state).await;
        assert_eq!(drain_pushes(&mut rx), 0);
        drop(empty);

        // Pass 2: three new flags across two accounts land in one pass.
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.label.queryLabels"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "labels": [
                    {"src": LABELER, "uri": "did:plc:lw_new_a", "val": "spam",
                     "cts": "2026-02-01T00:00:00Z"},
                    {"src": LABELER, "uri": "did:plc:lw_new_a", "val": "rude",
                     "cts": "2026-02-01T00:00:00Z"},
                    {"src": LABELER, "uri": "did:plc:lw_new_b", "val": "spam",
                     "cts": "2026-02-01T00:00:00Z"},
                ]
            })))
            .mount(&server)
            .await;

        let stats = run_labeler_watch(&state).await;
        assert_eq!(stats.upserted, 3);
        assert_eq!(
            drain_pushes(&mut rx),
            1,
            "N new flags in one pass are one batched push, never a page per row"
        );
    }

    #[tokio::test]
    async fn a_cts_refresh_fires_nothing() {
        let (state, mut rx) = state_with_admin_push(&[]).await;
        insert_account(&state.db, "did:plc:lw_refresh").await;

        let server = MockServer::start().await;
        seed_labeler_doc(&state.db, &server.uri()).await;

        let first = Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.label.queryLabels"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "labels": [
                    {"src": LABELER, "uri": "did:plc:lw_refresh", "val": "spam",
                     "cts": "2026-01-01T00:00:00Z"},
                ]
            })))
            .mount_as_scoped(&server)
            .await;
        run_labeler_watch(&state).await;
        assert_eq!(drain_pushes(&mut rx), 0, "seeding pass");
        drop(first);

        // The labeler re-issued the same label with a newer cts: the row refreshes, but the
        // operator already knows about this flag.
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.label.queryLabels"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "labels": [
                    {"src": LABELER, "uri": "did:plc:lw_refresh", "val": "spam",
                     "cts": "2026-03-01T00:00:00Z"},
                ]
            })))
            .mount(&server)
            .await;

        let stats = run_labeler_watch(&state).await;
        assert_eq!(stats.upserted, 1, "the cts refresh still persists");
        assert_eq!(drain_pushes(&mut rx), 0, "a cts refresh is not a new flag");
    }

    #[test]
    fn flag_notification_names_a_single_flag_and_counts_a_batch() {
        let flag = |did: &str, val: &str| ActiveLabel {
            did: did.to_string(),
            val: val.to_string(),
            cts: "2026-01-01T00:00:00Z".to_string(),
        };

        let single = flag_notification(&[flag("did:plc:alice", "spam")], "https://pds.example");
        assert_eq!(single.title, "Accounts flagged");
        assert_eq!(single.body, "did:plc:alice was flagged spam.");
        let data = single.data.unwrap();
        assert_eq!(data["server"], "https://pds.example");
        assert_eq!(data["screen"], "accounts");
        assert_eq!(data["count"], 1);

        let batch = flag_notification(
            &[
                flag("did:plc:alice", "spam"),
                flag("did:plc:alice", "rude"),
                flag("did:plc:bob", "spam"),
            ],
            "https://pds.example",
        );
        assert_eq!(
            batch.body,
            "3 new flags on 2 hosted accounts from watched labelers."
        );
        assert_eq!(batch.data.unwrap()["count"], 3);
    }

    #[tokio::test]
    async fn unwatched_labelers_labels_are_pruned() {
        // Watching nobody at the pass level still prunes leftovers from a labeler that was
        // removed from the config (here: rows attributed to a different labeler DID).
        let state = state_watching(&[]).await;
        insert_account(&state.db, "did:plc:lw_erin").await;
        sqlx::query(
            "INSERT INTO account_labels (did, labeler_did, val, cts) \
             VALUES ('did:plc:lw_erin', 'did:plc:formerlabeler', 'spam', '2026-01-01T00:00:00Z')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        crate::db::account_labels::mark_labeler_seeded(&state.db, "did:plc:formerlabeler")
            .await
            .unwrap();

        let server = MockServer::start().await;
        seed_labeler_doc(&state.db, &server.uri()).await;
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.label.queryLabels"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
            .mount(&server)
            .await;

        let stats = run_labeler_watch(&state).await;
        assert_eq!(stats.removed, 1);
        assert!(stored_labels(&state.db).await.is_empty());
        assert!(
            !crate::db::account_labels::is_labeler_seeded(&state.db, "did:plc:formerlabeler")
                .await
                .unwrap(),
            "the seeding marker leaves with the labeler, so a re-add re-suppresses backfill"
        );
    }
}
