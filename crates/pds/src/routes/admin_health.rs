// pattern: Imperative Shell
//
// Gathers: admin credentials (master token or signed device request), whole-server DB
//          aggregates, live firehose state, readable sweep last-run state
// Processes: admin auth → assemble the literal readouts (no derived verdicts)
// Returns: JSON health payload on success; ApiError on all failure paths

//! GET /v1/admin/health - Operator server-health readout.
//!
//! The JSON counterpart of `GET /metrics` for the companion app's Status screen: literal
//! row counts, firehose state, and sweep last-run facts, per relay. Deliberately reports
//! raw truth only — no ok/warn verdicts — so operational thresholds live with the operator
//! (or their dashboards), not in the API shape. The Prometheus endpoint remains the
//! scraper-facing surface; this one exists because OTel instruments are write-only
//! in-process and a phone renders JSON, not text exposition.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::Json;
use serde::Serialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::require_admin;
use crate::sweep_status::SweepRun;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    version: &'static str,
    uptime_seconds: u64,
    accounts: AccountCounts,
    storage: StorageCounts,
    firehose: FirehoseState,
    sweeps: SweepStates,
}

/// Derived-lifecycle buckets (takendown > suspended > deactivated precedence, matching the
/// account-listing `status` filter). The four buckets partition `total` exactly.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountCounts {
    total: i64,
    active: i64,
    deactivated: i64,
    suspended: i64,
    takendown: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StorageCounts {
    /// Physical blob rows (one per stored CID, shared across owners).
    blob_count: i64,
    blob_bytes: i64,
    /// Physical repo-block rows (MST nodes + records).
    block_count: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FirehoseState {
    /// Highest sequenced event; 0 before the first event ever.
    current_seq: u64,
    /// Currently connected `subscribeRepos` WebSocket subscribers.
    subscribers: usize,
    /// Retained `repo_seq` rows — the replayable backlog.
    retained_events: i64,
    /// Age in seconds of the oldest retained event (how far back a reconnecting
    /// subscriber's cursor replays exactly); `null` when the log is empty.
    backfill_window_seconds: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SweepStates {
    blob_gc: Option<SweepState>,
    firehose_gc: Option<SweepState>,
    account_reaper: Option<SweepState>,
    agent_claim_sweep: Option<SweepState>,
}

/// One sweep's last completed pass; `null` at the response level until the first pass
/// completes after boot (each sweep first runs one full interval after startup). A stale
/// `completedAt` — not an error field — is the signal that passes are failing.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SweepState {
    /// Unix seconds when the pass completed.
    completed_at: i64,
    /// Items acted on by that pass (deleted blobs, pruned seq rows, reaped accounts,
    /// expired claim attempts).
    swept: u64,
}

impl From<SweepRun> for SweepState {
    fn from(run: SweepRun) -> Self {
        Self {
            completed_at: run.completed_at,
            swept: run.swept,
        }
    }
}

/// GET /v1/admin/health
///
/// Operator server-health readout for the companion app's per-relay Status screen.
/// Admin-authed: the master token **or** an active companion-app device's signed request
/// ([`require_admin`]).
pub async fn admin_health(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<HealthResponse>, ApiError> {
    // Auth first so an unauthenticated caller cannot read instance-scale facts.
    require_admin(method.as_str(), uri.path(), &headers, &body, &state).await?;

    let stats = crate::db::server_stats::server_stats(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to gather server stats");
            ApiError::new(ErrorCode::InternalError, "failed to gather server stats")
        })?;

    // Oldest retained event → backfill window. An unparseable timestamp would be a writer
    // bug (the writer emits one fixed format); degrade to `null` rather than failing the
    // whole readout over one field.
    let backfill_window_seconds = match crate::db::firehose_seq::oldest_sequenced_at(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to read oldest firehose event");
            ApiError::new(
                ErrorCode::InternalError,
                "failed to read oldest firehose event",
            )
        })? {
        Some(oldest) => match chrono::DateTime::parse_from_rfc3339(&oldest) {
            Ok(ts) => Some(
                (chrono::Utc::now() - ts.with_timezone(&chrono::Utc))
                    .num_seconds()
                    .max(0),
            ),
            Err(e) => {
                tracing::warn!(error = %e, oldest, "unparseable sequenced_at in health readout");
                None
            }
        },
        None => None,
    };

    let sweeps = state.sweeps.snapshot();

    Ok(Json(HealthResponse {
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.started_at.elapsed().as_secs(),
        accounts: AccountCounts {
            total: stats.accounts_total,
            active: stats.accounts_active,
            deactivated: stats.accounts_deactivated,
            suspended: stats.accounts_suspended,
            takendown: stats.accounts_takendown,
        },
        storage: StorageCounts {
            blob_count: stats.blob_count,
            blob_bytes: stats.blob_bytes,
            block_count: stats.block_count,
        },
        firehose: FirehoseState {
            current_seq: state.firehose.current_seq(),
            subscribers: state.firehose.subscriber_count(),
            retained_events: stats.firehose_events,
            backfill_window_seconds,
        },
        sweeps: SweepStates {
            blob_gc: sweeps.blob_gc.map(SweepState::from),
            firehose_gc: sweeps.firehose_gc.map(SweepState::from),
            account_reaper: sweeps.account_reaper.map(SweepState::from),
            agent_claim_sweep: sweeps.agent_claim_sweep.map(SweepState::from),
        },
    }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::app::app;
    use crate::routes::test_utils::test_state_with_admin_token;

    async fn get_health(
        router: axum::Router,
        token: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder().uri("/v1/admin/health");
        if let Some(token) = token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        let response = router
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, json)
    }

    #[tokio::test]
    async fn health_requires_admin_auth() {
        let state = test_state_with_admin_token().await;
        let router = app(state);

        let (status, _) = get_health(router.clone(), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _) = get_health(router, Some("wrong-token")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn health_reports_empty_instance_zeros() {
        let state = test_state_with_admin_token().await;
        let router = app(state);

        let (status, json) = get_health(router, Some("test-admin-token")).await;
        assert_eq!(status, StatusCode::OK);

        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
        assert!(json["uptimeSeconds"].is_u64());
        assert_eq!(json["accounts"]["total"], 0);
        assert_eq!(json["accounts"]["active"], 0);
        assert_eq!(json["storage"]["blobCount"], 0);
        assert_eq!(json["storage"]["blobBytes"], 0);
        assert_eq!(json["storage"]["blockCount"], 0);
        assert_eq!(json["firehose"]["currentSeq"], 0);
        assert_eq!(json["firehose"]["subscribers"], 0);
        assert_eq!(json["firehose"]["retainedEvents"], 0);
        // Empty log: no backfill window, and no sweep has completed after boot.
        assert_eq!(
            json["firehose"]["backfillWindowSeconds"],
            serde_json::Value::Null
        );
        assert_eq!(json["sweeps"]["blobGc"], serde_json::Value::Null);
        assert_eq!(json["sweeps"]["firehoseGc"], serde_json::Value::Null);
        assert_eq!(json["sweeps"]["accountReaper"], serde_json::Value::Null);
        assert_eq!(json["sweeps"]["agentClaimSweep"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn health_reflects_firehose_events_and_sweep_runs() {
        let state = test_state_with_admin_token().await;

        state
            .firehose
            .emit_identity("did:plc:health-test".to_string(), None)
            .await
            .unwrap();
        // A completed blob-GC pass shows up with its literal facts.
        state.sweeps.record_blob_gc(crate::sweep_status::SweepRun {
            completed_at: 1_750_000_000,
            swept: 7,
        });

        let router = app(state);
        let (status, json) = get_health(router, Some("test-admin-token")).await;
        assert_eq!(status, StatusCode::OK);

        assert_eq!(json["firehose"]["currentSeq"], 1);
        assert_eq!(json["firehose"]["retainedEvents"], 1);
        // The event was just emitted, so the window is present and small.
        let window = json["firehose"]["backfillWindowSeconds"].as_i64().unwrap();
        assert!((0..60).contains(&window), "window was {window}");
        assert_eq!(json["sweeps"]["blobGc"]["completedAt"], 1_750_000_000);
        assert_eq!(json["sweeps"]["blobGc"]["swept"], 7);
        assert_eq!(json["sweeps"]["firehoseGc"], serde_json::Value::Null);
    }
}
