// pattern: Imperative Shell
//
// Gathers: admin credentials (master token or signed device request); the configured primary
//          relay + the hostname we advertise to it; the relay's `getHostStatus` answer; our exact
//          sequencer head; and the wall-clock time of the event the relay's cursor points at.
// Processes: admin auth → assemble the literal relay-federation readout (no ok/warn verdict).
// Returns: JSON relay-status payload on success; ApiError on auth failure.

//! GET /v1/admin/relay-status — is the upstream relay actually crawling/indexing this PDS?
//!
//! Compares our **exact** sequencer head (`firehose.current_seq()`) against what the relay reports
//! for our hostname (`com.atproto.sync.getHostStatus`) and derives the gap server-side. Because we
//! own the PDS we skip the approximation a third-party observer must make (opening `subscribeRepos`
//! in a timed window to guess our head) — the head is read directly.
//!
//! Like [`admin_health`](super::admin_health), it reports **raw truth only** — no
//! `ok`/`behind`/`stale` verdict. The gap thresholds (`< 500` fine, `< 5000` warn, else behind) and
//! the status mapping live with the operator (the companion app renders them), not in the API shape,
//! so the same readout stays useful whatever an operator's thresholds are.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::Json;
use serde::Serialize;

use common::ApiError;

use crate::app::AppState;
use crate::auth::guards::require_admin;
use crate::relay_status::{HostStatus, RelayReport};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayStatusResponse {
    /// The relay we queried — the first configured crawler, bare host. `null` when no crawler is
    /// configured: federation notifications are disabled, so there is nothing to poll.
    relay_host: Option<String>,
    /// Whether the relay answered at all. A `HostNotFound` still counts as reachable (the relay is
    /// up, it simply has no record of us yet); `false` means a transport failure or timeout.
    reachable: bool,
    /// The relay's lifecycle status for us (`active`/`idle`/`offline`/`throttled`/`banned`).
    /// `null` when the relay is unreachable or has never crawled us. Reported verbatim — an unknown
    /// value from a newer relay is passed through, not dropped.
    relay_status: Option<String>,
    /// The relay's cursor into our firehose seq-space — the last seq it consumed from us. `null`
    /// when unreachable, not-yet-crawled, or the relay reported no cursor.
    relay_seq: Option<u64>,
    /// How many of our accounts the relay has indexed. `null` when unavailable.
    account_count: Option<u64>,
    /// Our exact sequencer head — the highest seq we have emitted. Always present (0 before the
    /// first event ever).
    pds_head_seq: u64,
    /// `pdsHeadSeq − relaySeq`: how many events the relay is behind us (positive = relay behind).
    /// `null` when `relaySeq` is unknown. Signed, so a relay cursor briefly *ahead* of our
    /// in-memory frontier (possible right after a restart before the log is re-read) reads as a
    /// small negative rather than a bogus huge gap.
    gap: Option<i64>,
    /// The `sequenced_at` of our event at `relaySeq` — the wall-clock time of the newest event the
    /// relay has consumed ("caught up as of / not seen since T"). `null` when `relaySeq` is unknown
    /// or that event has already aged out of the retained log.
    relay_cursor_at: Option<String>,
    /// A short human reason when the relay is unreachable or has not crawled us; `null` on success.
    detail: Option<String>,
    /// When this readout polled the relay (RFC 3339, millis + `Z`).
    checked_at: String,
}

/// GET /v1/admin/relay-status
///
/// Admin-authed: the master token **or** an active companion-app device's signed request
/// ([`require_admin`]).
pub async fn relay_status(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<RelayStatusResponse>, ApiError> {
    // Auth first so an unauthenticated caller cannot probe our federation posture.
    require_admin(method.as_str(), uri.path(), &headers, &body, &state).await?;

    let pds_head_seq = state.firehose.current_seq();
    let checked_at = crate::time::now_rfc3339();

    // The primary relay is the first configured crawler. The default config is
    // `["https://bsky.network"]`; an operator who cleared it has federation disabled, so there is
    // nothing to poll — report that plainly rather than inventing a relay.
    let Some(relay_base) = state.config.crawlers.urls.first() else {
        return Ok(Json(RelayStatusResponse {
            relay_host: None,
            reachable: false,
            relay_status: None,
            relay_seq: None,
            account_count: None,
            pds_head_seq,
            gap: None,
            relay_cursor_at: None,
            detail: Some("no relay configured".to_string()),
            checked_at,
        }));
    };

    let relay_host = crate::crawler::host_from_url(relay_base);
    // The relay knows us by the same hostname the crawler advertises via requestCrawl.
    let our_hostname = crate::crawler::host_from_url(&state.config.public_url);

    let report =
        crate::relay_status::fetch_host_status(&state.http_client, relay_base, &our_hostname).await;

    let (reachable, relay_status, relay_seq, account_count, detail) = match report {
        RelayReport::Found(HostStatus {
            seq,
            account_count,
            status,
        }) => (true, status, seq, account_count, None),
        RelayReport::NotFound => (
            true,
            None,
            None,
            None,
            Some("relay has not crawled this host".to_string()),
        ),
        RelayReport::Unreachable(reason) => (false, None, None, None, Some(reason)),
    };

    // Signed exact gap: how far the relay's cursor trails our head.
    let gap = relay_seq.map(|rs| pds_head_seq as i64 - rs as i64);

    // The wall-clock time of the event the relay's cursor points at. A cursor of 0 (or below the
    // retained window) has no row and stays `null`. A DB read failure degrades to `null` rather
    // than failing the whole readout — the numeric facts above are the load-bearing ones.
    let relay_cursor_at = match relay_seq {
        Some(rs) if rs > 0 => {
            match crate::db::firehose_seq::sequenced_at_for_seq(&state.db, rs).await {
                Ok(at) => at,
                Err(e) => {
                    tracing::warn!(error = %e, relay_seq = rs, "failed to read relay cursor timestamp");
                    None
                }
            }
        }
        _ => None,
    };

    Ok(Json(RelayStatusResponse {
        relay_host: Some(relay_host),
        reachable,
        relay_status,
        relay_seq,
        account_count,
        pds_head_seq,
        gap,
        relay_cursor_at,
        detail,
        checked_at,
    }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::app::app;
    use crate::routes::test_utils::{body_json, test_state_with_admin_token};

    async fn get_relay_status(
        router: axum::Router,
        token: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder().uri("/v1/admin/relay-status");
        if let Some(token) = token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        let response = router
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let json = if status == StatusCode::OK {
            body_json(response).await
        } else {
            serde_json::Value::Null
        };
        (status, json)
    }

    #[tokio::test]
    async fn relay_status_requires_admin_auth() {
        let state = test_state_with_admin_token().await;
        let router = app(state);

        let (status, _) = get_relay_status(router.clone(), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _) = get_relay_status(router, Some("wrong-token")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn relay_status_reports_no_relay_when_none_configured() {
        // The test state configures no crawlers, so the readout reports the "federation disabled"
        // shape rather than attempting a network call.
        let state = test_state_with_admin_token().await;
        let router = app(state);

        let (status, json) = get_relay_status(router, Some("test-admin-token")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["relayHost"], serde_json::Value::Null);
        assert_eq!(json["reachable"], false);
        assert_eq!(json["relaySeq"], serde_json::Value::Null);
        assert_eq!(json["gap"], serde_json::Value::Null);
        assert_eq!(json["relayCursorAt"], serde_json::Value::Null);
        assert_eq!(json["detail"], "no relay configured");
        assert_eq!(json["pdsHeadSeq"], 0);
        assert!(json["checkedAt"].is_string());
    }

    #[tokio::test]
    async fn relay_status_reflects_the_exact_sequencer_head() {
        // Our head is read directly from the firehose — no approximation. Emitting events advances
        // it, and the readout reports the exact value.
        let state = test_state_with_admin_token().await;
        state
            .firehose
            .emit_identity("did:plc:relay-status-test".to_string(), None)
            .await
            .unwrap();
        let router = app(state);

        let (status, json) = get_relay_status(router, Some("test-admin-token")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["pdsHeadSeq"], 1);
    }
}
