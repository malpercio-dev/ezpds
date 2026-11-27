// pattern: Imperative Shell

//! Durable delivery for the space notifications that must arrive: the retry classifier and
//! schedules, the sweep that drives retries on the shared scheduler, the syncer-notice queue,
//! and the repo-update queue.
//!
//! **Syncer notices.** Two `notifySpaceUpdate` updates are owed to a registered syncer, not sent
//! best-effort like a `repoWrite`: `spaceDeleted` and `registrationExpired`. Each is written to
//! `space_syncer_notice_retries` (V082) in the transaction that causes it, tried once at once,
//! and retried from the queue after 1 m, 10 m, 1 h, 6 h, then every 12 h, each with 50–100%
//! jitter, until it is delivered or the 72 h window closes. A retry is not scheduled to stop at
//! the window, so the last lands after it; once that one fails too, the notice is abandoned.
//!
//! * A **deletion** queues one notice per registration, lapsed ones included, in the tombstone's
//!   transaction, and replaces any notice pending for the same registration. There is no
//!   fan-out cap.
//! * A **lapse** is claimed by the first update after it: the registration is marked notified
//!   and one `registrationExpired{spaceRev}` queued, in one transaction, in place of that
//!   update. An expiry never replaces a pending notice.
//!
//! **Guards**, checked at every attempt, the immediate one included:
//! * the authority's account is gone: the row is dropped (account purge already removed the
//!   space; the `#account` event carries the news);
//! * the authority is deactivated, suspended or taken down: delivery pauses (the row is
//!   rescheduled, and still abandoned once the window closes);
//! * the notice is no longer owed: a `spaceDeleted` whose space has been recreated, or a
//!   `registrationExpired` whose syncer has renewed since. The row is dropped unsent.
//!
//! **Repo updates.** A local repo's commit into a space governed elsewhere owes that space host a
//! `notifyRepoUpdate`. It is written to `space_repo_update_retries` (V084) in the commit's
//! transaction, one row per `(repo, space)` coalesced to the newest rev, tried once at once, and
//! retried after 1 m, doubling up to 1 h, with the same jitter, until it is delivered or the 24 h
//! window closes. A newer commit replaces the payload and restarts the schedule and the window, so
//! a space host that comes back gets one notification carrying the newest rev. Retries are capped
//! at the window, and a row found past it is dropped unsent. Guards, at every attempt: the repo's
//! account is gone (the row is dropped), the repo is deactivated, suspended or taken down
//! (delivery pauses), or the space is no longer governed elsewhere (deleted, taken down, or now
//! ours: the row is dropped unsent).
//!
//! **Classifier.** Network and resolution failures retry, and so do the reference's retryable
//! statuses (408, 425, 429, 500, 502, 503, 504, 522, 524). Any other answer is permanent: the
//! notice is abandoned at once.
//!
//! **Divergences from the reference.** The reference keeps a lapsed registration after its
//! expiry notice is delivered; here it is deleted once the notice is delivered *or* abandoned,
//! and the sweep prunes registrations that lapsed more than 72 h ago without being claimed. On
//! the wire, a syncer that returns much later is confirmed again. The reference also inserts a
//! row only after the first attempt fails; here it is written before, so a crash between commit
//! and delivery still delivers. One process serves the database, so there is no worker lease.
//! The reference applies a repo update whose authority is local in place of sending it; here a
//! repo update is only ever queued for a space governed elsewhere, and dropped if that changes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::FromRef;
use custos_core::sweep::{Pass, Sweep};
use custos_core::sweep_status::names;
use custos_core::time::unix_now_secs;
use custos_core::CoreState;
use custos_db::accounts::AccountLifecycle;
use futures_util::StreamExt as _;
use rand_core::{OsRng, RngCore};
use sqlx::SqliteConnection;

use crate::db::space_notice_retries::{self as queue, NoticeRow};
use crate::db::space_repo_update_retries::{self as repo_updates, RepoUpdateRow};
use crate::space_notify::{fanout_permits, syncer_url, NOTIFY_SPACE_UPDATE, SYNCER_CONCURRENCY};

/// How often the sweep looks for due retries. Half the shortest delay, whose jitter can bring
/// it down to 30 s.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Most retries one pass attempts. At [`SYNCER_CONCURRENCY`] at a time and a 10 s timeout each,
/// a pass of dead endpoints takes about two minutes; the rest wait for the next pass.
const BATCH: i64 = 50;

/// The delays before each retry of a syncer notice, repeating the last.
const SYNCER_NOTICE_DELAYS_SECS: [u64; 5] = [60, 10 * 60, 60 * 60, 6 * 60 * 60, 12 * 60 * 60];

/// How long a syncer notice is retried, from when it was queued.
pub const SYNCER_NOTICE_WINDOW_SECS: i64 = 72 * 60 * 60;

/// How long a repo update is retried, from its newest commit.
pub const REPO_UPDATE_WINDOW_SECS: i64 = 24 * 60 * 60;

const SPACE_DELETED: &str = "com.atproto.space.notifySpaceUpdate#spaceDeleted";
const REGISTRATION_EXPIRED: &str = "com.atproto.space.notifySpaceUpdate#registrationExpired";

/// Why a delivery failed, as far as retrying it goes.
#[derive(Debug)]
pub(crate) enum Failure {
    /// Worth another try: the request did not complete, or the answer asks for patience.
    Transient(String),
    /// The recipient rejected it; sending it again would only waste its capacity.
    Permanent(String),
}

/// The reference's retryable HTTP statuses (`isRetryableHttpStatus`).
pub(crate) fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429 | 500 | 502 | 503 | 504 | 522 | 524)
}

/// Classify one request's outcome. A request that never got an answer is transient.
pub(crate) fn classify(outcome: Result<reqwest::Response, reqwest::Error>) -> Result<(), Failure> {
    match outcome {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) if is_retryable_status(response.status().as_u16()) => Err(Failure::Transient(
            format!("recipient returned {}", response.status()),
        )),
        Ok(response) => Err(Failure::Permanent(format!(
            "recipient returned {}",
            response.status()
        ))),
        Err(error) => Err(Failure::Transient(error.to_string())),
    }
}

/// `delay` from `now`, with 50–100% jitter, so retries queued together spread out.
pub(crate) fn retry_after(now: i64, delay_secs: u64) -> i64 {
    let half = delay_secs / 2;
    let jitter = OsRng.next_u64() % (delay_secs - half + 1);
    now + i64::try_from(half + jitter).unwrap_or(i64::MAX - now)
}

/// The delay before retry number `attempts` (from 1) of a syncer notice.
fn syncer_notice_delay(attempts: i64) -> u64 {
    let index = usize::try_from(attempts.max(1) - 1).unwrap_or(usize::MAX);
    SYNCER_NOTICE_DELAYS_SECS[index.min(SYNCER_NOTICE_DELAYS_SECS.len() - 1)]
}

/// The retry sweep on the shared scheduler. One pass prunes long-lapsed registrations and
/// attempts every due syncer notice, up to [`BATCH`].
pub struct SpaceNotifyRetrySweep;

impl<St> Sweep<St> for SpaceNotifyRetrySweep
where
    St: Send + Sync + 'static,
    CoreState: FromRef<St>,
{
    const NAME: &'static str = names::SPACE_NOTIFY_RETRY_SWEEP;

    fn interval(&self) -> Duration {
        SWEEP_INTERVAL
    }

    fn skip_missed_ticks(&self) -> bool {
        true
    }

    async fn run(&self, state: &St) -> anyhow::Result<Pass> {
        let pass = retry_due(&CoreState::from_ref(state)).await?;
        if pass.swept > 0 {
            tracing::debug!(
                swept = pass.swept,
                errors = pass.errors,
                "space notify retry pass complete"
            );
        }
        Ok(pass)
    }
}

/// One sweep pass: `swept` counts registrations pruned plus notices and repo updates attempted,
/// `errors` the attempts that failed on the database.
pub(crate) async fn retry_due(state: &CoreState) -> Result<Pass, sqlx::Error> {
    let now = unix_now_secs();
    let pruned = queue::prune_unnotified_lapses(&state.db, now - SYNCER_NOTICE_WINDOW_SECS).await?;
    let rows = queue::due(&state.db, now, BATCH).await?;
    let updates = repo_updates::due(&state.db, now, BATCH).await?;
    let attempted = (rows.len() + updates.len()) as u64;
    let _permit = fanout_permits().acquire().await;
    let errors = attempt_all(state, rows).await + attempt_repo_updates(state, updates).await;
    Ok(Pass {
        swept: pruned + attempted,
        errors,
    })
}

/// Queue the `notifyRepoUpdate` owed for `repo_did`'s commit at `repo_rev` into a space governed
/// elsewhere, inside the commit's transaction. Follow the commit with [`deliver_repo_update`].
pub(crate) async fn queue_repo_update(
    conn: &mut SqliteConnection,
    space_uri: &str,
    repo_did: &str,
    repo_rev: &str,
    hash: &[u8],
) -> Result<(), sqlx::Error> {
    let now = unix_now_secs();
    repo_updates::queue(
        conn,
        repo_did,
        space_uri,
        repo_rev,
        hash,
        retry_after(now, repo_update_delay(1)),
        now + REPO_UPDATE_WINDOW_SECS,
    )
    .await
}

/// Try the pending repo update for `(repo, space)` at once, on a detached task. The
/// [`JoinHandle`](tokio::task::JoinHandle) is for tests; a commit never waits on delivery.
pub(crate) fn deliver_repo_update(
    state: &CoreState,
    space_uri: &str,
    repo_did: &str,
) -> tokio::task::JoinHandle<()> {
    let state = state.clone();
    let (space_uri, repo_did) = (space_uri.to_string(), repo_did.to_string());
    tokio::spawn(async move {
        let _permit = fanout_permits().acquire().await;
        match repo_updates::pending(&state.db, &repo_did, &space_uri).await {
            // Gone already: a concurrent attempt delivered it.
            Ok(None) => {}
            Ok(Some(row)) => {
                attempt_repo_updates(&state, vec![row]).await;
            }
            Err(error) => {
                tracing::debug!(%error, space = %space_uri, "space notify: failed to load repo update");
            }
        }
    })
}

/// The delay before retry number `attempts` (from 1) of a repo update: 1 m, doubling, up to 1 h.
fn repo_update_delay(attempts: i64) -> u64 {
    let doublings = u32::try_from(attempts.clamp(1, 7) - 1).unwrap_or(6);
    (60u64 << doublings).min(60 * 60)
}

/// Attempt each repo update, [`SYNCER_CONCURRENCY`] at a time. Returns how many failed on the
/// database.
async fn attempt_repo_updates(state: &CoreState, rows: Vec<RepoUpdateRow>) -> u64 {
    let errors = AtomicU64::new(0);
    futures_util::stream::iter(rows)
        .for_each_concurrent(SYNCER_CONCURRENCY, |row| {
            let errors = &errors;
            async move {
                if let Err(error) = attempt_repo_update(state, &row).await {
                    errors.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(%error, space = %row.space_uri, "space notify: repo update attempt failed");
                }
            }
        })
        .await;
    errors.into_inner()
}

/// One attempt at one queued repo update, guards first.
async fn attempt_repo_update(state: &CoreState, row: &RepoUpdateRow) -> Result<(), sqlx::Error> {
    let now = unix_now_secs();
    if row.expires_at <= now {
        if repo_updates::expire(&state.db, row, now).await? {
            tracing::warn!(space = %row.space_uri, repo = %row.repo_did, "space repo update abandoned after 24 hours");
        }
        return Ok(());
    }
    let Some(space) = custos_core::space_uri::parse_space_ref(&row.space_uri) else {
        return repo_updates::clear(&state.db, row).await;
    };
    match custos_db::accounts::account_lifecycle(&state.db, &row.repo_did).await {
        Ok(None) => return repo_updates::clear(&state.db, row).await,
        Ok(Some(AccountLifecycle::Active)) => {}
        Ok(Some(_)) => return reschedule_repo_update(state, row, now).await,
        Err(error) => {
            // Left as it is: due again on a later pass.
            tracing::debug!(%error, space = %row.space_uri, "space notify: failed to load repo account");
            return Ok(());
        }
    }
    // Owed only while the space is still governed elsewhere: a live row with no policy here.
    let governed_elsewhere = crate::db::spaces::get_space(&state.db, &row.space_uri)
        .await?
        .is_some_and(|s| s.deleted_at.is_none() && s.takendown_at.is_none() && s.policy.is_none());
    if !governed_elsewhere {
        return repo_updates::clear(&state.db, row).await;
    }
    match crate::space_notify::send_repo_update(state, &space, row).await {
        Ok(()) => repo_updates::clear(&state.db, row).await,
        Err(Failure::Permanent(error)) => {
            tracing::warn!(%error, space = %row.space_uri, repo = %row.repo_did, "space repo update will not be retried");
            repo_updates::clear(&state.db, row).await
        }
        Err(Failure::Transient(error)) => {
            tracing::debug!(%error, space = %row.space_uri, repo = %row.repo_did, "space repo update failed");
            reschedule_repo_update(state, row, now).await
        }
    }
}

/// Reschedule after a failed or paused attempt, never past the window.
async fn reschedule_repo_update(
    state: &CoreState,
    row: &RepoUpdateRow,
    now: i64,
) -> Result<(), sqlx::Error> {
    let attempts = row.attempts + 1;
    let retry_at = retry_after(now, repo_update_delay(attempts)).min(row.expires_at);
    repo_updates::reschedule(&state.db, row, attempts, retry_at).await
}

/// Queue a `spaceDeleted` notice for every registration of the space, inside the deletion's
/// transaction and before its registrations are dropped. Follow the commit with
/// [`deliver_untried`].
pub(crate) async fn queue_space_deleted(
    conn: &mut SqliteConnection,
    space_uri: &str,
) -> Result<u64, sqlx::Error> {
    let now = unix_now_secs();
    let notice = serde_json::json!({ "$type": SPACE_DELETED }).to_string();
    queue::queue_space_deleted(
        conn,
        space_uri,
        &notice,
        retry_after(now, syncer_notice_delay(1)),
        now + SYNCER_NOTICE_WINDOW_SECS,
    )
    .await
}

/// Claim the space's registrations that have lapsed since the last update, queue each its one
/// `registrationExpired{spaceRev}`, and try them at once. Called from the update's fan-out task,
/// after the update itself has gone to the active registrations.
pub(crate) async fn claim_lapses(state: &CoreState, space_uri: &str, space_rev: &str) {
    let now = unix_now_secs();
    let notice =
        serde_json::json!({ "$type": REGISTRATION_EXPIRED, "spaceRev": space_rev }).to_string();
    let claimed = queue::claim_lapsed(
        &state.db,
        space_uri,
        &notice,
        now,
        retry_after(now, syncer_notice_delay(1)),
        now + SYNCER_NOTICE_WINDOW_SECS,
    )
    .await;
    match claimed {
        Ok(0) => {}
        Ok(_) => attempt_untried(state, space_uri).await,
        Err(error) => {
            tracing::debug!(%error, space = %space_uri, "space notify: failed to claim lapses");
        }
    }
}

/// Try the space's freshly queued notices at once, on a detached task. The
/// [`JoinHandle`](tokio::task::JoinHandle) is for tests; a caller never waits on delivery.
pub(crate) fn deliver_untried(state: &CoreState, space_uri: &str) -> tokio::task::JoinHandle<()> {
    let state = state.clone();
    let space_uri = space_uri.to_string();
    tokio::spawn(async move {
        let _permit = fanout_permits().acquire().await;
        attempt_untried(&state, &space_uri).await;
    })
}

async fn attempt_untried(state: &CoreState, space_uri: &str) {
    match queue::untried(&state.db, space_uri).await {
        Ok(rows) => {
            attempt_all(state, rows).await;
        }
        Err(error) => {
            tracing::debug!(%error, space = %space_uri, "space notify: failed to load notices");
        }
    }
}

/// Attempt each row, [`SYNCER_CONCURRENCY`] at a time. Returns how many failed on the database.
async fn attempt_all(state: &CoreState, rows: Vec<NoticeRow>) -> u64 {
    let errors = AtomicU64::new(0);
    futures_util::stream::iter(rows)
        .for_each_concurrent(SYNCER_CONCURRENCY, |row| {
            let errors = &errors;
            async move {
                if let Err(error) = attempt(state, &row).await {
                    errors.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(%error, space = %row.space_uri, "space notify: notice attempt failed");
                }
            }
        })
        .await;
    errors.into_inner()
}

/// One attempt at one queued notice, guards first.
async fn attempt(state: &CoreState, row: &NoticeRow) -> Result<(), sqlx::Error> {
    let now = unix_now_secs();
    let expiry = row.notice.contains(REGISTRATION_EXPIRED);
    let Some(space) = custos_core::space_uri::parse_space_ref(&row.space_uri) else {
        return queue::clear(&state.db, row).await;
    };
    match custos_db::accounts::account_lifecycle(&state.db, &space.authority).await {
        Ok(None) => return queue::clear(&state.db, row).await,
        Ok(Some(AccountLifecycle::Active)) => {}
        Ok(Some(_)) => return retry_later(state, row, now, expiry).await,
        Err(error) => {
            // Left as it is: due again on a later pass.
            tracing::debug!(%error, space = %row.space_uri, "space notify: failed to load authority");
            return Ok(());
        }
    }
    let owed = if expiry {
        queue::registration_lapsed(&state.db, row, now).await?
    } else {
        crate::db::spaces::get_space(&state.db, &row.space_uri)
            .await?
            .is_some_and(|space| space.deleted_at.is_some())
    };
    if !owed {
        return queue::clear(&state.db, row).await;
    }
    match send_notice(state, row).await {
        Ok(()) => settle(state, row, now, expiry).await,
        Err(Failure::Permanent(error)) => {
            tracing::warn!(%error, space = %row.space_uri, endpoint = %row.endpoint, "syncer notice will not be retried");
            settle(state, row, now, expiry).await
        }
        Err(Failure::Transient(error)) => {
            tracing::debug!(%error, space = %row.space_uri, endpoint = %row.endpoint, "syncer notice failed");
            retry_later(state, row, now, expiry).await
        }
    }
}

/// Reschedule after a failed or paused attempt, or abandon the notice once its window has closed.
async fn retry_later(
    state: &CoreState,
    row: &NoticeRow,
    now: i64,
    expiry: bool,
) -> Result<(), sqlx::Error> {
    if row.expires_at <= now {
        tracing::warn!(space = %row.space_uri, endpoint = %row.endpoint, "syncer notice abandoned after 72 hours");
        return settle(state, row, now, expiry).await;
    }
    let attempts = row.attempts + 1;
    queue::reschedule(
        &state.db,
        row,
        attempts,
        retry_after(now, syncer_notice_delay(attempts)),
    )
    .await
}

/// The notice is done with, delivered or abandoned. An expiry notice takes its lapsed
/// registration with it; a deleted space's registrations went with the space.
async fn settle(
    state: &CoreState,
    row: &NoticeRow,
    now: i64,
    expiry: bool,
) -> Result<(), sqlx::Error> {
    queue::clear(&state.db, row).await?;
    if expiry {
        queue::remove_lapsed_registration(&state.db, row, now).await?;
    }
    Ok(())
}

/// Send one notice in the `{space, token, update}` envelope. The endpoint is the syncer's
/// choice, validated at registration, so it is fetched through the hardened client.
async fn send_notice(state: &CoreState, row: &NoticeRow) -> Result<(), Failure> {
    let update: serde_json::Value =
        serde_json::from_str(&row.notice).map_err(|e| Failure::Permanent(e.to_string()))?;
    let body = serde_json::json!({
        "space": row.space_uri,
        "token": row.token,
        "update": update,
    });
    classify(
        state
            .hardened_http_client
            .post(&syncer_url(&row.endpoint, NOTIFY_SPACE_UPDATE))
            .timeout(crate::space_notify::SYNCER_TIMEOUT)
            .json(&body)
            .send()
            .await,
    )
}

#[cfg(test)]
mod tests {
    //! The queue against a wiremock syncer: delivery at once, the schedule, abandonment, every
    //! guard, and the one expiry notice a lapse is owed.

    use super::*;
    use crate::db::space_notify::{put_registration, Registration, WriterRevs};
    use crate::test_support::{
        memberspace_policy, seed_account_with_repo, seed_authority_space, state_with_master_key,
    };
    use custos_core::space_uri::parse_space_ref;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const AUTHORITY: &str = "did:plc:authorityretryaaaaaaaaaa";
    const SPACE: &str = "at:space/did:plc:authorityretryaaaaaaaaaa/org.example.bucket/main";
    const UPDATE_PATH: &str = "/xrpc/com.atproto.space.notifySpaceUpdate";

    async fn setup() -> CoreState {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, AUTHORITY).await;
        seed_authority_space(&state.db, SPACE, &memberspace_policy(true)).await;
        state
    }

    /// A syncer answering every notice with `status`.
    async fn syncer(status: u16) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(UPDATE_PATH))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        server
    }

    async fn register(state: &CoreState, server: &MockServer, token: &str, expires_at: i64) {
        let registration = Registration {
            endpoint: server.uri(),
            token: token.to_string(),
        };
        put_registration(&state.db, SPACE, &registration, expires_at as u64, 100)
            .await
            .unwrap();
    }

    /// The deletion transaction's queue half, as `deleteSpace` runs it, without the attempt.
    async fn delete_space(state: &CoreState) {
        let mut tx = state.db.begin().await.unwrap();
        crate::db::spaces::mark_space_deleted(&mut *tx, SPACE)
            .await
            .unwrap();
        queue_space_deleted(&mut tx, SPACE).await.unwrap();
        crate::db::spaces::delete_notify_registrations(&mut *tx, SPACE)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    async fn queued(state: &CoreState) -> Vec<NoticeRow> {
        sqlx::query_as("SELECT * FROM space_syncer_notice_retries ORDER BY token")
            .fetch_all(&state.db)
            .await
            .unwrap()
    }

    async fn make_due(state: &CoreState) {
        sqlx::query("UPDATE space_syncer_notice_retries SET retry_at = 0")
            .execute(&state.db)
            .await
            .unwrap();
    }

    async fn bodies(server: &MockServer) -> Vec<serde_json::Value> {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect()
    }

    async fn registration_count(state: &CoreState) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM space_notify_registrations")
            .fetch_one(&state.db)
            .await
            .unwrap()
    }

    fn revs(space_rev: &str) -> WriterRevs {
        WriterRevs {
            space_rev: space_rev.to_string(),
            prev_space_rev: None,
        }
    }

    #[test]
    fn the_classifier_retries_only_the_reference_statuses() {
        for status in [408, 425, 429, 500, 502, 503, 504, 522, 524] {
            assert!(is_retryable_status(status), "{status}");
        }
        for status in [400, 401, 403, 404, 410, 413, 501, 505, 520, 523] {
            assert!(!is_retryable_status(status), "{status}");
        }
    }

    #[test]
    fn the_schedule_is_the_reference_ladder_with_jitter() {
        let delays: Vec<u64> = (1..=7).map(syncer_notice_delay).collect();
        assert_eq!(
            delays,
            [60, 600, 3600, 21600, 43200, 43200, 43200],
            "1 m, 10 m, 1 h, 6 h, then every 12 h"
        );
        for _ in 0..200 {
            let at = retry_after(1000, 600);
            assert!((1300..=1600).contains(&at), "{at}: 50–100% of the delay");
        }
    }

    /// A deletion is owed to every registration, lapsed included, and is tried at once in the
    /// `{space, token, update}` envelope. Delivered, nothing stays queued.
    #[tokio::test]
    async fn a_deletion_reaches_every_registration_at_once() {
        let state = setup().await;
        let server = syncer(200).await;
        let now = unix_now_secs();
        register(&state, &server, "live", now + 600).await;
        register(&state, &server, "lapsed", now - 600).await;

        delete_space(&state).await;
        assert_eq!(queued(&state).await.len(), 2, "one row per registration");
        deliver_untried(&state, SPACE).await.unwrap();

        let mut tokens: Vec<_> = bodies(&server)
            .await
            .into_iter()
            .map(|body| {
                assert_eq!(body["space"], SPACE);
                assert_eq!(
                    body["update"],
                    serde_json::json!({ "$type": SPACE_DELETED })
                );
                body["token"].as_str().unwrap().to_string()
            })
            .collect();
        tokens.sort();
        assert_eq!(tokens, ["lapsed", "live"]);
        assert!(queued(&state).await.is_empty());
    }

    /// A retryable failure is rescheduled on the ladder and retried by the sweep until it lands.
    #[tokio::test]
    async fn a_transient_failure_is_retried_until_delivered() {
        let state = setup().await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let now = unix_now_secs();
        register(&state, &server, "t", now + 600).await;
        delete_space(&state).await;

        deliver_untried(&state, SPACE).await.unwrap();
        let row = &queued(&state).await[0];
        assert_eq!(row.attempts, 1);
        assert!(
            (now + 30..=unix_now_secs() + 60).contains(&row.retry_at),
            "{row:?}"
        );
        assert_eq!(row.expires_at - now, SYNCER_NOTICE_WINDOW_SECS, "{row:?}");

        // Not due yet: the sweep leaves it.
        retry_due(&state).await.unwrap();
        assert_eq!(bodies(&server).await.len(), 1);

        make_due(&state).await;
        retry_due(&state).await.unwrap();
        let row = &queued(&state).await[0];
        assert_eq!(row.attempts, 2);
        assert!(
            row.retry_at >= now + 300,
            "the second delay is 10 m: {row:?}"
        );

        make_due(&state).await;
        let pass = retry_due(&state).await.unwrap();
        assert_eq!(pass.swept, 1);
        assert_eq!(bodies(&server).await.len(), 3);
        assert!(queued(&state).await.is_empty(), "delivered");
    }

    /// Past the window, the next failure abandons the notice.
    #[tokio::test]
    async fn a_notice_is_abandoned_once_its_window_closes() {
        let state = setup().await;
        let server = syncer(503).await;
        register(&state, &server, "t", unix_now_secs() + 600).await;
        delete_space(&state).await;
        sqlx::query("UPDATE space_syncer_notice_retries SET retry_at = 0, expires_at = 1")
            .execute(&state.db)
            .await
            .unwrap();

        retry_due(&state).await.unwrap();
        assert_eq!(
            bodies(&server).await.len(),
            1,
            "the last retry is still sent"
        );
        assert!(queued(&state).await.is_empty());
    }

    /// A recreated space is no longer owed its deletion: the row is dropped unsent.
    #[tokio::test]
    async fn a_recreated_space_drops_its_pending_deletion() {
        let state = setup().await;
        let server = syncer(200).await;
        register(&state, &server, "t", unix_now_secs() + 600).await;
        delete_space(&state).await;
        seed_authority_space(&state.db, SPACE, &memberspace_policy(true)).await;

        make_due(&state).await;
        retry_due(&state).await.unwrap();
        assert!(bodies(&server).await.is_empty());
        assert!(queued(&state).await.is_empty());
    }

    /// A deactivated authority pauses delivery; reactivated, the notice goes out.
    #[tokio::test]
    async fn a_suspended_authority_pauses_delivery() {
        let state = setup().await;
        let server = syncer(200).await;
        register(&state, &server, "t", unix_now_secs() + 600).await;
        delete_space(&state).await;
        let set_deactivated = |at: Option<&'static str>| {
            sqlx::query("UPDATE accounts SET deactivated_at = ? WHERE did = ?")
                .bind(at)
                .bind(AUTHORITY)
        };
        set_deactivated(Some("2026-01-01T00:00:00Z"))
            .execute(&state.db)
            .await
            .unwrap();

        make_due(&state).await;
        retry_due(&state).await.unwrap();
        assert!(bodies(&server).await.is_empty(), "paused");
        assert_eq!(queued(&state).await[0].attempts, 1, "rescheduled");

        set_deactivated(None).execute(&state.db).await.unwrap();
        make_due(&state).await;
        retry_due(&state).await.unwrap();
        assert_eq!(bodies(&server).await.len(), 1);
        assert!(queued(&state).await.is_empty());
    }

    /// An authority with no account here (purged) is owed nothing: the row is dropped unsent.
    #[tokio::test]
    async fn a_missing_authority_drops_the_notice() {
        let state = state_with_master_key().await;
        seed_authority_space(&state.db, SPACE, &memberspace_policy(true)).await;
        let server = syncer(200).await;
        register(&state, &server, "t", unix_now_secs() + 600).await;
        delete_space(&state).await;

        deliver_untried(&state, SPACE).await.unwrap();
        assert!(bodies(&server).await.is_empty());
        assert!(queued(&state).await.is_empty());
    }

    /// The first update after a lapse sends that registration one `registrationExpired` with
    /// the update's `spaceRev`, in place of the update; later updates send it nothing. Once the
    /// notice is delivered the registration is gone.
    #[tokio::test]
    async fn a_lapse_is_owed_exactly_one_expiry_notice() {
        let state = setup().await;
        let server = syncer(200).await;
        let now = unix_now_secs();
        register(&state, &server, "live", now + 600).await;
        register(&state, &server, "lapsed", now - 1).await;
        let space = parse_space_ref(SPACE).unwrap();

        for rev in ["3m22aaaaaaaa2", "3m22aaaaaaaa3"] {
            crate::space_notify::forward_write(&state, &space, AUTHORITY, "3lzz", &[1], revs(rev))
                .await
                .unwrap();
        }

        let bodies = bodies(&server).await;
        let to = |token: &str| -> Vec<&serde_json::Value> {
            bodies
                .iter()
                .filter(|b| b["token"] == token)
                .map(|b| &b["update"])
                .collect()
        };
        assert_eq!(to("live").len(), 2);
        assert!(to("live")
            .iter()
            .all(|u| u["$type"] == "com.atproto.space.defs#repoWrite"));
        assert_eq!(
            to("lapsed"),
            [&serde_json::json!({ "$type": REGISTRATION_EXPIRED, "spaceRev": "3m22aaaaaaaa2" })]
        );
        assert!(queued(&state).await.is_empty());
        assert_eq!(
            registration_count(&state).await,
            1,
            "the lapsed one is gone"
        );
    }

    /// A rejected expiry notice is abandoned at once, and takes its lapsed registration with it.
    #[tokio::test]
    async fn a_rejected_expiry_notice_is_abandoned() {
        let state = setup().await;
        let server = syncer(400).await;
        register(&state, &server, "lapsed", unix_now_secs() - 1).await;

        claim_lapses(&state, SPACE, "3m22aaaaaaaa2").await;
        assert_eq!(bodies(&server).await.len(), 1);
        assert!(queued(&state).await.is_empty());
        assert_eq!(registration_count(&state).await, 0);
    }

    /// A syncer that renewed is not owed its expiry notice: dropped unsent, registration kept.
    #[tokio::test]
    async fn a_renewed_registration_is_not_sent_its_expiry() {
        let state = setup().await;
        let server = syncer(503).await;
        let now = unix_now_secs();
        register(&state, &server, "t", now - 1).await;
        claim_lapses(&state, SPACE, "3m22aaaaaaaa2").await;
        assert_eq!(queued(&state).await.len(), 1, "queued for retry");

        register(&state, &server, "t", now + 600).await;
        make_due(&state).await;
        retry_due(&state).await.unwrap();
        assert_eq!(bodies(&server).await.len(), 1, "only the first try");
        assert!(queued(&state).await.is_empty());
        assert_eq!(registration_count(&state).await, 1);
    }

    /// A deletion replaces a pending expiry notice.
    #[tokio::test]
    async fn a_deletion_replaces_a_pending_expiry() {
        let state = setup().await;
        let server = syncer(503).await;
        register(&state, &server, "t", unix_now_secs() - 1).await;
        claim_lapses(&state, SPACE, "3m22aaaaaaaa2").await;

        delete_space(&state).await;
        let rows = queued(&state).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].attempts, 0);
        assert!(rows[0].notice.contains(SPACE_DELETED), "{rows:?}");
    }

    /// The sweep prunes registrations that lapsed more than 72 h ago unclaimed; a claimed one
    /// waits for its notice.
    #[tokio::test]
    async fn the_sweep_prunes_long_lapsed_unclaimed_registrations() {
        let state = setup().await;
        let server = syncer(200).await;
        let long_ago = unix_now_secs() - SYNCER_NOTICE_WINDOW_SECS - 60;
        register(&state, &server, "unclaimed", long_ago).await;
        register(&state, &server, "claimed", long_ago).await;
        register(&state, &server, "recent", unix_now_secs() - 60).await;
        sqlx::query(
            "UPDATE space_notify_registrations SET expiry_notified = 1 WHERE token = 'claimed'",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let pass = retry_due(&state).await.unwrap();
        assert_eq!(pass.swept, 1);
        let left: Vec<String> =
            sqlx::query_scalar("SELECT token FROM space_notify_registrations ORDER BY token")
                .fetch_all(&state.db)
                .await
                .unwrap();
        assert_eq!(left, ["claimed", "recent"]);
    }

    // ── repo updates ─────────────────────────────────────────────────────────────

    const WRITER: &str = "did:plc:writerretryaaaaaaaaaaaaa";
    const FOREIGN: &str = "did:plc:foreignretryaaaaaaaaaaaa";
    const FOREIGN_SPACE: &str = "at:space/did:plc:foreignretryaaaaaaaaaaaa/org.example.bucket/a";
    const REPO_UPDATE_PATH: &str = "/xrpc/com.atproto.space.notifyRepoUpdate";

    /// A repo host: `WRITER` is ours, `FOREIGN_SPACE` is governed by a space host at `server`.
    async fn repo_host(server: &MockServer) -> CoreState {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, WRITER).await;
        let space = parse_space_ref(FOREIGN_SPACE).unwrap();
        crate::db::spaces::insert_space(
            &state.db,
            &crate::db::spaces::NewSpace {
                uri: &space.uri,
                authority_did: &space.authority,
                space_type: &space.space_type,
                skey: &space.skey,
            },
        )
        .await
        .unwrap();
        custos_db::dids::seed_did_document(
            &state.db,
            FOREIGN,
            serde_json::json!({
                "id": FOREIGN,
                "service": [{
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": server.uri(),
                }],
            }),
        )
        .await;
        state
    }

    /// `WRITER`'s commit at `rev`, as the commit path queues and then tries it.
    async fn commit(state: &CoreState, rev: &str, hash: &[u8]) {
        let mut tx = state.db.begin().await.unwrap();
        queue_repo_update(&mut tx, FOREIGN_SPACE, WRITER, rev, hash)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        deliver_repo_update(state, FOREIGN_SPACE, WRITER)
            .await
            .unwrap();
    }

    async fn queued_updates(state: &CoreState) -> Vec<RepoUpdateRow> {
        sqlx::query_as("SELECT * FROM space_repo_update_retries")
            .fetch_all(&state.db)
            .await
            .unwrap()
    }

    async fn make_updates_due(state: &CoreState) {
        sqlx::query("UPDATE space_repo_update_retries SET retry_at = 0")
            .execute(&state.db)
            .await
            .unwrap();
    }

    #[test]
    fn the_repo_update_schedule_doubles_from_a_minute_to_an_hour() {
        let delays: Vec<u64> = (1..=9).map(repo_update_delay).collect();
        assert_eq!(delays, [60, 120, 240, 480, 960, 1920, 3600, 3600, 3600]);
    }

    /// The space host is down while three writes land: each is tried once and the queue keeps
    /// only the newest. Back up, it receives one `notifyRepoUpdate` carrying the newest rev, and
    /// nothing stays queued.
    #[tokio::test]
    async fn a_space_host_that_was_down_gets_one_update_with_the_newest_rev() {
        let server = MockServer::start().await;
        let down = Mock::given(method("POST"))
            .and(path(REPO_UPDATE_PATH))
            .respond_with(ResponseTemplate::new(503))
            .mount_as_scoped(&server)
            .await;
        let state = repo_host(&server).await;
        let now = unix_now_secs();
        for (rev, hash) in [
            ("3m22aaaaaaaa1", 1u8),
            ("3m22aaaaaaaa2", 2),
            ("3m22aaaaaaaa3", 3),
        ] {
            commit(&state, rev, &[hash]).await;
        }
        assert_eq!(bodies(&server).await.len(), 3, "each commit was tried once");
        let rows = queued_updates(&state).await;
        assert_eq!(rows.len(), 1, "coalesced: {rows:?}");
        assert_eq!(rows[0].repo_rev, "3m22aaaaaaaa3");
        assert_eq!(rows[0].attempts, 1);
        assert!(rows[0].retry_at >= now + 30, "{rows:?}");
        assert!(
            rows[0].expires_at - now >= REPO_UPDATE_WINDOW_SECS,
            "{rows:?}"
        );
        drop(down);

        Mock::given(method("POST"))
            .and(path(REPO_UPDATE_PATH))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let before = bodies(&server).await.len();
        make_updates_due(&state).await;
        retry_due(&state).await.unwrap();
        let sent = bodies(&server).await;
        assert_eq!(sent.len() - before, 1, "one update once it is back");
        assert_eq!(
            sent[before],
            serde_json::json!({
                "space": FOREIGN_SPACE,
                "repo": WRITER,
                "repoRev": "3m22aaaaaaaa3",
                "data": { "$bytes": "Aw" },
            })
        );
        assert!(queued_updates(&state).await.is_empty(), "delivered");
    }

    /// An older rev never replaces a newer one pending.
    #[tokio::test]
    async fn an_older_rev_never_replaces_a_newer_one() {
        let server = syncer(503).await;
        let state = repo_host(&server).await;
        let mut tx = state.db.begin().await.unwrap();
        for rev in ["3m22aaaaaaaa3", "3m22aaaaaaaa2"] {
            queue_repo_update(&mut tx, FOREIGN_SPACE, WRITER, rev, &[0])
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
        assert_eq!(queued_updates(&state).await[0].repo_rev, "3m22aaaaaaaa3");
    }

    /// Past its window, the update is dropped unsent.
    #[tokio::test]
    async fn a_repo_update_expires_after_its_window() {
        let server = syncer(200).await;
        let state = repo_host(&server).await;
        let mut tx = state.db.begin().await.unwrap();
        queue_repo_update(&mut tx, FOREIGN_SPACE, WRITER, "3m22aaaaaaaa1", &[0])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        sqlx::query("UPDATE space_repo_update_retries SET retry_at = 0, expires_at = 1")
            .execute(&state.db)
            .await
            .unwrap();

        retry_due(&state).await.unwrap();
        assert!(bodies(&server).await.is_empty());
        assert!(queued_updates(&state).await.is_empty());
    }

    /// A rejected update is not retried.
    #[tokio::test]
    async fn a_rejected_repo_update_is_dropped() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(REPO_UPDATE_PATH))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;
        let state = repo_host(&server).await;
        commit(&state, "3m22aaaaaaaa1", &[0]).await;
        assert_eq!(bodies(&server).await.len(), 1);
        assert!(queued_updates(&state).await.is_empty());
    }

    /// A deactivated repo pauses delivery; reactivated, the update goes out.
    #[tokio::test]
    async fn a_deactivated_repo_pauses_its_update() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(REPO_UPDATE_PATH))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let state = repo_host(&server).await;
        let set_deactivated = |at: Option<&'static str>| {
            sqlx::query("UPDATE accounts SET deactivated_at = ? WHERE did = ?")
                .bind(at)
                .bind(WRITER)
        };
        set_deactivated(Some("2026-01-01T00:00:00Z"))
            .execute(&state.db)
            .await
            .unwrap();
        commit(&state, "3m22aaaaaaaa1", &[0]).await;
        assert!(bodies(&server).await.is_empty(), "paused");
        assert_eq!(queued_updates(&state).await[0].attempts, 1, "rescheduled");

        set_deactivated(None).execute(&state.db).await.unwrap();
        make_updates_due(&state).await;
        retry_due(&state).await.unwrap();
        assert_eq!(bodies(&server).await.len(), 1);
        assert!(queued_updates(&state).await.is_empty());
    }
}
