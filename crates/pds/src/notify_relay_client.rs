// pattern: Imperative Shell

//! The pds's first *outbound* iroh leg. Everything else in `iroh_tunnel.rs` accepts; this
//! dials the configured notification relay on the `ezpds/notify/0` ALPN. It reuses that same
//! bound `Endpoint` — an iroh endpoint both accepts and dials, so the instance presents one
//! stable node identity to the relay, which is the identity the relay authorizes against
//! (`connection.remote_id()`; no credential ever travels in a message).
//!
//! Framing mirrors the relay's accept side: one JSON request per bidirectional stream,
//! delimited by our FIN, one JSON response back, under a per-stream deadline.
//!
//! Connections are lazy and cached, with a one-shot re-dial retry: the expected failure is a
//! *stale* connection after a relay restart. Enrollment is likewise not a startup step — the
//! client enrolls when the relay answers `notEnrolled`, so a relay restarted, re-provisioned,
//! or reached for the first time mid-run heals by itself. A relay that is down must never
//! become a pds outage, so every failure here is logged and swallowed by the caller
//! (`crate::notifications`), never propagated into a request path.
//!
//! The second half of the file is the fire-and-forget send worker: trigger sites enqueue
//! `NotifyJob`s onto an unbounded in-process mpsc (`NotifySender`) and return immediately.
//! The worker drains jobs sequentially, writes each minted handle back to every registration
//! naming that APNs token — the relay's rotation key, so one token has exactly one live handle
//! however many identities on a device share it — and prunes a registration the relay reports
//! `unregistered` (APNs 410).

use std::sync::Arc;
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr, EndpointId};
use notify_relay::protocol::{Request, Response, ALPN, MAX_MESSAGE_LEN};
use tokio::sync::Mutex;

/// Maximum time for one request/response exchange, matching the relay's own stream deadline.
const STREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a dial may take before we give up and let the next send retry.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// A dialing client for one configured relay.
pub struct NotifyRelayClient {
    endpoint: Endpoint,
    /// Where to dial. Built from the configured node id alone, so reaching the relay depends
    /// on iroh discovery + holepunching rather than on the operator knowing an address —
    /// which is the point of naming a relay by node id in the first place.
    relay_addr: EndpointAddr,
    /// The claim code from `[notifications] enrollment_code`, presented on every `enroll`.
    /// The relay consumes it once; later enrolls of an already-enrolled node succeed anyway,
    /// so re-presenting a spent code is harmless.
    enrollment_code: Option<String>,
    /// The live connection, if any. Behind an async mutex because establishing one is an
    /// `await`: without serializing, a burst of sends after a relay restart would each dial
    /// their own connection.
    connection: Mutex<Option<iroh::endpoint::Connection>>,
}

impl NotifyRelayClient {
    /// Build a client for `relay_node_id`, dialing from the pds's own endpoint.
    ///
    /// Fails only if the configured node id is unparseable — a config error worth surfacing
    /// at startup rather than as a silent non-delivery later.
    pub fn new(
        endpoint: Endpoint,
        relay_node_id: &str,
        enrollment_code: Option<String>,
    ) -> anyhow::Result<Self> {
        let relay_id: EndpointId = relay_node_id
            .parse()
            .map_err(|e| anyhow::anyhow!("notifications.relay is not a valid iroh node id: {e}"))?;
        Ok(Self::with_addr(
            endpoint,
            EndpointAddr::new(relay_id),
            enrollment_code,
        ))
    }

    /// Build a client for a relay at a known address, skipping discovery.
    ///
    /// The loopback end-to-end test dials a relay bound on 127.0.0.1 with iroh's `Minimal`
    /// preset, which has no discovery to resolve a bare node id against.
    pub fn with_addr(
        endpoint: Endpoint,
        relay_addr: EndpointAddr,
        enrollment_code: Option<String>,
    ) -> Self {
        Self {
            endpoint,
            relay_addr,
            enrollment_code,
            connection: Mutex::new(None),
        }
    }

    /// Send one request and await its response, dialing (and enrolling) as needed.
    pub async fn call(&self, request: Request) -> anyhow::Result<Response> {
        let response = self.exchange(request.clone()).await?;

        // Enrollment is not a startup step: the relay may have been restarted, re-provisioned,
        // or reached for the first time mid-run. Rather than tracking enrollment state we let
        // the relay tell us, and enroll exactly when it says we must. This is idempotent and
        // costs one extra round trip only on the first send after a relay forgets us.
        if matches!(response, Response::NotEnrolled) && !matches!(request, Request::Enroll { .. }) {
            let enrolled = self
                .exchange(Request::Enroll {
                    claim_code: self.enrollment_code.clone(),
                })
                .await?;
            if !matches!(enrolled, Response::Ok) {
                anyhow::bail!("relay refused enrollment: {enrolled:?}");
            }
            return self.exchange(request).await;
        }

        Ok(response)
    }

    /// One request/response exchange on a fresh stream over the cached connection.
    async fn exchange(&self, request: Request) -> anyhow::Result<Response> {
        let encoded = serde_json::to_vec(&request)?;

        // One retry, because the failure we expect is a *stale* cached connection: the relay
        // restarted and our handle to it is dead, which only surfaces when we try to use it.
        // Retrying with a fresh dial turns that into a transparent reconnect. A second failure
        // is a real outage, and the caller drops the notification.
        let mut last_error = None;
        for attempt in 0..2 {
            let connection = match self.connect(attempt == 1).await {
                Ok(c) => c,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };
            match Self::round_trip(&connection, &encoded).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::debug!(error = %e, attempt, "notify relay exchange failed");
                    // Drop the connection so the next attempt re-dials rather than reusing
                    // something we just proved broken.
                    *self.connection.lock().await = None;
                    last_error = Some(e);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("notify relay unreachable")))
    }

    /// Return the cached connection, dialing a new one if absent (or if `force_redial`).
    async fn connect(&self, force_redial: bool) -> anyhow::Result<iroh::endpoint::Connection> {
        let mut guard = self.connection.lock().await;
        if force_redial {
            *guard = None;
        }
        if let Some(connection) = guard.as_ref() {
            return Ok(connection.clone());
        }
        let connection = tokio::time::timeout(
            DIAL_TIMEOUT,
            self.endpoint.connect(self.relay_addr.clone(), ALPN),
        )
        .await
        .map_err(|_| anyhow::anyhow!("dialing the notify relay timed out"))?
        .map_err(|e| anyhow::anyhow!("failed to dial the notify relay: {e}"))?;
        *guard = Some(connection.clone());
        Ok(connection)
    }

    async fn round_trip(
        connection: &iroh::endpoint::Connection,
        encoded: &[u8],
    ) -> anyhow::Result<Response> {
        let exchange = async {
            let (mut send, mut recv) = connection.open_bi().await?;
            send.write_all(encoded).await?;
            // FIN is the frame delimiter: the relay reads to end, so without this it waits
            // forever and we time out against a perfectly healthy relay.
            send.finish()?;
            let bytes = recv.read_to_end(MAX_MESSAGE_LEN).await?;
            Ok::<Response, anyhow::Error>(serde_json::from_slice(&bytes)?)
        };
        tokio::time::timeout(STREAM_TIMEOUT, exchange)
            .await
            .map_err(|_| anyhow::anyhow!("notify relay exchange timed out"))?
    }
}

// ── The send worker ───────────────────────────────────────────────────────────
//
// Triggers must never wait on the relay: a claim ceremony that hangs because a push relay is
// slow has traded a missed banner for a broken request. So callers hand work to an unbounded
// in-process queue and return immediately.
//
// The queue is in-memory only, deliberately. A missed push is a missed *banner*, not lost
// data — the app reconciles state from Custos on next contact — so durable queuing would add
// a table, a sweep, and a retry policy to protect something that is already recoverable.

/// One unit of work for the relay worker.
#[derive(Debug)]
pub enum NotifyJob {
    /// Register (or re-register) a device's APNs token, recording the handle we get back.
    RegisterHandle {
        owner: RegistrationOwner,
        apns_token: String,
        apns_topic: String,
    },
    /// Forget a handle at the relay. Best effort: a handle we fail to drop expires with the
    /// device token rather than lingering forever.
    DropHandle { handle: String },
    /// Deliver one sealed payload.
    Push {
        owner: RegistrationOwner,
        handle: String,
        kid: i64,
        enc: String,
        ct: String,
    },
}

/// Which registration table a job's row lives in — the two surfaces are keyed differently, so
/// the worker needs to know which one to write a handle back to (or prune on a dead token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationOwner {
    /// A wallet account's device: `(did, device_uuid)`.
    Account { did: String, device_uuid: String },
    /// An admin-companion device, keyed by `admin_devices.id`.
    AdminDevice { admin_device_id: String },
}

/// The sender half handed to trigger sites, paired with the queue's depth counter. Cloning is
/// cheap; dropping every clone stops the worker.
///
/// The depth exists because the queue is unbounded: a relay outage cannot break a request path,
/// but it *can* grow this queue for as long as it lasts, and before this counter that growth was
/// only inferable from `warn!` volume. It is carried here rather than sampled from the receiver's
/// `len()` because the receiver is moved into the worker task, out of reach of the operator
/// health endpoint that reports the same number as JSON.
#[derive(Clone)]
pub struct NotifySender {
    tx: tokio::sync::mpsc::UnboundedSender<NotifyJob>,
    depth: Arc<QueueDepth>,
}

/// The queue's depth counter and its gauge, held separately from the sender so the worker can
/// decrement without owning a `tx` clone — a sender inside the worker task would keep the
/// channel open forever, and `rx.recv()` would never report the queue closed.
struct QueueDepth {
    /// Jobs enqueued but not yet finished. Signed so a pairing bug reads as a negative rather
    /// than wrapping into an astronomical unsigned value on a dashboard.
    count: std::sync::atomic::AtomicI64,
    metrics: Arc<crate::metrics::Metrics>,
}

impl QueueDepth {
    /// Apply a delta and publish the result to the gauge.
    fn bump(&self, delta: i64) {
        let depth = self
            .count
            .fetch_add(delta, std::sync::atomic::Ordering::Relaxed)
            + delta;
        self.metrics
            .notify_queue_depth
            .record(depth.max(0) as u64, &[]);
    }
}

impl NotifySender {
    /// Enqueue one job.
    ///
    /// Infallible from a caller's perspective: the only failure is a stopped worker, and every
    /// trigger site treats delivery as best effort — they all discarded the old `Result`
    /// identically. Handling it here means a dropped job is logged once instead of being
    /// silently swallowed at five call sites.
    pub fn send(&self, job: NotifyJob) {
        // Increment first: a job counted only after a successful send could be drained and
        // decremented before it was ever added, driving the depth negative under load.
        self.depth.bump(1);
        if self.tx.send(job).is_err() {
            // A rejected job never entered the queue, so it must not read as outstanding —
            // otherwise a stopped worker would look like a permanently growing backlog.
            self.depth.bump(-1);
            tracing::warn!("dropped a notification job: the relay worker is not running");
        }
    }

    /// Jobs outstanding right now. Read by `GET /v1/admin/health`, which works with
    /// `[telemetry] metrics_enabled` off — the same reason `sweep_status.rs` mirrors its gauges.
    pub fn depth(&self) -> i64 {
        self.depth.count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Spawn the worker that drains the queue against `client`.
///
/// Jobs run sequentially. That is intentional: the relay rate-limits per node, and the
/// volume here is device-count-scaled, not user-traffic-scaled. Sequential also means one
/// slow push delays the next rather than opening a connection storm at a struggling relay.
pub fn spawn_worker(
    client: Arc<NotifyRelayClient>,
    db: sqlx::SqlitePool,
    metrics: Arc<crate::metrics::Metrics>,
) -> (NotifySender, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<NotifyJob>();
    let depth = Arc::new(QueueDepth {
        count: std::sync::atomic::AtomicI64::new(0),
        metrics,
    });
    let worker_depth = depth.clone();
    let handle = tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            if let Err(e) = run_job(&client, &db, job).await {
                // Every relay failure ends here. Notification delivery is best-effort by
                // design, so this is a log line, not an error path anyone recovers from.
                tracing::warn!(error = %e, "notify relay job failed");
            }
            // Decremented *after* the job runs, not at `recv`, so the depth counts outstanding
            // work rather than only what is waiting. During the outage this metric exists for,
            // each job burns the full 30s stream timeout — a single stuck job is real backlog,
            // and a depth that read 0 through it would be reporting the wrong thing.
            worker_depth.bump(-1);
        }
        tracing::info!("notify relay worker stopped (queue closed)");
    });
    (NotifySender { tx, depth }, handle)
}

async fn run_job(
    client: &NotifyRelayClient,
    db: &sqlx::SqlitePool,
    job: NotifyJob,
) -> anyhow::Result<()> {
    use crate::db::notifications as store;
    use notify_relay::protocol::PushOutcome;

    match job {
        NotifyJob::RegisterHandle {
            owner,
            apns_token,
            apns_topic,
        } => {
            let response = client
                .call(Request::RegisterHandle {
                    apns_token: apns_token.clone(),
                    apns_topic,
                })
                .await?;
            let Response::Handle { handle } = response else {
                anyhow::bail!("relay refused handle registration: {response:?}");
            };
            // The relay rotates per `(node, token)`, so this handle supersedes every earlier
            // one for this token — including handles minted for a *different* identity on the
            // same device. `owner` therefore picks the table, not the row: every registration
            // naming this token is now reachable only through the handle we just got back.
            let stamped = match &owner {
                RegistrationOwner::Account { .. } => {
                    store::set_registration_handles_for_token(db, &apns_token, &handle).await?
                }
                RegistrationOwner::AdminDevice { .. } => {
                    store::set_admin_registration_handles_for_token(db, &apns_token, &handle)
                        .await?
                }
            };
            if stamped == 0 {
                reclaim_unclaimed_handle(client, handle).await;
            }
        }
        NotifyJob::DropHandle { handle } => {
            client.call(Request::DropHandle { handle }).await?;
        }
        NotifyJob::Push {
            owner,
            handle,
            kid,
            enc,
            ct,
        } => {
            let response = client
                .call(Request::Push {
                    handle,
                    // `kid` is a positive INTEGER PRIMARY KEY; the wire carries it as u32,
                    // which is the same value for every kid an instance will ever mint.
                    kid: kid as u32,
                    enc,
                    ct,
                    priority: None,
                    ttl_secs: None,
                    ping: None,
                })
                .await?;
            match response {
                Response::Pushed {
                    outcome: PushOutcome::Unregistered,
                } => {
                    // APNs 410, relayed back to us: this device token is permanently dead
                    // (app deleted, or reinstalled with a new token). Prune at the moment of
                    // proof — the alternative is fanning out to a corpse forever.
                    prune(db, &owner).await?;
                    tracing::info!("pruned a notification registration the relay reported dead");
                }
                Response::Pushed {
                    outcome: PushOutcome::Delivered,
                } => {}
                other => {
                    // Throttled, tooLarge, apnsError, unknownHandle — all real outcomes, none
                    // of them recoverable here. Log the shape and drop the banner.
                    tracing::warn!(?other, "notify relay declined a push");
                }
            }
        }
    }
    Ok(())
}

/// Give back a freshly minted handle that no registration claims.
///
/// Reachable when the row that asked for it was deleted, or had its APNs token replaced,
/// between the request that enqueued the job and the relay's answer. Left alone, the relay
/// would hold a live route to a device this instance can no longer address, expiring only when
/// the device token itself dies — the stale capability that rotate-on-register exists to
/// prevent, and the same thing the unregister route drops when it removes a row.
///
/// Best effort by construction, and deliberately not folded into the job's error channel: the
/// mint itself succeeded, and a failed reclaim costs a little of the relay's storage, never a
/// delivery.
async fn reclaim_unclaimed_handle(client: &NotifyRelayClient, handle: String) {
    tracing::info!("reclaiming a relay push handle that no registration claims");
    if let Err(e) = client.call(Request::DropHandle { handle }).await {
        tracing::warn!(error = %e, "failed to reclaim an unclaimed push handle");
    }
}

async fn prune(db: &sqlx::SqlitePool, owner: &RegistrationOwner) -> Result<(), sqlx::Error> {
    use crate::db::notifications as store;
    match owner {
        RegistrationOwner::Account { did, device_uuid } => {
            store::delete_registration(db, did, device_uuid).await?;
        }
        RegistrationOwner::AdminDevice { admin_device_id } => {
            store::delete_admin_registration(db, admin_device_id).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sender whose worker never runs, so the queue depth is observable without a relay.
    fn orphan_sender() -> NotifySender {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<NotifyJob>();
        // Held, not dropped: dropping the receiver would make every `send` fail.
        std::mem::forget(rx);
        NotifySender {
            tx,
            depth: Arc::new(QueueDepth {
                count: std::sync::atomic::AtomicI64::new(0),
                metrics: Arc::new(crate::metrics::Metrics::disabled()),
            }),
        }
    }

    #[test]
    fn queue_depth_counts_enqueued_jobs() {
        let sender = orphan_sender();
        assert_eq!(sender.depth(), 0, "a fresh queue is empty");

        for _ in 0..3 {
            sender.send(NotifyJob::DropHandle {
                handle: "h".to_owned(),
            });
        }
        assert_eq!(sender.depth(), 3);

        // A clone shares the counter — trigger sites hold clones, and each must observe the
        // same queue rather than its own.
        assert_eq!(sender.clone().depth(), 3);
    }

    #[test]
    fn a_send_to_a_stopped_worker_does_not_inflate_the_depth() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<NotifyJob>();
        drop(rx);
        let sender = NotifySender {
            tx,
            depth: Arc::new(QueueDepth {
                count: std::sync::atomic::AtomicI64::new(0),
                metrics: Arc::new(crate::metrics::Metrics::disabled()),
            }),
        };

        sender.send(NotifyJob::DropHandle {
            handle: "h".to_owned(),
        });
        // A rejected job never entered the queue, so it must not be counted as outstanding —
        // otherwise a stopped worker would read as a permanently growing backlog.
        assert_eq!(sender.depth(), 0);
    }

    #[tokio::test]
    async fn the_worker_decrements_the_depth_as_it_drains() {
        // No relay is reachable, so every job fails — which is exactly the outage case the
        // metric exists for, and the depth must still return to zero.
        //
        // The target is a bare node id with no address, under the `Minimal` preset's absent
        // discovery: the dial cannot resolve and fails immediately, rather than burning the
        // 15s DIAL_TIMEOUT twice.
        let unreachable = crate::iroh_tunnel::loopback_endpoint(false).await;
        let unreachable_id = unreachable.id();
        unreachable.close().await;

        let state = crate::state::test_state().await;
        let endpoint = crate::iroh_tunnel::loopback_endpoint(false).await;
        let client =
            NotifyRelayClient::with_addr(endpoint.clone(), EndpointAddr::new(unreachable_id), None);
        let (sender, _worker) = spawn_worker(
            Arc::new(client),
            state.db.clone(),
            Arc::new(crate::metrics::Metrics::disabled()),
        );

        sender.send(NotifyJob::DropHandle {
            handle: "h".to_owned(),
        });
        assert!(sender.depth() >= 1, "the job is outstanding once enqueued");

        // The dial fails fast against an unreachable node; poll rather than sleep a fixed span.
        for _ in 0..600 {
            if sender.depth() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(sender.depth(), 0, "a failed job still leaves the queue");
        endpoint.close().await;
    }

    #[tokio::test]
    async fn an_unparseable_relay_node_id_is_a_config_error() {
        let endpoint = crate::iroh_tunnel::loopback_endpoint(false).await;
        let err = match NotifyRelayClient::new(endpoint.clone(), "not-a-node-id", None) {
            Ok(_) => panic!("an unparseable node id must not build a client"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("notifications.relay"),
            "the error must name the offending config key: {err}"
        );
        endpoint.close().await;
    }
}
