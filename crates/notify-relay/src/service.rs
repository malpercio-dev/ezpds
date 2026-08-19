// pattern: Imperative Shell
//
// The RPC layer: one function from (caller node id, request) to response. It owns the
// cross-table sequences the `db/` submodules deliberately don't — redeeming an enrollment
// code and recording the enrollment in one transaction — and the authorization order that
// every RPC shares: enrollment first, then the rate-limit charge, then the work.
//
// Charging *after* the enrollment check is deliberate: an unenrolled node's requests are
// rejected on a cheap read, so it can never spend an enrolled node's budget, and a node
// that has not yet enrolled cannot exhaust a bucket keyed to an identity it hasn't earned.

use std::sync::Arc;

use sqlx::SqlitePool;

use crate::apns::{ApnsClient, PushRequest};
use crate::config::Config;
use crate::db;
use crate::protocol::{PushOutcome, Request, Response};
use crate::rate_limit::{Bucket, RateLimiter};

/// Everything an RPC needs: the store, the operator's policy, the limiter, and — once the
/// operator has wired an APNs key up — the leg to Apple.
pub struct RelayService {
    pub db: SqlitePool,
    pub config: Arc<Config>,
    pub limits: RateLimiter,
    /// `None` on a relay with no APNs credentials configured. Every other RPC still works,
    /// so an operator can enroll instances and collect handles before the key exists;
    /// pushes answer `apnsError` until it does.
    apns: Option<ApnsClient>,
}

/// Bytes of randomness behind a push handle. 128 bits: unguessable, and short enough that
/// a padded APNs payload doesn't pay for it.
const HANDLE_BYTES: usize = 16;

impl RelayService {
    pub fn new(db: SqlitePool, config: Arc<Config>) -> Self {
        let limits = RateLimiter::new(config.rate_limits.clone());
        Self {
            db,
            config,
            limits,
            apns: None,
        }
    }

    /// Attach the APNs leg. Separate from `new` because loading the operator's `.p8` is
    /// fallible I/O that `main.rs` must be able to refuse to start over — a relay that
    /// silently came up unable to push would look healthy and deliver nothing.
    pub fn with_apns(mut self, apns: Option<ApnsClient>) -> Self {
        self.apns = apns;
        self
    }

    /// Dispatch one request from `node_id` (the QUIC peer's verified identity).
    pub async fn handle(&self, node_id: &str, request: Request) -> Response {
        match request {
            Request::Enroll { claim_code } => self.enroll(node_id, claim_code.as_deref()).await,
            Request::RegisterHandle {
                apns_token,
                apns_topic,
            } => {
                self.register_handle(node_id, &apns_token, &apns_topic)
                    .await
            }
            Request::DropHandle { handle } => self.drop_handle(node_id, &handle).await,
            Request::Push {
                handle,
                kid,
                enc,
                ct,
                ttl_secs,
                ping,
                ..
            } => {
                self.push(
                    node_id,
                    &handle,
                    kid,
                    &enc,
                    &ct,
                    ttl_secs,
                    ping.unwrap_or(false),
                )
                .await
            }
        }
    }

    async fn enroll(&self, node_id: &str, claim_code: Option<&str>) -> Response {
        if !self.limits.check(node_id, Bucket::Registration) {
            return Response::Throttled;
        }

        if self.config.open_enrollment {
            return match db::enrollments::insert_enrollment(&self.db, node_id, None).await {
                // Idempotent whether or not a row was created: an open relay charges
                // nothing, so a repeat costs the caller nothing to report as success.
                Ok(_) => Response::Ok,
                Err(e) => internal(e, "failed to record enrollment"),
            };
        }

        // Everything below runs inside one transaction, enrollment probe included. Reading
        // "already enrolled?" outside it would let two concurrent enrolls both see `false`,
        // and the one that lost the insert would have spent its grant code for nothing.
        let mut tx = match self.db.begin().await {
            Ok(tx) => tx,
            Err(e) => return internal(e, "failed to open enrollment transaction"),
        };
        match db::enrollments::is_enrolled(&mut *tx, node_id).await {
            // Idempotent: a node re-enrolling after a restart is not charged a code again.
            // Dropping `tx` unread rolls back, so nothing was consumed.
            Ok(true) => return Response::Ok,
            Ok(false) => {}
            Err(e) => return internal(e, "failed to check enrollment"),
        }

        let Some(code) = claim_code else {
            // Same shape as a bad code: a caller cannot use the response to learn whether
            // this relay runs open enrollment beyond what its operator published.
            return Response::Denied;
        };

        match db::enrollment_codes::consume_code(&mut *tx, code, node_id).await {
            Ok(true) => {}
            Ok(false) => return Response::Denied,
            Err(e) => return internal(e, "failed to redeem enrollment code"),
        }
        match db::enrollments::insert_enrollment(&mut *tx, node_id, Some(code)).await {
            Ok(true) => {}
            // The row already existed despite the probe above — only reachable if another
            // writer slipped in. Abandon the transaction (rollback), which un-redeems the
            // code, and report the enrollment that already stands.
            Ok(false) => return Response::Ok,
            Err(e) => return internal(e, "failed to record enrollment"),
        }
        match tx.commit().await {
            Ok(()) => {
                tracing::info!(%node_id, "node enrolled with a grant code");
                Response::Ok
            }
            Err(e) => internal(e, "failed to commit enrollment"),
        }
    }

    async fn register_handle(&self, node_id: &str, apns_token: &str, apns_topic: &str) -> Response {
        match self.require_enrolled(node_id, Bucket::Registration).await {
            Ok(()) => {}
            Err(response) => return response,
        }

        if apns_token.is_empty() || apns_topic.is_empty() {
            return Response::BadRequest {
                reason: "apnsToken and apnsTopic are required".into(),
            };
        }
        // An empty served-topic list means "any topic" — the self-run posture, where the
        // operator owns every app that could register. A non-empty list is an allowlist.
        if !self.config.apns.topics.is_empty()
            && !self
                .config
                .apns
                .topics
                .iter()
                .any(|topic| topic == apns_topic)
        {
            return Response::BadRequest {
                reason: "this relay does not serve that apnsTopic".into(),
            };
        }

        let handle = generate_handle();
        match db::handles::register_handle(&self.db, node_id, apns_token, apns_topic, &handle).await
        {
            Ok(handle) => Response::Handle { handle },
            Err(e) => internal(e, "failed to register handle"),
        }
    }

    async fn drop_handle(&self, node_id: &str, handle: &str) -> Response {
        match self.require_enrolled(node_id, Bucket::Registration).await {
            Ok(()) => {}
            Err(response) => return response,
        }
        // Idempotent, and silent about ownership: dropping a handle that belongs to
        // another node is the same 'ok' as dropping one that never existed.
        match db::handles::drop_handle(&self.db, node_id, handle).await {
            Ok(_) => Response::Ok,
            Err(e) => internal(e, "failed to drop handle"),
        }
    }

    /// Deliver one sealed payload, reporting what became of it.
    ///
    /// Every failure travels as a `PushOutcome` rather than an error shape: each one is a
    /// normal result the instance acts on — `unregistered` prunes a registration,
    /// `throttled` backs off, `tooLarge` is a sender bug to fix.
    ///
    /// `ping` swaps the sealed alert envelope for a content-free `content-available`
    /// background push — the metadata-minimizing mode where the relay forwards only the fact
    /// that something happened. The request's `priority` field stays unconsulted: the push
    /// type dictates the priority (10 for an alert, and Apple *requires* 5 for a background
    /// push), and honouring a caller's `priority: 5` on an alert envelope would ask Apple to
    /// delay a banner the device is meant to show immediately.
    #[allow(clippy::too_many_arguments)]
    async fn push(
        &self,
        node_id: &str,
        handle: &str,
        kid: u32,
        enc: &str,
        ct: &str,
        ttl_secs: Option<u32>,
        ping: bool,
    ) -> Response {
        match db::enrollments::is_enrolled(&self.db, node_id).await {
            Ok(true) => {}
            Ok(false) => return pushed(PushOutcome::NotEnrolled),
            Err(e) => return internal(e, "failed to check enrollment"),
        }
        if !self.limits.check(node_id, Bucket::Push) {
            return pushed(PushOutcome::Throttled);
        }

        let row = match db::handles::resolve_handle(&self.db, node_id, handle).await {
            Ok(Some(row)) => row,
            Ok(None) => return pushed(PushOutcome::UnknownHandle),
            Err(e) => return internal(e, "failed to resolve handle"),
        };
        // Charged only once the handle has resolved, so probing for another node's handles
        // cannot spend a budget, and only against a handle the caller demonstrably owns.
        if !self.limits.check(handle, Bucket::HandlePush) {
            return pushed(PushOutcome::Throttled);
        }

        let Some(apns) = self.apns.as_ref() else {
            // No credentials configured. Reported as an upstream failure rather than a
            // delivery, because from the instance's side that is exactly what it is.
            tracing::warn!(%node_id, "push refused: this relay has no APNs credentials");
            return pushed(PushOutcome::ApnsError);
        };

        let outcome = apns
            .send(&PushRequest {
                device_token: &row.apns_token,
                topic: &row.apns_topic,
                kid,
                enc,
                ct,
                ttl_secs,
                ping,
            })
            .await;

        // A delivery timestamp is the only thing a push writes, and only on success:
        // `last_push_at` answers "did this registration recently work?", and a refused
        // push is not evidence that it did.
        //
        // On `unregistered` the row is deliberately left standing. The instance deletes
        // its own registration on receipt and stops pushing; keeping the handle here means
        // a retry after a lost response still answers `unregistered` rather than the
        // ambiguous `unknownHandle`. The row goes away when the device re-registers (which
        // rotates the handle) or when the instance drops it.
        if outcome == PushOutcome::Delivered {
            if let Err(e) = db::handles::touch_last_push(&self.db, node_id, handle).await {
                // Cosmetic bookkeeping. The notification is already with Apple, so failing
                // the RPC over this would report a delivery that happened as one that
                // did not.
                tracing::warn!(error = %e, "failed to record a delivery timestamp");
            }
        }
        pushed(outcome)
    }

    /// The shared gate for every RPC but `enroll`: enrolled first, then charged.
    async fn require_enrolled(&self, node_id: &str, bucket: Bucket) -> Result<(), Response> {
        match db::enrollments::is_enrolled(&self.db, node_id).await {
            Ok(true) => {}
            Ok(false) => return Err(Response::NotEnrolled),
            Err(e) => return Err(internal(e, "failed to check enrollment")),
        }
        if !self.limits.check(node_id, bucket) {
            return Err(Response::Throttled);
        }
        Ok(())
    }
}

/// A 128-bit handle rendered base64url without padding.
fn generate_handle() -> String {
    let mut bytes = [0u8; HANDLE_BYTES];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
    data_encoding::BASE64URL_NOPAD.encode(&bytes)
}

/// Wrap a push outcome in its response. Every push answers `pushed` — the outcome carries
/// the whole story, so a push never returns one of the shared refusal shapes.
fn pushed(outcome: PushOutcome) -> Response {
    Response::Pushed { outcome }
}

/// Log a storage failure and answer with a shape that reveals nothing about it.
fn internal(error: sqlx::Error, message: &'static str) -> Response {
    tracing::error!(error = %error, "{message}");
    Response::BadRequest {
        reason: "the relay could not process that request".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_from_env_only, RateLimitConfig};
    use std::collections::HashMap;

    fn config(open_enrollment: bool, topics: &[&str]) -> Arc<Config> {
        let mut env: HashMap<String, String> = HashMap::new();
        if open_enrollment {
            env.insert("EZPDS_NOTIFY_OPEN_ENROLLMENT".into(), "true".into());
        }
        if !topics.is_empty() {
            env.insert("EZPDS_NOTIFY_APNS_TOPICS".into(), topics.join(","));
        }
        Arc::new(load_from_env_only(&env).expect("valid test config"))
    }

    async fn service(open_enrollment: bool) -> RelayService {
        RelayService::new(db::test_pool().await, config(open_enrollment, &[]))
    }

    async fn mint(service: &RelayService, code: &str, ttl_secs: i64) {
        db::enrollment_codes::insert_code(&service.db, code, ttl_secs)
            .await
            .expect("mint code");
    }

    #[tokio::test]
    async fn a_valid_code_enrolls_and_a_reuse_is_denied() {
        let service = service(false).await;
        mint(&service, "GRANT-1", 3600).await;

        assert_eq!(
            service
                .handle(
                    "node-a",
                    Request::Enroll {
                        claim_code: Some("GRANT-1".into())
                    }
                )
                .await,
            Response::Ok
        );
        assert_eq!(
            service
                .handle(
                    "node-b",
                    Request::Enroll {
                        claim_code: Some("GRANT-1".into())
                    }
                )
                .await,
            Response::Denied,
            "a spent code must not enroll a second node"
        );
    }

    /// Re-enrolling an already-enrolled node succeeds without touching the offered code:
    /// the enrollment probe runs inside the redemption transaction, so a restart (or a
    /// racing second enroll) can never burn a grant that bought nothing.
    #[tokio::test]
    async fn re_enrolling_never_consumes_another_code() {
        let service = service(false).await;
        mint(&service, "GRANT-1", 3600).await;
        mint(&service, "GRANT-2", 3600).await;

        for code in ["GRANT-1", "GRANT-2"] {
            assert_eq!(
                service
                    .handle(
                        "node-a",
                        Request::Enroll {
                            claim_code: Some(code.to_owned())
                        }
                    )
                    .await,
                Response::Ok
            );
        }

        let spent: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM enrollment_codes WHERE consumed_at IS NOT NULL",
        )
        .fetch_one(&service.db)
        .await
        .expect("count");
        assert_eq!(spent, 1, "the second enroll must leave GRANT-2 redeemable");
    }

    #[tokio::test]
    async fn expired_absent_and_unknown_codes_are_all_denied() {
        let service = service(false).await;
        mint(&service, "STALE", -60).await;

        for code in [Some("STALE".to_owned()), Some("NEVER".to_owned()), None] {
            assert_eq!(
                service
                    .handle("node-a", Request::Enroll { claim_code: code })
                    .await,
                Response::Denied
            );
        }
    }

    #[tokio::test]
    async fn open_enrollment_admits_any_node_and_enroll_is_idempotent() {
        let service = service(true).await;
        assert_eq!(
            service
                .handle("node-a", Request::Enroll { claim_code: None })
                .await,
            Response::Ok
        );
        assert_eq!(
            service
                .handle("node-a", Request::Enroll { claim_code: None })
                .await,
            Response::Ok,
            "re-enrolling must be a no-op, not a refusal"
        );
    }

    #[tokio::test]
    async fn every_rpc_but_enroll_requires_enrollment() {
        let service = service(false).await;
        for request in [
            Request::RegisterHandle {
                apns_token: "tok".into(),
                apns_topic: "org.obsign.app".into(),
            },
            Request::DropHandle {
                handle: "whatever".into(),
            },
        ] {
            assert_eq!(
                service.handle("node-a", request).await,
                Response::NotEnrolled
            );
        }
        assert_eq!(
            service
                .handle(
                    "node-a",
                    Request::Push {
                        handle: "whatever".into(),
                        kid: 1,
                        enc: "e".into(),
                        ct: "c".into(),
                        priority: None,
                        ttl_secs: None,
                        ping: None,
                    }
                )
                .await,
            Response::Pushed {
                outcome: PushOutcome::NotEnrolled
            }
        );
    }

    #[tokio::test]
    async fn registering_mints_a_handle_and_re_registering_rotates_it() {
        let service = service(true).await;
        service
            .handle("node-a", Request::Enroll { claim_code: None })
            .await;

        let request = Request::RegisterHandle {
            apns_token: "tok".into(),
            apns_topic: "org.obsign.app".into(),
        };
        let Response::Handle { handle: first } = service.handle("node-a", request.clone()).await
        else {
            panic!("expected a handle");
        };
        let Response::Handle { handle: second } = service.handle("node-a", request).await else {
            panic!("expected a handle");
        };

        assert_ne!(first, second, "re-registration must rotate the handle");
        assert_eq!(
            data_encoding::BASE64URL_NOPAD
                .decode(first.as_bytes())
                .expect("base64url")
                .len(),
            HANDLE_BYTES
        );
    }

    #[tokio::test]
    async fn a_topic_outside_the_served_set_is_refused() {
        let service = RelayService::new(
            db::test_pool().await,
            config(true, &["org.obsign.identitywallet"]),
        );
        service
            .handle("node-a", Request::Enroll { claim_code: None })
            .await;

        let response = service
            .handle(
                "node-a",
                Request::RegisterHandle {
                    apns_token: "tok".into(),
                    apns_topic: "com.example.other".into(),
                },
            )
            .await;
        assert!(
            matches!(response, Response::BadRequest { .. }),
            "{response:?}"
        );
    }

    #[tokio::test]
    async fn one_node_can_neither_push_to_nor_drop_another_nodes_handle() {
        let service = service(true).await;
        for node in ["node-a", "node-b"] {
            service
                .handle(node, Request::Enroll { claim_code: None })
                .await;
        }
        let Response::Handle { handle } = service
            .handle(
                "node-a",
                Request::RegisterHandle {
                    apns_token: "tok".into(),
                    apns_topic: "org.obsign.app".into(),
                },
            )
            .await
        else {
            panic!("expected a handle");
        };

        assert_eq!(
            service
                .handle(
                    "node-b",
                    Request::Push {
                        handle: handle.clone(),
                        kid: 1,
                        enc: "e".into(),
                        ct: "c".into(),
                        priority: None,
                        ttl_secs: None,
                        ping: None,
                    }
                )
                .await,
            Response::Pushed {
                outcome: PushOutcome::UnknownHandle
            },
            "a foreign handle must be indistinguishable from a nonexistent one"
        );

        assert_eq!(
            service
                .handle(
                    "node-b",
                    Request::DropHandle {
                        handle: handle.clone()
                    }
                )
                .await,
            Response::Ok,
            "a foreign drop is silently a no-op, not an ownership oracle"
        );
        assert!(
            db::handles::resolve_handle(&service.db, "node-a", &handle)
                .await
                .expect("resolve")
                .is_some(),
            "the owner's handle must survive node B's drop"
        );
    }

    /// A relay brought up before its APNs key exists still enrolls instances and mints
    /// handles; only the delivery leg is missing, and it says so rather than claiming a
    /// delivery that never happened.
    #[tokio::test]
    async fn a_relay_with_no_apns_credentials_reports_an_upstream_failure() {
        let service = service(true).await;
        service
            .handle("node-a", Request::Enroll { claim_code: None })
            .await;
        let Response::Handle { handle } = service
            .handle(
                "node-a",
                Request::RegisterHandle {
                    apns_token: "tok".into(),
                    apns_topic: "org.obsign.app".into(),
                },
            )
            .await
        else {
            panic!("expected a handle");
        };

        assert_eq!(
            service
                .handle(
                    "node-a",
                    Request::Push {
                        handle,
                        kid: 1,
                        enc: "e".into(),
                        ct: "c".into(),
                        priority: None,
                        ttl_secs: None,
                        ping: None,
                    }
                )
                .await,
            Response::Pushed {
                outcome: PushOutcome::ApnsError
            }
        );
    }

    #[tokio::test]
    async fn an_exhausted_registration_budget_throttles() {
        let mut config = load_from_env_only(&HashMap::new()).expect("defaults");
        config.open_enrollment = true;
        config.rate_limits = RateLimitConfig {
            registrations_per_hour: 1,
            registrations_burst: 1,
            ..RateLimitConfig::default()
        };
        let service = RelayService::new(db::test_pool().await, Arc::new(config));

        assert_eq!(
            service
                .handle("node-a", Request::Enroll { claim_code: None })
                .await,
            Response::Ok
        );
        assert_eq!(
            service
                .handle(
                    "node-a",
                    Request::RegisterHandle {
                        apns_token: "tok".into(),
                        apns_topic: "org.obsign.app".into(),
                    }
                )
                .await,
            Response::Throttled,
            "the enroll spent the single registration token"
        );
    }

    /// The per-handle budget is what protects a *device* from an instance bug that loops
    /// on one registration, so it has to bite well before the node budget does — and it
    /// must not take the node's other handles down with it.
    #[tokio::test]
    async fn one_handles_exhausted_budget_leaves_the_nodes_other_handles_pushable() {
        let mut config = load_from_env_only(&HashMap::new()).expect("defaults");
        config.open_enrollment = true;
        config.rate_limits.handle_pushes_per_hour = 1;
        config.rate_limits.handle_pushes_burst = 1;
        let service = RelayService::new(db::test_pool().await, Arc::new(config));
        service
            .handle("node-a", Request::Enroll { claim_code: None })
            .await;

        let mut handles = Vec::new();
        for token in ["tok-phone", "tok-tablet"] {
            let Response::Handle { handle } = service
                .handle(
                    "node-a",
                    Request::RegisterHandle {
                        apns_token: token.into(),
                        apns_topic: "org.obsign.app".into(),
                    },
                )
                .await
            else {
                panic!("expected a handle");
            };
            handles.push(handle);
        }

        let push = |handle: &str| Request::Push {
            handle: handle.to_owned(),
            kid: 1,
            enc: "e".into(),
            ct: "c".into(),
            priority: None,
            ttl_secs: None,
            ping: None,
        };

        // No APNs credentials here, so a push that gets *past* the limiter answers
        // `apnsError` — which is precisely how a throttle is told apart from a delivery
        // attempt in this test.
        assert_eq!(
            service.handle("node-a", push(&handles[0])).await,
            Response::Pushed {
                outcome: PushOutcome::ApnsError
            }
        );
        assert_eq!(
            service.handle("node-a", push(&handles[0])).await,
            Response::Pushed {
                outcome: PushOutcome::Throttled
            },
            "the first handle's single token is spent"
        );
        assert_eq!(
            service.handle("node-a", push(&handles[1])).await,
            Response::Pushed {
                outcome: PushOutcome::ApnsError
            },
            "a second device on the same node must have its own budget"
        );
    }

    /// An unknown handle is refused before the per-handle bucket is touched, so probing
    /// for another node's handles cannot create — let alone spend — a budget for one.
    #[tokio::test]
    async fn probing_an_unknown_handle_does_not_spend_its_budget() {
        let mut config = load_from_env_only(&HashMap::new()).expect("defaults");
        config.open_enrollment = true;
        config.rate_limits.handle_pushes_per_hour = 1;
        config.rate_limits.handle_pushes_burst = 1;
        let service = RelayService::new(db::test_pool().await, Arc::new(config));
        for node in ["node-a", "node-b"] {
            service
                .handle(node, Request::Enroll { claim_code: None })
                .await;
        }
        let Response::Handle { handle } = service
            .handle(
                "node-a",
                Request::RegisterHandle {
                    apns_token: "tok".into(),
                    apns_topic: "org.obsign.app".into(),
                },
            )
            .await
        else {
            panic!("expected a handle");
        };

        let push = Request::Push {
            handle: handle.clone(),
            kid: 1,
            enc: "e".into(),
            ct: "c".into(),
            priority: None,
            ttl_secs: None,
            ping: None,
        };
        assert_eq!(
            service.handle("node-b", push.clone()).await,
            Response::Pushed {
                outcome: PushOutcome::UnknownHandle
            }
        );
        assert_eq!(
            service.handle("node-a", push).await,
            Response::Pushed {
                outcome: PushOutcome::ApnsError
            },
            "node B's probe must not have spent the owner's single per-handle token"
        );
    }

    #[tokio::test]
    async fn an_exhausted_push_budget_throttles_without_touching_registrations() {
        let mut config = load_from_env_only(&HashMap::new()).expect("defaults");
        config.open_enrollment = true;
        config.rate_limits = RateLimitConfig {
            pushes_per_hour: 1,
            pushes_burst: 1,
            ..RateLimitConfig::default()
        };
        let service = RelayService::new(db::test_pool().await, Arc::new(config));
        service
            .handle("node-a", Request::Enroll { claim_code: None })
            .await;
        let Response::Handle { handle } = service
            .handle(
                "node-a",
                Request::RegisterHandle {
                    apns_token: "tok".into(),
                    apns_topic: "org.obsign.app".into(),
                },
            )
            .await
        else {
            panic!("expected a handle");
        };

        let push = Request::Push {
            handle,
            kid: 1,
            enc: "e".into(),
            ct: "c".into(),
            priority: None,
            ttl_secs: None,
            ping: None,
        };
        assert_eq!(
            service.handle("node-a", push.clone()).await,
            Response::Pushed {
                outcome: PushOutcome::ApnsError
            }
        );
        assert_eq!(
            service.handle("node-a", push).await,
            Response::Pushed {
                outcome: PushOutcome::Throttled
            }
        );
        assert_eq!(
            service
                .handle(
                    "node-a",
                    Request::DropHandle {
                        handle: "anything".into()
                    }
                )
                .await,
            Response::Ok,
            "an exhausted push budget must not close the registration surface"
        );
    }
}
