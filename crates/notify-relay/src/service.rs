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

use crate::config::Config;
use crate::db;
use crate::protocol::{PushOutcome, Request, Response};
use crate::rate_limit::{Bucket, RateLimiter};

/// Everything an RPC needs: the store, the operator's policy, and the limiter.
pub struct RelayService {
    pub db: SqlitePool,
    pub config: Arc<Config>,
    pub limits: RateLimiter,
}

/// Bytes of randomness behind a push handle. 128 bits: unguessable, and short enough that
/// a padded APNs payload doesn't pay for it.
const HANDLE_BYTES: usize = 16;

impl RelayService {
    pub fn new(db: SqlitePool, config: Arc<Config>) -> Self {
        let limits = RateLimiter::new(config.rate_limits.clone());
        Self { db, config, limits }
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
            Request::Push { handle, .. } => self.push(node_id, &handle).await,
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

    async fn push(&self, node_id: &str, handle: &str) -> Response {
        match db::enrollments::is_enrolled(&self.db, node_id).await {
            Ok(true) => {}
            Ok(false) => {
                return Response::Pushed {
                    outcome: PushOutcome::NotEnrolled,
                }
            }
            Err(e) => return internal(e, "failed to check enrollment"),
        }
        if !self.limits.check(node_id, Bucket::Push) {
            return Response::Pushed {
                outcome: PushOutcome::Throttled,
            };
        }

        match db::handles::resolve_handle(&self.db, node_id, handle).await {
            Ok(Some(_)) => Response::Pushed {
                // The APNs pipeline lands in the next phase; until then a well-formed push
                // to a real handle is honestly reported as an upstream failure rather than
                // as a delivery that never happened.
                outcome: PushOutcome::ApnsError,
            },
            Ok(None) => Response::Pushed {
                outcome: PushOutcome::UnknownHandle,
            },
            Err(e) => internal(e, "failed to resolve handle"),
        }
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

    #[tokio::test]
    async fn push_reports_an_upstream_failure_until_the_apns_pipeline_lands() {
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
