// pattern: Imperative Shell
//
// The iroh accept loop, following the pds crate's `iroh_tunnel.rs` shape: bind an endpoint
// on one ALPN, spawn a detached loop, and handle each connection's bidirectional streams
// under a per-stream deadline. Per-connection errors are logged, never propagated — one
// misbehaving instance never stops the relay.
//
// Framing is one JSON request per stream, delimited by the peer's FIN, answered with one
// JSON response and our own FIN. A 64 KiB read cap bounds allocation and the 30 s deadline
// bounds a peer that stalls either half of the exchange.

use std::sync::Arc;

use iroh::endpoint::{presets, Incoming};
use iroh::{Endpoint, SecretKey};

use crate::protocol::{Request, Response, ALPN, MAX_MESSAGE_LEN};
use crate::service::RelayService;

/// Maximum time for one request/response exchange on a stream.
const STREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Bind the relay's endpoint with its persistent secret key.
///
/// `N0` preset (n0 discovery + relays) so an instance can dial by node id alone. When
/// `ipv6` is false the pre-configured transports are cleared and only IPv4 is bound — the
/// v4-only-host workaround the pds carries for the same reason.
pub async fn bind(secret: [u8; 32], ipv6: bool) -> anyhow::Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&secret))
        .alpns(vec![ALPN.to_vec()]);
    if !ipv6 {
        builder = builder
            .clear_ip_transports()
            .bind_addr("0.0.0.0:0")
            .map_err(|e| anyhow::anyhow!("invalid IPv4 bind address for v4-only iroh: {e}"))?;
    }
    builder
        .bind()
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind iroh endpoint: {e}"))
}

/// Spawn the accept loop as a detached background task. It runs until the endpoint is
/// closed, at which point `accept()` yields `None` and the task ends.
pub fn spawn_accept_loop(
    endpoint: Endpoint,
    service: Arc<RelayService>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(incoming, service).await {
                    tracing::debug!(error = %e, "notify connection ended with error");
                }
            });
        }
        tracing::info!("notify accept loop stopped (endpoint closed)");
    })
}

/// Serve one connection: every bidirectional stream the peer opens is one RPC.
async fn handle_connection(incoming: Incoming, service: Arc<RelayService>) -> anyhow::Result<()> {
    let connection = incoming.accept()?.await?;
    // The caller's identity, verified by QUIC before a byte of application data arrived.
    // Nothing in the request body is ever consulted for authorization.
    let node_id = connection.remote_id().to_string();
    tracing::debug!(%node_id, "notify connection accepted");

    loop {
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            // A failed accept means the peer hung up — a clean exit.
            Err(_) => break,
        };
        let service = Arc::clone(&service);
        let node_id = node_id.clone();
        let exchange = async move {
            let bytes = recv.read_to_end(MAX_MESSAGE_LEN).await?;
            let response = match serde_json::from_slice::<Request>(&bytes) {
                Ok(request) => service.handle(&node_id, request).await,
                // The parse error itself is never echoed: it would reflect attacker-chosen
                // bytes back and leak the serde shape.
                Err(e) => {
                    tracing::debug!(error = %e, %node_id, "unparseable notify request");
                    Response::BadRequest {
                        reason: "unparseable request".into(),
                    }
                }
            };
            let encoded = serde_json::to_vec(&response)?;
            send.write_all(&encoded).await?;
            send.finish()?;
            Ok::<(), anyhow::Error>(())
        };
        tokio::time::timeout(STREAM_TIMEOUT, exchange)
            .await
            .map_err(|_| anyhow::anyhow!("notify stream exchange timed out"))??;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{load_from_env_only, Config};
    use crate::db;
    use crate::protocol::PushOutcome;
    use iroh::EndpointAddr;
    use std::collections::HashMap;
    use std::time::Duration;

    /// An offline endpoint (`Minimal` preset: rustls provider only — no relay, no DNS
    /// discovery) bound to loopback, so the whole suite runs with no network.
    async fn loopback_endpoint(with_alpn: bool) -> Endpoint {
        let mut builder = Endpoint::builder(presets::Minimal)
            .bind_addr("127.0.0.1:0")
            .expect("valid bind addr");
        if with_alpn {
            builder = builder.alpns(vec![ALPN.to_vec()]);
        }
        builder.bind().await.expect("bind loopback endpoint")
    }

    fn test_config(open_enrollment: bool) -> Arc<Config> {
        let mut env = HashMap::new();
        if open_enrollment {
            env.insert("EZPDS_NOTIFY_OPEN_ENROLLMENT".to_owned(), "true".to_owned());
        }
        Arc::new(load_from_env_only(&env).expect("valid test config"))
    }

    /// A running relay plus a client endpoint, wired over loopback.
    struct Harness {
        server: Endpoint,
        client: Endpoint,
        service: Arc<RelayService>,
    }

    impl Harness {
        async fn start(open_enrollment: bool) -> Self {
            let service = Arc::new(RelayService::new(
                db::test_pool().await,
                test_config(open_enrollment),
            ));
            let server = loopback_endpoint(true).await;
            let _accept = spawn_accept_loop(server.clone(), Arc::clone(&service));
            let client = loopback_endpoint(false).await;
            Self {
                server,
                client,
                service,
            }
        }

        fn server_addr(&self) -> EndpointAddr {
            EndpointAddr::new(self.server.id()).with_ip_addr(self.server.bound_sockets()[0])
        }

        /// Send a batch of requests over one connection, returning each response.
        async fn call(&self, requests: Vec<Request>) -> Vec<Response> {
            tokio::time::timeout(Duration::from_secs(10), async {
                let conn = self
                    .client
                    .connect(self.server_addr(), ALPN)
                    .await
                    .expect("connect");
                let mut responses = Vec::new();
                for request in requests {
                    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
                    send.write_all(&serde_json::to_vec(&request).expect("encode"))
                        .await
                        .expect("write");
                    send.finish().expect("finish");
                    let bytes = recv.read_to_end(MAX_MESSAGE_LEN).await.expect("read");
                    responses.push(serde_json::from_slice(&bytes).expect("decode response"));
                }
                responses
            })
            .await
            .expect("rpc round trip timed out")
        }

        async fn close(self) {
            self.client.close().await;
            self.server.close().await;
        }
    }

    #[tokio::test]
    async fn a_full_enroll_register_drop_cycle_round_trips_over_iroh() {
        let harness = Harness::start(true).await;

        let responses = harness
            .call(vec![
                Request::Enroll { claim_code: None },
                Request::RegisterHandle {
                    apns_token: "tok".into(),
                    apns_topic: "org.obsign.app".into(),
                },
            ])
            .await;
        assert_eq!(responses[0], Response::Ok);
        let Response::Handle { handle } = responses[1].clone() else {
            panic!("expected a handle, got {:?}", responses[1]);
        };

        let dropped = harness
            .call(vec![Request::DropHandle {
                handle: handle.clone(),
            }])
            .await;
        assert_eq!(dropped[0], Response::Ok);
        assert!(
            db::handles::resolve_handle(
                &harness.service.db,
                &harness.client.id().to_string(),
                &handle
            )
            .await
            .expect("resolve")
            .is_none(),
            "the dropped handle must no longer resolve"
        );

        harness.close().await;
    }

    #[tokio::test]
    async fn the_caller_identity_comes_from_the_connection_not_the_message() {
        let harness = Harness::start(true).await;
        harness
            .call(vec![Request::Enroll { claim_code: None }])
            .await;

        let enrolled =
            db::enrollments::is_enrolled(&harness.service.db, &harness.client.id().to_string())
                .await
                .expect("probe");
        assert!(
            enrolled,
            "the enrolled node id must be the dialing endpoint's own, which no message field could name"
        );

        harness.close().await;
    }

    #[tokio::test]
    async fn a_code_gated_relay_denies_an_uncoded_enroll_and_admits_a_valid_one() {
        let harness = Harness::start(false).await;

        assert_eq!(
            harness
                .call(vec![Request::Enroll { claim_code: None }])
                .await[0],
            Response::Denied
        );
        db::enrollment_codes::insert_code(&harness.service.db, "GRANT-1", 3600)
            .await
            .expect("mint");
        assert_eq!(
            harness
                .call(vec![Request::Enroll {
                    claim_code: Some("GRANT-1".into())
                }])
                .await[0],
            Response::Ok
        );

        harness.close().await;
    }

    #[tokio::test]
    async fn an_unenrolled_node_cannot_register_a_handle() {
        let harness = Harness::start(false).await;
        assert_eq!(
            harness
                .call(vec![Request::RegisterHandle {
                    apns_token: "tok".into(),
                    apns_topic: "org.obsign.app".into(),
                }])
                .await[0],
            Response::NotEnrolled
        );
        harness.close().await;
    }

    #[tokio::test]
    async fn one_node_cannot_reach_another_nodes_handle_over_the_wire() {
        let harness = Harness::start(true).await;
        // Node A registers.
        let responses = harness
            .call(vec![
                Request::Enroll { claim_code: None },
                Request::RegisterHandle {
                    apns_token: "tok".into(),
                    apns_topic: "org.obsign.app".into(),
                },
            ])
            .await;
        let Response::Handle { handle } = responses[1].clone() else {
            panic!("expected a handle");
        };

        // Node B is a second, independently-keyed endpoint dialing the same relay.
        let node_b = loopback_endpoint(false).await;
        let conn = node_b
            .connect(harness.server_addr(), ALPN)
            .await
            .expect("connect");
        let ask = |request: Request| {
            let conn = conn.clone();
            async move {
                let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
                send.write_all(&serde_json::to_vec(&request).expect("encode"))
                    .await
                    .expect("write");
                send.finish().expect("finish");
                let bytes = recv.read_to_end(MAX_MESSAGE_LEN).await.expect("read");
                serde_json::from_slice::<Response>(&bytes).expect("decode")
            }
        };

        assert_eq!(
            ask(Request::Enroll { claim_code: None }).await,
            Response::Ok
        );
        assert_eq!(
            ask(Request::Push {
                handle: handle.clone(),
                kid: 1,
                enc: "e".into(),
                ct: "c".into(),
                priority: None,
                ttl_secs: None,
                ping: None,
            })
            .await,
            Response::Pushed {
                outcome: PushOutcome::UnknownHandle
            }
        );
        assert_eq!(
            ask(Request::DropHandle {
                handle: handle.clone()
            })
            .await,
            Response::Ok
        );
        assert!(
            db::handles::resolve_handle(
                &harness.service.db,
                &harness.client.id().to_string(),
                &handle
            )
            .await
            .expect("resolve")
            .is_some(),
            "node B's drop must not have removed node A's handle"
        );

        node_b.close().await;
        harness.close().await;
    }

    #[tokio::test]
    async fn an_unparseable_request_is_answered_without_echoing_it() {
        let harness = Harness::start(true).await;
        let response = tokio::time::timeout(Duration::from_secs(10), async {
            let conn = harness
                .client
                .connect(harness.server_addr(), ALPN)
                .await
                .expect("connect");
            let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
            send.write_all(b"{\"type\":\"launchMissiles\"}")
                .await
                .expect("write");
            send.finish().expect("finish");
            let bytes = recv.read_to_end(MAX_MESSAGE_LEN).await.expect("read");
            serde_json::from_slice::<Response>(&bytes).expect("decode")
        })
        .await
        .expect("round trip timed out");

        let Response::BadRequest { reason } = response else {
            panic!("expected a bad-request response, got {response:?}");
        };
        assert!(
            !reason.contains("launchMissiles"),
            "reason echoed the input: {reason}"
        );

        harness.close().await;
    }

    #[tokio::test]
    async fn an_unknown_alpn_is_rejected() {
        let harness = Harness::start(true).await;
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            harness
                .client
                .connect(harness.server_addr(), b"ezpds/notify/SOMETHING-ELSE")
                .await
        })
        .await
        .expect("connect attempt timed out");

        assert!(
            result.is_err(),
            "the relay must negotiate only ezpds/notify/0"
        );
        harness.close().await;
    }

    #[tokio::test]
    async fn an_exhausted_budget_throttles_over_the_wire() {
        let mut config = load_from_env_only(&HashMap::new()).expect("defaults");
        config.open_enrollment = true;
        config.rate_limits.registrations_per_hour = 1;
        config.rate_limits.registrations_burst = 1;
        let service = Arc::new(RelayService::new(db::test_pool().await, Arc::new(config)));
        let server = loopback_endpoint(true).await;
        let _accept = spawn_accept_loop(server.clone(), Arc::clone(&service));
        let client = loopback_endpoint(false).await;
        let harness = Harness {
            server,
            client,
            service,
        };

        let responses = harness
            .call(vec![
                Request::Enroll { claim_code: None },
                Request::Enroll { claim_code: None },
            ])
            .await;
        assert_eq!(responses[0], Response::Ok);
        assert_eq!(responses[1], Response::Throttled);

        harness.close().await;
    }
}
