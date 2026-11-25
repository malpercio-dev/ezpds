// pattern: Imperative Shell

//! Outbound Atproto Spaces notifications. Two legs, because a host is often both at once:
//!
//! * **Repo host → space host.** A user's write into a space whose authority lives elsewhere is
//!   pushed as one `notifyRepoUpdate` to the authority's `#atproto_pds`, under service auth signed
//!   by the repo's own key, so the authority can keep the writer set `listRepos` answers. The
//!   endpoint comes from the authority's DID document and is checked by `validate_proxy_endpoint`.
//!   Network failures and transient statuses (5xx, 408, 429) are retried with backoff.
//! * **Space host → registered syncers.** A write to any repo in a space we are the authority for
//!   is sent as `notifySpaceUpdate` to every active registration made through
//!   `authorizeSpaceSync`, carrying the `spaceRev` the writer set assigned it and the
//!   `prevSpaceRev` it follows, so a syncer that sees a gap knows it missed one. The envelope is
//!   `{space, token, update}`: the registration's token in the body is the only authentication,
//!   as the reference sends it. The endpoint was validated once, at registration
//!   (`validate_notify_endpoint`).
//!
//! **Best-effort.** Nothing here blocks a commit: the write has landed before the task is spawned.
//! Each syncer gets one attempt, and a failure is logged and nothing more. It never unregisters
//! the syncer, which heals from the `prevSpaceRev` gap with `listRepos`. A registration lapses
//! only at its own expiry.
//!
//! **Bounded, twice.** A space holds at most [`MAX_REGISTRATIONS`] active registrations, and one
//! fan-out runs [`SYNCER_CONCURRENCY`] deliveries at once. Across the process at most
//! [`MAX_CONCURRENT_FANOUTS`] notifications are in flight, because the per-space bound alone
//! bounds nothing under a write burst: each task competes for the single SQLite connection every
//! request handler also needs.

use custos_core::CoreState;
use std::sync::OnceLock;
use std::time::Duration;

use common::{ApiError, ErrorCode};
use futures_util::StreamExt as _;
use serde_json::Value;
use tokio::sync::Semaphore;

use crate::auth::space::unix_now;
use crate::db::space_notify::{Registration, WriterRevs};
use custos_core::identity::proxy::CallerUrl;
use custos_core::identity::resolution::{resolve_did_document, service_endpoint};
use custos_core::space_uri::SpaceRef;

/// Most active notification registrations one space holds. `authorizeSpaceSync` refuses a new
/// one past it (`TooManyRegistrations`), and it bounds every fan-out.
pub const MAX_REGISTRATIONS: i64 = 100;

/// Deliveries one fan-out runs at once, so a slow syncer doesn't hold up the others.
const SYNCER_CONCURRENCY: usize = 4;

/// How long one call to a syncer's endpoint may take: `confirmRegistration` or one notice.
const SYNCER_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest `confirmRegistration` answer read. The body is `{"challenge": …}`, at most 512 chars.
const MAX_CONFIRM_BODY_BYTES: usize = 4096;

/// Notifications in flight at once, across every space this process serves. Small on purpose:
/// the work behind a permit is mostly waiting (DNS, TLS, retry backoff), and what it holds
/// between waits is the one SQLite connection the request handlers share.
const MAX_CONCURRENT_FANOUTS: usize = 8;

/// The permits behind [`MAX_CONCURRENT_FANOUTS`]. Process-global rather than a `CoreState`
/// field because the resource being rationed — this process's sockets and its single database
/// connection — is process-global too, and nothing about the bound varies per request.
///
/// Tasks *wait* for a permit rather than shedding when none is free: a suspended task costs
/// bytes, while dropping the notification costs a syncer its liveness until it next pages
/// `listRepos`. Waiting bounds the expensive half without losing the cheap half.
// ponytail: unbounded wait queue — an mpsc-fed worker with a bounded channel if a write burst
// ever outpaces delivery for long enough that queued tasks, not connections, are the problem.
fn fanout_permits() -> &'static Semaphore {
    static PERMITS: OnceLock<Semaphore> = OnceLock::new();
    PERMITS.get_or_init(|| Semaphore::new(MAX_CONCURRENT_FANOUTS))
}

/// Send attempts per repo-host delivery (initial try plus retries), and the backoff base
/// (doubling).
const MAX_ATTEMPTS: u32 = 3;
const BASE_BACKOFF: Duration = Duration::from_millis(500);

/// Lifetime of the service-auth JWT minted for one delivery. Short: it authorizes exactly one
/// call to one method on one service, and is minted immediately before the request.
const SERVICE_AUTH_TTL_SECS: u64 = 60;

const NOTIFY_REPO_UPDATE: &str = "com.atproto.space.notifyRepoUpdate";
const NOTIFY_SPACE_UPDATE: &str = "com.atproto.space.notifySpaceUpdate";
const CONFIRM_REGISTRATION: &str = "com.atproto.space.confirmRegistration";

/// Repo host: report our own account's write into a space whose authority is elsewhere, as one
/// `notifyRepoUpdate` to that authority signed by the repo.
///
/// Only the local commit path calls this. An inbound `notifyRepoUpdate` is never reported onward:
/// this host would be signing for a repo on someone else's say-so.
///
/// Returns immediately; delivery runs on a detached task. The
/// [`JoinHandle`](tokio::task::JoinHandle) is returned so a test can await the effects;
/// production callers discard it, since a commit must never wait on delivery.
pub fn report_write(
    state: &CoreState,
    space: &SpaceRef,
    repo_did: &str,
    repo_rev: &str,
    hash: &[u8],
) -> tokio::task::JoinHandle<()> {
    let state = state.clone();
    let space = space.clone();
    let repo_did = repo_did.to_string();
    let body = serde_json::json!({
        "space": space.uri,
        "repo": repo_did,
        "repoRev": repo_rev,
        "data": crate::views::lex_bytes(hash),
    });
    tokio::spawn(async move {
        let _permit = fanout_permits().acquire().await;
        if authority_is_local(&state, &space).await != Some(false) {
            return;
        }
        let service = crate::auth::space::space_host_aud(&space);
        let (did, fragment) = split_service(&service);
        if let Err(error) =
            deliver(&state, did, fragment, &repo_did, NOTIFY_REPO_UPDATE, &body).await
        {
            tracing::debug!(%error, space = %space.uri, "space notify: report to authority failed");
        }
    })
}

/// Space host: send an update the writer set accepted to every active registration, as a
/// `repoWrite` with the `spaceRev`/`prevSpaceRev` it was assigned.
///
/// Returns like [`report_write`].
pub fn forward_write(
    state: &CoreState,
    space: &SpaceRef,
    repo_did: &str,
    repo_rev: &str,
    hash: &[u8],
    revs: WriterRevs,
) -> tokio::task::JoinHandle<()> {
    let state = state.clone();
    let space = space.clone();
    let mut update = serde_json::json!({
        "$type": "com.atproto.space.defs#repoWrite",
        "repo": repo_did,
        "repoRev": repo_rev,
        "data": crate::views::lex_bytes(hash),
        "spaceRev": revs.space_rev,
    });
    if let Some(prev) = revs.prev_space_rev {
        update["prevSpaceRev"] = prev.into();
    }
    tokio::spawn(async move {
        let _permit = fanout_permits().acquire().await;
        if authority_is_local(&state, &space).await != Some(true) {
            return;
        }
        let registrations = match crate::db::space_notify::registrations_for_space(
            &state.db,
            &space.uri,
            true,
            MAX_REGISTRATIONS,
        )
        .await
        {
            Ok(registrations) => registrations,
            Err(error) => {
                tracing::debug!(%error, space = %space.uri, "space notify: failed to load registrations");
                return;
            }
        };
        notify_syncers(&state, &space, registrations, &update).await;
    })
}

/// Tell every syncer registered for `space` that it has been deleted.
///
/// The registrations are captured by the caller *before* the deletion transaction drops them.
pub fn fan_out_space_deleted(
    state: &CoreState,
    space: &SpaceRef,
    registrations: Vec<Registration>,
) {
    if registrations.is_empty() {
        return;
    }
    let state = state.clone();
    let space = space.clone();
    let update = serde_json::json!({ "$type": "com.atproto.space.notifySpaceUpdate#spaceDeleted" });
    tokio::spawn(async move {
        let _permit = fanout_permits().acquire().await;
        notify_syncers(&state, &space, registrations, &update).await;
    });
}

/// Whether this host is `space`'s authority (a `spaces` row with a policy). `None` when there is
/// nothing to send for it: no row, a deleted or taken-down space (a taken-down space must stop
/// acting as space host entirely), or a failed read.
async fn authority_is_local(state: &CoreState, space: &SpaceRef) -> Option<bool> {
    match crate::db::spaces::get_space(&state.db, &space.uri).await {
        Ok(Some(row)) if row.deleted_at.is_none() && row.takendown_at.is_none() => {
            Some(row.policy.is_some())
        }
        Ok(_) => None,
        Err(error) => {
            tracing::debug!(%error, space = %space.uri, "space notify: failed to load space");
            None
        }
    }
}

/// One `notifySpaceUpdate` attempt to each registration, [`SYNCER_CONCURRENCY`] at a time.
async fn notify_syncers(
    state: &CoreState,
    space: &SpaceRef,
    registrations: Vec<Registration>,
    update: &Value,
) {
    futures_util::stream::iter(registrations)
        .for_each_concurrent(SYNCER_CONCURRENCY, |registration| async move {
            let body = serde_json::json!({
                "space": space.uri,
                "token": registration.token,
                "update": update,
            });
            let url = syncer_url(&registration.endpoint, NOTIFY_SPACE_UPDATE);
            let outcome = state
                .hardened_http_client
                .post(&url)
                .timeout(SYNCER_TIMEOUT)
                .json(&body)
                .send()
                .await;
            let error = match outcome {
                Ok(response) if response.status().is_success() => return,
                Ok(response) => format!("syncer returned {}", response.status()),
                Err(error) => error.to_string(),
            };
            tracing::debug!(
                %error,
                space = %space.uri,
                endpoint = %registration.endpoint,
                "space notify: syncer delivery failed"
            );
        })
        .await;
}

/// `method`'s URL on a syncer's registered base URL.
fn syncer_url(endpoint: &str, method: &str) -> CallerUrl {
    CallerUrl::new(endpoint).join(&format!("/xrpc/{method}"))
}

/// Check that a new registration was asked for: the endpoint must echo a fresh challenge back
/// from `confirmRegistration`, which it answers only for a token it issued for this space.
/// Anything else, a timeout or an unreachable endpoint included, is `RegistrationNotConfirmed`.
pub async fn confirm_registration(
    state: &CoreState,
    space: &SpaceRef,
    registration: &Registration,
) -> Result<(), ApiError> {
    let challenge = uuid::Uuid::new_v4().simple().to_string();
    let body = serde_json::json!({
        "space": space.uri,
        "token": registration.token,
        "challenge": challenge,
    });
    // The endpoint is the requester's choice, so it is fetched through the hardened client.
    let echoed = match state
        .hardened_http_client
        .post(&syncer_url(&registration.endpoint, CONFIRM_REGISTRATION))
        .timeout(SYNCER_TIMEOUT)
        .json(&body)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => read_challenge(response).await,
        Ok(response) => Err(format!("endpoint returned {}", response.status())),
        Err(error) => Err(error.to_string()),
    };
    match echoed {
        Ok(echo) if echo == challenge => Ok(()),
        outcome => {
            let error = outcome
                .err()
                .unwrap_or_else(|| "wrong challenge".to_string());
            tracing::warn!(
                %error,
                space = %space.uri,
                endpoint = %registration.endpoint,
                "registration not confirmed"
            );
            Err(ApiError::new(
                ErrorCode::RegistrationNotConfirmed,
                "notify endpoint did not confirm the registration",
            ))
        }
    }
}

/// The `challenge` of a `confirmRegistration` answer, read up to [`MAX_CONFIRM_BODY_BYTES`].
async fn read_challenge(mut response: reqwest::Response) -> Result<String, String> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_CONFIRM_BODY_BYTES {
            return Err("answer is too large".to_string());
        }
    }
    let answer: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    answer
        .get("challenge")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "answer carries no challenge".to_string())
}

/// A service identifier is a DID with an optional `#fragment` naming the DID-document entry to
/// deliver to. The DID alone is the service-auth `aud`.
fn split_service(service: &str) -> (&str, Option<&str>) {
    match service.split_once('#') {
        Some((did, fragment)) => (did, Some(fragment)),
        None => (service, None),
    }
}

/// Mint a service-auth token for the single method, then resolve the recipient and POST,
/// retrying with doubling backoff while the failure is transient: the DID document could not be
/// fetched, the request did not complete, or the recipient answered 5xx, 408 Request Timeout or
/// 429 Too Many Requests. A document with no matching service entry, or any other 4xx, is
/// permanent: retrying an argument the recipient has already rejected only wastes its capacity.
async fn deliver(
    state: &CoreState,
    did: &str,
    fragment: Option<&str>,
    signer_did: &str,
    lxm: &str,
    body: &Value,
) -> Result<(), String> {
    let master_key: &[u8; 32] = state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|s| &*s.0)
        .ok_or_else(|| "signing key master key not configured".to_string())?;
    let now = unix_now().map_err(|e| e.to_string())?;
    let token = custos_core::auth::signing_key::mint_account_service_auth(
        &state.db,
        master_key,
        signer_did,
        did,
        Some(lxm),
        now,
        now + SERVICE_AUTH_TTL_SECS,
    )
    .await
    .map_err(|e| e.to_string())?;

    let mut url = None;
    let mut backoff = BASE_BACKOFF;
    let mut last = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        match attempt_delivery(state, did, fragment, &mut url, &token, body, lxm).await {
            Ok(()) => return Ok(()),
            Err(Failure::Permanent(error)) => return Err(error),
            Err(Failure::Transient(error)) => last = error,
        }
        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(backoff).await;
            backoff *= 2;
        }
    }
    Err(last)
}

enum Failure {
    Transient(String),
    Permanent(String),
}

/// One delivery attempt. `url` caches the resolved endpoint across attempts, so a retry after a
/// failed POST does not fetch the DID document again.
async fn attempt_delivery(
    state: &CoreState,
    did: &str,
    fragment: Option<&str>,
    url: &mut Option<CallerUrl>,
    token: &str,
    body: &Value,
    lxm: &str,
) -> Result<(), Failure> {
    if url.is_none() {
        let doc = resolve_did_document(state, did)
            .await
            .map_err(|e| Failure::Transient(e.to_string()))?;
        let endpoint = endpoint_in(&doc, fragment)
            .ok_or_else(|| Failure::Permanent(format!("no service endpoint for {did}")))?;
        // The resolver behind the hardened client never sees an IP-literal host, so the
        // endpoint's address is checked here before anything is sent to it.
        custos_core::identity::proxy::validate_proxy_endpoint(
            &endpoint,
            state.allow_loopback_proxy_targets,
        )
        .await
        .map_err(|e| Failure::Permanent(e.to_string()))?;
        *url = Some(CallerUrl::new(endpoint).join(&format!("/xrpc/{lxm}")));
    }
    let Some(url) = url.as_ref() else {
        return Err(Failure::Permanent("endpoint not resolved".to_string()));
    };
    // The SSRF-hardened client: the endpoint comes from a DID document, so it is a
    // caller-influenced target like every other one.
    match state
        .hardened_http_client
        .post(url)
        .bearer_auth(token)
        .json(body)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response)
            if response.status().is_client_error()
                && !matches!(response.status().as_u16(), 408 | 429) =>
        {
            Err(Failure::Permanent(format!(
                "space host rejected: {}",
                response.status()
            )))
        }
        Ok(response) => Err(Failure::Transient(format!(
            "space host returned {}",
            response.status()
        ))),
        Err(error) => Err(Failure::Transient(error.to_string())),
    }
}

/// The delivery endpoint in `doc`: its entry named by `fragment`, or `#atproto_pds` when there is
/// none — where a space host (the authority's PDS) answers.
fn endpoint_in(doc: &Value, fragment: Option<&str>) -> Option<String> {
    service_endpoint(doc, fragment.unwrap_or("atproto_pds")).map(str::to_string)
}

#[cfg(test)]
mod tests {
    //! What actually leaves the machine, against a wiremock standing in for the far side: the
    //! envelope a syncer receives, the `notifyRepoUpdate` a foreign space host receives
    //! (`aud`/`lxm` scoping, the endpoint fallback, the retry ladder), and the confirmation
    //! handshake.

    use super::*;
    use crate::db::space_notify::put_registration;
    use crate::db::spaces::{insert_space, NewSpace};
    use crate::test_support::{seed_account_with_repo, state_with_master_key};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use custos_core::space_uri::parse_space_ref;
    use custos_db::dids::seed_did_document;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const AUTHORITY: &str = "did:plc:authoritynotifyaaaaaaaaa";
    const SYNCER: &str = "did:plc:syncernotifyaaaaaaaaaaaa";
    const WRITER: &str = "did:plc:writernotifyaaaaaaaaaaaa";
    const THROTTLER: &str = "did:plc:throttlernotifyaaaaaaaaa";
    const TIMED_OUT: &str = "did:plc:timedoutnotifyaaaaaaaaaa";
    const SPACE: &str = "at://did:plc:authoritynotifyaaaaaaaaa/space/org.example.bucket/main";

    /// A host that is the space's authority, holding the repo signing key the repo-host leg's
    /// service auth is minted against.
    async fn authority_state() -> CoreState {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, AUTHORITY).await;
        seed_space(&state, Some(&crate::test_support::memberspace_policy(true))).await;
        state
    }

    /// The space's row: with a policy this host is its authority, without one it only keeps
    /// repos in it.
    async fn seed_space(state: &CoreState, policy: Option<&str>) {
        match policy {
            Some(policy) => {
                crate::test_support::seed_authority_space(&state.db, SPACE, policy).await
            }
            None => {
                let space = parse_space_ref(SPACE).unwrap();
                insert_space(
                    &state.db,
                    &NewSpace {
                        uri: &space.uri,
                        authority_did: &space.authority,
                        space_type: &space.space_type,
                        skey: &space.skey,
                    },
                )
                .await
                .unwrap();
            }
        }
    }

    /// A DID document publishing exactly one service entry.
    async fn seed_host(state: &CoreState, did: &str, fragment: &str, endpoint: &str) {
        seed_did_document(
            &state.db,
            did,
            serde_json::json!({
                "id": did,
                "service": [{
                    "id": format!("#{fragment}"),
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": endpoint,
                }],
            }),
        )
        .await;
    }

    fn registration(endpoint: &str, token: &str) -> Registration {
        Registration {
            endpoint: endpoint.to_string(),
            token: token.to_string(),
        }
    }

    /// Register `(endpoint, token)` until `expires_at`.
    async fn register(state: &CoreState, endpoint: &str, token: &str, expires_at: u64) {
        let written = put_registration(
            &state.db,
            SPACE,
            &registration(endpoint, token),
            expires_at,
            MAX_REGISTRATIONS,
        )
        .await
        .unwrap();
        assert_eq!(written, crate::db::space_notify::PutRegistration::Written);
    }

    fn notify_ok(lxm: &str) -> Mock {
        Mock::given(method("POST"))
            .and(path(format!("/xrpc/{lxm}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
    }

    async fn received(server: &MockServer) -> Vec<wiremock::Request> {
        server.received_requests().await.unwrap_or_default()
    }

    fn body_of(request: &wiremock::Request) -> Value {
        serde_json::from_slice(&request.body).unwrap()
    }

    /// The claims of the service-auth token a delivery carried.
    fn claims(request: &wiremock::Request) -> Value {
        let header = request
            .headers
            .get("authorization")
            .expect("delivery carries an Authorization header")
            .to_str()
            .unwrap();
        let payload = header
            .strip_prefix("Bearer ")
            .expect("service auth is a bearer token")
            .split('.')
            .nth(1)
            .expect("JWT payload segment");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
    }

    /// Wait for a detached fan-out to reach `server` `n` times.
    async fn wait_for(server: &MockServer, n: usize) -> Vec<wiremock::Request> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let requests = received(server).await;
            if requests.len() >= n {
                return requests;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {n} deliveries"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// The `notifySpaceUpdate` a syncer receives: the `{space, token, update}` envelope, the
    /// update a typed `repoWrite`, and no Authorization header — the token in the body is the
    /// authentication. A lapsed registration is not sent the update.
    #[tokio::test]
    async fn a_write_reaches_each_active_syncer_in_the_envelope() {
        let state = authority_state().await;
        let server = MockServer::start().await;
        notify_ok(NOTIFY_SPACE_UPDATE).mount(&server).await;
        let now = unix_now().unwrap();
        register(&state, &server.uri(), "live-token", now + 600).await;
        register(&state, &format!("{}/lapsed", server.uri()), "old", now - 1).await;

        let space = parse_space_ref(SPACE).unwrap();
        forward_write(
            &state,
            &space,
            WRITER,
            "3lzz",
            &[0xde, 0xad],
            WriterRevs {
                space_rev: "3m22".to_string(),
                prev_space_rev: Some("3m21".to_string()),
            },
        )
        .await
        .unwrap();

        let requests = received(&server).await;
        assert_eq!(requests.len(), 1, "the lapsed registration is skipped");
        assert_eq!(
            requests[0].url.path(),
            "/xrpc/com.atproto.space.notifySpaceUpdate"
        );
        assert_eq!(
            body_of(&requests[0]),
            serde_json::json!({
                "space": SPACE,
                "token": "live-token",
                "update": {
                    "$type": "com.atproto.space.defs#repoWrite",
                    "repo": WRITER,
                    "repoRev": "3lzz",
                    "data": { "$bytes": "3q0=" },
                    "spaceRev": "3m22",
                    "prevSpaceRev": "3m21",
                },
            })
        );
        assert!(requests[0].headers.get("authorization").is_none());
    }

    /// One attempt per syncer, and a failure leaves the registration in place.
    #[tokio::test]
    async fn a_failed_syncer_delivery_is_not_retried_and_keeps_its_registration() {
        let state = authority_state().await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        register(&state, &server.uri(), "t", unix_now().unwrap() + 600).await;

        let revs = WriterRevs {
            space_rev: "3m22".to_string(),
            prev_space_rev: None,
        };
        let space = parse_space_ref(SPACE).unwrap();
        forward_write(&state, &space, WRITER, "3lzz", &[1], revs)
            .await
            .unwrap();

        assert_eq!(received(&server).await.len(), 1);
        let left = crate::db::space_notify::registrations_for_space(&state.db, SPACE, true, 10)
            .await
            .unwrap();
        assert_eq!(left.len(), 1);
    }

    /// The repo-host direction: a write into a space whose authority is elsewhere is one
    /// `notifyRepoUpdate` to that authority's `#atproto_pds`, signed by the writer.
    #[tokio::test]
    async fn a_repo_host_reports_once_to_the_authority() {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, WRITER).await;
        seed_space(&state, None).await;
        let server = MockServer::start().await;
        notify_ok(NOTIFY_REPO_UPDATE).mount(&server).await;
        seed_host(&state, AUTHORITY, "atproto_pds", &server.uri()).await;

        let space = parse_space_ref(SPACE).unwrap();
        report_write(&state, &space, WRITER, "3lzz", &[0xde, 0xad])
            .await
            .unwrap();

        let requests = received(&server).await;
        assert_eq!(requests.len(), 1, "exactly one report to the authority");
        assert_eq!(
            body_of(&requests[0]),
            serde_json::json!({
                "space": SPACE,
                "repo": WRITER,
                "repoRev": "3lzz",
                "data": { "$bytes": "3q0=" },
            }),
            "a repo host assigns no spaceRev — that is the authority's job"
        );
        let claims = claims(&requests[0]);
        assert_eq!(claims["iss"], WRITER, "the repo host speaks for its user");
        assert_eq!(claims["aud"], AUTHORITY);
        assert_eq!(claims["lxm"], NOTIFY_REPO_UPDATE);
    }

    /// A report is only ever sent for a space whose authority is elsewhere: called for a space
    /// this host is the authority for, it reaches nobody — no syncer, and not ourselves.
    #[tokio::test]
    async fn a_report_into_our_own_space_goes_nowhere() {
        let state = authority_state().await;
        let server = MockServer::start().await;
        notify_ok(NOTIFY_REPO_UPDATE).mount(&server).await;
        notify_ok(NOTIFY_SPACE_UPDATE).mount(&server).await;
        seed_host(&state, AUTHORITY, "atproto_pds", &server.uri()).await;
        register(&state, &server.uri(), "t", unix_now().unwrap() + 600).await;

        let space = parse_space_ref(SPACE).unwrap();
        report_write(&state, &space, WRITER, "3lzz", &[])
            .await
            .unwrap();
        assert!(received(&server).await.is_empty());
    }

    /// A deletion is a `spaceDeleted` update in the same envelope.
    #[tokio::test]
    async fn a_deletion_is_a_space_deleted_update() {
        let state = authority_state().await;
        let server = MockServer::start().await;
        notify_ok(NOTIFY_SPACE_UPDATE).mount(&server).await;

        let space = parse_space_ref(SPACE).unwrap();
        fan_out_space_deleted(&state, &space, vec![registration(&server.uri(), "t")]);

        let requests = wait_for(&server, 1).await;
        assert_eq!(
            body_of(&requests[0]),
            serde_json::json!({
                "space": SPACE,
                "token": "t",
                "update": { "$type": "com.atproto.space.notifySpaceUpdate#spaceDeleted" },
            })
        );
    }

    /// The endpoint must echo the challenge it was sent, for the token it was sent with. A wrong
    /// echo, an error status and an unreachable endpoint are all `RegistrationNotConfirmed`.
    #[tokio::test]
    async fn confirmation_requires_the_challenge_echoed() {
        let state = authority_state().await;
        let space = parse_space_ref(SPACE).unwrap();

        let echoing = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/xrpc/{CONFIRM_REGISTRATION}")))
            .respond_with(|request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "challenge": body["challenge"] }))
            })
            .mount(&echoing)
            .await;
        confirm_registration(&state, &space, &registration(&echoing.uri(), "tok"))
            .await
            .unwrap();
        let sent = body_of(&received(&echoing).await[0]);
        assert_eq!(sent["space"], SPACE);
        assert_eq!(sent["token"], "tok");

        let wrong = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "challenge": "x" })),
            )
            .mount(&wrong)
            .await;
        let refusing = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&refusing)
            .await;
        for endpoint in [
            wrong.uri(),
            refusing.uri(),
            "https://syncer.invalid".to_string(),
        ] {
            let error = confirm_registration(&state, &space, &registration(&endpoint, "tok"))
                .await
                .unwrap_err();
            assert_eq!(
                *error.code(),
                ErrorCode::RegistrationNotConfirmed,
                "{endpoint}"
            );
        }
    }

    /// The repo-host retry ladder. A 5xx, 408 or 429 is transient and spends every attempt; any
    /// other 4xx is the space host rejecting the argument, and re-sending it would only burn its
    /// capacity.
    #[tokio::test]
    async fn transient_failures_are_retried_and_rejections_are_not() {
        let state = authority_state().await;
        let body = serde_json::json!({ "space": SPACE });

        let flaky = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&flaky)
            .await;
        seed_host(&state, SYNCER, "atproto_pds", &flaky.uri()).await;
        let error = deliver(&state, SYNCER, None, AUTHORITY, NOTIFY_REPO_UPDATE, &body)
            .await
            .expect_err("every attempt failed");
        assert!(error.contains("503"), "{error}");
        assert_eq!(received(&flaky).await.len(), MAX_ATTEMPTS as usize);

        // 408 and 429 are 4xx, but they ask for patience rather than rejecting the argument.
        for (status, did) in [(408, THROTTLER), (429, TIMED_OUT)] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;
            seed_host(&state, did, "atproto_pds", &server.uri()).await;
            deliver(&state, did, None, AUTHORITY, NOTIFY_REPO_UPDATE, &body)
                .await
                .expect_err("every attempt failed");
            assert_eq!(
                received(&server).await.len(),
                MAX_ATTEMPTS as usize,
                "{status}"
            );
        }

        let rejecting = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&rejecting)
            .await;
        seed_host(&state, WRITER, "atproto_pds", &rejecting.uri()).await;
        let error = deliver(&state, WRITER, None, AUTHORITY, NOTIFY_REPO_UPDATE, &body)
            .await
            .expect_err("a rejected argument is a permanent failure");
        assert!(error.contains("400"), "{error}");
        assert_eq!(
            received(&rejecting).await.len(),
            1,
            "a rejection must not be retried"
        );
    }

    /// A space host endpoint whose host is a non-public IP literal is refused before anything is
    /// sent. The hardened client's resolver never sees an IP literal, so this check is the only
    /// guard on the repo-host leg.
    #[tokio::test]
    async fn a_non_public_ip_literal_endpoint_is_refused_without_a_request() {
        let mut state = authority_state().await;
        state.allow_loopback_proxy_targets = false;
        let body = serde_json::json!({ "space": SPACE });

        // Loopback stands in for an internal address we can observe: with the test-only
        // relaxation off, the mock must receive nothing.
        let internal = MockServer::start().await;
        notify_ok(NOTIFY_REPO_UPDATE).mount(&internal).await;
        seed_host(&state, SYNCER, "atproto_pds", &internal.uri()).await;
        let error = deliver(&state, SYNCER, None, AUTHORITY, NOTIFY_REPO_UPDATE, &body)
            .await
            .expect_err("a loopback endpoint is refused");
        assert!(error.contains("not a usable public"), "{error}");
        assert!(received(&internal).await.is_empty(), "nothing was sent");

        for (did, endpoint) in [
            (WRITER, "http://10.0.0.5"),
            (THROTTLER, "http://169.254.169.254"),
            (TIMED_OUT, "http://[::ffff:10.0.0.5]"),
        ] {
            seed_host(&state, did, "atproto_pds", endpoint).await;
            let error = deliver(&state, did, None, AUTHORITY, NOTIFY_REPO_UPDATE, &body)
                .await
                .expect_err("a private or link-local endpoint is refused");
            assert!(error.contains("not a usable public"), "{endpoint}: {error}");
        }
    }

    /// Space-host resolution against a *real* foreign document — fetched live from the DID's own
    /// authority (a stand-in plc.directory), through `resolve_did_document`.
    #[tokio::test]
    async fn a_foreign_did_resolves_to_its_space_host_at_atproto_pds() {
        let plc = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/did:plc:.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": AUTHORITY,
                "service": [{
                    "id": format!("{AUTHORITY}#atproto_pds"),
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://authority.example.com",
                }],
            })))
            .mount(&plc)
            .await;
        let state = crate::test_support::test_state_with_plc_url(plc.uri()).await;

        let doc = resolve_did_document(&state, AUTHORITY).await.unwrap();
        assert_eq!(
            endpoint_in(&doc, None).as_deref(),
            Some("https://authority.example.com"),
            "the fully-qualified `did#atproto_pds` id form resolves, and is the default"
        );
        assert!(
            endpoint_in(&doc, Some("atproto_space_host")).is_none(),
            "#atproto_space_host is no longer an alias"
        );
    }

    /// A DID document that cannot be fetched is a network failure like any other and is retried;
    /// one that is fetched but names no delivery endpoint is permanent and is not.
    #[tokio::test]
    async fn an_unfetchable_did_document_is_retried() {
        let plc = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/did:plc:.+"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&plc)
            .await;
        let base = crate::test_support::test_state_with_plc_url(plc.uri()).await;
        let mut config = (*base.config).clone();
        config.signing_key_master_key = state_with_master_key()
            .await
            .config
            .signing_key_master_key
            .clone();
        let state = custos_core::CoreState {
            config: std::sync::Arc::new(config),
            ..base.clone()
        };
        seed_account_with_repo(&state.db, AUTHORITY).await;
        let body = serde_json::json!({ "space": SPACE });

        deliver(&state, SYNCER, None, AUTHORITY, NOTIFY_REPO_UPDATE, &body)
            .await
            .expect_err("the document never resolved");
        assert_eq!(received(&plc).await.len(), MAX_ATTEMPTS as usize);

        // Fetched, but with no service entry at all: one try.
        seed_did_document(
            &state.db,
            WRITER,
            serde_json::json!({ "id": WRITER, "service": [] }),
        )
        .await;
        let error = deliver(&state, WRITER, None, AUTHORITY, NOTIFY_REPO_UPDATE, &body)
            .await
            .expect_err("no endpoint");
        assert!(error.contains("no service endpoint"), "{error}");
    }
}
