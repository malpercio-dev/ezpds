// pattern: Imperative Shell

//! Outbound Atproto Spaces write notifications — the space-host role's fan-out.
//!
//! Two directions ride one path, because a host is often both at once:
//!
//! * **Repo host → space host.** A user's write into a space whose authority lives elsewhere is
//!   pushed as one `notifyWrite` to the authority's `#atproto_space_host`, signed by the repo's
//!   own key, so the authority can maintain the writer set `listRepos` answers. No subscription
//!   is involved: the authority needs none to hear about a write into its own space.
//! * **Space host → registered syncers.** A write to any repo in a space we are the authority
//!   for — our own account's, or one an inbound `notifyWrite` told us about — is forwarded to
//!   every service that called `registerNotify`, carrying the `spaceRev` the writer set assigned
//!   it and the `prevSpaceRev` it follows, so a syncer that sees a gap knows it missed one.
//!
//! **Best-effort, by spec.** Nothing here blocks a commit: the durable write has already landed
//! and returned before the fan-out task is spawned. Each delivery retries network failures
//! (including fetching the recipient's DID document) and transient statuses (5xx, 408, 429) with
//! backoff, and stops on any other error. A subscriber that missed one heals from the set hash on
//! its next `listRepoOps`, or from the periodic `listRepos` sweep. A permanent failure
//! deliberately does **not** unregister the subscriber — a syncer that is briefly down or
//! mid-deploy would silently lose its subscription — so registrations lapse only at their own
//! expiry.
//!
//! **Bounded, twice.** One notification delivers to at most [`MAX_SUBSCRIBERS`] subscribers, in
//! sequence — so a space with many syncers costs one connection at a time, not a spawn storm.
//! And across the whole process at most [`MAX_CONCURRENT_FANOUTS`] notifications are in flight
//! at once, because the per-notification cap alone bounds nothing under a *write burst*: tasks
//! sleep between retries, and each one competes for the single SQLite connection every request
//! handler also needs. (`crawler.rs`, the pattern this follows, gets that second bound for free
//! from its 30-second per-crawler rate limit, which collapses a burst into one notification;
//! a space's writes must each be reported, so there is nothing to collapse here.)

use std::sync::OnceLock;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::Semaphore;

use crate::auth::space::unix_now;
use crate::db::space_notify::WriterRevs;
use crate::identity::resolution::{resolve_did_document, service_endpoint, space_host_endpoint};
use crate::space_uri::SpaceRef;
use crate::SpacesState;

/// How long a write-notification registration lives before it must be renewed. Long enough that
/// a syncer polling on any human cadence stays subscribed across a weekend outage; short enough
/// that a service that disappears stops being dialled within the week.
pub const REGISTRATION_TTL_SECS: i64 = 7 * 24 * 60 * 60;

/// Most subscribers one notification fans out to. A cap rather than a page loop: past this many
/// syncers a space's notification budget is better spent on `listRepos` sweeps than on delivery.
const MAX_SUBSCRIBERS: i64 = 100;

/// Notifications in flight at once, across every space this process serves. Small on purpose:
/// the work behind a permit is mostly waiting (DNS, TLS, retry backoff), and what it holds
/// between waits is the one SQLite connection the request handlers share.
const MAX_CONCURRENT_FANOUTS: usize = 8;

/// The permits behind [`MAX_CONCURRENT_FANOUTS`]. Process-global rather than an `SpacesState`
/// field because the resource being rationed — this process's sockets and its single database
/// connection — is process-global too, and nothing about the bound varies per request.
///
/// Tasks *wait* for a permit rather than shedding when none is free: a suspended task costs
/// bytes, while dropping the notification costs a syncer its liveness until the next `listRepos`
/// sweep. Waiting bounds the expensive half without losing the cheap half.
// ponytail: unbounded wait queue — an mpsc-fed worker with a bounded channel if a write burst
// ever outpaces delivery for long enough that queued tasks, not connections, are the problem.
fn fanout_permits() -> &'static Semaphore {
    static PERMITS: OnceLock<Semaphore> = OnceLock::new();
    PERMITS.get_or_init(|| Semaphore::new(MAX_CONCURRENT_FANOUTS))
}

/// Send attempts per delivery (initial try plus retries), and the backoff base (doubling).
const MAX_ATTEMPTS: u32 = 3;
const BASE_BACKOFF: Duration = Duration::from_millis(500);

/// Lifetime of the service-auth JWT minted for one delivery. Short: it authorizes exactly one
/// call to one method on one service, and is minted immediately before the request.
const SERVICE_AUTH_TTL_SECS: u64 = 60;

const NOTIFY_WRITE: &str = "com.atproto.space.notifyWrite";
const NOTIFY_SPACE_DELETED: &str = "com.atproto.space.notifySpaceDeleted";

/// Repo host: report our own account's write into a space whose authority is elsewhere, as one
/// `notifyWrite` to that authority signed by the repo.
///
/// Only the local commit path calls this. An inbound `notifyWrite` is never reported onward: this
/// host would be signing for a repo on someone else's say-so.
///
/// Returns immediately; delivery runs on a detached task. The
/// [`JoinHandle`](tokio::task::JoinHandle) is returned so a test can await the effects;
/// production callers discard it, since a commit must never wait on delivery.
pub fn report_write(
    state: &SpacesState,
    space: &SpaceRef,
    repo_did: &str,
    repo_rev: &str,
    hash: &[u8],
) -> tokio::task::JoinHandle<()> {
    spawn_write(state, space, repo_did, repo_rev, hash, None)
}

/// Space host: forward an update the writer set accepted to every registered syncer, with the
/// `spaceRev`/`prevSpaceRev` it was assigned. `repo_did`'s own host already knows about the write,
/// so it is skipped and a notification is never echoed back at its source.
///
/// Returns like [`report_write`].
pub fn forward_write(
    state: &SpacesState,
    space: &SpaceRef,
    repo_did: &str,
    repo_rev: &str,
    hash: &[u8],
    revs: WriterRevs,
) -> tokio::task::JoinHandle<()> {
    spawn_write(state, space, repo_did, repo_rev, hash, Some(revs))
}

/// The task behind [`report_write`] (`revs: None`) and [`forward_write`].
fn spawn_write(
    state: &SpacesState,
    space: &SpaceRef,
    repo_did: &str,
    repo_rev: &str,
    hash: &[u8],
    revs: Option<WriterRevs>,
) -> tokio::task::JoinHandle<()> {
    let state = state.clone();
    let space = space.clone();
    let repo_did = repo_did.to_string();
    let forwarding = revs.is_some();
    let mut body = serde_json::json!({
        "space": space.uri,
        "repo": repo_did,
        "repoRev": repo_rev,
        "hash": crate::views::lex_bytes(hash),
    });
    if let Some(revs) = revs {
        body["spaceRev"] = revs.space_rev.into();
        if let Some(prev) = revs.prev_space_rev {
            body["prevSpaceRev"] = prev.into();
        }
    }
    tokio::spawn(async move {
        let _permit = fanout_permits().acquire().await;

        // Whether this host is the space's authority: a `spaces` row with simplespace config. A
        // forward needs it, a report needs the authority elsewhere. A deleted or taken-down space
        // sends nothing: a taken-down space must stop acting as space host entirely.
        let is_authority = match crate::db::spaces::get_space(&state.db, &space.uri).await {
            Ok(Some(row)) if row.deleted_at.is_none() && row.takendown_at.is_none() => {
                row.policy.is_some()
            }
            Ok(_) => return,
            Err(error) => {
                tracing::debug!(%error, space = %space.uri, "space notify: failed to load space");
                return;
            }
        };
        if forwarding != is_authority {
            return;
        }

        if !forwarding {
            let service = crate::auth::space::space_host_aud(&space);
            let (did, fragment) = split_service(&service);
            if let Err(error) = deliver(&state, did, fragment, &repo_did, NOTIFY_WRITE, &body).await
            {
                tracing::debug!(%error, space = %space.uri, "space notify: report to authority failed");
            }
            return;
        }

        let subscribers = match crate::db::space_notify::subscribers_for_space(
            &state.db,
            &space.uri,
            MAX_SUBSCRIBERS,
        )
        .await
        {
            Ok(subscribers) => subscribers,
            Err(error) => {
                tracing::debug!(%error, space = %space.uri, "space notify: failed to load subscribers");
                return;
            }
        };
        deliver_all(
            &state,
            subscribers,
            &repo_did,
            &space.authority,
            NOTIFY_WRITE,
            body,
        )
        .await;
    })
}

/// Tell every service registered for `space` that it has been deleted and their copies must go.
///
/// The subscriber list is captured by the caller *before* the deletion transaction drops the
/// registrations — the rows are gone by the time this task runs.
pub fn fan_out_space_deleted(state: &SpacesState, space: &SpaceRef, subscribers: Vec<String>) {
    if subscribers.is_empty() {
        return;
    }
    let state = state.clone();
    let signer_did = space.authority.clone();
    let body = serde_json::json!({ "space": space.uri });
    tokio::spawn(async move {
        let _permit = fanout_permits().acquire().await;
        deliver_all(
            &state,
            subscribers,
            "",
            &signer_did,
            NOTIFY_SPACE_DELETED,
            body,
        )
        .await;
    });
}

/// Deliver one notification to each subscriber in turn, skipping `origin`'s own service.
async fn deliver_all(
    state: &SpacesState,
    subscribers: Vec<String>,
    origin: &str,
    signer_did: &str,
    lxm: &str,
    body: Value,
) {
    for service in subscribers {
        let (did, fragment) = split_service(&service);
        if !origin.is_empty() && did == origin {
            continue;
        }
        if let Err(error) = deliver(state, did, fragment, signer_did, lxm, &body).await {
            tracing::debug!(%error, service = %service, lxm, "space notify: delivery failed");
        }
    }
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
    state: &SpacesState,
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
    let token = crate::auth::signing_key::mint_account_service_auth(
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
    state: &SpacesState,
    did: &str,
    fragment: Option<&str>,
    url: &mut Option<crate::identity::proxy::CallerUrl>,
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
        *url = Some(crate::identity::proxy::CallerUrl::new(format!(
            "{}/xrpc/{lxm}",
            endpoint.trim_end_matches('/')
        )));
    }
    let Some(url) = url.as_ref() else {
        return Err(Failure::Permanent("endpoint not resolved".to_string()));
    };
    // The SSRF-hardened client: the endpoint comes from a DID document a caller named at
    // registerNotify, so it is a caller-influenced target like every other one.
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
                "subscriber rejected: {}",
                response.status()
            )))
        }
        Ok(response) => Err(Failure::Transient(format!(
            "subscriber returned {}",
            response.status()
        ))),
        Err(error) => Err(Failure::Transient(error.to_string())),
    }
}

/// The delivery endpoint in `doc`: its entry named by `fragment`. No fragment, and the
/// authority's `#atproto_space_host` a repo host reports to, fall back to `#atproto_pds`, which is
/// where the alpha's own hosts answer (see `identity::resolution::space_host_endpoint`).
fn endpoint_in(doc: &Value, fragment: Option<&str>) -> Option<String> {
    match fragment {
        None | Some("atproto_space_host") => space_host_endpoint(doc),
        Some(fragment) => service_endpoint(doc, fragment),
    }
    .map(str::to_string)
}

/// Whether a subscriber's service identifier resolves to a DID document with a matching service
/// endpoint — `registerNotify`'s `ServiceNotResolvable` check. Run at registration so a typo is
/// reported to the syncer that made it, rather than silently producing a subscription that never
/// delivers.
pub async fn service_is_resolvable(state: &SpacesState, service: &str) -> bool {
    let (did, fragment) = split_service(service);
    resolve_service_endpoint(state, did, fragment)
        .await
        .is_some()
}

async fn resolve_service_endpoint(
    state: &SpacesState,
    did: &str,
    fragment: Option<&str>,
) -> Option<String> {
    let doc = resolve_did_document(state, did).await.ok()?;
    endpoint_in(&doc, fragment)
}

#[cfg(test)]
mod tests {
    //! What actually leaves the machine. The route tests next door deliberately guarantee that
    //! nothing does (see `routes::space_notify_routes_test`), so the request Custos puts on a
    //! foreign space host's wire — body shape, `aud`/`lxm` scoping, the endpoint fallback, the
    //! retry ladder — is only observable here, against a wiremock standing in for that host.

    use super::*;
    use crate::db::dids::seed_did_document;
    use crate::db::space_notify::upsert_registration;
    use crate::db::spaces::{insert_space, NewSpace};
    use crate::space_uri::parse_space_ref;
    use crate::test_support::{seed_account_with_repo, state_with_master_key};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const AUTHORITY: &str = "did:plc:authoritynotifyaaaaaaaaa";
    const SYNCER: &str = "did:plc:syncernotifyaaaaaaaaaaaa";
    const WRITER: &str = "did:plc:writernotifyaaaaaaaaaaaa";
    const THROTTLER: &str = "did:plc:throttlernotifyaaaaaaaaa";
    const TIMED_OUT: &str = "did:plc:timedoutnotifyaaaaaaaaaa";
    const SPACE: &str = "at://did:plc:authoritynotifyaaaaaaaaa/space/org.example.bucket/main";

    /// A host that is the space's authority, holding the repo signing key every
    /// authority-side notification is minted against.
    async fn authority_state() -> SpacesState {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, AUTHORITY).await;
        seed_space(&state, Some("public")).await;
        state
    }

    /// The space's row: with a policy this host is its authority, without one it only keeps
    /// repos in it.
    async fn seed_space(state: &SpacesState, policy: Option<&str>) {
        insert_space(
            &state.db,
            &NewSpace {
                uri: SPACE,
                authority_did: AUTHORITY,
                space_type: "org.example.bucket",
                skey: "main",
                policy,
                app_access: policy.map(|_| "open"),
                app_allowed: None,
                managing_app: None,
                write_policy: None,
                write_managing_app: None,
            },
        )
        .await
        .unwrap();
    }

    /// A subscriber's DID document, publishing exactly one service entry.
    async fn seed_host(state: &SpacesState, did: &str, fragment: &str, endpoint: &str) {
        seed_did_document(
            &state.db,
            did,
            serde_json::json!({
                "id": did,
                "service": [{
                    "id": format!("#{fragment}"),
                    "type": "AtprotoSpaceHost",
                    "serviceEndpoint": endpoint,
                }],
            }),
        )
        .await;
    }

    async fn register(state: &SpacesState, service: &str) {
        upsert_registration(&state.db, SPACE, service, REGISTRATION_TTL_SECS)
            .await
            .unwrap();
    }

    fn notify_ok(lxm: &str) -> Mock {
        Mock::given(method("POST"))
            .and(path(format!("/xrpc/{lxm}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
    }

    async fn received(server: &MockServer) -> Vec<wiremock::Request> {
        server.received_requests().await.unwrap_or_default()
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

    /// The `notifyWrite` a foreign space host actually receives: the spec body, under a
    /// service-auth token scoped to that host and to that one method. The write's own origin is
    /// skipped, so a notification is never echoed back at its source.
    #[tokio::test]
    async fn notify_write_delivers_the_spec_body_under_method_scoped_service_auth() {
        let state = authority_state().await;
        let server = MockServer::start().await;
        notify_ok(NOTIFY_WRITE).mount(&server).await;

        // Both are registered and both resolve — only the origin skip keeps the writer's own
        // host off the wire.
        seed_host(&state, SYNCER, "atproto_space_host", &server.uri()).await;
        seed_host(&state, WRITER, "atproto_space_host", &server.uri()).await;
        register(&state, SYNCER).await;
        register(&state, WRITER).await;

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
        assert_eq!(requests.len(), 1, "the write's own origin must be skipped");
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
            serde_json::json!({
                "space": SPACE,
                "repo": WRITER,
                "repoRev": "3lzz",
                "hash": { "$bytes": "3q0=" },
                "spaceRev": "3m22",
                "prevSpaceRev": "3m21",
            }),
            "the hash rides as lexicon bytes, not a hex or multibase string"
        );

        let claims = claims(&requests[0]);
        assert_eq!(
            claims["iss"], AUTHORITY,
            "the authority speaks for its space"
        );
        assert_eq!(
            claims["aud"], SYNCER,
            "the aud is the bare DID — the #fragment names a service entry, not an audience"
        );
        assert_eq!(claims["lxm"], NOTIFY_WRITE);
    }

    /// The repo-host direction: a write into a space whose authority is elsewhere is one
    /// `notifyWrite` to that authority, signed by the writer, with no registration row left
    /// behind. The authority publishes only `#atproto_pds`, like the reference implementation and
    /// the hosted alpha, so this also pins the `#atproto_space_host` → `#atproto_pds` fallback.
    #[tokio::test]
    async fn a_repo_host_reports_once_to_the_authority_without_registering() {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, WRITER).await;
        seed_space(&state, None).await;
        let server = MockServer::start().await;
        notify_ok(NOTIFY_WRITE).mount(&server).await;
        seed_host(&state, AUTHORITY, "atproto_pds", &server.uri()).await;

        let space = parse_space_ref(SPACE).unwrap();
        report_write(&state, &space, WRITER, "3lzz", &[0xde, 0xad])
            .await
            .unwrap();

        let requests = received(&server).await;
        assert_eq!(requests.len(), 1, "exactly one report to the authority");
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
            serde_json::json!({
                "space": SPACE,
                "repo": WRITER,
                "repoRev": "3lzz",
                "hash": { "$bytes": "3q0=" },
            }),
            "a repo host assigns no spaceRev — that is the authority's job"
        );
        let claims = claims(&requests[0]);
        assert_eq!(claims["iss"], WRITER, "the repo host speaks for its user");
        assert_eq!(claims["aud"], AUTHORITY);
        assert_eq!(claims["lxm"], NOTIFY_WRITE);

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM space_notify_registrations")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(rows, 0, "reporting a write subscribes nobody");
    }

    /// A report is only ever sent for a space whose authority is elsewhere: called for a space
    /// this host is the authority for, it reaches nobody — no syncer, and not ourselves.
    #[tokio::test]
    async fn a_report_into_our_own_space_goes_nowhere() {
        let state = authority_state().await;
        let server = MockServer::start().await;
        notify_ok(NOTIFY_WRITE).mount(&server).await;
        seed_host(&state, SYNCER, "atproto_space_host", &server.uri()).await;
        seed_host(&state, AUTHORITY, "atproto_space_host", &server.uri()).await;
        register(&state, SYNCER).await;

        let space = parse_space_ref(SPACE).unwrap();
        report_write(&state, &space, WRITER, "3lzz", &[])
            .await
            .unwrap();
        assert!(received(&server).await.is_empty());
    }

    /// `notifySpaceDeleted` names the space and nothing else, under its own method scope.
    #[tokio::test]
    async fn notify_space_deleted_names_the_space_alone_under_its_own_lxm() {
        let state = authority_state().await;
        let server = MockServer::start().await;
        notify_ok(NOTIFY_SPACE_DELETED).mount(&server).await;
        seed_host(&state, SYNCER, "atproto_space_host", &server.uri()).await;

        let space = parse_space_ref(SPACE).unwrap();
        fan_out_space_deleted(&state, &space, vec![SYNCER.to_string()]);

        // Detached with no handle to await, unlike `forward_write`.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let requests = loop {
            let requests = received(&server).await;
            if !requests.is_empty() {
                break requests;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for the space-deleted notification"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        };

        assert_eq!(
            serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
            serde_json::json!({ "space": SPACE })
        );
        let claims = claims(&requests[0]);
        assert_eq!(claims["iss"], AUTHORITY);
        assert_eq!(claims["aud"], SYNCER);
        assert_eq!(claims["lxm"], NOTIFY_SPACE_DELETED);
    }

    /// The retry ladder. A 5xx, 408 or 429 is transient and spends every attempt; any other 4xx is the
    /// subscriber rejecting the argument, and re-sending it would only burn its capacity.
    #[tokio::test]
    async fn transient_failures_are_retried_and_rejections_are_not() {
        let state = authority_state().await;
        let body = serde_json::json!({ "space": SPACE });

        let flaky = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&flaky)
            .await;
        seed_host(&state, SYNCER, "atproto_space_host", &flaky.uri()).await;
        let error = deliver(&state, SYNCER, None, AUTHORITY, NOTIFY_WRITE, &body)
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
            seed_host(&state, did, "atproto_space_host", &server.uri()).await;
            deliver(&state, did, None, AUTHORITY, NOTIFY_WRITE, &body)
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
        seed_host(&state, WRITER, "atproto_space_host", &rejecting.uri()).await;
        let error = deliver(&state, WRITER, None, AUTHORITY, NOTIFY_WRITE, &body)
            .await
            .expect_err("a rejected argument is a permanent failure");
        assert!(error.contains("400"), "{error}");
        assert_eq!(
            received(&rejecting).await.len(),
            1,
            "a rejection must not be retried"
        );
    }

    /// Space-host resolution against a *real* foreign document — fetched live from the DID's own
    /// authority (a stand-in plc.directory), through `resolve_did_document` →
    /// `space_host_endpoint`, with the `#fragment` split applied to the service identifier.
    /// The document publishes no `#atproto_space_host`, exactly like the reference
    /// implementation and the hosted alpha.
    #[tokio::test]
    async fn a_foreign_did_resolves_to_its_space_host_through_the_pds_fallback() {
        let plc = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/did:plc:.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": SYNCER,
                "service": [{
                    "id": format!("{SYNCER}#atproto_pds"),
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://syncer.example.com",
                }],
            })))
            .mount(&plc)
            .await;
        let state = crate::test_support::test_state_with_plc_url(plc.uri()).await;

        assert_eq!(
            resolve_service_endpoint(&state, SYNCER, Some("atproto_space_host"))
                .await
                .unwrap(),
            "https://syncer.example.com",
            "the fully-qualified `did#atproto_pds` id form resolves, and covers the missing \
             #atproto_space_host"
        );
        assert!(service_is_resolvable(&state, &format!("{SYNCER}#atproto_space_host")).await);
        assert!(
            service_is_resolvable(&state, SYNCER).await,
            "a bare DID takes the same fallback"
        );
        assert!(
            !service_is_resolvable(&state, &format!("{SYNCER}#atproto_labeler")).await,
            "a fragment naming an entry the document lacks is not resolvable"
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
        let state = SpacesState::new(custos_core::CoreState {
            config: std::sync::Arc::new(config),
            ..base.core.clone()
        });
        seed_account_with_repo(&state.db, AUTHORITY).await;
        let body = serde_json::json!({ "space": SPACE });

        deliver(&state, SYNCER, None, AUTHORITY, NOTIFY_WRITE, &body)
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
        let error = deliver(&state, WRITER, None, AUTHORITY, NOTIFY_WRITE, &body)
            .await
            .expect_err("no endpoint");
        assert!(error.contains("no service endpoint"), "{error}");
    }
}
