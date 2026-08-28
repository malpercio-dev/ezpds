// pattern: Imperative Shell

//! Outbound Atproto Spaces write notifications — the space-host role's fan-out.
//!
//! Two directions ride one path, because a host is often both at once:
//!
//! * **Repo host → space host.** A user's write into a space whose authority lives elsewhere is
//!   reported to that authority so it can maintain the writer set `listRepos` answers. The
//!   subscription is created by the write itself (the spec's auto-registration): every commit
//!   upserts a per-repo registration naming the authority's `#atproto_space_host`, which both
//!   establishes it on the first write and renews it on every later one.
//! * **Space host → registered syncers.** A write to any repo in a space we are the authority
//!   for — our own account's, or one an inbound `notifyWrite` told us about — is forwarded to
//!   every service that called `registerNotify`.
//!
//! **Best-effort, by spec.** Nothing here blocks a commit: the durable write has already landed
//! and returned before the fan-out task is spawned. Each delivery is retried with backoff and
//! then dropped; a subscriber that missed one heals from the set hash on its next
//! `listRepoOps`, or from the periodic `listRepos` sweep. A permanent failure deliberately does
//! **not** unregister the subscriber — a syncer that is briefly down or mid-deploy would
//! silently lose its subscription — so registrations lapse only at their own expiry.
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

use crate::app::AppState;
use crate::auth::space::unix_now;
use crate::identity::resolution::{resolve_did_document, service_endpoint, space_host_endpoint};
use crate::space_uri::SpaceRef;

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

/// The permits behind [`MAX_CONCURRENT_FANOUTS`]. Process-global rather than an `AppState`
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

/// Announce that `repo_did`'s repo in `space` advanced to `rev`/`hash`.
///
/// Returns immediately: the registration upsert and every delivery happen on a detached task, so
/// a write path calls this after its commit and never waits. `repo_did` is also the DID whose
/// host already knows about this write — the repo itself for our own commit, and likewise for an
/// inbound `notifyWrite` we are forwarding — so it is skipped in the fan-out and a notification
/// is never echoed back at its source.
///
/// The [`JoinHandle`](tokio::task::JoinHandle) is returned rather than dropped so a test can
/// await the effects; production callers discard it, since a commit must never wait on delivery.
pub fn fan_out_write(
    state: &AppState,
    space: &SpaceRef,
    repo_did: &str,
    rev: &str,
    hash: &[u8],
) -> tokio::task::JoinHandle<()> {
    let state = state.clone();
    let space = space.clone();
    let repo_did = repo_did.to_string();
    let body = serde_json::json!({
        "space": space.uri,
        "repo": repo_did,
        "rev": rev,
        "hash": crate::routes::space_views::lex_bytes(hash),
    });
    tokio::spawn(async move {
        let _permit = fanout_permits().acquire().await;

        // Whether this host is the space's authority: a `spaces` row with simplespace config.
        // Also picks the signer — as the authority we speak for the space, otherwise we speak
        // for the account whose repo advanced.
        let is_authority = match crate::db::spaces::get_space(&state.db, &space.uri).await {
            Ok(Some(row)) if row.deleted_at.is_none() => row.policy.is_some(),
            Ok(_) => return,
            Err(error) => {
                tracing::debug!(%error, space = %space.uri, "space notify: failed to load space");
                return;
            }
        };

        // Repo host: (re-)subscribe the authority to this repo before looking for subscribers, so
        // the very first write into a shared space already reaches it.
        if !is_authority {
            let service = crate::auth::space::space_host_aud(&space);
            if let Err(error) = crate::db::space_notify::upsert_registration(
                &state.db,
                &space.uri,
                &service,
                &repo_did,
                REGISTRATION_TTL_SECS,
            )
            .await
            {
                tracing::debug!(%error, space = %space.uri, "space notify: authority auto-registration failed");
            }
        }

        let signer_did = if is_authority {
            space.authority.clone()
        } else {
            repo_did.clone()
        };
        let subscribers = match crate::db::space_notify::subscribers_for_write(
            &state.db,
            &space.uri,
            &repo_did,
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
            &signer_did,
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
pub fn fan_out_space_deleted(state: &AppState, space: &SpaceRef, subscribers: Vec<String>) {
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
    state: &AppState,
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

/// Resolve one subscriber, mint a service-auth token for the single method, and POST — retrying
/// transport failures and 5xx with doubling backoff. A 4xx is permanent: retrying an argument
/// the subscriber has already rejected only wastes its capacity.
async fn deliver(
    state: &AppState,
    did: &str,
    fragment: Option<&str>,
    signer_did: &str,
    lxm: &str,
    body: &Value,
) -> Result<(), String> {
    let endpoint = resolve_service_endpoint(state, did, fragment).await?;
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

    let url = format!("{}/xrpc/{lxm}", endpoint.trim_end_matches('/'));
    let mut backoff = BASE_BACKOFF;
    let mut last = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        // The SSRF-hardened client: the endpoint comes from a DID document a caller named at
        // registerNotify, so it is a caller-influenced target like every other one.
        match state
            .hardened_http_client
            .post(&url)
            .bearer_auth(&token)
            .json(body)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) if response.status().is_client_error() => {
                return Err(format!("subscriber rejected: {}", response.status()));
            }
            Ok(response) => last = format!("subscriber returned {}", response.status()),
            Err(error) => last = error.to_string(),
        }
        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(backoff).await;
            backoff *= 2;
        }
    }
    Err(last)
}

/// The URL to deliver to: the named entry of the subscriber's DID document. An identifier with
/// no fragment — and the `#atproto_space_host` one a repo host auto-registers — fall back to
/// `#atproto_pds`, which is where the alpha's own hosts answer (see
/// `identity::resolution::space_host_endpoint`).
async fn resolve_service_endpoint(
    state: &AppState,
    did: &str,
    fragment: Option<&str>,
) -> Result<String, String> {
    let doc = resolve_did_document(state, did)
        .await
        .map_err(|e| e.to_string())?;
    let endpoint = match fragment {
        None | Some("atproto_space_host") => space_host_endpoint(&doc),
        Some(fragment) => service_endpoint(&doc, fragment),
    };
    endpoint
        .map(str::to_string)
        .ok_or_else(|| format!("no service endpoint for {did}"))
}

/// Whether a subscriber's service identifier resolves to a DID document with a matching service
/// endpoint — `registerNotify`'s `ServiceNotResolvable` check. Run at registration so a typo is
/// reported to the syncer that made it, rather than silently producing a subscription that never
/// delivers.
pub async fn service_is_resolvable(state: &AppState, service: &str) -> bool {
    let (did, fragment) = split_service(service);
    resolve_service_endpoint(state, did, fragment).await.is_ok()
}

#[cfg(test)]
mod tests {
    //! What actually leaves the machine. The route tests next door deliberately guarantee that
    //! nothing does (see `routes::space_notify_routes_test`), so the request Custos puts on a
    //! foreign space host's wire — body shape, `aud`/`lxm` scoping, the endpoint fallback, the
    //! retry ladder — is only observable here, against a wiremock standing in for that host.

    use super::*;
    use crate::db::dids::seed_did_document;
    use crate::db::space_notify::{upsert_registration, WHOLE_SPACE};
    use crate::db::spaces::{insert_space, NewSpace};
    use crate::routes::test_utils::{seed_account_with_repo, state_with_master_key};
    use crate::space_uri::parse_space_ref;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const AUTHORITY: &str = "did:plc:authoritynotifyaaaaaaaaa";
    const SYNCER: &str = "did:plc:syncernotifyaaaaaaaaaaaa";
    const WRITER: &str = "did:plc:writernotifyaaaaaaaaaaaa";
    const SPACE: &str = "at://did:plc:authoritynotifyaaaaaaaaa/space/org.example.bucket/main";

    /// A host that is the space's authority, holding the repo signing key every
    /// authority-side notification is minted against.
    async fn authority_state() -> AppState {
        let state = state_with_master_key().await;
        seed_account_with_repo(&state.db, AUTHORITY).await;
        insert_space(
            &state.db,
            &NewSpace {
                uri: SPACE,
                authority_did: AUTHORITY,
                space_type: "org.example.bucket",
                skey: "main",
                policy: Some("public"),
                app_access: Some("open"),
                app_allowed: None,
                managing_app: None,
            },
        )
        .await
        .unwrap();
        state
    }

    /// A subscriber's DID document, publishing exactly one service entry.
    async fn seed_host(state: &AppState, did: &str, fragment: &str, endpoint: &str) {
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

    async fn register(state: &AppState, service: &str) {
        upsert_registration(
            &state.db,
            SPACE,
            service,
            WHOLE_SPACE,
            REGISTRATION_TTL_SECS,
        )
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
        fan_out_write(&state, &space, WRITER, "3lzz", &[0xde, 0xad])
            .await
            .unwrap();

        let requests = received(&server).await;
        assert_eq!(requests.len(), 1, "the write's own origin must be skipped");
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
            serde_json::json!({
                "space": SPACE,
                "repo": WRITER,
                "rev": "3lzz",
                "hash": { "$bytes": "3q0=" },
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

    /// The endpoint fallback that *is* the interop path: neither the reference implementation
    /// nor the hosted alpha publishes an `#atproto_space_host` service, while the repo-host
    /// auto-registration always names one. Both have to land on `#atproto_pds`.
    #[tokio::test]
    async fn the_auto_registered_space_host_fragment_falls_back_to_atproto_pds() {
        let state = authority_state().await;
        let server = MockServer::start().await;
        notify_ok(NOTIFY_WRITE).mount(&server).await;

        seed_host(&state, SYNCER, "atproto_pds", &server.uri()).await;
        register(&state, &format!("{SYNCER}#atproto_space_host")).await;

        let space = parse_space_ref(SPACE).unwrap();
        fan_out_write(&state, &space, WRITER, "3lzz", &[])
            .await
            .unwrap();

        let requests = received(&server).await;
        assert_eq!(
            requests.len(),
            1,
            "a host with only #atproto_pds is reachable"
        );
        assert_eq!(claims(&requests[0])["aud"], SYNCER);
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

        // Detached with no handle to await, unlike `fan_out_write`.
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

    /// The retry ladder. A 5xx is transient and spends every attempt; a 4xx is the subscriber
    /// rejecting the argument, and re-sending it would only burn its capacity.
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
        let state = crate::state::test_state_with_plc_url(plc.uri()).await;

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
}
