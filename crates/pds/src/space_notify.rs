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
//! **Bounded.** One detached task per notification, delivering to at most
//! [`MAX_SUBSCRIBERS`] subscribers in sequence. A busy space costs one task and one connection
//! at a time, not a spawn storm per commit.

use std::time::Duration;

use serde_json::Value;

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
