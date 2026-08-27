// pattern: Imperative Shell

//! Shared ATProto identity-resolution helpers.
//!
//! Routes gather query/body parameters and delegate the actual lookup here, so `resolveHandle`,
//! `resolveIdentity`, `refreshIdentity`, and `resolveDid` all apply the same fallback chain:
//! local `handles` table → DNS TXT (`_atproto.<handle>`) → HTTP `.well-known/atproto-did`.
//!
//! DID-document reads are cache-first over two tiers, consulted in this order:
//!
//!   1. The `did_documents` table — this server's own accounts and migrated-in ones. No TTL,
//!      because we are the authority for those documents; `resolve_did_document_force_refresh`
//!      is the only path that un-stales a row (`db::dids::rewrite_did_document`, UPDATE-only),
//!      backing `refreshIdentity` and the migration-`createAccount` verify retry.
//!   2. `AppState::did_document_cache` — every *remote* document, held on the reference PDS's
//!      1h-stale / 24h-hard TTLs with stale-while-revalidate. Without it every proxied request,
//!      service-auth verification, and Lexicon-authority lookup pays a live fetch of
//!      plc.directory or a did:web endpoint, which puts a third party's latency (and its 504s)
//!      directly in our request path.
//!
//! A document reaching neither tier is fetched from its authority and recorded in tier 2 unless
//! it belongs to tier 1.
//!
//! The pure DID-document accessors at the bottom (`atproto_verification_key`, `service_endpoint`)
//! also carry the Atproto Spaces resolution fallbacks: `space_verification_key`
//! (`#atproto_space` → `#atproto`) and `space_host_endpoint` (`#atproto_space_host` →
//! `#atproto_pds`).
//!
//! The `atproto-proxy` header target guard (SSRF validation + the DNS-pinning hardened client)
//! lives in the sibling `proxy` module.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{ApiError, ErrorCode};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::app::AppState;

use super::proxy::validate_proxy_endpoint;

pub const INVALID_HANDLE: &str = "handle.invalid";

/// Resolve a handle to a DID using ezpds' ATProto handle-resolution chain:
/// local handles table → DNS TXT `_atproto.<handle>` → HTTP `.well-known/atproto-did`.
///
/// Infrastructure errors in DNS / well-known are logged and treated as misses so later fallbacks
/// still get a chance to resolve the handle. Database errors fail closed.
pub async fn resolve_handle_to_did(
    state: &AppState,
    handle: &str,
) -> Result<Option<String>, ApiError> {
    super::handle::validate_handle_structure(handle)
        .map_err(|message| ApiError::new(ErrorCode::InvalidHandle, message))?;

    let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
        .bind(handle)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, handle = %handle, "failed to query handle");
            ApiError::new(ErrorCode::InternalError, "handle lookup failed")
        })?;

    if let Some((did,)) = row {
        return Ok(Some(did));
    }

    if let Some(resolver) = &state.txt_resolver {
        let name = format!("_atproto.{handle}");
        match resolver.txt_lookup(&name).await {
            Ok(records) => {
                let mut dids: Vec<&str> = records
                    .iter()
                    .filter_map(|r| r.strip_prefix("did="))
                    .collect();
                dids.sort_unstable();
                dids.dedup();
                match dids.as_slice() {
                    [] => {}
                    [did] => return Ok(Some((*did).to_string())),
                    _ => {
                        // Per the handle spec, multiple `did=` TXT records naming different
                        // DIDs is ambiguous — resolution must not pick one by DNS answer order.
                        // Fall through to well-known rather than fail closed, matching the
                        // lookup-error handling below.
                        tracing::warn!(
                            handle = %handle,
                            count = dids.len(),
                            "ambiguous _atproto TXT records (multiple distinct DIDs); falling through to well-known"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    handle = %handle,
                    "DNS TXT lookup failed; falling through to well-known"
                );
            }
        }
    }

    if let Some(resolver) = &state.well_known_resolver {
        match resolver.resolve(handle).await {
            Ok(Some(did)) => return Ok(Some(did)),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    handle = %handle,
                    "HTTP well-known lookup failed"
                );
            }
        }
    }

    Ok(None)
}

// ── Remote DID-document cache ───────────────────────────────────────────────

/// How long a resolved remote document is served with no re-resolution at all.
const DID_CACHE_STALE_TTL: Duration = Duration::from_secs(60 * 60);

/// How long a resolved remote document may still be served *while* being re-resolved in the
/// background. Past this it is dropped and the next read blocks on the authority.
///
/// Both bounds match the reference PDS (`PDS_DID_CACHE_STALE_TTL` / `PDS_DID_CACHE_MAX_TTL`).
/// The gap between them is the point of the cache: inside it, an authority that is slow or
/// returning 504s costs a background task rather than a failed request.
const DID_CACHE_MAX_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Distinct DIDs held before the map is pruned. A document is a few hundred bytes, so this is a
/// bound on pathological growth rather than a tuned working-set size.
const DID_CACHE_MAX_ENTRIES: usize = 10_000;

pub struct CachedDidDocument {
    doc: Value,
    fetched_at: Instant,
    /// Set while a background refresh for this DID is in flight, so a burst of requests arriving
    /// against one stale entry spawns one refresh rather than one each.
    refreshing: bool,
}

/// TTL cache of *remote* DID documents, held in [`AppState`] and shared across all requests.
pub type DidDocumentCache = Arc<Mutex<HashMap<String, CachedDidDocument>>>;

/// Create an empty [`DidDocumentCache`].
pub fn new_did_document_cache() -> DidDocumentCache {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Decide what to do with a cache entry of a given age, latching `refreshing` when *this* caller
/// is the one that should refresh it.
///
/// `None` means the entry is past [`DID_CACHE_MAX_TTL`] and must not be served at all.
/// `Some(needs_refresh)` means serve it, re-resolving behind the response when `needs_refresh`.
/// Split out from [`cached_did_document`] so the TTL policy is checkable without winding a
/// monotonic clock backwards, which is not something `Instant` supports on a freshly booted host.
fn cache_decision(age: Duration, refreshing: &mut bool) -> Option<bool> {
    if age >= DID_CACHE_MAX_TTL {
        return None;
    }
    if age < DID_CACHE_STALE_TTL {
        return Some(false);
    }
    // Latch: of a burst arriving against one stale entry, only the first is asked to refresh.
    Some(!std::mem::replace(refreshing, true))
}

/// Read `did` from the remote-document cache.
///
/// Returns `(document, needs_refresh)` while the entry is servable per [`cache_decision`]. An
/// entry past the hard bound is dropped and reported as a miss, so the next read blocks on the
/// authority rather than serving it.
async fn cached_did_document(state: &AppState, did: &str) -> Option<(Value, bool)> {
    let mut map = state.did_document_cache.lock().await;

    let hit = match map.get_mut(did) {
        Some(entry) => cache_decision(entry.fetched_at.elapsed(), &mut entry.refreshing)
            .map(|needs_refresh| (entry.doc.clone(), needs_refresh)),
        None => None,
    };

    // A miss here means either no entry or an expired one; removing unconditionally retires the
    // latter without a second lookup, and is a no-op for the former.
    if hit.is_none() {
        map.remove(did);
    }

    hit
}

/// Record a freshly resolved remote document, replacing any existing entry (and clearing its
/// in-flight refresh flag).
async fn store_did_document(state: &AppState, did: &str, doc: &Value) {
    let mut map = state.did_document_cache.lock().await;

    // ponytail: prune-on-insert rather than LRU eviction — a cache this cheap to rebuild does not
    // justify tracking recency. If dropping expired entries leaves the map still at the cap then
    // every entry is live, and clearing beats growing without bound; swap in an LRU if the
    // re-resolution churn ever shows up in latency.
    if map.len() >= DID_CACHE_MAX_ENTRIES {
        map.retain(|_, entry| entry.fetched_at.elapsed() < DID_CACHE_MAX_TTL);
        if map.len() >= DID_CACHE_MAX_ENTRIES {
            map.clear();
        }
    }

    map.insert(
        did.to_string(),
        CachedDidDocument {
            doc: doc.clone(),
            fetched_at: Instant::now(),
            refreshing: false,
        },
    );
}

/// Re-resolve `did` off the request path and replace its cache entry.
///
/// Fire-and-forget: the caller has already been handed the stale document, so a failure is a
/// logged warning and nothing more — the entry keeps its old `fetched_at` and goes on being
/// served (and re-attempted) until [`DID_CACHE_MAX_TTL`] retires it. That is deliberate: an
/// authority that is down must not cost us a document we already hold.
fn spawn_did_document_refresh(state: &AppState, did: &str) {
    let state = state.clone();
    let did = did.to_string();

    tokio::spawn(async move {
        match fetch_did_document(&state, &did).await {
            // The replacement entry carries `refreshing: false`, so success clears the flag.
            Ok(doc) => store_did_document(&state, &did, &doc).await,
            Err(e) => {
                tracing::warn!(did = %did, error = %e, "background DID-document refresh failed; continuing to serve the stale document");
                if let Some(entry) = state.did_document_cache.lock().await.get_mut(&did) {
                    entry.refreshing = false;
                }
            }
        }
    });
}

/// Fetch a DID document from its authority, consulting no cache.
async fn fetch_did_document(state: &AppState, did: &str) -> Result<Value, ApiError> {
    if did.starts_with("did:plc:") {
        resolve_plc_did_document(state, did).await
    } else if did.starts_with("did:web:") {
        resolve_web_did_document(state, did).await
    } else {
        Err(ApiError::new(ErrorCode::DidNotFound, "DID not found"))
    }
}

/// Resolve a DID to its current DID document, preferring the local caches.
///
/// Reads the `did_documents` table first, then the remote-document TTL cache; only a DID in
/// neither reaches its authority — `did:plc` values through the configured PLC directory,
/// `did:web` values through the method's `did.json` URL. Returned documents must assert the
/// requested DID in their `id` field.
pub async fn resolve_did_document(state: &AppState, did: &str) -> Result<Value, ApiError> {
    resolve_did_document_inner(state, did, false).await
}

/// Resolve a DID to its current DID document, **bypassing both caches** and rewriting whichever
/// one holds the DID with the freshly-fetched document.
///
/// The `did_documents` table is a persistent store with no TTL: a DID whose PLC document was
/// rewritten after this server cached it (e.g. an `#atproto` key rotation during an account's
/// identity-migration leg) is otherwise served against the fossil key forever. This is the
/// "force refresh" the reference PDS's `refreshIdentity` performs, and the retry the migration
/// `createAccount` verifier takes on a signature failure. On success the fresh document is written
/// back over the existing cache row (UPDATE-only — see [`crate::db::dids::rewrite_did_document`]),
/// so a subsequent cache-first read (including this server's own `resolveDid`/`getSession`)
/// reflects it.
///
/// A remote DID has no such row; for those the fresh document replaces the TTL-cache entry
/// instead, which is what makes this the escape hatch for a rotation that lands inside
/// [`DID_CACHE_STALE_TTL`] — the service-auth verifier takes it on a signature failure precisely
/// so a stale cached key can never be the last word.
pub async fn resolve_did_document_force_refresh(
    state: &AppState,
    did: &str,
) -> Result<Value, ApiError> {
    resolve_did_document_inner(state, did, true).await
}

/// Force-refresh `did`'s document to heal a token whose signature failed against the cached
/// verification key, at most once per DID per cool-down window.
///
/// The one seam every signature-mismatch retry goes through — the space-token verifier
/// (`auth::space`) and the service-auth guard (`auth::service_auth`) both take this path, so the
/// cool-down and the `did_signature_refresh` counter are derived once for both. Callers reach it
/// only *after* a verification failed specifically on the signature: a fossil cached key is the
/// only reason a refresh could help (see [`resolve_did_document_force_refresh`]).
///
/// The refresh deliberately bypasses the TTL-less `did_documents` cache, so without a bound a
/// caller replaying one badly-signed token for a real DID buys an upstream plc.directory /
/// did:web fetch per request. A **suppressed** refresh returns `InvalidToken`: the cached document
/// was there and the signature did not verify against it, so that verdict stands. A refresh that
/// was attempted and **failed** returns the resolution error unchanged — an unreachable PLC
/// directory is not an invalid token, and each caller decides whether to surface or absorb it.
///
/// Deliberately *not* folded into [`resolve_did_document_force_refresh`] itself — `refreshIdentity`
/// and `activateAccount` call that as an explicit operator/user action, and throttling a refresh
/// someone asked for would break the healing they came for.
pub async fn refresh_did_document_after_signature_mismatch(
    state: &AppState,
    did: &str,
) -> Result<Value, ApiError> {
    let outcome = |o: &'static str| {
        state.metrics.did_signature_refresh.add(
            1,
            &[crate::metrics::label(
                crate::metrics::names::LABEL_OUTCOME,
                o,
            )],
        );
    };

    if !state.rate_limiter.allow_did_refresh(did) {
        outcome("rate_limited");
        tracing::debug!(
            did = %did,
            "signature-mismatch DID refresh suppressed by the per-DID cool-down"
        );
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "token signature does not verify against the issuer's published key",
        ));
    }

    tracing::info!(
        did = %did,
        "token signature failed against the cached DID document; \
         force-refreshing the key and retrying once"
    );
    match resolve_did_document_force_refresh(state, did).await {
        Ok(doc) => {
            outcome("ok");
            Ok(doc)
        }
        Err(e) => {
            outcome("error");
            Err(e)
        }
    }
}

async fn resolve_did_document_inner(
    state: &AppState,
    did: &str,
    force_refresh: bool,
) -> Result<Value, ApiError> {
    if !did.starts_with("did:") {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    if !force_refresh {
        if let Some(doc) = crate::db::dids::get_did_document(&state.db, did).await? {
            return validate_did_doc_id(doc, did, ErrorCode::InternalError);
        }
        if let Some((doc, needs_refresh)) = cached_did_document(state, did).await {
            if needs_refresh {
                spawn_did_document_refresh(state, did);
            }
            return Ok(doc);
        }
    }

    let doc = fetch_did_document(state, did).await?;

    // Heal the `did_documents` row so subsequent cache-first reads reflect the fresh document.
    // Best-effort: the authority already answered, so a cache-write failure must not fail the
    // resolution. The UPDATE's row count also tells us which tier this DID belongs to.
    let mut has_db_row = false;
    if force_refresh {
        match crate::db::dids::rewrite_did_document(&state.db, did, &doc).await {
            Ok(updated) => has_db_row = updated,
            Err(e) => {
                tracing::warn!(did = %did, error = %e, "failed to rewrite cached DID document after force refresh (non-fatal)");
            }
        }
    }

    // Tier 2 holds remote documents only. A DID with a `did_documents` row is served from that
    // row before this cache is consulted, so an entry for one would be dead weight — and would
    // outlive a purged row, resurrecting a deleted account's document for the rest of the TTL.
    if !has_db_row {
        store_did_document(state, did, &doc).await;
    }

    Ok(doc)
}

/// Return the verified handle for `did` and `did_doc`, or `handle.invalid` when the document's
/// `alsoKnownAs` handles do not resolve back to the DID.
pub async fn verified_handle_for_did(
    state: &AppState,
    did: &str,
    did_doc: &Value,
) -> Result<String, ApiError> {
    for handle in also_known_as_handles(did_doc) {
        if resolve_handle_to_did(state, &handle).await?.as_deref() == Some(did) {
            return Ok(handle);
        }
    }

    Ok(INVALID_HANDLE.to_string())
}

/// Verify a caller-provided handle against a DID document and the handle-resolution chain.
pub async fn verified_handle_for_identifier(
    state: &AppState,
    did: &str,
    did_doc: &Value,
    handle: &str,
) -> Result<String, ApiError> {
    let asserted = also_known_as_handles(did_doc)
        .into_iter()
        .any(|candidate| candidate == handle);
    if !asserted {
        return Ok(INVALID_HANDLE.to_string());
    }

    if resolve_handle_to_did(state, handle).await?.as_deref() == Some(did) {
        Ok(handle.to_string())
    } else {
        Ok(INVALID_HANDLE.to_string())
    }
}

async fn resolve_plc_did_document(state: &AppState, did: &str) -> Result<Value, ApiError> {
    let plc_url = format!(
        "{}/{}",
        state.config.plc_directory_url.trim_end_matches('/'),
        did
    );
    let response = state.http_client.get(&plc_url).send().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, plc_url = %plc_url, "failed to contact plc.directory");
        ApiError::new(ErrorCode::PlcDirectoryError, "failed to contact plc.directory")
    })?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        tracing::debug!(did = %did, "DID not found in plc.directory");
        return Err(ApiError::new(ErrorCode::DidNotFound, "DID not found"));
    }

    if response.status() == reqwest::StatusCode::GONE {
        tracing::debug!(did = %did, "DID deactivated in plc.directory");
        return Err(ApiError::new(ErrorCode::DidDeactivated, "DID deactivated"));
    }

    if !response.status().is_success() {
        let status = response.status();
        let truncated = bounded_body_preview(response).await;
        tracing::error!(did = %did, status = %status, response_body = %truncated, "plc.directory returned error");
        return Err(ApiError::new(
            ErrorCode::PlcDirectoryError,
            "plc.directory returned error",
        ));
    }

    let doc: Value = response.json().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to parse plc.directory response");
        ApiError::new(
            ErrorCode::PlcDirectoryError,
            "invalid response from plc.directory",
        )
    })?;

    validate_did_doc_id(doc, did, ErrorCode::PlcDirectoryError)
}

pub(crate) async fn resolve_web_did_document(
    state: &AppState,
    did: &str,
) -> Result<Value, ApiError> {
    let url = did_web_document_url(did)?;
    // The did:web authority is caller-controlled (the requested `did`), so this fetch is
    // SSRF-guarded exactly like resolve_web_did_document_bytes: validate the endpoint's URL shape
    // (and, for an IP literal, its address), then send on the shared hardened client whose DNS
    // resolver re-checks any domain-name resolution against the allowlist at connect time.
    let authority = did_web_authority(&url)?;
    validate_proxy_endpoint(&authority, state.allow_loopback_proxy_targets).await?;
    let response = state.hardened_http_client.get(&url).send().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, url = %url, "failed to resolve did:web document");
        ApiError::new(
            ErrorCode::PlcDirectoryError,
            "failed to resolve did:web document",
        )
    })?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(ApiError::new(ErrorCode::DidNotFound, "DID not found"));
    }

    if response.status() == reqwest::StatusCode::GONE {
        tracing::debug!(did = %did, "DID deactivated at did:web endpoint");
        return Err(ApiError::new(ErrorCode::DidDeactivated, "DID deactivated"));
    }

    if !response.status().is_success() {
        let status = response.status();
        let truncated = bounded_body_preview(response).await;
        tracing::error!(did = %did, status = %status, response_body = %truncated, "did:web endpoint returned error");
        return Err(ApiError::new(
            ErrorCode::PlcDirectoryError,
            "did:web endpoint returned error",
        ));
    }

    let doc: Value = response.json().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to parse did:web response");
        ApiError::new(ErrorCode::PlcDirectoryError, "invalid did:web response")
    })?;

    validate_did_doc_id(doc, did, ErrorCode::PlcDirectoryError)
}

/// Fetch the authoritative did:web response without normalizing JSON whitespace or key order.
/// The wallet mint ceremony uses this to prove the user published the exact reviewed bytes.
pub(crate) async fn resolve_web_did_document_bytes(
    state: &AppState,
    did: &str,
) -> Result<String, ApiError> {
    let url = did_web_document_url(did)?;
    let authority = did_web_authority(&url)?;
    validate_proxy_endpoint(&authority, state.allow_loopback_proxy_targets).await?;
    let response = state.hardened_http_client.get(&url).send().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, url = %url, "failed to resolve did:web document bytes");
        ApiError::new(
            ErrorCode::PlcDirectoryError,
            "failed to resolve did:web document",
        )
    })?;
    if !response.status().is_success() {
        return Err(ApiError::new(
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                ErrorCode::DidNotFound
            } else {
                ErrorCode::PlcDirectoryError
            },
            "did:web endpoint returned error",
        ));
    }
    response.text().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to read did:web document bytes");
        ApiError::new(ErrorCode::PlcDirectoryError, "invalid did:web response")
    })
}

fn validate_did_doc_id(doc: Value, did: &str, error_code: ErrorCode) -> Result<Value, ApiError> {
    if doc.get("id").and_then(Value::as_str) == Some(did) {
        Ok(doc)
    } else {
        tracing::warn!(did = %did, doc_id = ?doc.get("id"), "DID document id mismatch");
        Err(ApiError::new(error_code, "DID document id mismatch"))
    }
}

const ERROR_BODY_PREVIEW_BYTES: usize = 2048;

/// Read up to [`ERROR_BODY_PREVIEW_BYTES`] of an error response body for logging, instead of
/// buffering the whole thing — an erroneous upstream (plc.directory, a did:web endpoint) is not
/// trusted to bound its own response size. Shared with `identity::genesis`'s plc.directory POST.
pub(crate) async fn bounded_body_preview(mut response: reqwest::Response) -> String {
    let mut body = Vec::new();
    while body.len() < ERROR_BODY_PREVIEW_BYTES {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) | Err(_) => break,
        };
        let remaining = ERROR_BODY_PREVIEW_BYTES - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }

    safe_body_preview(&String::from_utf8_lossy(&body))
}

fn safe_body_preview(body: &str) -> String {
    body.chars().take(500).collect()
}

/// Extract the `https://host[:port]` authority from an already-built did:web document URL, for the
/// SSRF `validate_proxy_endpoint` shape check. Shared by both did:web fetch paths.
fn did_web_authority(url: &str) -> Result<String, ApiError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| ApiError::new(ErrorCode::InvalidClaim, "invalid did:web DID"))?;
    parsed
        .host_str()
        .map(|host| match parsed.port() {
            Some(port) => format!("https://{host}:{port}"),
            None => format!("https://{host}"),
        })
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidClaim, "invalid did:web DID"))
}

fn did_web_document_url(did: &str) -> Result<String, ApiError> {
    let method_specific = did
        .strip_prefix("did:web:")
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidClaim, "invalid did:web DID"))?;
    if method_specific.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "invalid did:web DID",
        ));
    }

    let segments = method_specific
        .split(':')
        .map(|segment| {
            urlencoding::decode(segment)
                .map(|decoded| decoded.into_owned())
                .map_err(|_| ApiError::new(ErrorCode::InvalidClaim, "invalid did:web DID"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let Some(host) = segments.first() else {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "invalid did:web DID",
        ));
    };
    if host.is_empty()
        || forbidden_did_web_authority(host)
        || segments.iter().any(|segment| {
            segment.is_empty()
                || segment.contains('/')
                || segment.contains('\\')
                || segment.contains('?')
                || segment.contains('#')
        })
    {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "invalid did:web DID",
        ));
    }

    if segments.len() == 1 {
        Ok(format!("https://{host}/.well-known/did.json"))
    } else {
        let path = segments[1..].join("/");
        Ok(format!("https://{host}/{path}/did.json"))
    }
}

fn forbidden_did_web_authority(authority: &str) -> bool {
    if authority.contains('@') || authority.contains('[') || authority.contains(']') {
        return true;
    }

    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => host,
        Some(_) => return true,
        None => authority,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();

    host == "localhost" || host.ends_with(".localhost") || host.parse::<IpAddr>().is_ok()
}

/// Extract the account's `#atproto` repo signing key from a resolved DID document as a
/// `did:key:` URI. Walks the W3C `verificationMethod` array for the entry whose `id` ends in
/// `#atproto` and returns `did:key:{publicKeyMultibase}`. Returns `None` if absent or malformed.
///
/// Used by migration-mode `createAccount` to verify a foreign old-PDS-signed service-auth JWT
/// against the migrating identity's own signing key.
pub fn atproto_verification_key(did_doc: &Value) -> Option<crypto::DidKeyUri> {
    verification_key(did_doc, "atproto")
}

/// The key a space authority signs space credentials with: its `#atproto_space` verification
/// method, falling back to `#atproto` when the optional dedicated entry is absent (Atproto
/// Spaces, proposal 0016). Consumed by `auth::space::verify_space_credential`.
pub fn space_verification_key(did_doc: &Value) -> Option<crypto::DidKeyUri> {
    dedicated_space_verification_key(did_doc).or_else(|| atproto_verification_key(did_doc))
}

/// The authority's dedicated `#atproto_space` verification method alone — no `#atproto`
/// fallback. Lets a credential verifier tell "publishes no space key" from "publishes one", so
/// an authority that separated its space key from its repo key is never verified against the
/// repo key.
pub fn dedicated_space_verification_key(did_doc: &Value) -> Option<crypto::DidKeyUri> {
    verification_key(did_doc, "atproto_space")
}

/// The endpoint a space authority is reached at as the space host: its `#atproto_space_host`
/// service, falling back to `#atproto_pds` when the optional dedicated entry is absent
/// (Atproto Spaces, proposal 0016). Consumed by the space-host routing that lands with the
/// space write/notify surface; published ahead of it like `space_verification_key`.
#[allow(dead_code)]
pub fn space_host_endpoint(did_doc: &Value) -> Option<&str> {
    service_endpoint(did_doc, "atproto_space_host")
        .or_else(|| service_endpoint(did_doc, "atproto_pds"))
}

/// The `did:key:` URI of the `verificationMethod` entry whose `id` ends in `#{fragment}` —
/// matching both the abbreviated (`#atproto`) and fully-qualified (`did#atproto`) id forms.
fn verification_key(did_doc: &Value, fragment: &str) -> Option<crypto::DidKeyUri> {
    let suffix = format!("#{fragment}");
    did_doc
        .get("verificationMethod")?
        .as_array()?
        .iter()
        .find_map(|method| {
            let id = method.get("id")?.as_str()?;
            if !id.ends_with(&suffix) {
                return None;
            }
            let multibase = method.get("publicKeyMultibase")?.as_str()?;
            Some(crypto::DidKeyUri(format!("did:key:{multibase}")))
        })
}

/// The `serviceEndpoint` of the `service` entry whose `id` ends in `#{fragment}` — matching
/// both the abbreviated (`#atproto_pds`) and fully-qualified (`did#atproto_pds`) id forms.
pub fn service_endpoint<'a>(did_doc: &'a Value, fragment: &str) -> Option<&'a str> {
    let suffix = format!("#{fragment}");
    did_doc
        .get("service")?
        .as_array()?
        .iter()
        .find(|entry| {
            entry
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| id.ends_with(&suffix))
        })?
        .get("serviceEndpoint")?
        .as_str()
}

fn also_known_as_handles(did_doc: &Value) -> Vec<String> {
    did_doc
        .get("alsoKnownAs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|alias| alias.strip_prefix("at://"))
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        did_web_document_url, refresh_did_document_after_signature_mismatch, safe_body_preview,
        service_endpoint, space_host_endpoint, space_verification_key,
    };
    use common::ErrorCode;

    /// The cool-down admits one signature-mismatch refresh per DID per window, and denies the
    /// next one *without* going upstream: the PLC directory here is an unroutable address, so a
    /// refresh that actually fetched would spend the client timeout and report a PLC error. The
    /// suppressed call must come back promptly as an `InvalidToken` signature verdict instead.
    #[tokio::test]
    async fn signature_mismatch_refresh_is_cooled_down_per_did() {
        let mut state =
            crate::app::test_state_with_plc_url("http://127.0.0.1:1/plc".to_string()).await;
        state.rate_limiter = std::sync::Arc::new(crate::rate_limit::RateLimiterState::new(
            &common::RateLimitConfig {
                enabled: true,
                ..common::RateLimitConfig::default()
            },
        ));

        let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";

        // First attempt spends the allowance and really tries: the unreachable directory's error
        // passes through unflattened, so a caller can still tell "PLC is down" from "bad token".
        let attempted = refresh_did_document_after_signature_mismatch(&state, did)
            .await
            .expect_err("unreachable PLC directory must fail");
        assert_ne!(*attempted.code(), ErrorCode::InvalidToken);

        // Second attempt inside the window is suppressed — no fetch, and the signature-mismatch
        // verdict stands.
        let suppressed = refresh_did_document_after_signature_mismatch(&state, did)
            .await
            .expect_err("the cool-down must deny the second refresh");
        assert_eq!(*suppressed.code(), ErrorCode::InvalidToken);

        // The cool-down is per DID: a different issuer is unaffected.
        let other = refresh_did_document_after_signature_mismatch(
            &state,
            "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .await
        .expect_err("unreachable PLC directory must fail");
        assert_ne!(*other.code(), ErrorCode::InvalidToken);
    }

    fn doc(methods: &[(&str, &str)], services: &[(&str, &str)]) -> serde_json::Value {
        serde_json::json!({
            "id": "did:plc:space",
            "verificationMethod": methods.iter().map(|(id, key)| serde_json::json!({
                "id": id, "type": "Multikey", "controller": "did:plc:space", "publicKeyMultibase": key
            })).collect::<Vec<_>>(),
            "service": services.iter().map(|(id, endpoint)| serde_json::json!({
                "id": id, "type": "AtprotoPersonalDataServer", "serviceEndpoint": endpoint
            })).collect::<Vec<_>>(),
        })
    }

    #[test]
    fn space_entries_win_when_published() {
        let doc = doc(
            &[
                ("did:plc:space#atproto", "zRepo"),
                ("#atproto_space", "zSpace"),
            ],
            &[
                ("#atproto_pds", "https://pds.example.com"),
                (
                    "did:plc:space#atproto_space_host",
                    "https://space.example.com",
                ),
            ],
        );
        assert_eq!(space_verification_key(&doc).unwrap().0, "did:key:zSpace");
        assert_eq!(space_host_endpoint(&doc), Some("https://space.example.com"));
    }

    #[test]
    fn space_entries_fall_back_to_atproto_and_pds() {
        let doc = doc(
            &[("did:plc:space#atproto", "zRepo")],
            &[("#atproto_pds", "https://pds.example.com")],
        );
        assert_eq!(space_verification_key(&doc).unwrap().0, "did:key:zRepo");
        assert_eq!(space_host_endpoint(&doc), Some("https://pds.example.com"));
        // `#atproto_space` must not be mistaken for `#atproto` by a suffix match, and vice versa.
        let only_space = doc_with_only_space();
        assert_eq!(
            space_verification_key(&only_space).unwrap().0,
            "did:key:zSpace"
        );
        assert!(service_endpoint(&only_space, "atproto_pds").is_none());
        assert_eq!(
            space_host_endpoint(&only_space),
            Some("https://space.example.com")
        );
    }

    fn doc_with_only_space() -> serde_json::Value {
        doc(
            &[("#atproto_space", "zSpace")],
            &[("#atproto_space_host", "https://space.example.com")],
        )
    }

    #[test]
    fn space_helpers_are_none_on_an_empty_document() {
        let doc = serde_json::json!({ "id": "did:plc:space" });
        assert!(space_verification_key(&doc).is_none());
        assert!(space_host_endpoint(&doc).is_none());
    }

    #[test]
    fn did_web_url_uses_well_known_for_bare_domain() {
        assert_eq!(
            did_web_document_url("did:web:example.com").unwrap(),
            "https://example.com/.well-known/did.json"
        );
    }

    #[test]
    fn did_web_url_uses_path_segments_when_present() {
        assert_eq!(
            did_web_document_url("did:web:example.com:users:alice").unwrap(),
            "https://example.com/users/alice/did.json"
        );
    }

    #[test]
    fn did_web_url_decodes_percent_encoded_host_port() {
        assert_eq!(
            did_web_document_url("did:web:example.com%3A8443").unwrap(),
            "https://example.com:8443/.well-known/did.json"
        );
    }

    #[test]
    fn did_web_url_rejects_path_separator_inside_segment() {
        assert!(did_web_document_url("did:web:example.com:%2Fadmin").is_err());
    }

    #[test]
    fn did_web_url_rejects_userinfo_loopback_and_ip_literals() {
        assert!(did_web_document_url("did:web:user%40example.com").is_err());
        assert!(did_web_document_url("did:web:localhost").is_err());
        assert!(did_web_document_url("did:web:sub.localhost").is_err());
        assert!(did_web_document_url("did:web:127.0.0.1").is_err());
        assert!(did_web_document_url("did:web:10.0.0.1%3A8443").is_err());
        assert!(did_web_document_url("did:web:%5B%3A%3A1%5D").is_err());
        assert!(did_web_document_url("did:web:%3A443").is_err());
        assert!(did_web_document_url("did:web:example.com%3A99999").is_err());
    }

    #[test]
    fn safe_body_preview_truncates_on_char_boundary() {
        let preview = safe_body_preview(&"é".repeat(600));
        assert_eq!(preview.chars().count(), 500);
        assert!(preview.is_char_boundary(preview.len()));
    }

    #[test]
    fn cache_decision_follows_the_reference_ttls() {
        use super::{cache_decision, DID_CACHE_MAX_TTL, DID_CACHE_STALE_TTL};
        use std::time::Duration;

        let second = Duration::from_secs(1);
        let mut refreshing = false;

        // Under the stale bound: served untouched, nobody refreshes.
        assert_eq!(cache_decision(Duration::ZERO, &mut refreshing), Some(false));
        assert_eq!(
            cache_decision(DID_CACHE_STALE_TTL - second, &mut refreshing),
            Some(false)
        );
        assert!(!refreshing);

        // Between the bounds: still served, and the *first* caller is the one told to refresh.
        assert_eq!(
            cache_decision(DID_CACHE_STALE_TTL, &mut refreshing),
            Some(true)
        );
        assert!(refreshing);
        assert_eq!(
            cache_decision(DID_CACHE_MAX_TTL - second, &mut refreshing),
            Some(false)
        );

        // Past the hard bound: not served at all, however recently a refresh was attempted.
        assert_eq!(cache_decision(DID_CACHE_MAX_TTL, &mut refreshing), None);
    }

    #[tokio::test]
    async fn remote_documents_round_trip_through_the_cache() {
        use super::{cached_did_document, store_did_document};

        let state = crate::state::test_state().await;
        let did = "did:web:api.bsky.app";
        let doc = serde_json::json!({ "id": did });

        assert!(cached_did_document(&state, did).await.is_none());

        store_did_document(&state, did, &doc).await;
        assert_eq!(
            cached_did_document(&state, did).await,
            Some((doc, false)),
            "a freshly stored document is served without asking for a refresh"
        );
    }
}
